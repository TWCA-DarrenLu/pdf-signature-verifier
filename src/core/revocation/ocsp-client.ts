import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'
import type { ParsedCertificate, RevocationResult, RevocationReason } from '@/types'
import { t } from '@/i18n'
import { toArrayBuffer, asBufferSource } from '../bytes'

const { OCSPRequest, OCSPResponse, BasicOCSPResponse, CertID } = pkijs

/**
 * Check certificate revocation status via OCSP
 */
export async function checkOcspStatus(
  certificate: ParsedCertificate,
  issuerCertificate: ParsedCertificate
): Promise<RevocationResult> {
  const ocspUrls = certificate.authorityInfoAccess?.ocsp || []

  if (ocspUrls.length === 0) {
    return {
      status: 'unknown',
      checkedAt: new Date(),
      method: 'ocsp',
      details: t('core.revocation.noOcspUrl'),
      detailsI18nKey: 'core.revocation.noOcspUrl',
    }
  }

  for (const url of ocspUrls) {
    try {
      const result = await queryOcsp(url, certificate, issuerCertificate)
      return result
    } catch (error) {
      console.warn(`OCSP query to ${url} failed:`, error)
      continue
    }
  }

  return {
    status: 'error',
    checkedAt: new Date(),
    method: 'ocsp',
    details: t('core.revocation.allOcspFailed'),
    detailsI18nKey: 'core.revocation.allOcspFailed',
  }
}

/**
 * Query a single OCSP responder
 */
async function queryOcsp(
  url: string,
  certificate: ParsedCertificate,
  issuerCertificate: ParsedCertificate
): Promise<RevocationResult> {
  // Build OCSP request
  const ocspRequest = await buildOcspRequest(certificate, issuerCertificate)
  const requestData = ocspRequest.toSchema(true).toBER()

  // Send request via background script (to avoid CORS issues)
  const response = await sendOcspRequest(url, new Uint8Array(requestData))

  if (!response) {
    throw new Error('No response from OCSP responder')
  }

  // Parse response and append issuer info
  const result = parseOcspResponse(response)
  const issuerSuffix = t('core.revocation.issuerSuffix', { issuer: issuerCertificate.subject })
  return {
    ...result,
    details: `${result.details}${issuerSuffix}`,
    detailsI18nKey: result.detailsI18nKey,
    detailsI18nParams: result.detailsI18nParams,
  }
}

/**
 * Send an OCSP request for `certificate` to each responder URL in its AIA
 * extension and return the first raw response. The caller MUST validate the
 * response (signature, responder authorization, CertID) before using it —
 * see revocation-validator.ts.
 */
export async function requestOcspResponse(
  certificate: ParsedCertificate,
  issuerCertificate: ParsedCertificate
): Promise<Uint8Array | null> {
  const urls = certificate.authorityInfoAccess?.ocsp || []
  if (urls.length === 0) return null
  const request = await buildOcspRequest(certificate, issuerCertificate)
  const requestData = new Uint8Array(request.toSchema(true).toBER())
  for (const url of urls) {
    try {
      const response = await sendOcspRequest(url, requestData)
      if (response) return response
    } catch {
      continue
    }
  }
  return null
}

/**
 * Build OCSP request for a certificate
 */
async function buildOcspRequest(
  certificate: ParsedCertificate,
  issuerCertificate: ParsedCertificate
): Promise<pkijs.OCSPRequest> {
  // Hash issuer name
  const issuerNameHash = await crypto.subtle.digest(
    'SHA-1',
    issuerCertificate.raw.subject.toSchema().toBER()
  )

  // Hash issuer public key
  const issuerKeyHash = await crypto.subtle.digest(
    'SHA-1',
    asBufferSource(issuerCertificate.raw.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView)
  )

  // Create CertID with all fields at once; copy serialNumber to avoid
  // reusing an ASN.1 node from the certificate's own tree (which causes
  // "toBER is not a function" during serialization).
  const certId = new CertID({
    hashAlgorithm: new pkijs.AlgorithmIdentifier({
      algorithmId: '1.3.14.3.2.26', // SHA-1
    }),
    issuerNameHash: new asn1js.OctetString({ valueHex: issuerNameHash }),
    issuerKeyHash: new asn1js.OctetString({ valueHex: issuerKeyHash }),
    serialNumber: new asn1js.Integer({
      valueHex: certificate.raw.serialNumber.valueBlock.valueHexView,
    }),
  })

  // Create request
  const ocspRequest = new OCSPRequest()
  ocspRequest.tbsRequest = new pkijs.TBSRequest({
    requestList: [
      new pkijs.Request({
        reqCert: certId,
      }),
    ],
  })

  return ocspRequest
}

/**
 * Parse OCSP response
 */
function parseOcspResponse(data: Uint8Array): RevocationResult {
  const asn1 = asn1js.fromBER(toArrayBuffer(data))
  if (asn1.offset === -1) {
    throw new Error('Failed to parse OCSP response ASN.1')
  }

  const ocspResponse = new OCSPResponse({ schema: asn1.result })

  // Check response status
  const responseStatus = ocspResponse.responseStatus.valueBlock.valueDec
  if (responseStatus !== 0) {
    // 0 = successful
    return {
      status: 'error',
      checkedAt: new Date(),
      method: 'ocsp',
      details: t('core.revocation.ocspResponseStatus', { status: getOcspStatusText(responseStatus) }),
      detailsI18nKey: 'core.revocation.ocspResponseStatus',
      detailsI18nParams: { status: getOcspStatusText(responseStatus) },
    }
  }

  // Parse basic response
  if (!ocspResponse.responseBytes) {
    throw new Error('No response bytes in OCSP response')
  }

  const responseData = ocspResponse.responseBytes.response.valueBlock.valueHexView
  const basicAsn1 = asn1js.fromBER(responseData)
  if (basicAsn1.offset === -1) {
    throw new Error('Failed to parse BasicOCSPResponse')
  }

  const basicResponse = new BasicOCSPResponse({ schema: basicAsn1.result })
  const tbsResponseData = basicResponse.tbsResponseData

  // Get single response (we only query for one certificate)
  if (tbsResponseData.responses.length === 0) {
    throw new Error('No responses in BasicOCSPResponse')
  }

  const singleResponse = tbsResponseData.responses[0]
  const certStatus = singleResponse.certStatus

  // Parse cert status
  if (certStatus.idBlock.tagNumber === 0) {
    // Good
    return {
      status: 'good',
      checkedAt: new Date(),
      method: 'ocsp',
      details: t('core.revocation.ocspNotRevoked'),
      detailsI18nKey: 'core.revocation.ocspNotRevoked',
    }
  } else if (certStatus.idBlock.tagNumber === 1) {
    // Revoked
    const revokedInfo = certStatus as asn1js.Constructed

    let revokedAt: Date | undefined
    let reason: RevocationReason | undefined

    for (const item of revokedInfo.valueBlock.value) {
      if (item instanceof asn1js.GeneralizedTime) {
        revokedAt = item.toDate()
      } else if (item instanceof asn1js.Enumerated) {
        reason = getRevocationReason(item.valueBlock.valueDec)
      }
    }

    return {
      status: 'revoked',
      checkedAt: new Date(),
      method: 'ocsp',
      revokedAt,
      reason,
      details: reason
        ? t('core.revocation.ocspRevokedWithReason', { reason })
        : t('core.revocation.ocspRevoked'),
      detailsI18nKey: reason ? 'core.revocation.ocspRevokedWithReason' : 'core.revocation.ocspRevoked',
      detailsI18nParams: reason ? { reason } : undefined,
    }
  } else {
    // Unknown
    return {
      status: 'unknown',
      checkedAt: new Date(),
      method: 'ocsp',
      details: t('core.revocation.ocspUnknown'),
      detailsI18nKey: 'core.revocation.ocspUnknown',
    }
  }
}

/**
 * Send OCSP request via shared network helper
 */
async function sendOcspRequest(url: string, data: Uint8Array): Promise<Uint8Array | null> {
  const { fetchOcspResponse } = await import('../network')
  return fetchOcspResponse(url, data)
}

function getOcspStatusText(status: number): string {
  const statuses: Record<number, string> = {
    0: 'successful',
    1: 'malformedRequest',
    2: 'internalError',
    3: 'tryLater',
    5: 'sigRequired',
    6: 'unauthorized',
  }
  return statuses[status] || `unknown (${status})`
}

function getRevocationReason(code: number): RevocationReason {
  const reasons: Record<number, RevocationReason> = {
    0: 'unspecified',
    1: 'keyCompromise',
    2: 'caCompromise',
    3: 'affiliationChanged',
    4: 'superseded',
    5: 'cessationOfOperation',
    6: 'certificateHold',
    8: 'removeFromCRL',
    9: 'privilegeWithdrawn',
    10: 'aaCompromise',
  }
  return reasons[code] || 'unspecified'
}

export interface EmbeddedOcspResult extends RevocationResult {
  targetSerial?: string
  producedAt?: Date
  thisUpdate?: Date
  nextUpdate?: Date
}

/**
 * Parse embedded OCSP response from PDF.
 * DSS (Document Security Store) may embed either:
 * 1. Full OCSPResponse (SEQUENCE { responseStatus, responseBytes })
 * 2. Raw BasicOCSPResponse directly (without OCSPResponse wrapper)
 */
export function parseEmbeddedOcspResponse(data: Uint8Array): EmbeddedOcspResult {
  // Try full OCSPResponse first
  try {
    return parseFullOcspResponseWithMeta(data)
  } catch {
    // Fall through to try BasicOCSPResponse
  }

  // Try parsing as raw BasicOCSPResponse (common in DSS)
  try {
    return parseBasicOcspResponseWithMeta(data)
  } catch {
    // Fall through
  }

  return {
    status: 'error',
    checkedAt: new Date(),
    method: 'embedded',
    details: t('core.revocation.cannotParseEmbeddedOcsp'),
    detailsI18nKey: 'core.revocation.cannotParseEmbeddedOcsp',
  }
}

function parseFullOcspResponseWithMeta(data: Uint8Array): EmbeddedOcspResult {
  const asn1Result = asn1js.fromBER(toArrayBuffer(data))
  if (asn1Result.offset === -1) {
    throw new Error('Failed to parse OCSP response ASN.1')
  }

  const ocspResponse = new OCSPResponse({ schema: asn1Result.result })
  const responseStatus = ocspResponse.responseStatus.valueBlock.valueDec
  if (responseStatus !== 0 || !ocspResponse.responseBytes) {
    const base = parseOcspResponse(data)
    return base
  }

  const responseData = ocspResponse.responseBytes.response.valueBlock.valueHexView
  const basicAsn1 = asn1js.fromBER(responseData)
  if (basicAsn1.offset === -1) {
    throw new Error('Failed to parse BasicOCSPResponse')
  }

  return extractOcspMeta(new BasicOCSPResponse({ schema: basicAsn1.result }), 'embedded')
}

function parseBasicOcspResponseWithMeta(data: Uint8Array): EmbeddedOcspResult {
  const asn1 = asn1js.fromBER(toArrayBuffer(data))
  if (asn1.offset === -1) {
    throw new Error('Failed to parse BasicOCSPResponse ASN.1')
  }

  return extractOcspMeta(new BasicOCSPResponse({ schema: asn1.result }), 'embedded')
}

/**
 * Extract revocation result + metadata (targetSerial, producedAt, thisUpdate, nextUpdate)
 * from a BasicOCSPResponse.
 */
function extractOcspMeta(
  basicResponse: pkijs.BasicOCSPResponse,
  method: 'ocsp' | 'embedded'
): EmbeddedOcspResult {
  const tbsResponseData = basicResponse.tbsResponseData

  if (tbsResponseData.responses.length === 0) {
    throw new Error('No responses in BasicOCSPResponse')
  }

  const singleResponse = tbsResponseData.responses[0]
  const certStatus = singleResponse.certStatus

  // Extract certID serial number for matching
  let targetSerial: string | undefined
  try {
    const certId = singleResponse.certID
    if (certId.serialNumber) {
      targetSerial = bufferToHex(certId.serialNumber.valueBlock.valueHexView)
    }
  } catch {
    // certID extraction is best-effort
  }

  // Extract time fields
  // pkijs types these as Date directly
  const producedAt = tbsResponseData.producedAt instanceof Date
    ? tbsResponseData.producedAt
    : (tbsResponseData.producedAt as { value?: Date } | undefined)?.value
  const thisUpdate = singleResponse.thisUpdate instanceof Date
    ? singleResponse.thisUpdate
    : (singleResponse.thisUpdate as { value?: Date } | undefined)?.value
  const nextUpdate = singleResponse.nextUpdate instanceof Date
    ? singleResponse.nextUpdate
    : (singleResponse.nextUpdate as { value?: Date } | undefined)?.value

  if (certStatus.idBlock.tagNumber === 0) {
    return {
      status: 'good',
      checkedAt: new Date(),
      method,
      details: method === 'embedded'
        ? t('core.revocation.ocspNotRevokedEmbedded')
        : t('core.revocation.ocspNotRevoked'),
      detailsI18nKey: method === 'embedded' ? 'core.revocation.ocspNotRevokedEmbedded' : 'core.revocation.ocspNotRevoked',
      targetSerial,
      producedAt,
      thisUpdate,
      nextUpdate,
    }
  } else if (certStatus.idBlock.tagNumber === 1) {
    const revokedInfo = certStatus as asn1js.Constructed

    let revokedAt: Date | undefined
    let reason: RevocationReason | undefined

    for (const item of revokedInfo.valueBlock.value) {
      if (item instanceof asn1js.GeneralizedTime) {
        revokedAt = item.toDate()
      } else if (item instanceof asn1js.Enumerated) {
        reason = getRevocationReason(item.valueBlock.valueDec)
      }
    }

    return {
      status: 'revoked',
      checkedAt: new Date(),
      method,
      revokedAt,
      reason,
      details: reason
        ? t('core.revocation.ocspRevokedWithReason', { reason })
        : t('core.revocation.ocspRevoked'),
      detailsI18nKey: reason ? 'core.revocation.ocspRevokedWithReason' : 'core.revocation.ocspRevoked',
      detailsI18nParams: reason ? { reason } : undefined,
      targetSerial,
      producedAt,
      thisUpdate,
      nextUpdate,
    }
  } else {
    return {
      status: 'unknown',
      checkedAt: new Date(),
      method,
      details: t('core.revocation.ocspUnknown'),
      detailsI18nKey: 'core.revocation.ocspUnknown',
      targetSerial,
      producedAt,
      thisUpdate,
      nextUpdate,
    }
  }
}

function bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}
