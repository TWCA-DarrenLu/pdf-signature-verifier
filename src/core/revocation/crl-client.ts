import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'
import type { ParsedCertificate, RevocationResult, CrlInfo } from '@/types'
import { t } from '@/i18n'
import { toArrayBuffer } from '../bytes'

const { CertificateRevocationList } = pkijs

/**
 * Check certificate revocation status via CRL
 */
export async function checkCrlStatus(
  certificate: ParsedCertificate,
  issuerCertificate: ParsedCertificate
): Promise<RevocationResult> {
  const crlUrls = certificate.crlDistributionPoints

  if (crlUrls.length === 0) {
    return {
      status: 'unknown',
      checkedAt: new Date(),
      method: 'crl',
      details: t('core.revocation.noCrlDistPoints'),
      detailsI18nKey: 'core.revocation.noCrlDistPoints',
    }
  }

  for (const url of crlUrls) {
    try {
      const result = await queryCrl(url, certificate, issuerCertificate)
      return result
    } catch (error) {
      console.warn(`CRL fetch from ${url} failed:`, error)
      continue
    }
  }

  return {
    status: 'error',
    checkedAt: new Date(),
    method: 'crl',
    details: t('core.revocation.allCrlFailed'),
    detailsI18nKey: 'core.revocation.allCrlFailed',
  }
}

/**
 * Fetch and check CRL
 */
async function queryCrl(
  url: string,
  certificate: ParsedCertificate,
  _issuerCertificate: ParsedCertificate
): Promise<RevocationResult> {
  // Fetch CRL via background script
  const crlData = await fetchCrl(url)

  if (!crlData) {
    throw new Error('Failed to fetch CRL')
  }

  // Parse CRL
  const crlInfo = parseCrl(crlData)

  // Check if certificate is in CRL (use normalized comparison: strip leading zeros)
  const isRevoked = isSerialInCrl(certificate.serialNumber, crlInfo)
  const revokedEntry = isRevoked ? certificate.serialNumber : undefined

  if (revokedEntry) {
    return {
      status: 'revoked',
      checkedAt: new Date(),
      method: 'crl',
      details: t('core.revocation.serialInCrl', { issuer: crlInfo.issuer }),
      detailsI18nKey: 'core.revocation.serialInCrl',
      detailsI18nParams: { issuer: crlInfo.issuer },
    }
  }

  // Check CRL validity
  const now = new Date()
  if (now < crlInfo.thisUpdate) {
    return {
      status: 'unknown',
      checkedAt: new Date(),
      method: 'crl',
      details: t('core.revocation.crlNotYetValid', { issuer: crlInfo.issuer }),
      detailsI18nKey: 'core.revocation.crlNotYetValid',
      detailsI18nParams: { issuer: crlInfo.issuer },
    }
  }

  if (crlInfo.nextUpdate && now > crlInfo.nextUpdate) {
    return {
      status: 'unknown',
      checkedAt: new Date(),
      method: 'crl',
      details: t('core.revocation.crlExpired', { issuer: crlInfo.issuer }),
      detailsI18nKey: 'core.revocation.crlExpired',
      detailsI18nParams: { issuer: crlInfo.issuer },
    }
  }

  return {
    status: 'good',
    checkedAt: new Date(),
    method: 'crl',
    details: t('core.revocation.notInCrl', { issuer: crlInfo.issuer }),
    detailsI18nKey: 'core.revocation.notInCrl',
    detailsI18nParams: { issuer: crlInfo.issuer },
  }
}

/**
 * Fetch CRL via shared network helper
 */
async function fetchCrl(url: string): Promise<Uint8Array | null> {
  const { fetchBinary } = await import('../network')
  return fetchBinary(url)
}

/**
 * Parse CRL data
 */
export function parseCrl(data: Uint8Array): CrlInfo {
  const asn1 = asn1js.fromBER(toArrayBuffer(data))
  if (asn1.offset === -1) {
    throw new Error('Failed to parse CRL ASN.1')
  }

  const crl = new CertificateRevocationList({ schema: asn1.result })

  // Get issuer
  const issuer = crl.issuer.typesAndValues
    .map((tv) => `${getOidName(tv.type)}=${tv.value.valueBlock.value}`)
    .join(', ')

  // Get validity times
  const thisUpdate = crl.thisUpdate.value
  const nextUpdate = crl.nextUpdate?.value

  // Get revoked serial numbers
  const serialNumbers: string[] = []
  if (crl.revokedCertificates) {
    for (const revoked of crl.revokedCertificates) {
      const serial = bufferToHex(revoked.userCertificate.valueBlock.valueHexView)
      serialNumbers.push(serial)
    }
  }

  return {
    issuer,
    thisUpdate,
    nextUpdate,
    serialNumbers,
  }
}

/**
 * Parse embedded CRL from PDF
 */
export function parseEmbeddedCrl(data: Uint8Array): CrlInfo {
  return parseCrl(data)
}

/**
 * Check if serial number is in CRL
 */
export function isSerialInCrl(serialNumber: string, crlInfo: CrlInfo): boolean {
  const normalizedSerial = serialNumber.toLowerCase().replace(/^0+/, '')
  return crlInfo.serialNumbers.some(
    (sn) => sn.toLowerCase().replace(/^0+/, '') === normalizedSerial
  )
}

/**
 * Check if CRL is currently valid
 */
export function isCrlValid(crlInfo: CrlInfo): boolean {
  const now = new Date()

  if (now < crlInfo.thisUpdate) {
    return false
  }

  if (crlInfo.nextUpdate && now > crlInfo.nextUpdate) {
    return false
  }

  return true
}

/**
 * Get CRL cache key
 */
export function getCrlCacheKey(url: string): string {
  return `crl:${url}`
}

function getOidName(oid: string): string {
  const names: Record<string, string> = {
    '2.5.4.3': 'CN',
    '2.5.4.5': 'serialNumber',
    '2.5.4.6': 'C',
    '2.5.4.7': 'L',
    '2.5.4.8': 'ST',
    '2.5.4.10': 'O',
    '2.5.4.11': 'OU',
    '2.5.4.12': 'T',
    '2.5.4.46': 'dnQualifier',
    '1.2.840.113549.1.9.1': 'emailAddress',
  }
  return names[oid] || oid
}

function bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}
