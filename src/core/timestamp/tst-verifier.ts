import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'
import type { TimestampInfo, CheckResult, ParsedCertificate, CertificateChain, DigestAlgorithm } from '@/types'
import { createPassedCheck, createFailedCheck } from '@/types'
import { parseCertificate, parseCertificateFromBytes } from '../certificate/cert-utils'
import { toArrayBuffer } from '../bytes'
import { buildCertificateChain } from '../certificate/chain-builder'
import { computeDigest } from '../crypto/digest-verifier'
import {
  digestAlgorithmFromOid,
  findSignerCertificate,
  getEncapsulatedContentBytes,
  verifyCmsSignerInfo,
} from '../crypto/pki-verify'
import { ensurePkijsEngine } from '../crypto/pkijs-engine'
import { t } from '@/i18n'
import { isTsaTrustStoreEmpty, getAnchorCategory, getAnchorVendor } from '@/trust-store/trust-manager'
import type { CertificateChain as Chain } from '@/types'

const { ContentInfo, SignedData, Certificate } = pkijs

const OID_SIGNED_DATA = '1.2.840.113549.1.7.2'
const OID_CT_TST_INFO = '1.2.840.113549.1.9.16.1.4'
const EKU_TIME_STAMPING = 'timeStamping'
const OID_EKU_TIME_STAMPING = '1.3.6.1.5.5.7.3.8'

/**
 * Internal parsed TSTInfo per RFC 3161 Section 2.4.2
 */
interface TstInfoParsed {
  version: number
  policy: string
  messageImprint: {
    algorithm: string
    algorithmOid: string
    hash: Uint8Array
  }
  serialNumber: string
  time: Date
}

export type TimestampFailure =
  | 'parse'
  | 'unsupportedAlgorithm'
  | 'imprintMismatch'
  | 'tsaCertMissing'
  | 'signatureInvalid'
  | 'tsaNotTimestampingCert'
  | 'tsaCertNotValidAtTime'
  | 'tsaUntrusted'
  /** Set by the caller after revocation checking of the TSA path. */
  | 'tsaRevoked'
  | 'tsaRevocationUnknown'

export interface TimestampVerifyOptions {
  /** Extra DER certificates for TSA path building (e.g. PDF DSS /Certs). */
  extraCertBytes?: Uint8Array[]
  /** Fetch missing TSA issuers via AIA. Default true. */
  fetchMissing?: boolean
  /** Also trust the selected international TSA roots (user option). Default false. */
  trustInternational?: boolean
}

export interface TimestampVerifyResult {
  /** Imprint, TSA signature, TSA certificate and TSA path all verified. */
  valid: boolean
  info: TimestampInfo | null
  check: CheckResult
  failure?: TimestampFailure
  /** TSA certification path (leaf first) when a TSA certificate was found. */
  tsaChain?: CertificateChain
}

/**
 * Verify an RFC 3161 timestamp token over `data` (the bytes that were
 * timestamped). The digest is computed with the algorithm the token declares.
 */
export async function verifyTimestampForData(
  timestampData: Uint8Array,
  data: Uint8Array,
  options: TimestampVerifyOptions = {}
): Promise<TimestampVerifyResult> {
  const digestAlgorithm = readImprintAlgorithm(timestampData)
  if (!digestAlgorithm) {
    return failed('unsupportedAlgorithm', null, 'core.timestampVerifier.unsupportedAlgorithm')
  }
  const digest = await computeDigest(digestAlgorithm, data)
  return verifyTimestamp(timestampData, digest, options)
}

/**
 * Verify RFC 3161 timestamp token against an expected message imprint.
 *
 * A token is valid only when ALL of these hold:
 *   1. it is SignedData with eContentType id-ct-TSTInfo,
 *   2. TSTInfo.messageImprint equals the expected digest,
 *   3. the TSA signer certificate (located via sid) is present and carries
 *      the id-kp-timeStamping extended key usage,
 *   4. the messageDigest attribute matches TSTInfo and the TSA signature verifies,
 *   5. genTime lies within the TSA certificate validity, and
 *   6. the TSA certificate chains — every signature verified — to an anchor
 *      in the TSA trust store.
 */
export async function verifyTimestamp(
  timestampData: Uint8Array,
  messageImprint: Uint8Array,
  options: TimestampVerifyOptions = {}
): Promise<TimestampVerifyResult> {
  ensurePkijsEngine()
  try {
    const parsed = parseToken(timestampData)
    if ('error' in parsed) {
      return failed('parse', null, parsed.error)
    }
    const { signedData, tstInfoBytes } = parsed

    const tstInfo = parseTstInfo(tstInfoBytes)
    if (!tstInfo) {
      return failed('parse', null, 'core.timestampVerifier.cannotParseTstInfo')
    }

    const tsaCerts = (signedData.certificates || []).filter(
      (c): c is pkijs.Certificate => c instanceof Certificate
    )
    // certReq=false tokens carry no certificate; the PDF's DSS may.
    for (const bytes of options.extraCertBytes ?? []) {
      try {
        tsaCerts.push((await parseCertificateFromBytes(bytes)).raw)
      } catch {
        // ignore unparsable DSS entries
      }
    }
    const signerInfo = signedData.signerInfos[0]
    const tsaRaw = signerInfo ? findSignerCertificate(signerInfo, tsaCerts) : null
    const tsaCert = tsaRaw ? await parseCertificate(tsaRaw) : null
    const tsaName = tsaCert ? getCommonName(tsaCert.subject) : t('core.timestampVerifier.unknownTsa')
    const untrustedInfo = toTimestampInfo(tstInfo, tsaName, false)

    // 2. imprint (algorithm must be one we can compute)
    if (!digestAlgorithmFromOid(tstInfo.messageImprint.algorithmOid)) {
      return failed('unsupportedAlgorithm', untrustedInfo, 'core.timestampVerifier.unsupportedAlgorithm')
    }
    if (!verifyMessageImprint(tstInfo.messageImprint, messageImprint)) {
      return failed('imprintMismatch', untrustedInfo, 'core.timestampVerifier.digestMismatch', {
        detailsKey: 'core.timestampVerifier.digestMismatchDetails',
      })
    }

    // 3. TSA certificate present + timeStamping EKU
    if (!signerInfo || !tsaRaw || !tsaCert) {
      return failed('tsaCertMissing', untrustedInfo, 'core.timestampVerifier.tsaCertMissing')
    }
    if (!isTimestampingCertificate(tsaCert)) {
      return failed('tsaNotTimestampingCert', untrustedInfo, 'core.timestampVerifier.tsaNotTimestampingCert', {
        params: { tsa: tsaName },
      })
    }

    // 4. messageDigest + signature
    const sig = await verifyCmsSignerInfo(signerInfo, tsaRaw, tstInfoBytes, OID_CT_TST_INFO)
    if (!sig.valid && (sig.failure === 'unsupportedDigest' || sig.failure === 'unsupportedAlgorithm')) {
      return failed('unsupportedAlgorithm', untrustedInfo, 'core.timestampVerifier.unsupportedAlgorithm')
    }
    if (!sig.valid) {
      return failed('signatureInvalid', untrustedInfo, 'core.timestampVerifier.tsaSignatureInvalid', {
        detailsKey: 'core.timestampVerifier.tsaSignatureInvalidDetails',
      })
    }

    // 5. genTime within TSA certificate validity
    if (!isTimestampWithinCertValidity(tstInfo.time, tsaCert)) {
      return failed('tsaCertNotValidAtTime', untrustedInfo, 'core.timestampVerifier.tsaCertNotValidAtTime', {
        params: { tsa: tsaName },
      })
    }

    // 6. TSA path to a TSA trust anchor
    const otherCerts: ParsedCertificate[] = []
    for (const c of tsaCerts) {
      if (c !== tsaRaw) otherCerts.push(await parseCertificate(c))
    }
    const tsaChain = await buildCertificateChain(tsaCert, otherCerts, {
      anchorStore: 'tsa',
      fetchMissing: options.fetchMissing ?? true,
      additionalCertBytes: options.extraCertBytes ?? [],
      trustInternational: options.trustInternational === true,
    })
    if (!tsaChain.isTrusted) {
      const empty = isTsaTrustStoreEmpty()
      // would a bundled international TSA root anchor it? (international option off)
      let intlVendor: string | null = null
      if (options.trustInternational !== true) {
        const alternative: Chain = await buildCertificateChain(tsaCert, otherCerts, {
          anchorStore: 'tsa',
          fetchMissing: options.fetchMissing ?? true,
          additionalCertBytes: options.extraCertBytes ?? [],
          trustInternational: true,
        })
        if (alternative.isTrusted && alternative.root && getAnchorCategory(alternative.root) === 'international') {
          intlVendor = getAnchorVendor(alternative.root) ?? tsaName
        }
      }
      const detailsKey = empty
        ? 'core.timestampVerifier.tsaTrustStoreEmpty'
        : intlVendor
          ? 'core.timestampVerifier.tsaInternationalNotEnabled'
          : 'core.timestampVerifier.tsaUntrustedDetails'
      const result = failed('tsaUntrusted', untrustedInfo, 'core.timestampVerifier.tsaUntrusted', {
        params: { tsa: tsaName },
        detailsKey,
        detailsParams: empty ? undefined : { tsa: tsaName, vendor: intlVendor ?? '' },
      })
      return { ...result, tsaChain }
    }

    const info = toTimestampInfo(tstInfo, tsaName, true)
    return {
      valid: true,
      info,
      tsaChain,
      check: createPassedCheck(
        t('core.timestampVerifier.verifiedWithDigest'),
        t('core.timestampVerifier.verifiedTime', { time: info.time.toISOString() }),
        {
          key: 'core.timestampVerifier.verifiedWithDigest',
          detailsKey: 'core.timestampVerifier.verifiedTime',
          detailsParams: { time: info.time.toISOString() },
        }
      ),
    }
  } catch (error) {
    return {
      valid: false,
      info: null,
      failure: 'parse',
      check: createFailedCheck(
        t('core.timestampVerifier.verificationError'),
        error instanceof Error ? error.message : t('core.error.unknownError'),
        { key: 'core.timestampVerifier.verificationError' }
      ),
    }
  }
}

function failed(
  failure: TimestampFailure,
  info: TimestampInfo | null,
  key: string,
  extra: {
    params?: Record<string, string | number>
    detailsKey?: string
    detailsParams?: Record<string, string | number>
  } = {}
): TimestampVerifyResult {
  return {
    valid: false,
    info,
    failure,
    check: createFailedCheck(
      t(key, extra.params),
      extra.detailsKey ? t(extra.detailsKey, extra.detailsParams) : undefined,
      { key, params: extra.params, detailsKey: extra.detailsKey, detailsParams: extra.detailsParams }
    ),
  }
}

function parseToken(
  timestampData: Uint8Array
): { signedData: pkijs.SignedData; tstInfoBytes: Uint8Array } | { error: string } {
  const asn1 = asn1js.fromBER(toArrayBuffer(timestampData))
  if (asn1.offset === -1) return { error: 'core.timestampVerifier.cannotParseAsn1' }
  const contentInfo = new ContentInfo({ schema: asn1.result })
  if (contentInfo.contentType !== OID_SIGNED_DATA) return { error: 'core.timestampVerifier.notSignedData' }
  const signedData = new SignedData({ schema: contentInfo.content })
  if (signedData.encapContentInfo?.eContentType !== OID_CT_TST_INFO) {
    return { error: 'core.timestampVerifier.noTstInfo' }
  }
  const tstInfoBytes = getEncapsulatedContentBytes(signedData)
  if (!tstInfoBytes || tstInfoBytes.length === 0) return { error: 'core.timestampVerifier.noTstInfo' }
  return { signedData, tstInfoBytes }
}

/** Hash algorithm declared in the token's messageImprint (null if unreadable). */
export function readImprintAlgorithm(timestampData: Uint8Array): DigestAlgorithm | null {
  try {
    const parsed = parseToken(timestampData)
    if ('error' in parsed) return null
    const tst = parseTstInfo(parsed.tstInfoBytes)
    return tst ? digestAlgorithmFromOid(tst.messageImprint.algorithmOid) : null
  } catch {
    return null
  }
}

/** RFC 3161 §2.3: the TSA certificate must carry id-kp-timeStamping. */
export function isTimestampingCertificate(cert: ParsedCertificate): boolean {
  return cert.extKeyUsage.includes(EKU_TIME_STAMPING) || cert.extKeyUsage.includes(OID_EKU_TIME_STAMPING)
}

/**
 * Parse TSTInfo structure per RFC 3161 Section 2.4.2
 */
function parseTstInfo(data: ArrayBuffer | Uint8Array): TstInfoParsed | null {
  try {
    const buffer = data instanceof Uint8Array ? toArrayBuffer(data) : data
    const asn1 = asn1js.fromBER(buffer)
    if (asn1.offset === -1) {
      return null
    }

    const seq = asn1.result
    if (!(seq instanceof asn1js.Sequence)) {
      return null
    }

    const values = seq.valueBlock.value
    if (values.length < 5) {
      return null
    }

    // Field 0: version INTEGER
    const versionItem = values[0]
    if (!(versionItem instanceof asn1js.Integer)) {
      return null
    }
    const version = versionItem.valueBlock.valueDec

    // Field 1: policy OBJECT IDENTIFIER
    const policyItem = values[1]
    if (!(policyItem instanceof asn1js.ObjectIdentifier)) {
      return null
    }
    const policy = policyItem.valueBlock.toString()

    // Field 2: messageImprint SEQUENCE { hashAlgorithm, hashedMessage }
    const msgImprintItem = values[2]
    if (!(msgImprintItem instanceof asn1js.Sequence)) {
      return null
    }
    const msgImprintValues = msgImprintItem.valueBlock.value
    if (msgImprintValues.length < 2) {
      return null
    }

    const algIdItem = msgImprintValues[0]
    if (!(algIdItem instanceof asn1js.Sequence)) {
      return null
    }
    const algOidItem = algIdItem.valueBlock.value[0]
    if (!(algOidItem instanceof asn1js.ObjectIdentifier)) {
      return null
    }
    const algorithmOid = algOidItem.valueBlock.toString()
    const algorithm = getAlgorithmName(algorithmOid)

    const hashItem = msgImprintValues[1]
    if (!(hashItem instanceof asn1js.OctetString)) {
      return null
    }
    const hash = new Uint8Array(hashItem.valueBlock.valueHexView)

    // Field 3: serialNumber INTEGER
    const serialItem = values[3]
    if (!(serialItem instanceof asn1js.Integer)) {
      return null
    }
    const serialNumber = bufferToHex(serialItem.valueBlock.valueHexView)

    // Field 4: genTime GeneralizedTime
    const genTimeItem = values[4]
    if (!(genTimeItem instanceof asn1js.GeneralizedTime)) {
      return null
    }
    const time = genTimeItem.toDate()

    return {
      version,
      policy,
      messageImprint: { algorithm, algorithmOid, hash },
      serialNumber,
      time,
    }
  } catch {
    return null
  }
}

function toTimestampInfo(
  tstInfo: TstInfoParsed,
  issuer: string,
  isValid: boolean
): TimestampInfo {
  return {
    time: tstInfo.time,
    issuer,
    serialNumber: tstInfo.serialNumber,
    hashAlgorithm: tstInfo.messageImprint.algorithm,
    isValid,
  }
}

function verifyMessageImprint(
  imprint: { algorithm: string; hash: Uint8Array },
  expectedHash: Uint8Array
): boolean {
  if (imprint.hash.length !== expectedHash.length) {
    return false
  }
  let result = 0
  for (let i = 0; i < imprint.hash.length; i++) {
    result |= imprint.hash[i] ^ expectedHash[i]
  }
  return result === 0
}

export async function getTsaInfo(
  timestampData: Uint8Array
): Promise<{ name: string; certificate: ParsedCertificate | null }> {
  try {
    const asn1 = asn1js.fromBER(toArrayBuffer(timestampData))
    if (asn1.offset === -1) {
      return { name: t('core.timestampVerifier.unknownTsa'), certificate: null }
    }

    const contentInfo = new ContentInfo({ schema: asn1.result })
    const signedData = new SignedData({ schema: contentInfo.content })
    const certs = (signedData.certificates || []).filter(
      (c): c is pkijs.Certificate => c instanceof Certificate
    )
    const signerInfo = signedData.signerInfos[0]
    const raw = signerInfo ? findSignerCertificate(signerInfo, certs) : null
    if (!raw) {
      return { name: t('core.timestampVerifier.unknownTsa'), certificate: null }
    }
    const parsed = await parseCertificate(raw)
    return { name: getCommonName(parsed.subject), certificate: parsed }
  } catch {
    return { name: t('core.timestampVerifier.unknownTsa'), certificate: null }
  }
}

export function isTimestampWithinCertValidity(
  timestampTime: Date,
  certificate: ParsedCertificate
): boolean {
  return timestampTime >= certificate.notBefore && timestampTime <= certificate.notAfter
}

export function getEffectiveSigningTime(
  signingTime: Date | null,
  timestampInfo: TimestampInfo | null
): Date {
  if (timestampInfo?.time) {
    return timestampInfo.time
  }
  if (signingTime) {
    return signingTime
  }
  return new Date()
}

function getAlgorithmName(oid: string): string {
  const names: Record<string, string> = {
    '2.16.840.1.101.3.4.2.1': 'SHA-256',
    '2.16.840.1.101.3.4.2.2': 'SHA-384',
    '2.16.840.1.101.3.4.2.3': 'SHA-512',
    '1.3.14.3.2.26': 'SHA-1',
  }
  return names[oid] || oid
}

function getCommonName(subject: string): string {
  const match = subject.match(/CN=([^,]+)/)
  return match ? match[1] : subject
}

function bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}
