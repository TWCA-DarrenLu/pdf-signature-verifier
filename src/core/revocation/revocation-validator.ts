import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'
import type { ParsedCertificate, RevocationReason } from '@/types'
import { computeDigest, compareBytes } from '../crypto/digest-verifier'
import {
  digestAlgorithmFromOid,
  verifyCertSignature,
  verifyWithCertificate,
} from '../crypto/pki-verify'
import { parseCertificate } from '../certificate/cert-utils'
import { toArrayBuffer } from '../bytes'
import { asBufferSource } from '../bytes'

/**
 * Cryptographically validated revocation evidence for ONE certificate.
 * Produced only when the OCSP response / CRL is signed by an authorized
 * party for the certificate's issuer. Unverifiable data yields `null`.
 */
export interface RevocationEvidence {
  status: 'good' | 'revoked' | 'unknown'
  kind: 'ocsp' | 'crl'
  thisUpdate: Date
  nextUpdate?: Date
  producedAt?: Date
  revokedAt?: Date
  reason?: RevocationReason
  /** Subject DN of the OCSP responder / CRL issuer (for display). */
  signerName: string
}

const OID_OCSP_BASIC = '1.3.6.1.5.5.7.48.1.1'
const OID_EKU_OCSP_SIGNING = '1.3.6.1.5.5.7.3.9'
const OID_OCSP_NOCHECK = '1.3.6.1.5.5.7.48.1.5'

const REASONS: Record<number, RevocationReason> = {
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

// ─── OCSP ────────────────────────────────────────────────────────

/**
 * Parse either a full OCSPResponse or a bare BasicOCSPResponse.
 */
export function parseBasicOcsp(data: Uint8Array): pkijs.BasicOCSPResponse | null {
  const asn1 = asn1js.fromBER(toArrayBuffer(data))
  if (asn1.offset === -1) return null
  try {
    const response = new pkijs.OCSPResponse({ schema: asn1.result })
    if (response.responseStatus.valueBlock.valueDec !== 0 || !response.responseBytes) return null
    if (response.responseBytes.responseType !== OID_OCSP_BASIC) return null
    return pkijs.BasicOCSPResponse.fromBER(asBufferSource(response.responseBytes.response.valueBlock.valueHexView))
  } catch {
    // not wrapped
  }
  try {
    return new pkijs.BasicOCSPResponse({ schema: asn1.result })
  } catch {
    return null
  }
}

/**
 * Validate an OCSP response for `cert` (issued by `issuer`).
 * Returns null when the response is not about this certificate or cannot be
 * authenticated (bad signature, unauthorized responder, malformed).
 */
export async function validateOcspResponse(
  data: Uint8Array,
  cert: ParsedCertificate,
  issuer: ParsedCertificate
): Promise<RevocationEvidence | null> {
  const basic = parseBasicOcsp(data)
  if (!basic) return null
  const tbs = basic.tbsResponseData

  const single = await findSingleResponse(tbs.responses, cert, issuer)
  if (!single) return null

  const responder = await findAuthorizedResponder(basic, issuer, tbs.producedAt)
  if (!responder) return null

  const signed = await verifyWithCertificate(
    new Uint8Array(tbs.tbsView),
    basic.signature,
    responder.raw,
    basic.signatureAlgorithm
  )
  if (!signed) return null

  const base = {
    kind: 'ocsp' as const,
    thisUpdate: single.thisUpdate,
    nextUpdate: single.nextUpdate,
    producedAt: tbs.producedAt,
    signerName: responder.subject,
  }
  const certStatus = single.certStatus as asn1js.BaseBlock
  const tag = certStatus.idBlock.tagNumber
  if (tag === 0) return { ...base, status: 'good' }
  if (tag === 1) {
    let revokedAt: Date | undefined
    let reason: RevocationReason | undefined
    for (const item of (certStatus as asn1js.Constructed).valueBlock.value ?? []) {
      if (item instanceof asn1js.GeneralizedTime) revokedAt = item.toDate()
      if (item instanceof asn1js.Constructed) {
        const inner = item.valueBlock.value[0]
        if (inner instanceof asn1js.Enumerated) reason = REASONS[inner.valueBlock.valueDec] ?? 'unspecified'
      }
    }
    return { ...base, status: 'revoked', revokedAt, reason }
  }
  return { ...base, status: 'unknown' }
}

async function findSingleResponse(
  responses: pkijs.SingleResponse[],
  cert: ParsedCertificate,
  issuer: ParsedCertificate
): Promise<pkijs.SingleResponse | null> {
  const serial = stripZeros(new Uint8Array(cert.raw.serialNumber.valueBlock.valueHexView))
  for (const single of responses) {
    const id = single.certID
    if (!bytesEqual(stripZeros(new Uint8Array(id.serialNumber.valueBlock.valueHexView)), serial)) continue
    const hash = digestAlgorithmFromOid(id.hashAlgorithm.algorithmId)
    if (!hash) continue
    const nameHash = await computeDigest(hash, encodedName(issuer.raw.subject))
    const keyHash = await computeDigest(
      hash,
      new Uint8Array(issuer.raw.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView)
    )
    if (
      compareBytes(nameHash, new Uint8Array(id.issuerNameHash.valueBlock.valueHexView)) &&
      compareBytes(keyHash, new Uint8Array(id.issuerKeyHash.valueBlock.valueHexView))
    ) {
      return single
    }
  }
  return null
}

/**
 * RFC 6960 §4.2.2.2: the responder is the issuing CA itself, or a delegated
 * responder certificate issued directly by that CA with id-kp-OCSPSigning.
 */
async function findAuthorizedResponder(
  basic: pkijs.BasicOCSPResponse,
  issuer: ParsedCertificate,
  producedAt: Date
): Promise<ParsedCertificate | null> {
  const responderId = basic.tbsResponseData.responderID
  const embedded: ParsedCertificate[] = []
  for (const c of basic.certs ?? []) {
    try {
      embedded.push(await parseCertificate(c))
    } catch {
      // skip
    }
  }

  const matchesId = async (c: ParsedCertificate): Promise<boolean> => {
    if (responderId instanceof pkijs.RelativeDistinguishedNames) {
      return c.raw.subject.isEqual(responderId)
    }
    if (responderId instanceof asn1js.OctetString) {
      const keyHash = await computeDigest(
        'SHA-1',
        new Uint8Array(c.raw.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView)
      )
      return compareBytes(keyHash, new Uint8Array(responderId.valueBlock.valueHexView))
    }
    return false
  }

  if (await matchesId(issuer)) return issuer

  for (const candidate of embedded) {
    if (!(await matchesId(candidate))) continue
    if (sameKey(candidate, issuer)) return candidate
    // cert-utils maps id-kp-OCSPSigning to the name 'ocspSigning'
    if (!candidate.extKeyUsage.includes('ocspSigning') && !candidate.extKeyUsage.includes(OID_EKU_OCSP_SIGNING)) {
      continue
    }
    if (candidate.issuer !== issuer.subject) continue
    if (producedAt < candidate.notBefore || producedAt > candidate.notAfter) continue
    if (!(await verifyCertSignature(candidate, issuer))) continue
    return candidate
  }
  return null
}

/** Whether a delegated responder certificate carries id-pkix-ocsp-nocheck. */
export function hasOcspNoCheck(cert: ParsedCertificate): boolean {
  return (cert.raw.extensions ?? []).some((e) => e.extnID === OID_OCSP_NOCHECK)
}

// ─── CRL ─────────────────────────────────────────────────────────

/**
 * Validate a CRL for `cert` (issued by `issuer`). Only direct CRLs signed by
 * the certificate's issuer are accepted. Returns null otherwise.
 */
export async function validateCrl(
  data: Uint8Array,
  cert: ParsedCertificate,
  issuer: ParsedCertificate
): Promise<RevocationEvidence | null> {
  const crl = parseCrlCached(data)
  if (!crl) return null

  if (!crl.issuer.isEqual(issuer.raw.subject)) return null
  if (issuer.keyUsagePresent && !issuer.keyUsage.crlSign) return null
  if (!crlScopeCovers(crl, cert)) return null
  if (!(await verifyCrlCached(data, crl, issuer))) return null

  const base = {
    kind: 'crl' as const,
    thisUpdate: crl.thisUpdate.value,
    nextUpdate: crl.nextUpdate?.value,
    signerName: issuer.subject,
  }

  const serial = stripZeros(new Uint8Array(cert.raw.serialNumber.valueBlock.valueHexView))
  for (const entry of crl.revokedCertificates ?? []) {
    const entrySerial = stripZeros(new Uint8Array(entry.userCertificate.valueBlock.valueHexView))
    if (!bytesEqual(entrySerial, serial)) continue
    let reason: RevocationReason | undefined
    const reasonExt = entry.crlEntryExtensions?.extensions.find((e) => e.extnID === '2.5.29.21')
    if (reasonExt?.parsedValue instanceof asn1js.Enumerated) {
      reason = REASONS[reasonExt.parsedValue.valueBlock.valueDec] ?? 'unspecified'
    }
    if (reason === 'removeFromCRL') break
    return { ...base, status: 'revoked', revokedAt: entry.revocationDate.value, reason }
  }
  return { ...base, status: 'good' }
}

const OID_CRL_NUMBER = '2.5.29.20'
const OID_DELTA_CRL_INDICATOR = '2.5.29.27'
const OID_ISSUING_DISTRIBUTION_POINT = '2.5.29.28'
const OID_AUTHORITY_KEY_ID = '2.5.29.35'
const OID_FRESHEST_CRL = '2.5.29.46'
const UNDERSTOOD_CRL_EXTENSIONS = new Set([
  OID_CRL_NUMBER,
  OID_ISSUING_DISTRIBUTION_POINT,
  OID_AUTHORITY_KEY_ID,
  OID_FRESHEST_CRL,
])

/**
 * RFC 5280 §6.3.3: a CRL only proves "not revoked" for certificates inside its
 * scope. Delta CRLs, indirect CRLs, reason-partitioned CRLs and CRLs with
 * unknown critical extensions are not used. A partitioned CRL (IDP with a
 * distribution point, e.g. TWCA's yearly "..._2024_sha2.crl") must match one
 * of the certificate's own CRL distribution points.
 */
function crlScopeCovers(crl: pkijs.CertificateRevocationList, cert: ParsedCertificate): boolean {
  for (const ext of crl.crlExtensions?.extensions ?? []) {
    if (ext.extnID === OID_DELTA_CRL_INDICATOR) return false
    if (ext.critical && !UNDERSTOOD_CRL_EXTENSIONS.has(ext.extnID)) return false
    if (ext.extnID !== OID_ISSUING_DISTRIBUTION_POINT) continue

    const idp = ext.parsedValue
    if (!(idp instanceof pkijs.IssuingDistributionPoint)) return false
    if (idp.indirectCRL || idp.onlyContainsAttributeCerts || idp.onlySomeReasons !== undefined) return false
    if (idp.onlyContainsUserCerts && cert.isCA) return false
    if (idp.onlyContainsCACerts && !cert.isCA) return false
    if (idp.distributionPoint !== undefined) {
      if (!Array.isArray(idp.distributionPoint)) return false
      const idpUris = idp.distributionPoint.filter((n) => n.type === 6).map((n) => String(n.value).toLowerCase())
      const certUris = cert.crlDistributionPoints.map((u) => u.toLowerCase())
      if (!idpUris.some((u) => certUris.includes(u))) return false
    }
  }
  return true
}

// The same embedded CRLs are checked against every certificate of every
// chain in a document; parse and verify each (CRL, issuer) pair only once.
const parsedCrls = new WeakMap<Uint8Array, pkijs.CertificateRevocationList | null>()
const verifiedCrls = new WeakMap<Uint8Array, Map<string, Promise<boolean>>>()

function parseCrlCached(data: Uint8Array): pkijs.CertificateRevocationList | null {
  if (parsedCrls.has(data)) return parsedCrls.get(data) ?? null
  let crl: pkijs.CertificateRevocationList | null = null
  try {
    const asn1 = asn1js.fromBER(toArrayBuffer(data))
    if (asn1.offset !== -1) crl = new pkijs.CertificateRevocationList({ schema: asn1.result })
  } catch {
    crl = null
  }
  parsedCrls.set(data, crl)
  return crl
}

function verifyCrlCached(
  data: Uint8Array,
  crl: pkijs.CertificateRevocationList,
  issuer: ParsedCertificate
): Promise<boolean> {
  let byIssuer = verifiedCrls.get(data)
  if (!byIssuer) {
    byIssuer = new Map()
    verifiedCrls.set(data, byIssuer)
  }
  let result = byIssuer.get(issuer.fingerprint)
  if (!result) {
    result = crl.verify({ issuerCertificate: issuer.raw }).catch(() => false)
    byIssuer.set(issuer.fingerprint, result)
  }
  return result
}

// ─── Freshness ───────────────────────────────────────────────────

const CLOCK_SKEW_MS = 5 * 60 * 1000

/**
 * Whether evidence can speak for the certificate's status at `atTime`
 * (RFC 5280 §6.3 "current" CRL semantics): not from the future, and its
 * validity window reaches `atTime` (nextUpdate ≥ atTime). Evidence issued
 * before the certificate itself is acceptable — e.g. short-lived HSM signing
 * certificates are issued seconds before signing, after the CA's last CRL.
 */
export function evidenceCoversTime(
  evidence: RevocationEvidence,
  atTime: Date,
  now: Date = new Date()
): boolean {
  if (evidence.thisUpdate.getTime() > now.getTime() + CLOCK_SKEW_MS) return false
  if (!evidence.nextUpdate) {
    // No validity window: it only attests the status as of thisUpdate.
    return evidence.thisUpdate.getTime() + CLOCK_SKEW_MS >= atTime.getTime()
  }
  return evidence.nextUpdate.getTime() + CLOCK_SKEW_MS >= atTime.getTime()
}

// ─── helpers ─────────────────────────────────────────────────────

function encodedName(name: pkijs.RelativeDistinguishedNames): Uint8Array {
  const original = name.valueBeforeDecode
  if (original && original.byteLength > 0) return new Uint8Array(original)
  return new Uint8Array(name.toSchema().toBER())
}

function sameKey(a: ParsedCertificate, b: ParsedCertificate): boolean {
  return bytesEqual(
    new Uint8Array(a.raw.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView),
    new Uint8Array(b.raw.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView)
  )
}

function stripZeros(x: Uint8Array): Uint8Array {
  let i = 0
  while (i < x.length - 1 && x[i] === 0) i++
  return x.subarray(i)
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i])
}
