import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'
import type { DigestAlgorithm, ParsedCertificate } from '@/types'
import { computeDigest, compareBytes } from './digest-verifier'
import { ensurePkijsEngine } from './pkijs-engine'
import { toArrayBuffer } from '../bytes'

/**
 * Central place for every cryptographic signature check (certificates, CMS
 * signer infos, OCSP responses, CRLs). All checks use the ORIGINAL encoded
 * bytes (tbsView / signedAttrs.encodedValue) and import the public key with
 * the hash of the operation being verified, never the hash of whatever
 * algorithm happened to sign the key's own certificate.
 */

const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4'
const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3'

const DIGEST_OIDS: Record<string, DigestAlgorithm> = {
  '1.3.14.3.2.26': 'SHA-1',
  '2.16.840.1.101.3.4.2.1': 'SHA-256',
  '2.16.840.1.101.3.4.2.2': 'SHA-384',
  '2.16.840.1.101.3.4.2.3': 'SHA-512',
}

export function digestAlgorithmFromOid(oid: string): DigestAlgorithm | null {
  return DIGEST_OIDS[oid] ?? null
}

/**
 * Verify that `subject` was signed by `issuer`'s key.
 */
export async function verifyCertSignature(
  subject: ParsedCertificate,
  issuer: ParsedCertificate
): Promise<boolean> {
  ensurePkijsEngine()
  try {
    return await subject.raw.verify(issuer.raw)
  } catch {
    return false
  }
}

/**
 * Verify a signature over `data` made with `cert`'s key.
 */
export async function verifyWithCertificate(
  data: Uint8Array,
  signature: asn1js.BitString | asn1js.OctetString,
  cert: pkijs.Certificate,
  signatureAlgorithm: pkijs.AlgorithmIdentifier,
  hash?: DigestAlgorithm
): Promise<boolean> {
  ensurePkijsEngine()
  try {
    return await pkijs
      .getCrypto(true)
      .verifyWithPublicKey(toArrayBuffer(data), signature, cert.subjectPublicKeyInfo, signatureAlgorithm, hash)
  } catch {
    return false
  }
}

export type CmsVerifyFailure =
  | 'unsupportedDigest'
  | 'unsupportedAlgorithm'
  | 'missingMessageDigest'
  | 'digestMismatch'
  | 'contentTypeMismatch'
  | 'signatureInvalid'

export interface CmsVerifyResult {
  valid: boolean
  failure?: CmsVerifyFailure
  digestAlgorithm?: DigestAlgorithm
}

/**
 * Verify one CMS SignerInfo against the (detached or encapsulated) content:
 *   1. messageDigest signed attribute == hash(content)
 *   2. contentType signed attribute matches, when an expected type is given
 *   3. signature over the DER of the signed attributes (as received)
 */
export async function verifyCmsSignerInfo(
  signerInfo: pkijs.SignerInfo,
  signerCert: pkijs.Certificate,
  content: Uint8Array,
  expectedContentType?: string
): Promise<CmsVerifyResult> {
  const digestAlgorithm = digestAlgorithmFromOid(signerInfo.digestAlgorithm.algorithmId)
  if (!digestAlgorithm) return { valid: false, failure: 'unsupportedDigest' }
  if (!isSupportedKey(signerCert) || !SUPPORTED_SIGNATURE_OIDS.has(signerInfo.signatureAlgorithm.algorithmId)) {
    return { valid: false, failure: 'unsupportedAlgorithm', digestAlgorithm }
  }

  let signedBytes = content
  if (signerInfo.signedAttrs) {
    const attrs = signerInfo.signedAttrs.attributes
    const md = attrs.find((a) => a.type === OID_MESSAGE_DIGEST)?.values[0]
    if (!(md instanceof asn1js.OctetString)) {
      return { valid: false, failure: 'missingMessageDigest', digestAlgorithm }
    }
    const actual = await computeDigest(digestAlgorithm, content)
    if (!compareBytes(actual, new Uint8Array(md.valueBlock.valueHexView))) {
      return { valid: false, failure: 'digestMismatch', digestAlgorithm }
    }
    if (expectedContentType) {
      const ct = attrs.find((a) => a.type === OID_CONTENT_TYPE)?.values[0]
      if (!(ct instanceof asn1js.ObjectIdentifier) || ct.valueBlock.toString() !== expectedContentType) {
        return { valid: false, failure: 'contentTypeMismatch', digestAlgorithm }
      }
    }
    // encodedValue already carries the SET OF tag (0x31) required for hashing;
    // attributes built in code have none, so encode them.
    const original = signerInfo.signedAttrs.encodedValue
    if (original && original.byteLength > 0) {
      signedBytes = new Uint8Array(original)
    } else {
      signedBytes = new Uint8Array(signerInfo.signedAttrs.toSchema().toBER())
      signedBytes[0] = 0x31
    }
  }

  const ok = await verifyWithCertificate(
    signedBytes,
    signerInfo.signature,
    signerCert,
    signerInfo.signatureAlgorithm,
    digestAlgorithm
  )
  return ok ? { valid: true, digestAlgorithm } : { valid: false, failure: 'signatureInvalid', digestAlgorithm }
}

const SUPPORTED_SIGNATURE_OIDS = new Set([
  '1.2.840.113549.1.1.1', // rsaEncryption (hash from digestAlgorithm)
  '1.2.840.113549.1.1.5', // sha1WithRSAEncryption
  '1.2.840.113549.1.1.11', // sha256WithRSAEncryption
  '1.2.840.113549.1.1.12', // sha384WithRSAEncryption
  '1.2.840.113549.1.1.13', // sha512WithRSAEncryption
  '1.2.840.113549.1.1.10', // RSASSA-PSS
  '1.2.840.10045.2.1', // ecPublicKey (hash from digestAlgorithm)
  '1.2.840.10045.4.1', // ecdsa-with-SHA1
  '1.2.840.10045.4.3.2', // ecdsa-with-SHA256
  '1.2.840.10045.4.3.3', // ecdsa-with-SHA384
  '1.2.840.10045.4.3.4', // ecdsa-with-SHA512
])
const SUPPORTED_CURVES = new Set(['1.2.840.10045.3.1.7', '1.3.132.0.34', '1.3.132.0.35'])

/** RSA keys, or EC keys on P-256 / P-384 / P-521 (what Web Crypto can verify). */
function isSupportedKey(cert: pkijs.Certificate): boolean {
  const alg = cert.subjectPublicKeyInfo.algorithm
  if (alg.algorithmId === '1.2.840.113549.1.1.1' || alg.algorithmId === '1.2.840.113549.1.1.10') return true
  if (alg.algorithmId !== '1.2.840.10045.2.1') return false
  const params = alg.algorithmParams
  return params instanceof asn1js.ObjectIdentifier && SUPPORTED_CURVES.has(params.valueBlock.toString())
}

/**
 * Locate the certificate a SignerInfo refers to (issuerAndSerialNumber or
 * subjectKeyIdentifier). Returns null rather than guessing.
 */
export function findSignerCertificate(
  signerInfo: pkijs.SignerInfo,
  certs: pkijs.Certificate[]
): pkijs.Certificate | null {
  const sid = signerInfo.sid
  if (sid instanceof pkijs.IssuerAndSerialNumber) {
    const serial = new Uint8Array(sid.serialNumber.valueBlock.valueHexView)
    return (
      certs.find(
        (c) =>
          sameBytes(new Uint8Array(c.serialNumber.valueBlock.valueHexView), serial) &&
          c.issuer.isEqual(sid.issuer)
      ) ?? null
    )
  }
  if (sid instanceof asn1js.Primitive || sid instanceof asn1js.OctetString) {
    const ski = new Uint8Array(sid.valueBlock.valueHexView)
    return (
      certs.find((c) => {
        const ext = c.extensions?.find((e) => e.extnID === '2.5.29.14')
        const parsed = ext?.parsedValue
        return parsed instanceof asn1js.OctetString && sameBytes(new Uint8Array(parsed.valueBlock.valueHexView), ski)
      }) ?? null
    )
  }
  return null
}

/**
 * Bytes of the encapsulated content (handles constructed / BER OCTET STRINGs).
 */
export function getEncapsulatedContentBytes(signedData: pkijs.SignedData): Uint8Array | null {
  const eContent = signedData.encapContentInfo?.eContent
  if (!eContent) return null
  if (eContent.idBlock.isConstructed) {
    const parts = (eContent.valueBlock.value as asn1js.OctetString[]).map(
      (p) => new Uint8Array(p.valueBlock.valueHexView)
    )
    const total = parts.reduce((n, p) => n + p.length, 0)
    const out = new Uint8Array(total)
    let offset = 0
    for (const p of parts) {
      out.set(p, offset)
      offset += p.length
    }
    return out
  }
  return new Uint8Array(eContent.valueBlock.valueHexView)
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  // Leading zero bytes are not significant for INTEGER serial numbers.
  const strip = (x: Uint8Array) => {
    let i = 0
    while (i < x.length - 1 && x[i] === 0) i++
    return x.subarray(i)
  }
  const x = strip(a)
  const y = strip(b)
  return x.length === y.length && x.every((v, i) => v === y[i])
}

