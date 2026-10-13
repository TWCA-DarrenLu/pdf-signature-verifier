import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'
import type {
  ParsedCertificate,
  KeyUsageFlags,
  AuthorityInfoAccess,
} from '@/types'
import { toArrayBuffer } from '../bytes'

const { Certificate } = pkijs

/**
 * Parse a pkijs Certificate into a structured format
 */
export async function parseCertificate(
  cert: pkijs.Certificate,
  originalDer?: Uint8Array
): Promise<ParsedCertificate> {
  const subject = formatDN(cert.subject)
  const issuer = formatDN(cert.issuer)
  const serialNumber = bufferToHex(cert.serialNumber.valueBlock.valueHexView)
  const notBefore = cert.notBefore.value
  const notAfter = cert.notAfter.value

  // Check if self-signed
  const isSelfSigned = subject === issuer

  // Fingerprint = SHA-256 of the DER as received (re-encoding is only a
  // fallback for certificates built in code).
  const der = originalDer ?? new Uint8Array(cert.toSchema().toBER())
  const fingerprint = await computeFingerprint(toArrayBuffer(der))

  // Get public key
  let publicKey: CryptoKey | null = null
  try {
    publicKey = await cert.getPublicKey()
  } catch {
    // May fail for unsupported key types
  }

  // Parse extensions
  let isCA = false
  let pathLenConstraint: number | null = null
  let keyUsagePresent = false
  let keyUsage: KeyUsageFlags = createEmptyKeyUsage()
  let extKeyUsage: string[] = []
  let authorityInfoAccess: AuthorityInfoAccess | null = null
  let crlDistributionPoints: string[] = []
  let subjectKeyIdentifier: string | null = null
  let authorityKeyIdentifier: string | null = null

  if (cert.extensions) {
    for (const ext of cert.extensions) {
      switch (ext.extnID) {
        case '2.5.29.19': // BasicConstraints
          if (ext.parsedValue instanceof pkijs.BasicConstraints) {
            isCA = ext.parsedValue.cA ?? false
            const pathLen = ext.parsedValue.pathLenConstraint
            if (typeof pathLen === 'number') {
              pathLenConstraint = pathLen
            } else if (pathLen instanceof asn1js.Integer) {
              pathLenConstraint = pathLen.valueBlock.valueDec
            }
          }
          break

        case '2.5.29.15': // KeyUsage
          keyUsage = parseKeyUsage(ext)
          keyUsagePresent = true
          break

        case '2.5.29.37': // ExtKeyUsage
          extKeyUsage = parseExtKeyUsage(ext)
          break

        case '1.3.6.1.5.5.7.1.1': // AuthorityInfoAccess
          authorityInfoAccess = parseAuthorityInfoAccess(ext)
          break

        case '2.5.29.31': // CRLDistributionPoints
          crlDistributionPoints = parseCrlDistributionPoints(ext)
          break

        case '2.5.29.14': // SubjectKeyIdentifier
          if (ext.parsedValue instanceof asn1js.OctetString) {
            subjectKeyIdentifier = bufferToHex(ext.parsedValue.valueBlock.valueHexView)
          }
          break

        case '2.5.29.35': // AuthorityKeyIdentifier
          if (ext.parsedValue instanceof pkijs.AuthorityKeyIdentifier) {
            if (ext.parsedValue.keyIdentifier) {
              authorityKeyIdentifier = bufferToHex(
                ext.parsedValue.keyIdentifier.valueBlock.valueHexView
              )
            }
          }
          break
      }
    }
  }

  return {
    raw: cert,
    der,
    subject,
    issuer,
    serialNumber,
    notBefore,
    notAfter,
    publicKey,
    fingerprint,
    isCA,
    isSelfSigned,
    pathLenConstraint,
    keyUsagePresent,
    keyUsage,
    extKeyUsage,
    authorityInfoAccess,
    crlDistributionPoints,
    subjectKeyIdentifier,
    authorityKeyIdentifier,
  }
}

/**
 * Parse DER/PEM encoded certificate
 */
export async function parseCertificateFromBytes(data: Uint8Array): Promise<ParsedCertificate> {
  let derData = data

  // Check if PEM
  const text = new TextDecoder().decode(data)
  if (text.includes('-----BEGIN CERTIFICATE-----')) {
    derData = pemToDer(text)
  }

  const asn1 = asn1js.fromBER(toArrayBuffer(derData))
  if (asn1.offset === -1) {
    throw new Error('Failed to parse certificate ASN.1')
  }

  const cert = new Certificate({ schema: asn1.result })
  return parseCertificate(cert, derData)
}

/**
 * Parse whatever an AIA caIssuers URL returns: a single DER/PEM certificate
 * or a PKCS#7 "certs-only" bundle (.p7b / .p7c, e.g. GRCA's IssuedToThisCA.p7b).
 */
export async function parseCertificatesFromBundle(data: Uint8Array): Promise<ParsedCertificate[]> {
  try {
    return [await parseCertificateFromBytes(data)]
  } catch {
    // not a bare certificate — try PKCS#7
  }
  try {
    const asn1 = asn1js.fromBER(toArrayBuffer(data))
    if (asn1.offset === -1) return []
    const contentInfo = new pkijs.ContentInfo({ schema: asn1.result })
    const signedData = new pkijs.SignedData({ schema: contentInfo.content })
    const out: ParsedCertificate[] = []
    for (const c of signedData.certificates ?? []) {
      if (c instanceof Certificate) out.push(await parseCertificate(c))
    }
    return out
  } catch {
    return []
  }
}

export { toArrayBuffer }

/**
 * Convert PEM to DER
 */
export function pemToDer(pem: string): Uint8Array {
  const lines = pem.split('\n')
  const base64Lines: string[] = []

  let inCert = false
  for (const line of lines) {
    if (line.includes('-----BEGIN CERTIFICATE-----')) {
      inCert = true
      continue
    }
    if (line.includes('-----END CERTIFICATE-----')) {
      break
    }
    if (inCert) {
      base64Lines.push(line.trim())
    }
  }

  const base64 = base64Lines.join('')
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0))
}

/**
 * Convert DER to PEM
 */
export function derToPem(der: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...der))
  const lines: string[] = []

  for (let i = 0; i < base64.length; i += 64) {
    lines.push(base64.slice(i, i + 64))
  }

  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`
}

/**
 * Format Distinguished Name
 */
function formatDN(name: pkijs.RelativeDistinguishedNames): string {
  const parts: string[] = []

  for (const rdn of name.typesAndValues) {
    const type = getOidName(rdn.type)
    const value = rdn.value.valueBlock.value
    parts.push(`${type}=${value}`)
  }

  return parts.join(', ')
}

/**
 * Get human-readable OID name
 */
function getOidName(oid: string): string {
  const names: Record<string, string> = {
    '2.5.4.3': 'CN',
    '2.5.4.6': 'C',
    '2.5.4.7': 'L',
    '2.5.4.8': 'ST',
    '2.5.4.10': 'O',
    '2.5.4.11': 'OU',
    '2.5.4.5': 'serialNumber',
    '1.2.840.113549.1.9.1': 'emailAddress',
  }
  return names[oid] || oid
}

function createEmptyKeyUsage(): KeyUsageFlags {
  return {
    digitalSignature: false,
    nonRepudiation: false,
    keyEncipherment: false,
    dataEncipherment: false,
    keyAgreement: false,
    keyCertSign: false,
    crlSign: false,
    encipherOnly: false,
    decipherOnly: false,
  }
}

function parseKeyUsage(ext: pkijs.Extension): KeyUsageFlags {
  const flags = createEmptyKeyUsage()

  if (ext.parsedValue instanceof asn1js.BitString) {
    const bits = ext.parsedValue.valueBlock.valueHexView

    if (bits.length > 0) {
      const byte0 = bits[0]
      flags.digitalSignature = (byte0 & 0x80) !== 0
      flags.nonRepudiation = (byte0 & 0x40) !== 0
      flags.keyEncipherment = (byte0 & 0x20) !== 0
      flags.dataEncipherment = (byte0 & 0x10) !== 0
      flags.keyAgreement = (byte0 & 0x08) !== 0
      flags.keyCertSign = (byte0 & 0x04) !== 0
      flags.crlSign = (byte0 & 0x02) !== 0
      flags.encipherOnly = (byte0 & 0x01) !== 0
    }

    if (bits.length > 1) {
      flags.decipherOnly = (bits[1] & 0x80) !== 0
    }
  }

  return flags
}

function parseExtKeyUsage(ext: pkijs.Extension): string[] {
  const usages: string[] = []

  if (ext.parsedValue instanceof pkijs.ExtKeyUsage) {
    for (const oid of ext.parsedValue.keyPurposes) {
      usages.push(getExtKeyUsageName(oid))
    }
  }

  return usages
}

function getExtKeyUsageName(oid: string): string {
  const names: Record<string, string> = {
    '1.3.6.1.5.5.7.3.1': 'serverAuth',
    '1.3.6.1.5.5.7.3.2': 'clientAuth',
    '1.3.6.1.5.5.7.3.3': 'codeSigning',
    '1.3.6.1.5.5.7.3.4': 'emailProtection',
    '1.3.6.1.5.5.7.3.8': 'timeStamping',
    '1.3.6.1.5.5.7.3.9': 'ocspSigning',
    '1.3.6.1.4.1.311.10.3.12': 'documentSigning',
  }
  return names[oid] || oid
}

function parseAuthorityInfoAccess(ext: pkijs.Extension): AuthorityInfoAccess | null {
  const result: AuthorityInfoAccess = {
    ocsp: [],
    caIssuers: [],
  }

  if (ext.parsedValue instanceof pkijs.InfoAccess) {
    for (const desc of ext.parsedValue.accessDescriptions) {
      if (desc instanceof pkijs.AccessDescription) {
        addAiaEntry(desc, result)
      }
    }
  } else if (ext.parsedValue instanceof pkijs.AccessDescription) {
    addAiaEntry(ext.parsedValue, result)
  }

  if (result.ocsp.length === 0 && result.caIssuers.length === 0) {
    return null
  }

  return result
}

function addAiaEntry(desc: pkijs.AccessDescription, result: AuthorityInfoAccess): void {
  const location = desc.accessLocation
  if (location.type !== 6) return // uniformResourceIdentifier

  const url = location.value as string

  if (desc.accessMethod === '1.3.6.1.5.5.7.48.1') {
    // OCSP
    result.ocsp.push(url)
  } else if (desc.accessMethod === '1.3.6.1.5.5.7.48.2') {
    // caIssuers
    result.caIssuers.push(url)
  }
}

function parseCrlDistributionPoints(ext: pkijs.Extension): string[] {
  const urls: string[] = []

  if (ext.parsedValue instanceof pkijs.CRLDistributionPoints) {
    for (const dp of ext.parsedValue.distributionPoints) {
      if (dp.distributionPoint) {
        const names = dp.distributionPoint
        if (Array.isArray(names)) {
          for (const name of names) {
            if (name.type === 6) {
              urls.push(name.value as string)
            }
          }
        }
      }
    }
  }

  return urls
}

async function computeFingerprint(der: ArrayBuffer): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', der)
  return bufferToHex(new Uint8Array(hash))
}

function bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Check if certificate is currently valid
 */
export function isCertificateValid(cert: ParsedCertificate, atTime: Date = new Date()): boolean {
  return atTime >= cert.notBefore && atTime <= cert.notAfter
}

/**
 * Check if certificate can sign documents
 */
export function canSignDocuments(cert: ParsedCertificate): boolean {
  // Must have digital signature or non-repudiation key usage
  if (!cert.keyUsage.digitalSignature && !cert.keyUsage.nonRepudiation) {
    return false
  }

  // If CA, should not be used for signing documents
  if (cert.isCA) {
    return false
  }

  return true
}

/**
 * Get common name from subject
 */
export function getCommonName(cert: ParsedCertificate): string {
  const cnMatch = cert.subject.match(/CN=([^,]+)/)
  return cnMatch ? cnMatch[1] : cert.subject
}
