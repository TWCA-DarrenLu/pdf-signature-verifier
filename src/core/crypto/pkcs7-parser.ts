import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'
import { t } from '@/i18n'
import type {
  ParsedPkcs7,
  SignerInfo,
  SignedAttribute,
  UnsignedAttribute,
  EmbeddedTimestamp,
  EmbeddedRevocationInfo,
} from '@/types'
import { parseCertificate } from '../certificate/cert-utils'
import { toArrayBuffer } from '../bytes'
import type { ParsedCertificate } from '@/types'
import { findSignerCertificate, getEncapsulatedContentBytes } from './pki-verify'

const { ContentInfo, SignedData, Certificate } = pkijs

// OID constants
const OID = {
  SIGNED_DATA: '1.2.840.113549.1.7.2',
  DATA: '1.2.840.113549.1.7.1',
  CONTENT_TYPE: '1.2.840.113549.1.9.3',
  MESSAGE_DIGEST: '1.2.840.113549.1.9.4',
  SIGNING_TIME: '1.2.840.113549.1.9.5',
  TIMESTAMP_TOKEN: '1.2.840.113549.1.9.16.2.14',
  TST_INFO: '1.2.840.113549.1.9.16.1.4',
  ADOBE_REVOCATION_INFO_ARCHIVAL: '1.2.840.113583.1.1.8',
  ID_PKIX_OCSP_BASIC: '1.3.6.1.5.5.7.48.1.1',
  SIGNING_CERTIFICATE: '1.2.840.113549.1.9.16.2.12',
  SIGNING_CERTIFICATE_V2: '1.2.840.113549.1.9.16.2.47',
}

/**
 * Parse PKCS#7/CMS SignedData structure
 */
export async function parsePkcs7(data: Uint8Array): Promise<ParsedPkcs7> {
  // Parse ASN.1 structure
  const asn1 = asn1js.fromBER(toArrayBuffer(data))
  if (asn1.offset === -1) {
    throw new Error('Failed to parse ASN.1 structure')
  }

  // Parse ContentInfo
  const contentInfo = new ContentInfo({ schema: asn1.result })

  // Verify it's SignedData
  if (contentInfo.contentType !== OID.SIGNED_DATA) {
    throw new Error(`Expected SignedData OID, got ${contentInfo.contentType}`)
  }

  // Parse SignedData
  const signedData = new SignedData({ schema: contentInfo.content })

  // Parse certificates (keeping each one's original DER)
  const certificates: ParsedCertificate[] = []
  if (signedData.certificates) {
    const ders = originalCertificateDers(asn1.result)
    const aligned = ders.length === signedData.certificates.length
    for (const [i, cert] of signedData.certificates.entries()) {
      if (cert instanceof Certificate) {
        const parsed = await parseCertificate(cert, aligned ? ders[i] : undefined)
        certificates.push(parsed)
      }
    }
  }

  // Parse signer infos
  const signerInfos: SignerInfo[] = []
  for (const si of signedData.signerInfos) {
    const signerInfo = await parseSignerInfo(si, certificates)
    signerInfos.push(signerInfo)
  }

  // Signature timestamp of the first SignerInfo — the one that is verified.
  let embeddedTimestamp: EmbeddedTimestamp | null = null
  const tsAttr = signerInfos[0]?.unsignedAttributes.find((attr) => attr.oid === OID.TIMESTAMP_TOKEN)
  if (tsAttr && tsAttr.value instanceof Uint8Array) {
    embeddedTimestamp = await parseTimestampToken(tsAttr.value)
  }

  // Extract embedded revocation info
  const embeddedRevocationInfo = extractRevocationInfo(signedData)

  return {
    contentInfo,
    signedData,
    signerInfos,
    certificates,
    embeddedTimestamp,
    embeddedRevocationInfo,
  }
}

async function parseSignerInfo(
  si: pkijs.SignerInfo,
  certificates: ParsedCertificate[]
): Promise<SignerInfo> {
  // Find signer certificate by sid (issuer + serial, or SKI) — no guessing.
  const rawSigner = findSignerCertificate(si, certificates.map((c) => c.raw))
  const signerCertificate: ParsedCertificate | null =
    certificates.find((cert) => cert.raw === rawSigner) ?? null

  // Get digest algorithm
  const digestAlgorithm = getAlgorithmName(si.digestAlgorithm.algorithmId)

  // Get signature algorithm
  const signatureAlgorithm = getAlgorithmName(si.signatureAlgorithm.algorithmId)

  // Get signature value
  const signatureValue = new Uint8Array(si.signature.valueBlock.valueHexView)

  // Parse signed attributes
  const signedAttributes: SignedAttribute[] = []
  let messageDigest: Uint8Array | null = null
  let signingTime: Date | null = null
  let signingCertificateHash: string | undefined
  let signingCertificateHashAlgorithm: string | undefined

  if (si.signedAttrs) {
    for (const attr of si.signedAttrs.attributes) {
      const oid = attr.type
      const name = getAttributeName(oid)
      let value: unknown = null

      if (attr.values.length > 0) {
        value = parseAttributeValue(oid, attr.values[0])

        if (oid === OID.MESSAGE_DIGEST && attr.values[0] instanceof asn1js.OctetString) {
          messageDigest = new Uint8Array(attr.values[0].valueBlock.valueHexView)
        }

        if (oid === OID.SIGNING_TIME) {
          signingTime = parseSigningTime(attr.values[0])
        }

        // CAdES: extract certHash from SigningCertificate or SigningCertificateV2
        if (oid === OID.SIGNING_CERTIFICATE_V2 || oid === OID.SIGNING_CERTIFICATE) {
          const essCert = extractSigningCertificateHash(attr.values[0], oid === OID.SIGNING_CERTIFICATE_V2)
          signingCertificateHash = essCert?.hash
          signingCertificateHashAlgorithm = essCert?.algorithm
        }
      }

      signedAttributes.push({ oid, name, value })
    }
  }

  // Parse unsigned attributes
  const unsignedAttributes: UnsignedAttribute[] = []
  if (si.unsignedAttrs) {
    for (const attr of si.unsignedAttrs.attributes) {
      const oid = attr.type
      const name = getAttributeName(oid)
      let value: unknown = null

      if (attr.values.length > 0) {
        if (oid === OID.TIMESTAMP_TOKEN) {
          // Store raw timestamp token
          const encoded = attr.values[0].toBER()
          value = new Uint8Array(encoded)
        } else {
          value = parseAttributeValue(oid, attr.values[0])
        }
      }

      unsignedAttributes.push({ oid, name, value })
    }
  }

  return {
    signerCertificate,
    digestAlgorithm,
    signatureAlgorithm,
    signatureValue,
    signedAttributes,
    unsignedAttributes,
    messageDigest,
    signingTime,
    signingCertificateHash,
    signingCertificateHashAlgorithm,
  }
}

async function parseTimestampToken(data: Uint8Array): Promise<EmbeddedTimestamp | null> {
  try {
    const asn1 = asn1js.fromBER(toArrayBuffer(data))
    if (asn1.offset === -1) {
      return null
    }

    const tspContentInfo = new ContentInfo({ schema: asn1.result })
    if (tspContentInfo.contentType !== OID.SIGNED_DATA) {
      return null
    }

    const tspSignedData = new SignedData({ schema: tspContentInfo.content })

    // Get TSTInfo from encapContentInfo
    if (!tspSignedData.encapContentInfo?.eContent) {
      return null
    }

    const tstInfoData = getEncapsulatedContentBytes(tspSignedData)
    if (!tstInfoData) {
      return null
    }
    const tstInfoAsn1 = asn1js.fromBER(toArrayBuffer(tstInfoData))
    if (tstInfoAsn1.offset === -1) {
      return null
    }

    // Parse TSTInfo sequence
    const tstInfo = tstInfoAsn1.result as asn1js.Sequence
    if (!(tstInfo instanceof asn1js.Sequence)) {
      return null
    }

    // TSTInfo ::= SEQUENCE {
    //   version        INTEGER { v1(1) },          -- [0]
    //   policy         OBJECT IDENTIFIER,           -- [1]
    //   messageImprint MessageImprint,              -- [2]
    //   serialNumber   INTEGER,                     -- [3]
    //   genTime        GeneralizedTime,             -- [4]
    //   ...
    // }

    const values = tstInfo.valueBlock.value
    if (values.length < 5) {
      return null
    }

    // Field 0: version (skip)
    // Field 1: policy (skip)

    // Field 2: messageImprint SEQUENCE { AlgorithmIdentifier, OCTET STRING }
    let hashAlgorithm = ''
    const msgImprintItem = values[2]
    if (msgImprintItem instanceof asn1js.Sequence && msgImprintItem.valueBlock.value.length >= 2) {
      const algSeq = msgImprintItem.valueBlock.value[0]
      if (algSeq instanceof asn1js.Sequence && algSeq.valueBlock.value.length > 0) {
        const algOid = algSeq.valueBlock.value[0]
        if (algOid instanceof asn1js.ObjectIdentifier) {
          hashAlgorithm = getAlgorithmName(algOid.valueBlock.toString())
        }
      }
    }

    // Field 3: serialNumber INTEGER
    let serialNumber = ''
    const serialItem = values[3]
    if (serialItem instanceof asn1js.Integer) {
      serialNumber = bufferToHex(serialItem.valueBlock.valueHexView)
    }

    // Field 4: genTime GeneralizedTime
    const genTimeItem = values[4]
    if (!(genTimeItem instanceof asn1js.GeneralizedTime)) {
      return null
    }
    const time = genTimeItem.toDate()

    // TSA name from the certificate the SignerInfo actually refers to
    let issuer = t('core.timestampVerifier.unknownTsa')
    const tsaCerts = (tspSignedData.certificates ?? []).filter(
      (c): c is pkijs.Certificate => c instanceof Certificate
    )
    const tsaSignerInfo = tspSignedData.signerInfos[0]
    const tsaCert = tsaSignerInfo ? findSignerCertificate(tsaSignerInfo, tsaCerts) : null
    if (tsaCert) {
      const parsed = await parseCertificate(tsaCert)
      const cn = parsed.subject.match(/CN=([^,]+)/)
      issuer = cn ? cn[1] : parsed.subject
    }

    return {
      raw: data,
      time,
      issuer,
      serialNumber,
      hashAlgorithm,
    }
  } catch {
    return null
  }
}

/**
 * Original DER of each SignedData.certificates entry, in order.
 * ContentInfo ::= SEQUENCE { contentType, [0] EXPLICIT SignedData }
 * SignedData  ::= SEQUENCE { version, digestAlgorithms, encapContentInfo,
 *                            certificates [0] IMPLICIT SET OF ..., ... }
 */
function originalCertificateDers(contentInfo: asn1js.AsnType): Uint8Array[] {
  try {
    const explicit = (contentInfo as asn1js.Sequence).valueBlock.value[1] as asn1js.Constructed
    const signedData = explicit.valueBlock.value[0] as asn1js.Sequence
    const certs = signedData.valueBlock.value.find(
      (n) => n.idBlock.tagClass === 3 && n.idBlock.tagNumber === 0
    ) as asn1js.Constructed | undefined
    return certs ? certs.valueBlock.value.map((n) => new Uint8Array(n.valueBeforeDecodeView)) : []
  } catch {
    return []
  }
}

function extractRevocationInfo(signedData: pkijs.SignedData): EmbeddedRevocationInfo | null {
  const ocspResponses: Uint8Array[] = []
  const crls: Uint8Array[] = []

  // Adobe revocation info (adbe-revocationInfoArchival). ISO 32000-1 §12.8.3.3.2
  // places it in the SIGNED attributes (Acrobat, TWCA signing services);
  // some producers put it in the unsigned attributes — accept both.
  for (const si of signedData.signerInfos) {
    for (const attrs of [si.signedAttrs, si.unsignedAttrs]) {
      if (!attrs) continue
      for (const attr of attrs.attributes) {
        if (attr.type === OID.ADOBE_REVOCATION_INFO_ARCHIVAL) {
          for (const val of attr.values) {
            if (val instanceof asn1js.Sequence) {
              extractFromRevocationInfoArchival(val, ocspResponses, crls)
            }
          }
        }
      }
    }
  }

  // Check CRLs in SignedData
  if (signedData.crls) {
    for (const crl of signedData.crls) {
      if (crl instanceof pkijs.CertificateRevocationList) {
        crls.push(new Uint8Array(crl.toSchema().toBER()))
      }
    }
  }

  if (ocspResponses.length === 0 && crls.length === 0) {
    return null
  }

  return { ocspResponses, crls, certs: [] }
}

function extractFromRevocationInfoArchival(
  seq: asn1js.Sequence,
  ocspResponses: Uint8Array[],
  crls: Uint8Array[]
): void {
  // RevocationInfoArchival ::= SEQUENCE {
  //   crl  [0] EXPLICIT SEQUENCE OF CRLs OPTIONAL,
  //   ocsp [1] EXPLICIT SEQUENCE OF OCSPResponse OPTIONAL, ... }
  // Some producers omit the inner SEQUENCE OF; accept both shapes.
  for (const item of seq.valueBlock.value) {
    if (!(item instanceof asn1js.Constructed) || item.idBlock.tagClass !== 3) continue
    const tagNumber = item.idBlock.tagNumber
    const target = tagNumber === 0 ? crls : tagNumber === 1 ? ocspResponses : null
    if (!target) continue
    const looksLikeElement = tagNumber === 0 ? looksLikeCrl : looksLikeOcspResponse
    for (const child of item.valueBlock.value) {
      if (looksLikeElement(child)) {
        target.push(new Uint8Array(child.toBER()))
      } else if (child instanceof asn1js.Sequence) {
        for (const element of child.valueBlock.value) {
          target.push(new Uint8Array(element.toBER()))
        }
      }
    }
  }
}

/** CertificateList ::= SEQUENCE { tbsCertList SEQUENCE, signatureAlgorithm SEQUENCE, signature BIT STRING } */
function looksLikeCrl(node: asn1js.AsnType): boolean {
  if (!(node instanceof asn1js.Sequence)) return false
  const v = node.valueBlock.value
  return v.length === 3 && v[0] instanceof asn1js.Sequence && v[2] instanceof asn1js.BitString
}

/** OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, responseBytes [0] EXPLICIT ... OPTIONAL } */
function looksLikeOcspResponse(node: asn1js.AsnType): boolean {
  if (!(node instanceof asn1js.Sequence)) return false
  return node.valueBlock.value[0] instanceof asn1js.Enumerated
}

/**
 * Extract certHash from SigningCertificate or SigningCertificateV2 attribute.
 * Structure: SEQUENCE { SEQUENCE OF ESSCertIDv2 { SEQUENCE { hashAlgorithm?, certHash OCTET STRING, ... } }, ... }
 */
function extractSigningCertificateHash(
  value: asn1js.AsnType,
  isV2: boolean
): { hash: string; algorithm: string } | undefined {
  try {
    // SigningCertificate   ::= SEQUENCE { certs SEQUENCE OF ESSCertID, ... }
    //   ESSCertID          ::= SEQUENCE { certHash OCTET STRING (SHA-1), ... }
    // SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2, ... }
    //   ESSCertIDv2        ::= SEQUENCE { hashAlgorithm DEFAULT sha-256, certHash OCTET STRING, ... }
    if (!(value instanceof asn1js.Sequence)) return undefined

    const certs = value.valueBlock.value[0]
    if (!(certs instanceof asn1js.Sequence)) return undefined

    const firstCertId = certs.valueBlock.value[0]
    if (!(firstCertId instanceof asn1js.Sequence)) return undefined

    let algorithm = isV2 ? 'SHA-256' : 'SHA-1'
    for (const item of firstCertId.valueBlock.value) {
      if (isV2 && item instanceof asn1js.Sequence) {
        const oid = item.valueBlock.value[0]
        if (oid instanceof asn1js.ObjectIdentifier) {
          algorithm = getAlgorithmName(oid.valueBlock.toString())
        }
      }
      if (item instanceof asn1js.OctetString) {
        return { hash: bufferToHex(item.valueBlock.valueHexView), algorithm }
      }
    }

    return undefined
  } catch {
    return undefined
  }
}

function parseSigningTime(value: asn1js.AsnType): Date | null {
  if (value instanceof asn1js.UTCTime) {
    return value.toDate()
  }
  if (value instanceof asn1js.GeneralizedTime) {
    return value.toDate()
  }
  return null
}

function parseAttributeValue(_oid: string, value: asn1js.AsnType): unknown {
  if (value instanceof asn1js.OctetString) {
    return new Uint8Array(value.valueBlock.valueHexView)
  }
  if (value instanceof asn1js.ObjectIdentifier) {
    return value.valueBlock.toString()
  }
  if (value instanceof asn1js.UTCTime || value instanceof asn1js.GeneralizedTime) {
    return value.toDate()
  }
  if (value instanceof asn1js.PrintableString || value instanceof asn1js.Utf8String) {
    return value.valueBlock.value
  }
  return value.toBER()
}

function getAlgorithmName(oid: string): string {
  const names: Record<string, string> = {
    '1.2.840.113549.1.1.1': 'RSA',
    '1.2.840.113549.1.1.5': 'SHA1withRSA',
    '1.2.840.113549.1.1.11': 'SHA256withRSA',
    '1.2.840.113549.1.1.12': 'SHA384withRSA',
    '1.2.840.113549.1.1.13': 'SHA512withRSA',
    '1.2.840.113549.1.1.10': 'RSA-PSS',
    '1.2.840.10045.4.1': 'SHA1withECDSA',
    '1.2.840.10045.4.3.2': 'SHA256withECDSA',
    '1.2.840.10045.4.3.3': 'SHA384withECDSA',
    '1.2.840.10045.4.3.4': 'SHA512withECDSA',
    '2.16.840.1.101.3.4.2.1': 'SHA-256',
    '2.16.840.1.101.3.4.2.2': 'SHA-384',
    '2.16.840.1.101.3.4.2.3': 'SHA-512',
    '1.3.14.3.2.26': 'SHA-1',
  }
  return names[oid] || oid
}

function getAttributeName(oid: string): string {
  const names: Record<string, string> = {
    '1.2.840.113549.1.9.3': 'contentType',
    '1.2.840.113549.1.9.4': 'messageDigest',
    '1.2.840.113549.1.9.5': 'signingTime',
    '1.2.840.113549.1.9.16.2.14': 'timeStampToken',
    '1.2.840.113583.1.1.8': 'adobeRevocationInfoArchival',
    '1.2.840.113549.1.9.16.2.12': 'signingCertificate',
    '1.2.840.113549.1.9.16.2.47': 'signingCertificateV2',
  }
  return names[oid] || oid
}

function bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Get the DER-encoded signed attributes for verification
 */
export function getSignedAttributesData(signedData: pkijs.SignedData, signerIndex: number): Uint8Array | null {
  const signerInfo = signedData.signerInfos[signerIndex]
  if (!signerInfo?.signedAttrs) {
    return null
  }

  // Original encoding as received (re-encoding can change the bytes);
  // pkijs already rewrites the IMPLICIT [0] tag to SET (0x31). Attributes
  // built in code have no original encoding — encode them.
  const original = signerInfo.signedAttrs.encodedValue
  if (original && original.byteLength > 0) return new Uint8Array(original)
  const encoded = new Uint8Array(signerInfo.signedAttrs.toSchema().toBER())
  encoded[0] = 0x31
  return encoded
}
