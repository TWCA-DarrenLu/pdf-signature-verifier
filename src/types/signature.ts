import type { ContentInfo, SignedData } from 'pkijs'
import type { ParsedCertificate } from './certificate'

export interface PdfSignatureField {
  name: string
  byteRange: ByteRange
  contents: Uint8Array
  subFilter: string
  isDocTimeStamp?: boolean
  reason?: string
  location?: string
  contactInfo?: string
  signDate?: Date
  m?: Date
  /**
   * Audit P2-7: DocMDP info derived from the signature's /Reference
   * /TransformMethod /DocMDP and the document catalog's /Perms /DocMDP.
   * Presence => this is a certification signature.
   */
  docMdp?: {
    permissionLevel: 1 | 2 | 3
    digestMethod?: string
  }
  /**
   * Audit P2-7: FieldMDP info (constrains modifications to specific fields).
   */
  fieldMdp?: {
    /** "All", "Include", "Exclude" */
    action: 'All' | 'Include' | 'Exclude'
    fields: string[]
  }
}

export interface ByteRange {
  start1: number
  length1: number
  start2: number
  length2: number
}

export interface ParsedPkcs7 {
  contentInfo: ContentInfo
  signedData: SignedData
  signerInfos: SignerInfo[]
  certificates: ParsedCertificate[]
  embeddedTimestamp: EmbeddedTimestamp | null
  embeddedRevocationInfo: EmbeddedRevocationInfo | null
}

export interface SignerInfo {
  signerCertificate: ParsedCertificate | null
  digestAlgorithm: string
  signatureAlgorithm: string
  signatureValue: Uint8Array
  signedAttributes: SignedAttribute[]
  unsignedAttributes: UnsignedAttribute[]
  messageDigest: Uint8Array | null
  signingTime: Date | null
  signingCertificateHash?: string
  /** Hash algorithm of signingCertificateHash (SHA-1 for v1, declared/SHA-256 for v2) */
  signingCertificateHashAlgorithm?: string
}

export interface SignedAttribute {
  oid: string
  name: string
  value: unknown
}

export interface UnsignedAttribute {
  oid: string
  name: string
  value: unknown
}

export interface EmbeddedTimestamp {
  raw: Uint8Array
  time: Date
  issuer: string
  serialNumber: string
  hashAlgorithm: string
}

export interface EmbeddedRevocationInfo {
  ocspResponses: Uint8Array[]
  crls: Uint8Array[]
  certs: Uint8Array[]
}

export interface DigestResult {
  algorithm: string
  digest: Uint8Array
  expected: Uint8Array | null
  matches: boolean
}

export interface SignatureVerificationResult {
  isValid: boolean
  algorithm: string
  keySize?: number
  error?: string
}

export const SUPPORTED_DIGEST_ALGORITHMS = [
  'SHA-1',
  'SHA-256',
  'SHA-384',
  'SHA-512',
] as const

export const SUPPORTED_SIGNATURE_ALGORITHMS = [
  'RSASSA-PKCS1-v1_5',
  'RSA-PSS',
  'ECDSA',
] as const

export type DigestAlgorithm = (typeof SUPPORTED_DIGEST_ALGORITHMS)[number]
export type SignatureAlgorithm = (typeof SUPPORTED_SIGNATURE_ALGORITHMS)[number]

export const OID_MAP: Record<string, string> = {
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
  '1.2.840.113549.1.9.3': 'contentType',
  '1.2.840.113549.1.9.4': 'messageDigest',
  '1.2.840.113549.1.9.5': 'signingTime',
  '1.2.840.113549.1.9.16.2.14': 'timeStampToken',
  '1.2.840.113549.1.9.16.1.4': 'id-smime-ct-TSTInfo',
}
