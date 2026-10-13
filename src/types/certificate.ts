import type { Certificate } from 'pkijs'

export interface ParsedCertificate {
  raw: Certificate
  /** Original DER as received (fingerprints and ESS cert hashes use this). */
  der?: Uint8Array
  subject: string
  issuer: string
  serialNumber: string
  notBefore: Date
  notAfter: Date
  publicKey: CryptoKey | null
  fingerprint: string
  isCA: boolean
  isSelfSigned: boolean
  /** basicConstraints pathLenConstraint, when present */
  pathLenConstraint?: number | null
  /** Whether the keyUsage extension is present (absent = no restriction) */
  keyUsagePresent?: boolean
  keyUsage: KeyUsageFlags
  extKeyUsage: string[]
  authorityInfoAccess: AuthorityInfoAccess | null
  crlDistributionPoints: string[]
  subjectKeyIdentifier: string | null
  authorityKeyIdentifier: string | null
}

export interface KeyUsageFlags {
  digitalSignature: boolean
  nonRepudiation: boolean
  keyEncipherment: boolean
  dataEncipherment: boolean
  keyAgreement: boolean
  keyCertSign: boolean
  crlSign: boolean
  encipherOnly: boolean
  decipherOnly: boolean
}

export interface AuthorityInfoAccess {
  ocsp: string[]
  caIssuers: string[]
}

export interface CertificateChain {
  /** Leaf first. Every link has been cryptographically verified. */
  certificates: ParsedCertificate[]
  root: ParsedCertificate | null
  /** Path reaches a self-signed certificate (trusted or not). */
  isComplete: boolean
  /** Path ends at a trust anchor (fingerprint match). */
  isTrusted: boolean
  /** The end-entity certificate is self-signed (never supported). */
  selfSignedLeaf?: boolean
}

export interface TrustAnchor {
  name: string
  certificate: ParsedCertificate
  fingerprint: string
}

export type RevocationStatus = 'good' | 'revoked' | 'unknown' | 'error'

export interface RevocationResult {
  status: RevocationStatus
  checkedAt: Date
  method: 'ocsp' | 'crl' | 'embedded' | 'none'
  revokedAt?: Date
  reason?: RevocationReason
  details?: string
  detailsI18nKey?: string
  detailsI18nParams?: Record<string, string | number>
}

export type RevocationReason =
  | 'unspecified'
  | 'keyCompromise'
  | 'caCompromise'
  | 'affiliationChanged'
  | 'superseded'
  | 'cessationOfOperation'
  | 'certificateHold'
  | 'removeFromCRL'
  | 'privilegeWithdrawn'
  | 'aaCompromise'
