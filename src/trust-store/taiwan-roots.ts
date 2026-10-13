/**
 * Taiwan PKI trust anchors (signing CAs).
 *
 * The certificate data lives in `generated-anchors.ts`, produced by
 * `scripts/trust-store/build-trust-store.mjs` from the DER files and the
 * manifest under `scripts/trust-store/`. Every entry is pinned by SHA-256;
 * the trust manager refuses an entry whose computed fingerprint differs.
 *
 * Coverage (default policy: Taiwan certificates only, no self-signed certs):
 *   - government: GRCA G1 / G2 / G3 (MOICA, GCA, XCA, MOEACA … chain to these)
 *   - private:    TWCA (Root CA SHA-1 + SHA-256, Global Root CA, CYBER Root CA)
 *                 Chunghwa Telecom (ePKI Root CA, ePKI Root CA - G2, HiPKI Root CA - G1)
 *
 * Intermediates (MOICA G2, GCA, XCA, MOEACA) are NOT anchors; they are only
 * offered to the path builder so chains can be completed offline.
 */
import { GENERATED_ROOTS, GENERATED_INTERMEDIATES } from './generated-anchors'

export type TrustCategory = 'government' | 'private' | 'international'
export type TrustUsage = 'signing' | 'timestamping'

export interface TrustAnchorEntry {
  /** Human-readable name (used in UI and report) */
  name: string
  /** Taiwan government (GPKI), Taiwan private (commercial) or international CA */
  category: TrustCategory
  /** International CAs: vendor shown to the user (e.g. DigiCert). */
  vendor?: string
  /** International CAs: hierarchies this root anchors. Taiwan roots anchor both. */
  usage?: TrustUsage[]
  /** PEM-encoded X.509 certificate. Empty string = not yet populated. */
  pem: string
  /** SHA-256 fingerprint of the DER. Lowercase hex, colon-separated. */
  expectedFingerprint?: string
  /** Where the certificate was obtained from. */
  source: string
  /** Free-form notes (subject, validity, …). */
  notes?: string
}

export const TAIWAN_ROOT_CERTIFICATES: TrustAnchorEntry[] = GENERATED_ROOTS.filter(
  (entry) => entry.category !== 'international'
)

export const TAIWAN_INTERMEDIATE_CERTIFICATES: TrustAnchorEntry[] = GENERATED_INTERMEDIATES

/**
 * Whether the build has at least one PEM populated.
 */
export function hasAnyEmbeddedPem(): boolean {
  return TAIWAN_ROOT_CERTIFICATES.some((entry) => entry.pem.trim().length > 0)
}

/**
 * Return only entries that have a PEM body (filtering out unpopulated slots).
 */
export function getPopulatedEntries(): TrustAnchorEntry[] {
  return TAIWAN_ROOT_CERTIFICATES.filter((entry) => entry.pem.trim().length > 0)
}

/**
 * Get all root certificate PEM strings (populated only)
 */
export function getAllRootCertificates(): string[] {
  return getPopulatedEntries().map((cert) => cert.pem)
}

/**
 * Get root certificate names
 */
export function getRootCertificateNames(): string[] {
  return TAIWAN_ROOT_CERTIFICATES.map((cert) => cert.name)
}
