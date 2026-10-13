import type { ParsedCertificate, TrustAnchor } from '@/types'
import { parseCertificateFromBytes, pemToDer } from '@/core/certificate/cert-utils'
import {
  TAIWAN_ROOT_CERTIFICATES,
  TAIWAN_INTERMEDIATE_CERTIFICATES,
  type TrustAnchorEntry,
  hasAnyEmbeddedPem,
} from './taiwan-roots'
import {
  TAIWAN_TSA_ROOT_CERTIFICATES,
  hasAnyEmbeddedTsaPem,
} from './taiwan-tsa-roots'
import { INTERNATIONAL_ROOT_CERTIFICATES } from './international-roots'

let signingTrustCache: ParsedCertificate[] | null = null
let tsaTrustCache: ParsedCertificate[] | null = null
/** International anchors: trusted only when the caller opts in. */
let intlSigningCache: ParsedCertificate[] | null = null
let intlTsaCache: ParsedCertificate[] | null = null
let intermediateCache: ParsedCertificate[] | null = null
let initWarnings: string[] = []
/** Root fingerprint → category (government / private / international) and vendor. */
const anchorInfo = new Map<string, { category: TrustAnchorEntry['category']; vendor?: string }>()

/**
 * Convert a fingerprint string (with or without colons) to a normalized
 * lowercase hex string for comparison.
 */
function normalizeFingerprint(fp: string): string {
  return fp.toLowerCase().replace(/[^0-9a-f]/g, '')
}

async function loadEntries(
  entries: TrustAnchorEntry[],
  storeLabel: string,
  optional = false
): Promise<{ anchors: ParsedCertificate[]; warnings: string[] }> {
  const anchors: ParsedCertificate[] = []
  const warnings: string[] = []

  const populated = entries.filter((e) => e.pem.trim().length > 0)
  if (populated.length === 0) {
    if (optional) return { anchors, warnings }
    warnings.push(
      `[${storeLabel}] Trust store is EMPTY — no certificates loaded. ` +
        `Regenerate src/trust-store/generated-anchors.ts (scripts/trust-store/build-trust-store.mjs).`
    )
    return { anchors, warnings }
  }

  for (const entry of populated) {
    try {
      const der = pemToDer(entry.pem)
      const parsed = await parseCertificateFromBytes(der)

      // Fingerprint pinning: refuse any entry whose DER does not hash to the
      // recorded fingerprint (accidental swap-in or tampering of the source).
      if (!entry.expectedFingerprint) {
        warnings.push(`[${storeLabel}] Refusing "${entry.name}": no pinned fingerprint`)
        continue
      }
      const expected = normalizeFingerprint(entry.expectedFingerprint)
      const actual = normalizeFingerprint(parsed.fingerprint)
      if (expected !== actual) {
        warnings.push(
          `[${storeLabel}] Refusing to trust "${entry.name}": ` +
            `fingerprint mismatch (expected ${expected.slice(0, 16)}..., got ${actual.slice(0, 16)}...)`
        )
        continue
      }

      anchors.push(parsed)
      anchorInfo.set(normalizeFingerprint(parsed.fingerprint), { category: entry.category, vendor: entry.vendor })
    } catch (error) {
      warnings.push(
        `[${storeLabel}] Failed to parse "${entry.name}": ${
          error instanceof Error ? error.message : String(error)
        }`
      )
    }
  }

  return { anchors, warnings }
}

/**
 * Initialize trust stores (signing CAs, TSAs, known intermediates).
 * Idempotent — second call returns the cached anchors.
 */
export async function initializeTrustStore(): Promise<ParsedCertificate[]> {
  if (signingTrustCache && tsaTrustCache && intlSigningCache && intlTsaCache && intermediateCache) {
    return signingTrustCache
  }

  initWarnings = []

  const signing = await loadEntries(TAIWAN_ROOT_CERTIFICATES, 'signing-ca')
  signingTrustCache = signing.anchors
  initWarnings.push(...signing.warnings)

  const tsa = await loadEntries(TAIWAN_TSA_ROOT_CERTIFICATES, 'tsa')
  tsaTrustCache = tsa.anchors
  initWarnings.push(...tsa.warnings)

  const withUsage = (usage: 'signing' | 'timestamping') =>
    INTERNATIONAL_ROOT_CERTIFICATES.filter((entry) => entry.usage?.includes(usage))
  const intlSigning = await loadEntries(withUsage('signing'), 'intl-signing', true)
  intlSigningCache = intlSigning.anchors
  initWarnings.push(...intlSigning.warnings)

  const intlTsa = await loadEntries(withUsage('timestamping'), 'intl-tsa', true)
  intlTsaCache = intlTsa.anchors
  initWarnings.push(...intlTsa.warnings)

  const intermediates = await loadEntries(TAIWAN_INTERMEDIATE_CERTIFICATES, 'intermediate')
  intermediateCache = intermediates.anchors
  initWarnings.push(...intermediates.warnings)

  for (const w of initWarnings) {
    console.warn(w)
  }

  return signingTrustCache
}

/**
 * Get warnings raised during the last initializeTrustStore() call.
 */
export function getTrustStoreWarnings(): string[] {
  return [...initWarnings]
}

export function isTrustStoreEmpty(): boolean {
  return !hasAnyEmbeddedPem()
}

export function isTsaTrustStoreEmpty(): boolean {
  return !hasAnyEmbeddedTsaPem()
}

/**
 * Get signing CA trust anchors (must call initializeTrustStore first):
 * Taiwan roots, plus the selected international roots when opted in.
 */
export function getTrustAnchors(includeInternational = false): ParsedCertificate[] {
  return [...(signingTrustCache ?? []), ...(includeInternational ? intlSigningCache ?? [] : [])]
}

/**
 * Get TSA trust anchors (must call initializeTrustStore first):
 * Taiwan roots, plus the selected international TSA roots when opted in.
 */
export function getTsaTrustAnchors(includeInternational = false): ParsedCertificate[] {
  return [...(tsaTrustCache ?? []), ...(includeInternational ? intlTsaCache ?? [] : [])]
}

/**
 * Every bundled root, trusted or not under the current option. Path-building
 * candidates only: a chain is trusted solely by the anchor set in use.
 */
export function getKnownRoots(): ParsedCertificate[] {
  const all = [...(signingTrustCache ?? []), ...(tsaTrustCache ?? []), ...(intlSigningCache ?? []), ...(intlTsaCache ?? [])]
  return [...new Map(all.map((c) => [normalizeFingerprint(c.fingerprint), c] as const)).values()]
}

/**
 * Known Taiwan intermediates — path-building helpers, never anchors.
 */
export function getKnownIntermediates(): ParsedCertificate[] {
  return intermediateCache ?? []
}

/**
 * Anchors are matched by SHA-256 fingerprint of the exact DER only. Name or
 * serial-number matches are never sufficient: anyone can mint a certificate
 * with an arbitrary subject DN and serial number.
 */
function findByFingerprint(
  cert: ParsedCertificate,
  anchors: ParsedCertificate[]
): ParsedCertificate | null {
  const certFp = normalizeFingerprint(cert.fingerprint)
  return anchors.find((anchor) => normalizeFingerprint(anchor.fingerprint) === certFp) ?? null
}

/**
 * Check if a certificate is a trust anchor (signing CA store).
 */
export function isTrustAnchor(cert: ParsedCertificate): boolean {
  return findByFingerprint(cert, getTrustAnchors()) !== null
}

/**
 * Check if a certificate is a TSA trust anchor.
 */
export function isTsaTrustAnchor(cert: ParsedCertificate): boolean {
  return findByFingerprint(cert, getTsaTrustAnchors()) !== null
}

/**
 * Return the signing-store anchor that IS this certificate (fingerprint match).
 */
export function findTrustAnchor(cert: ParsedCertificate): ParsedCertificate | null {
  return findByFingerprint(cert, getTrustAnchors())
}

/** Category of a bundled root (by fingerprint), or null if it is not one. */
export function getAnchorCategory(cert: ParsedCertificate): TrustAnchorEntry['category'] | null {
  return anchorInfo.get(normalizeFingerprint(cert.fingerprint))?.category ?? null
}

/** Vendor of a bundled international root (by fingerprint), or null. */
export function getAnchorVendor(cert: ParsedCertificate): string | null {
  return anchorInfo.get(normalizeFingerprint(cert.fingerprint))?.vendor ?? null
}

export function getTrustAnchorInfo(): TrustAnchor[] {
  return getTrustAnchors().map((cert) => ({
    name: getCommonName(cert.subject),
    certificate: cert,
    fingerprint: cert.fingerprint,
  }))
}

function getCommonName(dn: string): string {
  const match = dn.match(/CN=([^,]+)/)
  if (match) return match[1].trim()
  const ouMatch = dn.match(/OU=([^,]+)/)
  if (ouMatch) return ouMatch[1].trim()
  const oMatch = dn.match(/O=([^,]+)/)
  if (oMatch) return oMatch[1].trim()
  return dn
}

/**
 * Add a custom trust anchor (tests only; the shipped extension never calls it).
 * `international` puts it among the opt-in international anchors.
 */
export async function addCustomTrustAnchor(
  pem: string,
  options: { international?: boolean; vendor?: string; timestamping?: boolean } = {}
): Promise<void> {
  if (!signingTrustCache) {
    await initializeTrustStore()
  }
  const parsed = await parseCertificateFromBytes(pemToDer(pem))
  if (options.international) {
    anchorInfo.set(normalizeFingerprint(parsed.fingerprint), { category: 'international', vendor: options.vendor })
    if (options.timestamping) intlTsaCache = [...(intlTsaCache ?? []), parsed]
    else intlSigningCache = [...(intlSigningCache ?? []), parsed]
    return
  }
  signingTrustCache = [...signingTrustCache!, parsed]
}

export async function addCustomTsaTrustAnchor(pem: string): Promise<void> {
  if (!tsaTrustCache) {
    await initializeTrustStore()
  }
  const parsed = await parseCertificateFromBytes(pemToDer(pem))
  tsaTrustCache = [...tsaTrustCache!, parsed]
}

export function clearTrustAnchors(): void {
  signingTrustCache = null
  tsaTrustCache = null
  intlSigningCache = null
  intlTsaCache = null
  intermediateCache = null
  initWarnings = []
}

export function getTrustStoreStats(): {
  totalAnchors: number
  totalTsaAnchors: number
  totalIntermediates: number
  signingAnchors: Array<{ name: string; validUntil: Date; fingerprint: string }>
  tsaAnchors: Array<{ name: string; validUntil: Date; fingerprint: string }>
  warnings: string[]
} {
  const summarize = (a: ParsedCertificate) => ({
    name: getCommonName(a.subject),
    validUntil: a.notAfter,
    fingerprint: a.fingerprint.slice(0, 16) + '...',
  })
  return {
    totalAnchors: getTrustAnchors().length,
    totalTsaAnchors: getTsaTrustAnchors().length,
    totalIntermediates: getKnownIntermediates().length,
    signingAnchors: getTrustAnchors().map(summarize),
    tsaAnchors: getTsaTrustAnchors().map(summarize),
    warnings: getTrustStoreWarnings(),
  }
}
