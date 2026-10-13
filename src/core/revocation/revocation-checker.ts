import type { EmbeddedRevocationInfo, ParsedCertificate } from '@/types'
import {
  validateOcspResponse,
  validateCrl,
  evidenceCoversTime,
  type RevocationEvidence,
} from './revocation-validator'
import { requestOcspResponse } from './ocsp-client'
import { getCachedRevocation, putCachedRevocation } from './revocation-cache'

export interface RevocationContext {
  /** Revocation data embedded in the PDF (signature attribute + DSS). */
  embedded: EmbeddedRevocationInfo | null
  /** Whether OCSP / CRL may be fetched over the network. */
  allowOnline: boolean
  /** Time the status must hold for: trusted signing time, else now. */
  atTime: Date
  /** atTime comes from a trusted RFC 3161 timestamp. */
  atTimeTrusted: boolean
  /** Skip cached online answers (user asked to check again). */
  freshOnline?: boolean
  now?: Date
}

export interface CertRevocationOutcome {
  status: 'good' | 'revoked' | 'unknown'
  source: 'embedded' | 'online' | 'none'
  evidence?: RevocationEvidence
  /** Revoked, but only after the (trusted) signing time. */
  revokedAfterSigning?: boolean
  /** Verified embedded evidence covering atTime (what LTV relies on). */
  embeddedEvidence?: RevocationEvidence
}

const CLOCK_SKEW_MS = 5 * 60 * 1000

/**
 * Determine the revocation status of `cert` at ctx.atTime.
 *
 * Sources: embedded (OCSP, CRL) and — when allowed and the certificate is
 * unexpired — online (OCSP, CRL). Only cryptographically validated evidence
 * counts (see revocation-validator.ts). A revocation from any source wins;
 * otherwise embedded "good" (LTV) is preferred over online "good".
 * CAs drop expired certificates from CRLs/OCSP, so evidence issued after the
 * certificate expired is ignored, and expired certificates are not checked
 * online — they need embedded (LTV) data.
 */
export async function checkCertificateRevocation(
  cert: ParsedCertificate,
  issuer: ParsedCertificate,
  ctx: RevocationContext
): Promise<CertRevocationOutcome> {
  const now = ctx.now ?? new Date()
  const embedded = await findEmbeddedEvidence(cert, issuer, ctx, now)
  const online = ctx.allowOnline && now <= cert.notAfter ? await findOnlineEvidence(cert, issuer, now, ctx.freshOnline === true) : null

  const fromEmbedded = embedded ? { ...interpret(embedded, ctx), source: 'embedded' as const, evidence: embedded } : null
  const fromOnline = online ? { ...interpret(online, ctx), source: 'online' as const, evidence: online } : null

  if (fromEmbedded?.status === 'revoked') return fromEmbedded
  if (fromOnline?.status === 'revoked') return fromOnline
  if (fromEmbedded?.status === 'good') return { ...fromEmbedded, embeddedEvidence: embedded! }
  if (fromOnline?.status === 'good') return fromOnline
  return { status: 'unknown', source: 'none' }
}

async function findEmbeddedEvidence(
  cert: ParsedCertificate,
  issuer: ParsedCertificate,
  ctx: RevocationContext,
  now: Date
): Promise<RevocationEvidence | null> {
  if (!ctx.embedded) return null
  const found: RevocationEvidence[] = []
  // "Good" issued after the certificate expired proves nothing (the CA may
  // already have dropped it); a revocation entry is always meaningful.
  const usable = (ev: RevocationEvidence | null): ev is RevocationEvidence =>
    !!ev &&
    ev.status !== 'unknown' &&
    evidenceCoversTime(ev, ctx.atTime, now) &&
    (ev.status === 'revoked' || ev.thisUpdate.getTime() <= cert.notAfter.getTime() + CLOCK_SKEW_MS)
  for (const data of ctx.embedded.ocspResponses) {
    const ev = await validateOcspResponse(data, cert, issuer)
    if (usable(ev)) found.push(ev)
  }
  for (const data of ctx.embedded.crls) {
    const ev = await validateCrl(data, cert, issuer)
    if (usable(ev)) found.push(ev)
  }
  // A revocation that predates atTime outweighs any "good" evidence.
  const revoked = found.find((ev) => ev.status === 'revoked' && interpret(ev, ctx).status === 'revoked')
  return revoked ?? found[0] ?? null
}

async function findOnlineEvidence(
  cert: ParsedCertificate,
  issuer: ParsedCertificate,
  now: Date,
  fresh: boolean
): Promise<RevocationEvidence | null> {
  try {
    const ev = await cachedOrFetched(
      `ocsp:${issuer.fingerprint}:${cert.serialNumber}`,
      fresh,
      now,
      () => requestOcspResponse(cert, issuer),
      async (bytes) => {
        const ev = await validateOcspResponse(bytes, cert, issuer)
        return ev && ev.status !== 'unknown' && isCurrent(ev, now) ? ev : null
      }
    )
    if (ev) return ev
  } catch {
    // fall through to CRL
  }

  const { fetchBinary } = await import('../network')
  for (const url of cert.crlDistributionPoints) {
    try {
      const ev = await cachedOrFetched(`crl:${url}`, fresh, now, () => fetchBinary(url), async (bytes) => {
        const ev = await validateCrl(bytes, cert, issuer)
        return ev && isCurrent(ev, now) ? ev : null
      })
      if (ev) return ev
    } catch {
      continue
    }
  }
  return null
}

/**
 * Use a cached answer when it still validates, otherwise fetch and cache.
 * Bytes are validated in both cases; the cache only saves the round trip.
 */
async function cachedOrFetched(
  key: string,
  fresh: boolean,
  now: Date,
  fetch: () => Promise<Uint8Array | null>,
  validate: (bytes: Uint8Array) => Promise<RevocationEvidence | null>
): Promise<RevocationEvidence | null> {
  if (!fresh) {
    const cached = await getCachedRevocation(key, now.getTime())
    const ev = cached ? await validate(cached) : null
    if (ev) return ev
  }
  const bytes = await fetch()
  if (!bytes) return null
  const ev = await validate(bytes)
  if (ev) await putCachedRevocation(key, bytes, ev, now.getTime())
  return ev
}

const MAX_AGE_WITHOUT_NEXT_UPDATE_MS = 24 * 60 * 60 * 1000

function isCurrent(ev: RevocationEvidence, now: Date): boolean {
  if (ev.thisUpdate.getTime() > now.getTime() + CLOCK_SKEW_MS) return false
  if (!ev.nextUpdate) {
    // No validity window (and no nonce): only accept a recent answer.
    return now.getTime() - ev.thisUpdate.getTime() <= MAX_AGE_WITHOUT_NEXT_UPDATE_MS
  }
  return ev.nextUpdate.getTime() + CLOCK_SKEW_MS >= now.getTime()
}

function interpret(
  ev: RevocationEvidence,
  ctx: RevocationContext
): Pick<CertRevocationOutcome, 'status' | 'revokedAfterSigning'> {
  if (ev.status !== 'revoked') return { status: ev.status }
  // certificateHold is a suspension, not a final revocation: indeterminate.
  if (ev.reason === 'certificateHold') return { status: 'unknown' }
  if (ctx.atTimeTrusted && ev.revokedAt && ev.revokedAt.getTime() > ctx.atTime.getTime()) {
    // Revoked after a timestamp-proven signing time: the signature was
    // created while the certificate was still valid.
    return { status: 'good', revokedAfterSigning: true }
  }
  return { status: 'revoked' }
}
