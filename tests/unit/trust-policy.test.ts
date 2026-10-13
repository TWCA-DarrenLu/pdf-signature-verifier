import { describe, it, expect, beforeAll } from 'vitest'
import { determineSignatureStatus, type SignatureStatusInput } from '@/core/verifier'
import { isTimestampingCertificate } from '@/core/timestamp/tst-verifier'
import { evidenceCoversTime, type RevocationEvidence } from '@/core/revocation/revocation-validator'
import {
  clearTrustAnchors,
  getKnownIntermediates,
  getTrustAnchors,
  getTrustStoreWarnings,
  initializeTrustStore,
  isTrustAnchor,
} from '@/trust-store/trust-manager'
import { TAIWAN_ROOT_CERTIFICATES } from '@/trust-store/taiwan-roots'
import { issueCertificate } from '../helpers/test-pki'

const allGood: SignatureStatusInput = {
  integrityPassed: true,
  selfSignedSigner: false,
  chainTrusted: true,
  validityPassed: true,
  revocation: 'good',
  timestampFailure: null,
  docMdpViolation: false,
  unexplainedChanges: false,
}

describe('determineSignatureStatus', () => {
  it('is trusted only when every check is proven', () => {
    expect(determineSignatureStatus(allGood)).toBe('trusted')
  })

  it.each([
    ['integrity failure', { integrityPassed: false }],
    ['self-signed signer', { selfSignedSigner: true }],
    ['revoked certificate', { revocation: 'revoked' as const }],
    ['DocMDP violation', { docMdpViolation: true }],
    ['timestamp imprint mismatch', { timestampFailure: 'imprintMismatch' as const }],
    ['timestamp signature invalid', { timestampFailure: 'signatureInvalid' as const }],
  ])('fails on %s', (_label, override) => {
    expect(determineSignatureStatus({ ...allGood, ...override })).toBe('failed')
  })

  it.each([
    ['untrusted chain', { chainTrusted: false }],
    ['validity not established', { validityPassed: false }],
    ['unknown revocation status', { revocation: 'unknown' as const }],
    ['untrusted TSA', { timestampFailure: 'tsaUntrusted' as const }],
    ['unexplained changes after signing', { unexplainedChanges: true }],
  ])('is unknown on %s', (_label, override) => {
    expect(determineSignatureStatus({ ...allGood, ...override })).toBe('unknown')
  })

  it('a revoked certificate fails regardless of UI language (no message matching)', () => {
    // The old implementation matched the English word "revoked" in the
    // localized message, so zh-TW users saw revoked certificates as trusted.
    expect(determineSignatureStatus({ ...allGood, revocation: 'revoked' })).toBe('failed')
  })
})

describe('trust store', () => {
  beforeAll(async () => {
    clearTrustAnchors()
    await initializeTrustStore()
  })

  it('loads every bundled Taiwan root with its pinned fingerprint and no warnings', () => {
    expect(getTrustStoreWarnings()).toEqual([])
    expect(getTrustAnchors()).toHaveLength(TAIWAN_ROOT_CERTIFICATES.length)
    for (const anchor of getTrustAnchors()) {
      expect(anchor.subject).toBe(anchor.issuer) // roots only
    }
  })

  it('covers both government and private Taiwan CAs', () => {
    const categories = new Set(TAIWAN_ROOT_CERTIFICATES.map((e) => e.category))
    expect(categories).toEqual(new Set(['government', 'private']))
    const names = getTrustAnchors().map((a) => a.subject).join('\n')
    for (const expected of ['Government Root Certification Authority', 'TWCA Global Root CA', 'HiPKI Root CA - G1']) {
      expect(names).toContain(expected)
    }
  })

  it('keeps known intermediates out of the anchor set', () => {
    expect(getKnownIntermediates().length).toBeGreaterThan(0)
    for (const ca of getKnownIntermediates()) {
      expect(isTrustAnchor(ca)).toBe(false)
    }
  })
})

describe('isTimestampingCertificate', () => {
  it('requires the id-kp-timeStamping extended key usage', async () => {
    const tsa = await issueCertificate({ subjectCN: 'Test TSA', extKeyUsage: ['1.3.6.1.5.5.7.3.8'] })
    const signer = await issueCertificate({ subjectCN: 'Test Signer', extKeyUsage: ['1.3.6.1.5.5.7.3.4'] })
    const none = await issueCertificate({ subjectCN: 'Test No EKU' })
    expect(isTimestampingCertificate(tsa.parsed)).toBe(true)
    expect(isTimestampingCertificate(signer.parsed)).toBe(false)
    expect(isTimestampingCertificate(none.parsed)).toBe(false)
  })
})

describe('evidenceCoversTime', () => {
  const evidence = (thisUpdate: string, nextUpdate?: string): RevocationEvidence => ({
    status: 'good',
    kind: 'crl',
    thisUpdate: new Date(thisUpdate),
    nextUpdate: nextUpdate ? new Date(nextUpdate) : undefined,
    signerName: 'Test CA',
  })
  const now = new Date('2026-01-01T00:00:00Z')

  it('accepts a CRL that is current at the signing time', () => {
    expect(evidenceCoversTime(evidence('2025-08-18T20:00:00Z', '2025-08-19T20:00:00Z'), new Date('2025-08-19T08:09:06Z'), now)).toBe(true)
  })

  it('rejects a CRL that expired before the signing time', () => {
    expect(evidenceCoversTime(evidence('2025-08-10T00:00:00Z', '2025-08-11T00:00:00Z'), new Date('2025-08-19T08:09:06Z'), now)).toBe(false)
  })

  it('rejects evidence dated in the future', () => {
    expect(evidenceCoversTime(evidence('2026-06-01T00:00:00Z'), new Date('2025-08-19T08:09:06Z'), now)).toBe(false)
  })
})
