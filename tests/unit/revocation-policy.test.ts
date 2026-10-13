import { describe, it, expect, vi, beforeEach } from 'vitest'
import { checkCertificateRevocation } from '@/core/revocation/revocation-checker'
import { clearRevocationCache } from '@/core/revocation/revocation-cache'
import { fetchBinary } from '@/core/network'
import { issueCertificate, issueCrl, type TestCert } from '../helpers/test-pki'

const onlineCrls = new Map<string, Uint8Array>()
vi.mock('@/core/network', () => ({
  fetchCertificateBytes: vi.fn(() => Promise.resolve(null)),
  fetchBinary: vi.fn((url: string) => Promise.resolve(onlineCrls.get(url) ?? null)),
  fetchOcspResponse: vi.fn(() => Promise.resolve(null)),
}))

const CRL_URL = 'http://crl.test/ca.crl'
let ca: TestCert

beforeEach(async () => {
  onlineCrls.clear()
  await clearRevocationCache()
  vi.mocked(fetchBinary).mockClear()
  ca = await issueCertificate({ subjectCN: 'Test CA', isCA: true })
})

const leafOf = (serial: number, notAfter?: Date) =>
  issueCertificate({
    subjectCN: 'Test Signer',
    issuerCN: 'Test CA',
    issuerKey: ca.key,
    serial,
    crlUrl: CRL_URL,
    notBefore: new Date(Date.now() - 30 * 86_400_000),
    notAfter,
  })

describe('checkCertificateRevocation', () => {
  it('lets an online revocation override embedded "good"', async () => {
    const leaf = await leafOf(5)
    const embedded = await issueCrl({ issuer: ca, thisUpdate: new Date(Date.now() - 3_600_000) })
    onlineCrls.set(CRL_URL, await issueCrl({ issuer: ca, revokedSerials: [5] }))
    const outcome = await checkCertificateRevocation(leaf.parsed, ca.parsed, {
      embedded: { ocspResponses: [], crls: [embedded], certs: [] },
      allowOnline: true,
      atTime: new Date(),
      atTimeTrusted: false,
    })
    expect(outcome.status).toBe('revoked')
  })

  it('treats certificateHold as indeterminate, not revoked', async () => {
    const leaf = await leafOf(6)
    const crl = await issueCrl({ issuer: ca, revokedSerials: [6], reason: 6 })
    const outcome = await checkCertificateRevocation(leaf.parsed, ca.parsed, {
      embedded: { ocspResponses: [], crls: [crl], certs: [] },
      allowOnline: false,
      atTime: new Date(),
      atTimeTrusted: false,
    })
    expect(outcome.status).toBe('unknown')
  })

  it('ignores "good" evidence issued after the certificate expired, but not a revocation', async () => {
    const expiredAt = new Date(Date.now() - 10 * 86_400_000)
    const signingTime = new Date(Date.now() - 12 * 86_400_000)
    const leaf = await leafOf(7, expiredAt)
    const ctx = (crl: Uint8Array) => ({
      embedded: { ocspResponses: [], crls: [crl], certs: [] },
      allowOnline: false,
      atTime: signingTime,
      atTimeTrusted: true,
    })
    const lateGood = await issueCrl({ issuer: ca, thisUpdate: new Date(Date.now() - 86_400_000) })
    expect((await checkCertificateRevocation(leaf.parsed, ca.parsed, ctx(lateGood))).status).toBe('unknown')

    const lateRevoked = await issueCrl({
      issuer: ca,
      thisUpdate: new Date(Date.now() - 86_400_000),
      revokedSerials: [7],
      revokedAt: new Date(Date.now() - 20 * 86_400_000),
    })
    expect((await checkCertificateRevocation(leaf.parsed, ca.parsed, ctx(lateRevoked))).status).toBe('revoked')

    const timelyGood = await issueCrl({
      issuer: ca,
      thisUpdate: new Date(Date.now() - 12.5 * 86_400_000),
      nextUpdate: new Date(Date.now() - 11 * 86_400_000),
    })
    expect((await checkCertificateRevocation(leaf.parsed, ca.parsed, ctx(timelyGood))).status).toBe('good')
  })

  it('accepts a revocation dated after a trusted signing time', async () => {
    const leaf = await leafOf(8)
    const signingTime = new Date(Date.now() - 5 * 86_400_000)
    const crl = await issueCrl({ issuer: ca, revokedSerials: [8], revokedAt: new Date(Date.now() - 86_400_000) })
    const outcome = await checkCertificateRevocation(leaf.parsed, ca.parsed, {
      embedded: { ocspResponses: [], crls: [crl], certs: [] },
      allowOnline: false,
      atTime: signingTime,
      atTimeTrusted: true,
    })
    // The CRL is current (nextUpdate ≥ now) but must also reach back to the
    // signing time; it does, so the late revocation means "valid when signed".
    expect(outcome.status).toBe('good')
    expect(outcome.revokedAfterSigning).toBe(true)
  })
})

describe('online revocation cache', () => {
  const online = { embedded: null, allowOnline: true, atTime: new Date(), atTimeTrusted: false }

  it('reuses a CRL until its nextUpdate instead of downloading it again', async () => {
    const leaf = await leafOf(11)
    onlineCrls.set(CRL_URL, await issueCrl({ issuer: ca }))
    expect((await checkCertificateRevocation(leaf.parsed, ca.parsed, online)).status).toBe('good')
    expect((await checkCertificateRevocation(leaf.parsed, ca.parsed, online)).status).toBe('good')
    expect(fetchBinary).toHaveBeenCalledTimes(1)
  })

  it('asks again on re-check and sees a new revocation', async () => {
    const leaf = await leafOf(12)
    onlineCrls.set(CRL_URL, await issueCrl({ issuer: ca }))
    expect((await checkCertificateRevocation(leaf.parsed, ca.parsed, online)).status).toBe('good')
    onlineCrls.set(CRL_URL, await issueCrl({ issuer: ca, revokedSerials: [12] }))
    // cached answer is still within its validity window
    expect((await checkCertificateRevocation(leaf.parsed, ca.parsed, online)).status).toBe('good')
    const fresh = await checkCertificateRevocation(leaf.parsed, ca.parsed, { ...online, freshOnline: true })
    expect(fresh.status).toBe('revoked')
    expect(fetchBinary).toHaveBeenCalledTimes(2)
  })

  it('downloads again once the cached CRL is past its nextUpdate', async () => {
    const leaf = await leafOf(13)
    onlineCrls.set(CRL_URL, await issueCrl({ issuer: ca, nextUpdate: new Date(Date.now() + 60_000) }))
    await checkCertificateRevocation(leaf.parsed, ca.parsed, online)
    const later = new Date(Date.now() + 2 * 60_000 + 5 * 60_000 + 1_000) // past nextUpdate + clock skew
    onlineCrls.set(CRL_URL, await issueCrl({ issuer: ca, thisUpdate: new Date(), nextUpdate: new Date(Date.now() + 86_400_000) }))
    const outcome = await checkCertificateRevocation(leaf.parsed, ca.parsed, { ...online, atTime: later, now: later })
    expect(outcome.status).toBe('good')
    expect(fetchBinary).toHaveBeenCalledTimes(2)
  })
})
