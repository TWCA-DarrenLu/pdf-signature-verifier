import { describe, it, expect, vi, beforeEach } from 'vitest'
import { verifyTimestamp } from '@/core/timestamp/tst-verifier'
import { addCustomTsaTrustAnchor, clearTrustAnchors, initializeTrustStore } from '@/trust-store/trust-manager'
import { generateKey, issueCertificate, issueTimestampToken, type TestCert } from '../helpers/test-pki'

vi.mock('@/core/network', () => ({
  fetchCertificateBytes: vi.fn(() => Promise.resolve(null)),
  fetchBinary: vi.fn(() => Promise.resolve(null)),
  fetchOcspResponse: vi.fn(() => Promise.resolve(null)),
}))

const TIME_STAMPING = '1.3.6.1.5.5.7.3.8'
const imprint = new Uint8Array(32).fill(7)

describe('verifyTimestamp — TSA trust', () => {
  let root: TestCert

  beforeEach(async () => {
    clearTrustAnchors()
    await initializeTrustStore()
    root = await issueCertificate({ subjectCN: 'Test TSA Root', isCA: true })
    await addCustomTsaTrustAnchor(root.pem)
  })

  it('accepts a token from a TSA that chains to a TSA anchor', async () => {
    const tsa = await issueCertificate({ subjectCN: 'Test TSA', issuerCN: 'Test TSA Root', issuerKey: root.key, extKeyUsage: [TIME_STAMPING] })
    const token = await issueTimestampToken({ tsa, imprint, bag: [tsa.cert, root.cert] })
    const result = await verifyTimestamp(token, imprint, { fetchMissing: false })
    expect(result.failure).toBeUndefined()
    expect(result.valid).toBe(true)
    expect(result.tsaChain?.isTrusted).toBe(true)
  })

  it('rejects a TSA whose certificate does not chain to the anchor, even if the anchor is in the token', async () => {
    // Regression: the old check accepted any token whose certificate bag
    // merely CONTAINED an anchor.
    const stranger = await generateKey()
    const tsa = await issueCertificate({ subjectCN: 'Test TSA', issuerCN: 'Test TSA Root', issuerKey: stranger, extKeyUsage: [TIME_STAMPING] })
    const token = await issueTimestampToken({ tsa, imprint, bag: [tsa.cert, root.cert] })
    const result = await verifyTimestamp(token, imprint, { fetchMissing: false })
    expect(result.valid).toBe(false)
    expect(result.failure).toBe('tsaUntrusted')
  })

  it('rejects a TSA certificate without the timeStamping EKU', async () => {
    const tsa = await issueCertificate({ subjectCN: 'Test TSA', issuerCN: 'Test TSA Root', issuerKey: root.key })
    const token = await issueTimestampToken({ tsa, imprint, bag: [tsa.cert, root.cert] })
    const result = await verifyTimestamp(token, imprint, { fetchMissing: false })
    expect(result.failure).toBe('tsaNotTimestampingCert')
  })

  it('rejects a token for different data', async () => {
    const tsa = await issueCertificate({ subjectCN: 'Test TSA', issuerCN: 'Test TSA Root', issuerKey: root.key, extKeyUsage: [TIME_STAMPING] })
    const token = await issueTimestampToken({ tsa, imprint, bag: [tsa.cert, root.cert] })
    const result = await verifyTimestamp(token, new Uint8Array(32).fill(8), { fetchMissing: false })
    expect(result.failure).toBe('imprintMismatch')
  })

  it('rejects a token whose TSTInfo was altered after signing', async () => {
    const tsa = await issueCertificate({ subjectCN: 'Test TSA', issuerCN: 'Test TSA Root', issuerKey: root.key, extKeyUsage: [TIME_STAMPING] })
    const token = await issueTimestampToken({ tsa, imprint, bag: [tsa.cert, root.cert], tamperAfterSigning: true })
    const result = await verifyTimestamp(token, imprint, { fetchMissing: false })
    expect(result.valid).toBe(false)
    expect(result.failure).toBe('signatureInvalid')
  })
})
