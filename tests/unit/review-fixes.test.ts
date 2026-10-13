import { describe, it, expect, vi, beforeEach } from 'vitest'
import { signingUsageProblem } from '@/core/verifier'
import { buildCertificateChain } from '@/core/certificate/chain-builder'
import { validateCrl } from '@/core/revocation/revocation-validator'
import { requestOcspResponse } from '@/core/revocation/ocsp-client'
import { verifyTimestamp } from '@/core/timestamp/tst-verifier'
import { addCustomTsaTrustAnchor, clearTrustAnchors, initializeTrustStore } from '@/trust-store/trust-manager'
import { issueCertificate, issueCrl, issueTimestampToken, generateKey } from '../helpers/test-pki'

const fetchOcspResponse = vi.fn((_url: string, _body: Uint8Array) => Promise.resolve(null as Uint8Array | null))
vi.mock('@/core/network', () => ({
  fetchCertificateBytes: vi.fn(() => Promise.resolve(null)),
  fetchBinary: vi.fn(() => Promise.resolve(null)),
  fetchOcspResponse: (url: string, body: Uint8Array) => fetchOcspResponse(url, body),
}))

const CRL_URL = 'http://crl.test/ca-2024.crl'

beforeEach(async () => {
  clearTrustAnchors()
  await initializeTrustStore()
})

describe('signer certificate must be meant for signing', () => {
  it('accepts an ordinary end-entity signing certificate', async () => {
    const leaf = await issueCertificate({ subjectCN: 'Test Signer', extKeyUsage: ['1.3.6.1.5.5.7.3.4'] })
    expect(signingUsageProblem(leaf.parsed)).toBeNull()
  })

  it('rejects a CA certificate', async () => {
    const ca = await issueCertificate({ subjectCN: 'Test CA', isCA: true })
    expect(signingUsageProblem(ca.parsed)).toBe('core.chain.signerIsCa')
  })

  it('rejects a TLS server or TSA certificate', async () => {
    const tls = await issueCertificate({ subjectCN: 'test.example', extKeyUsage: ['1.3.6.1.5.5.7.3.1'] })
    const tsa = await issueCertificate({ subjectCN: 'Test TSA', extKeyUsage: ['1.3.6.1.5.5.7.3.8'] })
    expect(signingUsageProblem(tls.parsed)).toBe('core.chain.ekuNotForSigning')
    expect(signingUsageProblem(tsa.parsed)).toBe('core.chain.ekuNotForSigning')
  })
})

describe('self-signed detection', () => {
  it('treats a certificate signed by its own key as self-signed even with a different issuer name', async () => {
    const odd = await issueCertificate({ subjectCN: 'Test Signer', issuerCN: 'Some Other Name' })
    const chain = await buildCertificateChain(odd.parsed, [])
    expect(chain.selfSignedLeaf).toBe(true)
  })
})

describe('validateCrl scope', () => {
  async function setup() {
    const ca = await issueCertificate({ subjectCN: 'Test CA', isCA: true })
    const leaf = await issueCertificate({ subjectCN: 'Test Signer', issuerCN: 'Test CA', issuerKey: ca.key, serial: 77, crlUrl: CRL_URL })
    return { ca, leaf }
  }

  it('uses a partitioned CRL whose IDP matches the certificate CRL distribution point', async () => {
    const { ca, leaf } = await setup()
    const crl = await issueCrl({ issuer: ca, idpUri: CRL_URL })
    expect((await validateCrl(crl, leaf.parsed, ca.parsed))?.status).toBe('good')
  })

  it('ignores a partitioned CRL for another partition', async () => {
    const { ca, leaf } = await setup()
    const crl = await issueCrl({ issuer: ca, idpUri: 'http://crl.test/ca-2025.crl' })
    expect(await validateCrl(crl, leaf.parsed, ca.parsed)).toBeNull()
  })

  it('ignores delta CRLs', async () => {
    const { ca, leaf } = await setup()
    const crl = await issueCrl({ issuer: ca, delta: true })
    expect(await validateCrl(crl, leaf.parsed, ca.parsed)).toBeNull()
  })

  it('reports a listed serial as revoked', async () => {
    const { ca, leaf } = await setup()
    const crl = await issueCrl({ issuer: ca, revokedSerials: [77] })
    expect((await validateCrl(crl, leaf.parsed, ca.parsed))?.status).toBe('revoked')
  })

  it('ignores a CRL signed by another key', async () => {
    const { ca, leaf } = await setup()
    const impostor = await issueCertificate({ subjectCN: 'Test CA', isCA: true })
    const crl = await issueCrl({ issuer: impostor })
    expect(await validateCrl(crl, leaf.parsed, ca.parsed)).toBeNull()
  })
})

describe('online OCSP request', () => {
  it('serialises a request built in code (pkijs encodeFlag)', async () => {
    const ca = await issueCertificate({ subjectCN: 'Test CA', isCA: true })
    const leaf = await issueCertificate({ subjectCN: 'Test Signer', issuerCN: 'Test CA', issuerKey: ca.key })
    const withOcsp = { ...leaf.parsed, authorityInfoAccess: { ocsp: ['http://ocsp.test/'], caIssuers: [] } }
    fetchOcspResponse.mockClear()
    await requestOcspResponse(withOcsp, ca.parsed)
    expect(fetchOcspResponse).toHaveBeenCalledTimes(1)
    expect(fetchOcspResponse.mock.calls[0][1].length).toBeGreaterThan(30)
  })
})

describe('timestamp algorithm and certificate sources', () => {
  const TIME_STAMPING = '1.3.6.1.5.5.7.3.8'

  it('treats an unsupported imprint algorithm as unsupported, not as a mismatch', async () => {
    const root = await issueCertificate({ subjectCN: 'Test TSA Root', isCA: true })
    await addCustomTsaTrustAnchor(root.pem)
    const tsa = await issueCertificate({ subjectCN: 'Test TSA', issuerCN: 'Test TSA Root', issuerKey: root.key, extKeyUsage: [TIME_STAMPING] })
    const token = await issueTimestampToken({ tsa, imprint: new Uint8Array(28), bag: [tsa.cert], hashOid: '2.16.840.1.101.3.4.2.4' })
    const result = await verifyTimestamp(token, new Uint8Array(28), { fetchMissing: false })
    expect(result.failure).toBe('unsupportedAlgorithm')
  })

  it('finds the TSA certificate in extra (DSS) certificates when the token carries none', async () => {
    const root = await issueCertificate({ subjectCN: 'Test TSA Root', isCA: true })
    await addCustomTsaTrustAnchor(root.pem)
    const tsa = await issueCertificate({ subjectCN: 'Test TSA', issuerCN: 'Test TSA Root', issuerKey: root.key, extKeyUsage: [TIME_STAMPING] })
    const imprint = new Uint8Array(32).fill(3)
    const token = await issueTimestampToken({ tsa, imprint, bag: [] })
    const der = (c: typeof tsa) => new Uint8Array(c.cert.toSchema().toBER(false))
    const result = await verifyTimestamp(token, imprint, { fetchMissing: false, extraCertBytes: [der(tsa), der(root)] })
    expect(result.failure).toBeUndefined()
    expect(result.valid).toBe(true)
  })

  it('still rejects a TSA certificate from extra certificates that does not chain to an anchor', async () => {
    const root = await issueCertificate({ subjectCN: 'Test TSA Root', isCA: true })
    await addCustomTsaTrustAnchor(root.pem)
    const stranger = await generateKey()
    const tsa = await issueCertificate({ subjectCN: 'Test TSA', issuerCN: 'Test TSA Root', issuerKey: stranger, extKeyUsage: [TIME_STAMPING] })
    const imprint = new Uint8Array(32).fill(3)
    const token = await issueTimestampToken({ tsa, imprint, bag: [] })
    const result = await verifyTimestamp(token, imprint, {
      fetchMissing: false,
      extraCertBytes: [new Uint8Array(tsa.cert.toSchema().toBER(false))],
    })
    expect(result.failure).toBe('tsaUntrusted')
  })
})
