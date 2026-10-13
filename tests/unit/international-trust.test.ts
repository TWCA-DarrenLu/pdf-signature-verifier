import { describe, it, expect, vi, beforeEach } from 'vitest'
import { buildCertificateChain } from '@/core/certificate/chain-builder'
import {
  addCustomTrustAnchor,
  clearTrustAnchors,
  initializeTrustStore,
  getAnchorCategory,
  getAnchorVendor,
} from '@/trust-store/trust-manager'
import { issueCertificate, type TestCert } from '../helpers/test-pki'

vi.mock('@/core/network', () => ({
  fetchCertificateBytes: vi.fn(() => Promise.resolve(null)),
  fetchBinary: vi.fn(() => Promise.resolve(null)),
  fetchOcspResponse: vi.fn(() => Promise.resolve(null)),
}))

/**
 * International CAs are opt-in: Taiwan roots are always anchors, the bundled
 * international roots only when `trustInternational` is set. While off, an
 * international root still completes the path (so the UI can say which CA it
 * is) but the path is not trusted.
 */
describe('international trust option', () => {
  let intlRoot: TestCert
  let intlTsaRoot: TestCert

  beforeEach(async () => {
    clearTrustAnchors()
    await initializeTrustStore()
    intlRoot = await issueCertificate({ subjectCN: 'Example Global Document Signing Root', isCA: true })
    intlTsaRoot = await issueCertificate({ subjectCN: 'Example Global Timestamping Root', isCA: true })
    await addCustomTrustAnchor(intlRoot.pem, { international: true, vendor: 'ExampleCA' })
    await addCustomTrustAnchor(intlTsaRoot.pem, { international: true, vendor: 'ExampleCA', timestamping: true })
  })

  const SIGNING_ROOT = 'Example Global Document Signing Root'
  const TSA_ROOT = 'Example Global Timestamping Root'
  const leafUnder = (root: TestCert, cn: string) =>
    issueCertificate({ subjectCN: cn, issuerCN: root === intlRoot ? SIGNING_ROOT : TSA_ROOT, issuerKey: root.key })

  it('does not trust an international root unless the option is on', async () => {
    const leaf = await leafUnder(intlRoot, 'Signer')
    const off = await buildCertificateChain(leaf.parsed, [], {})
    expect(off.isTrusted).toBe(false)
    // the root is known, so the path is complete and the UI can name the CA
    expect(off.isComplete).toBe(true)
    expect(getAnchorCategory(off.root!)).toBe('international')
    expect(getAnchorVendor(off.root!)).toBe('ExampleCA')

    const on = await buildCertificateChain(leaf.parsed, [], { trustInternational: true })
    expect(on.isTrusted).toBe(true)
  })

  it('keeps signing and timestamping roots apart', async () => {
    const signer = await leafUnder(intlTsaRoot, 'Signer under a TSA-only root')
    expect((await buildCertificateChain(signer.parsed, [], { trustInternational: true })).isTrusted).toBe(false)

    const tsa = await leafUnder(intlTsaRoot, 'Example TSA')
    expect((await buildCertificateChain(tsa.parsed, [], { anchorStore: 'tsa' })).isTrusted).toBe(false)
    expect((await buildCertificateChain(tsa.parsed, [], { anchorStore: 'tsa', trustInternational: true })).isTrusted).toBe(true)
  })

  it('labels the bundled Taiwan roots with their category and vendor', async () => {
    const { parseCertificateFromBytes } = await import('@/core/certificate/cert-utils')
    const { readFileSync } = await import('fs')
    const { resolve } = await import('path')
    const twca = await parseCertificateFromBytes(
      new Uint8Array(readFileSync(resolve(__dirname, '../../scripts/trust-store/certs/twca-global-root-ca.cer')))
    )
    expect(getAnchorCategory(twca)).toBe('private')
    expect(getAnchorVendor(twca)).toBe('TWCA')
  })
})

describe('document-signing purpose for international signers', () => {
  it('accepts AATL, document-signing and S/MIME purposes, not TLS or client-auth only', async () => {
    const { hasDocumentSigningEku } = await import('@/core/verifier')
    const withEku = (extKeyUsage: string[]) => ({ extKeyUsage }) as unknown as Parameters<typeof hasDocumentSigningEku>[0]
    expect(hasDocumentSigningEku(withEku(['1.2.840.113583.1.1.5']))).toBe(true) // DocuSign / AATL
    expect(hasDocumentSigningEku(withEku(['1.3.6.1.5.5.7.3.36']))).toBe(true) // RFC 9336
    expect(hasDocumentSigningEku(withEku(['documentSigning']))).toBe(true) // Microsoft
    expect(hasDocumentSigningEku(withEku(['emailProtection', 'clientAuth']))).toBe(true)
    expect(hasDocumentSigningEku(withEku(['serverAuth', 'clientAuth']))).toBe(false)
    expect(hasDocumentSigningEku(withEku(['clientAuth']))).toBe(false)
    expect(hasDocumentSigningEku(withEku([]))).toBe(false)
  })
})
