import { describe, it, expect, vi, beforeEach } from 'vitest'
import { readFileSync } from 'fs'
import { resolve } from 'path'
import type { ParsedCertificate, KeyUsageFlags } from '@/types'
import { buildCertificateChain } from '@/core/certificate/chain-builder'
import { parseCertificateFromBytes } from '@/core/certificate/cert-utils'
import {
  addCustomTrustAnchor,
  clearTrustAnchors,
  initializeTrustStore,
  isTrustAnchor,
} from '@/trust-store/trust-manager'
import { generateKey, issueCertificate } from '../helpers/test-pki'

// Never touch the network from unit tests (AIA fetches return nothing).
vi.mock('@/core/network', () => ({
  fetchCertificateBytes: vi.fn(() => Promise.resolve(null)),
  fetchBinary: vi.fn(() => Promise.resolve(null)),
  fetchOcspResponse: vi.fn(() => Promise.resolve(null)),
}))

const CERT_DIR = resolve(__dirname, '../../scripts/trust-store/certs')
const realCert = (file: string) =>
  parseCertificateFromBytes(new Uint8Array(readFileSync(resolve(CERT_DIR, file))))

function createEmptyKeyUsage(): KeyUsageFlags {
  return {
    digitalSignature: false,
    nonRepudiation: false,
    keyEncipherment: false,
    dataEncipherment: false,
    keyAgreement: false,
    keyCertSign: false,
    crlSign: false,
    encipherOnly: false,
    decipherOnly: false,
  }
}

function createMockCert(overrides: Partial<ParsedCertificate>): ParsedCertificate {
  return {
    raw: {} as ParsedCertificate['raw'],
    subject: 'CN=Test',
    issuer: 'CN=Test CA',
    serialNumber: '01',
    notBefore: new Date('2024-01-01'),
    notAfter: new Date('2025-12-31'),
    publicKey: null,
    fingerprint: 'aabb',
    isCA: false,
    isSelfSigned: false,
    keyUsage: createEmptyKeyUsage(),
    extKeyUsage: [],
    authorityInfoAccess: null,
    crlDistributionPoints: [],
    subjectKeyIdentifier: null,
    authorityKeyIdentifier: null,
    ...overrides,
  }
}

describe('chain-builder', () => {
  beforeEach(async () => {
    clearTrustAnchors()
    await initializeTrustStore()
  })

  describe('buildCertificateChain (real signatures)', () => {
    it('rejects a self-signed end-entity certificate, even an anchor', async () => {
      const root = await realCert('grca-g2.cer')
      expect(isTrustAnchor(root)).toBe(true)
      const chain = await buildCertificateChain(root, [])
      expect(chain.selfSignedLeaf).toBe(true)
      expect(chain.isTrusted).toBe(false)
    })

    it('builds MOICA G2 to GRCA G2 (same-name GRCA G1 is not used)', async () => {
      const moica = await realCert('moica-g2.cer')
      const chain = await buildCertificateChain(moica, [])
      expect(chain.isTrusted).toBe(true)
      expect(chain.certificates).toHaveLength(2)
      expect(chain.root?.fingerprint).toBe((await realCert('grca-g2.cer')).fingerprint)
    })

    it('builds MOEACA G3 to GRCA G3', async () => {
      const chain = await buildCertificateChain(await realCert('moeaca-g3.cer'), [])
      expect(chain.isTrusted).toBe(true)
      expect(chain.root?.subject).toContain('G3')
    })

    it('builds leaf, intermediate, anchor with every link verified', async () => {
      const root = await issueCertificate({ subjectCN: 'Test Root', isCA: true })
      const ca = await issueCertificate({ subjectCN: 'Test CA', issuerCN: 'Test Root', issuerKey: root.key, isCA: true })
      const leaf = await issueCertificate({ subjectCN: 'Test Signer', issuerCN: 'Test CA', issuerKey: ca.key })
      await addCustomTrustAnchor(root.pem)

      const chain = await buildCertificateChain(leaf.parsed, [ca.parsed])
      expect(chain.isTrusted).toBe(true)
      expect(chain.certificates.map((c) => c.subject)).toEqual([
        leaf.parsed.subject,
        ca.parsed.subject,
        root.parsed.subject,
      ])
    })

    it('never trusts a lookalike root with the same DN and serial but another key', async () => {
      const anchor = await issueCertificate({ subjectCN: 'Test Root', isCA: true, serial: 4242 })
      await addCustomTrustAnchor(anchor.pem)
      const lookalike = await issueCertificate({ subjectCN: 'Test Root', isCA: true, serial: 4242 })
      const leaf = await issueCertificate({ subjectCN: 'Test Signer', issuerCN: 'Test Root', issuerKey: lookalike.key })

      expect(isTrustAnchor(lookalike.parsed)).toBe(false)
      const chain = await buildCertificateChain(leaf.parsed, [lookalike.parsed])
      expect(chain.isTrusted).toBe(false)
    })

    it('does not accept a link whose signature fails (issuer name alone is not enough)', async () => {
      const root = await issueCertificate({ subjectCN: 'Test Root', isCA: true })
      await addCustomTrustAnchor(root.pem)
      const stranger = await generateKey()
      const leaf = await issueCertificate({ subjectCN: 'Test Signer', issuerCN: 'Test Root', issuerKey: stranger })

      const chain = await buildCertificateChain(leaf.parsed, [])
      expect(chain.isTrusted).toBe(false)
      expect(chain.isComplete).toBe(false)
    })

    it('backtracks across same-name issuers and picks the one whose signature verifies', async () => {
      const root = await issueCertificate({ subjectCN: 'Test Root', isCA: true })
      await addCustomTrustAnchor(root.pem)
      const caA = await issueCertificate({ subjectCN: 'Test CA', issuerCN: 'Test Root', issuerKey: root.key, isCA: true })
      const caB = await issueCertificate({ subjectCN: 'Test CA', issuerCN: 'Test Root', issuerKey: root.key, isCA: true })
      const leaf = await issueCertificate({ subjectCN: 'Test Signer', issuerCN: 'Test CA', issuerKey: caB.key })

      const chain = await buildCertificateChain(leaf.parsed, [caA.parsed, caB.parsed])
      expect(chain.isTrusted).toBe(true)
      expect(chain.certificates[1].fingerprint).toBe(caB.parsed.fingerprint)
    })

    it('refuses an issuer that is not a CA', async () => {
      const root = await issueCertificate({ subjectCN: 'Test Root', isCA: true })
      await addCustomTrustAnchor(root.pem)
      const notCa = await issueCertificate({ subjectCN: 'Test Not CA', issuerCN: 'Test Root', issuerKey: root.key })
      const leaf = await issueCertificate({ subjectCN: 'Test Signer', issuerCN: 'Test Not CA', issuerKey: notCa.key })

      const chain = await buildCertificateChain(leaf.parsed, [notCa.parsed])
      expect(chain.isTrusted).toBe(false)
    })

    it('enforces pathLenConstraint', async () => {
      const root = await issueCertificate({ subjectCN: 'Test Root', isCA: true })
      await addCustomTrustAnchor(root.pem)
      const ca1 = await issueCertificate({ subjectCN: 'Test CA 1', issuerCN: 'Test Root', issuerKey: root.key, isCA: true, pathLen: 0 })
      const ca2 = await issueCertificate({ subjectCN: 'Test CA 2', issuerCN: 'Test CA 1', issuerKey: ca1.key, isCA: true })
      const leaf = await issueCertificate({ subjectCN: 'Test Signer', issuerCN: 'Test CA 2', issuerKey: ca2.key })

      const chain = await buildCertificateChain(leaf.parsed, [ca1.parsed, ca2.parsed])
      expect(chain.isTrusted).toBe(false)
    })

    it('reports an incomplete chain when the issuer is missing', async () => {
      const ca = await issueCertificate({ subjectCN: 'Test CA', isCA: true })
      const leaf = await issueCertificate({ subjectCN: 'Test Signer', issuerCN: 'Test CA', issuerKey: ca.key })
      const chain = await buildCertificateChain(leaf.parsed, [])
      expect(chain.isComplete).toBe(false)
      expect(chain.isTrusted).toBe(false)
      expect(chain.root).toBeNull()
    })

    it('reports a complete but untrusted chain for an unknown self-signed root', async () => {
      const root = await issueCertificate({ subjectCN: 'Test Unknown Root', isCA: true })
      const leaf = await issueCertificate({ subjectCN: 'Test Signer', issuerCN: 'Test Unknown Root', issuerKey: root.key })
      const chain = await buildCertificateChain(leaf.parsed, [root.parsed])
      expect(chain.isComplete).toBe(true)
      expect(chain.isTrusted).toBe(false)
      expect(chain.root?.fingerprint).toBe(root.parsed.fingerprint)
    })
  })

  describe('getChainSummary', () => {
    it('should label end entity as [EE] and root as [Root]', async () => {
      const { getChainSummary } = await import('@/core/certificate/chain-builder')

      const chain = {
        certificates: [
          createMockCert({ subject: 'CN=Signer' }),
          createMockCert({ subject: 'CN=Root CA', isSelfSigned: true }),
        ],
        root: createMockCert({ subject: 'CN=Root CA' }),
        isComplete: true,
        isTrusted: true,
      }

      const summary = getChainSummary(chain)
      expect(summary).toHaveLength(2)
      expect(summary[0]).toContain('[EE]')
      expect(summary[0]).toContain('CN=Signer')
      expect(summary[1]).toContain('[Root]')
      expect(summary[1]).toContain('CN=Root CA')
      expect(summary[1]).toContain('[Trusted]')
    })

    it('should label middle certs as [CA]', async () => {
      const { getChainSummary } = await import('@/core/certificate/chain-builder')

      const chain = {
        certificates: [
          createMockCert({ subject: 'CN=Signer' }),
          createMockCert({ subject: 'CN=Intermediate' }),
          createMockCert({ subject: 'CN=Root CA' }),
        ],
        root: createMockCert({ subject: 'CN=Root CA' }),
        isComplete: true,
        isTrusted: true,
      }

      const summary = getChainSummary(chain)
      expect(summary[1]).toContain('[CA]')
      expect(summary[1]).toContain('CN=Intermediate')
    })

    it('should not show [Trusted] on root if chain is not trusted', async () => {
      const { getChainSummary } = await import('@/core/certificate/chain-builder')

      const chain = {
        certificates: [
          createMockCert({ subject: 'CN=Signer' }),
          createMockCert({ subject: 'CN=Root CA' }),
        ],
        root: null,
        isComplete: false,
        isTrusted: false,
      }

      const summary = getChainSummary(chain)
      expect(summary[1]).not.toContain('[Trusted]')
    })
  })

  describe('verifyIssuedBy', () => {
    it('should return false when issuer name does not match subject', async () => {
      const { verifyIssuedBy } = await import('@/core/certificate/chain-builder')

      const subject = createMockCert({
        issuer: 'CN=Real CA',
      })
      const issuer = createMockCert({
        subject: 'CN=Different CA',
      })

      const result = await verifyIssuedBy(subject, issuer)
      expect(result).toBe(false)
    })

    it('should return false when AKI does not match SKI', async () => {
      const { verifyIssuedBy } = await import('@/core/certificate/chain-builder')

      const subject = createMockCert({
        issuer: 'CN=CA',
        authorityKeyIdentifier: 'aaa',
      })
      const issuer = createMockCert({
        subject: 'CN=CA',
        subjectKeyIdentifier: 'bbb',
      })

      const result = await verifyIssuedBy(subject, issuer)
      expect(result).toBe(false)
    })
  })
})
