// @vitest-environment node
import { describe, it, expect, beforeAll, vi } from 'vitest'
import { existsSync, readFileSync } from 'fs'
import { resolve } from 'path'
import { verifyPdfSignatures } from '@/core/verifier'
import { setLocale } from '@/i18n'
import type { VerificationResult } from '@/types'

/**
 * End-to-end checks against real signed PDFs in PDF_Sample/ (gitignored —
 * local only; the suite is skipped when the folder is absent).
 *
 * Expected local samples (generic names):
 *   hsm-signed-a.pdf / hsm-signed-b.pdf — TWCA HSM signer + MyTWES signature, embedded CRLs, TWCA TSA
 *   ixml-plus-signed.pdf                — signer under TWCA Information XML Plus Root CA + MyTWES signature
 *   expired-hsm-and-foreign-ca.pdf      — expired one-day HSM certificate + co-signature under a foreign root
 *   foreign-tsa.pdf                     — Taiwan signer, timestamp from a non-Taiwan TSA
 *   self-signed.pdf                     — self-signed signer
 *   attached-signed-pdfs.pdf            — self-signed outer signature, signed PDFs as attachments
 *   unsigned.pdf                        — no signature
 *   encrypted-signed.pdf                — encrypted, signed document
 *
 * Default run is OFFLINE (no OCSP / CRL / AIA fetches): the outcome depends
 * only on the PDF content and the bundled Taiwan trust store. Set
 * PDF_SAMPLE_ONLINE=1 to also run the online expectations.
 *
 * Policy under test: Taiwan PKI roots only, self-signed signers rejected,
 * revocation must be proven (signer path and TSA path), timestamps must chain
 * to a Taiwan TSA root.
 */
vi.setConfig({ testTimeout: 120_000 })

const SAMPLE_DIR = resolve(__dirname, '../../PDF_Sample')
const hasSamples = existsSync(SAMPLE_DIR)
const HSM_SAMPLES = ['hsm-signed-a.pdf', 'hsm-signed-b.pdf']

async function verify(file: string, online = false): Promise<VerificationResult> {
  const data = readFileSync(resolve(SAMPLE_DIR, file))
  return verifyPdfSignatures(data, file, { checkOnlineRevocation: online })
}

describe.skipIf(!hasSamples)('Sample PDF verification (offline)', () => {
  beforeAll(() => setLocale('zh-TW'))

  it('HSM samples: signatures intact and trusted path, but TSA revocation is not embedded', async () => {
    for (const file of HSM_SAMPLES) {
      const result = await verify(file)
      expect(result.signatures, file).toHaveLength(2)
      for (const sig of result.signatures) {
        expect(sig.checks.integrity.passed).toBe(true)
        expect(sig.checks.certificateChain.passed).toBe(true)
        expect(sig.checks.trustRoot.passed).toBe(true)
        // The documents embed CRLs for the signer path only; without the TSA's
        // revocation data the timestamp time cannot be relied on offline.
        expect(sig.checks.timestamp?.passed).toBe(false)
        expect(sig.checks.timestamp?.detailsI18nKey).toBe('core.timestampVerifier.tsaRevocationUnknown')
        expect(sig.status).toBe('unknown')
      }
      expect(result.status).toBe('unknown')
    }
  })

  it('rejects a self-signed signer', async () => {
    const result = await verify('self-signed.pdf')
    expect(result.status).toBe('failed')
    expect(result.signatures[0].checks.certificateChain.i18nKey).toBe('core.chain.selfSignedNotSupported')
    expect(result.signatures[0].checks.integrity.passed).toBe(true)
  })

  it('ignores signatures inside attached PDFs and rejects the self-signed outer signature', async () => {
    const result = await verify('attached-signed-pdfs.pdf')
    expect(result.signatures).toHaveLength(1)
    expect(result.signatures[0].checks.certificateChain.i18nKey).toBe('core.chain.selfSignedNotSupported')
    expect(result.status).toBe('failed')
  })

  it('expired one-day HSM certificate without embedded revocation data stays unknown', async () => {
    const result = await verify('expired-hsm-and-foreign-ca.pdf')
    expect(result.status).toBe('unknown')
    const twca = result.signatures.find((s) => /HSMT/.test(s.signerName))!
    expect(twca.checks.integrity.passed).toBe(true)
    expect(twca.checks.trustRoot.passed).toBe(true)
    expect(twca.checks.revocation.passed).toBe(false)
    expect(twca.status).toBe('unknown')
    // DocuSign chains to DigiCert, which is not a Taiwan root
    const docusign = result.signatures.find((s) => /DocuSign/i.test(s.signerName))!
    expect(docusign.checks.integrity.passed).toBe(true)
    expect(docusign.checks.trustRoot.passed).toBe(false)
    expect(docusign.status).toBe('unknown')
  })

  it('does not accept a timestamp from a non-Taiwan TSA', async () => {
    const result = await verify('foreign-tsa.pdf')
    const sig = result.signatures[0]
    expect(sig.checks.trustRoot.passed).toBe(true)
    expect(sig.checks.timestamp?.passed).toBe(false)
    expect(sig.status).toBe('unknown')
  })

  it('IXML signatures chain to TWCA Information XML Plus Root CA (official TWCA repository)', async () => {
    const result = await verify('ixml-plus-signed.pdf')
    expect(result.signatures).toHaveLength(2)
    expect(result.signatures[0].checks.trustRoot.passed).toBe(true)
    expect(result.signatures[0].checks.trustRoot.details).toContain('TWCA Information XML Plus Root CA')
    expect(result.signatures[1].checks.trustRoot.passed).toBe(true)
    // Offline the TSA revocation cannot be proven (not embedded).
    expect(result.status).toBe('unknown')
  })

  it('reports no signatures for an unsigned document', async () => {
    const result = await verify('unsigned.pdf')
    expect(result.signatures).toHaveLength(0)
    expect(result.status).toBe('unknown')
  })

  it('never reports an encrypted document it cannot fully inspect as trusted', async () => {
    const result = await verify('encrypted-signed.pdf')
    expect(result.status).not.toBe('trusted')
    expect(result.signatures[0].checks.integrity.passed).toBe(true)
  })
})

describe.skipIf(!hasSamples || !process.env.PDF_SAMPLE_ONLINE)('Sample PDF verification (online)', () => {
  beforeAll(() => setLocale('zh-TW'))

  it('HSM and IXML samples are trusted once the TSA and signer revocation can be checked online', async () => {
    for (const file of [...HSM_SAMPLES, 'ixml-plus-signed.pdf']) {
      const result = await verify(file, true)
      expect(result.status, file).toBe('trusted')
      for (const sig of result.signatures) {
        expect(sig.checks.timestamp?.passed).toBe(true)
        expect(sig.checks.revocation.passed).toBe(true)
      }
    }
  })
})
