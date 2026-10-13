// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { existsSync, readdirSync, readFileSync } from 'fs'
import { resolve } from 'path'
import { verifyPdfSignatures } from '@/core/verifier'

/**
 * Developer report: verifies every PDF in PDF_Sample/ (gitignored, local only)
 * and prints a one-line-per-check summary. Opt-in: PDF_SAMPLE_REPORT=1 npx vitest run tests/samples
 */
const SAMPLE_DIR = resolve(__dirname, '../../PDF_Sample')
const files = existsSync(SAMPLE_DIR)
  ? readdirSync(SAMPLE_DIR).filter((f) => f.toLowerCase().endsWith('.pdf'))
  : []

const mark = (passed: boolean | undefined) => (passed === undefined ? '-' : passed ? 'PASS' : 'FAIL')

describe.skipIf(files.length === 0 || !process.env.PDF_SAMPLE_REPORT)('PDF_Sample report', () => {
  for (const file of files) {
    it(file, async () => {
      const offline = process.env.PDF_SAMPLE_OFFLINE === '1'
      const result = await verifyPdfSignatures(readFileSync(resolve(SAMPLE_DIR, file)), file, { checkOnlineRevocation: !offline })
      const lines = [`### ${file} => ${result.status} (${result.signatures.length} sig)`]
      for (const sig of result.signatures) {
        const c = sig.checks
        lines.push(
          `  #${sig.index} ${sig.signerName} [${sig.status}] ltv=${sig.ltvLevel ?? '-'}`,
          `    integrity=${mark(c.integrity.passed)} ${c.integrity.message} | ${c.integrity.details ?? ''}`,
          `    chain=${mark(c.certificateChain.passed)} ${c.certificateChain.message} | ${c.certificateChain.details ?? ''}`,
          `    trust=${mark(c.trustRoot.passed)} ${c.trustRoot.message} | ${c.trustRoot.details ?? ''}`,
          `    validity=${mark(c.validity.passed)} ${c.validity.message}`,
          `    revocation=${mark(c.revocation.passed)} ${c.revocation.message} | ${c.revocation.details ?? ''}`,
          `    timestamp=${mark(c.timestamp?.passed)} ${c.timestamp?.message ?? ''} | ${c.timestamp?.details ?? ''}`,
          `    ltv=${mark(c.ltv.passed)} ${c.ltv.message} | ${c.ltv.details ?? ''}`,
          `    chainCerts=${sig.certificateChain.map((x) => x.subject.match(/CN=([^,]+)/)?.[1] ?? x.subject).join(' -> ')}`
        )
      }
      console.log(lines.join('\n'))
      expect(result).toBeDefined()
    }, 120_000)
  }
})
