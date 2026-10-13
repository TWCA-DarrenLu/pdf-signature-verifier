/**
 * End-to-end: load the built extension (.output/chrome-mv3) into Chromium,
 * open a signed PDF over HTTP, press the injected "verify" button and read the
 * verdict from the results panel.
 *
 * Prerequisites: `npm run build` and sample PDFs in PDF_Sample/ (gitignored).
 * Run: npx playwright test --project=chromium --reporter=list
 */
import { test, expect, chromium, type BrowserContext } from '@playwright/test'
import { createServer, type Server } from 'http'
import { existsSync, readFileSync, mkdtempSync } from 'fs'
import { tmpdir } from 'os'
import { join, resolve } from 'path'
import { fileURLToPath } from 'url'

const ROOT = fileURLToPath(new URL('../..', import.meta.url))
const EXTENSION_DIR = resolve(ROOT, '.output/chrome-mv3')
const SAMPLE_DIR = resolve(ROOT, 'PDF_Sample')

const CASES = [
  { file: '範例文件(以工商憑證換發AATL憑證簽署).pdf', expected: 'trusted' },
  { file: '自發簽章.pdf', expected: 'failed' },
  // expired one-day HSM cert without embedded TWCA revocation data + foreign (DigiCert) co-signature
  { file: '(TWCA 正式環境)Docusign TSP 簽章範例.pdf', expected: 'unknown' },
]

test.skip(!existsSync(EXTENSION_DIR) || !existsSync(SAMPLE_DIR), 'needs npm run build and PDF_Sample/')
test.describe.configure({ mode: 'serial' })

let server: Server
let baseUrl: string
let context: BrowserContext

test.beforeAll(async ({}, testInfo) => {
  testInfo.setTimeout(120_000)
  server = createServer((req, res) => {
    const name = decodeURIComponent((req.url ?? '/').slice(1))
    const path = join(SAMPLE_DIR, name)
    if (!name || !existsSync(path)) {
      res.writeHead(404).end()
      return
    }
    res.writeHead(200, { 'Content-Type': 'application/pdf' }).end(readFileSync(path))
  })
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done))
  const address = server.address()
  baseUrl = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`

  context = await chromium.launchPersistentContext(mkdtempSync(join(tmpdir(), 'pdftrust-e2e-')), {
    channel: 'chromium',
    args: [`--disable-extensions-except=${EXTENSION_DIR}`, `--load-extension=${EXTENSION_DIR}`],
  })
  // No need to wait for the service worker: Chrome starts it on the first message.
})

test.afterAll(async () => {
  await context?.close()
  await new Promise((done) => server?.close(done))
})

for (const { file, expected } of CASES) {
  test(`${file} → ${expected}`, async () => {
    test.setTimeout(120_000)
    const page = await context.newPage()
    await page.goto(`${baseUrl}/${encodeURIComponent(file)}`)

    const button = page.locator('#pdf-verifier-floating-button')
    await expect(button).toBeVisible({ timeout: 30_000 })
    await button.click()

    // The button reflects the overall status once verification finishes.
    await expect(button).not.toHaveAttribute('data-pdf-verifier-state', 'busy', { timeout: 90_000 })
    const state = await button.getAttribute('data-pdf-verifier-state')
    const label = (await button.innerText()).trim()
    console.log(`${file}: state=${state} label=${label}`)
    expect(state).toBe(expected)
    await page.close()
  })
}
