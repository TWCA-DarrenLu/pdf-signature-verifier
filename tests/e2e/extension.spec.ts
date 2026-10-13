/**
 * End-to-end: load the built extension (.output/chrome-mv3) into Chromium,
 * open PDFs over HTTP and read the verdict from the injected notification bar.
 * Verification starts automatically when a PDF is opened (setting "autoVerify",
 * on by default); in Chrome the results panel opens by itself for signed PDFs.
 *
 * Prerequisites: `npm run build` and sample PDFs in PDF_Sample/ (gitignored).
 * Run: npx playwright test --project=chromium --reporter=list
 */
import { test, expect, chromium, type BrowserContext, type Page } from '@playwright/test'
import { createServer, type Server } from 'http'
import { existsSync, readFileSync, mkdtempSync } from 'fs'
import { tmpdir } from 'os'
import { join, resolve } from 'path'
import { fileURLToPath } from 'url'

const ROOT = fileURLToPath(new URL('../..', import.meta.url))
const EXTENSION_DIR = resolve(ROOT, '.output/chrome-mv3')
const SAMPLE_DIR = resolve(ROOT, 'PDF_Sample')

const CASES = [
  { file: 'hsm-signed-a.pdf', expected: 'trusted' },
  { file: 'self-signed.pdf', expected: 'failed' },
  // expired one-day HSM certificate without embedded revocation data + co-signature under a foreign root
  { file: 'expired-hsm-and-foreign-ca.pdf', expected: 'unknown' },
]
const FINAL_STATES = ['trusted', 'failed', 'unknown', 'error', 'none']

test.skip(!existsSync(EXTENSION_DIR) || !existsSync(SAMPLE_DIR), 'needs npm run build and PDF_Sample/')
test.describe.configure({ mode: 'serial' })

let server: Server
let baseUrl: string
let context: BrowserContext
/** GET count per sample file, to see which document a re-check fetched. */
const requests = new Map<string, number>()

test.beforeAll(async ({}, testInfo) => {
  testInfo.setTimeout(120_000)
  server = createServer((req, res) => {
    const name = decodeURIComponent((req.url ?? '/').slice(1))
    requests.set(name, (requests.get(name) ?? 0) + 1)
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
})

test.afterAll(async () => {
  await context?.close()
  await new Promise((done) => server?.close(done))
})

async function openPdf(file: string): Promise<Page> {
  const page = await context.newPage()
  await page.goto(`${baseUrl}/${encodeURIComponent(file)}`)
  await expect(page.locator('#pdf-verifier-floating-button')).toBeVisible({ timeout: 30_000 })
  return page
}

/** Wait until the bar's button shows a final verdict (no click needed). */
async function finalState(page: Page): Promise<string | null> {
  const button = page.locator('#pdf-verifier-floating-button')
  await expect
    .poll(() => button.getAttribute('data-pdf-verifier-state'), { timeout: 90_000 })
    .toMatch(new RegExp(`^(${FINAL_STATES.join('|')})$`))
  return button.getAttribute('data-pdf-verifier-state')
}

async function setAutoVerify(enabled: boolean) {
  const worker = context.serviceWorkers()[0] ?? (await context.waitForEvent('serviceworker'))
  const extensionId = new URL(worker.url()).host
  const page = await context.newPage()
  await page.goto(`chrome-extension://${extensionId}/popup.html`)
  await page.evaluate(
    (value) => chrome.storage.local.set({ 'pdf-verifier-settings': { autoVerify: value } }),
    enabled
  )
  await page.close()
}

for (const { file, expected } of CASES) {
  test(`auto-verify ${file} → ${expected}`, async () => {
    test.setTimeout(120_000)
    const page = await openPdf(file)

    const state = await finalState(page)
    const label = (await page.locator('#pdf-verifier-floating-button').innerText()).trim()
    console.log(`${file}: state=${state} label=${label}`)
    expect(state).toBe(expected)

    // Signed PDF in Chrome: the results panel opens on its own
    await expect(page.locator('#pdf-verifier-panel-overlay')).toBeVisible({ timeout: 10_000 })
    await page.close()
  })
}

test('unsigned PDF → no signatures, no panel', async () => {
  test.setTimeout(120_000)
  const page = await openPdf('unsigned.pdf')
  expect(await finalState(page)).toBe('none')
  await expect(page.locator('#pdf-verifier-panel-overlay')).toHaveCount(0)
  await page.close()
})

test('panel re-check verifies again and keeps the verdict', async () => {
  test.setTimeout(150_000)
  const page = await openPdf('hsm-signed-b.pdf')
  expect(await finalState(page)).toBe('trusted')

  const panel = page.frameLocator('#pdf-verifier-panel-overlay iframe')
  const recheck = panel.getByTestId('panel-recheck')
  await expect(recheck).toBeVisible({ timeout: 10_000 })
  const before = requests.get('hsm-signed-b.pdf') ?? 0
  await recheck.click()
  await expect(recheck).toBeDisabled()
  await expect(recheck).toBeEnabled({ timeout: 90_000 })
  // the same document was downloaded again
  expect(requests.get('hsm-signed-b.pdf')).toBe(before + 1)
  expect(await page.locator('#pdf-verifier-floating-button').getAttribute('data-pdf-verifier-state')).toBe('trusted')

  // Closing and clicking the bar button shows the finished result again
  await panel.locator('header button').click()
  await expect(page.locator('#pdf-verifier-panel-overlay')).toHaveCount(0)
  await page.locator('#pdf-verifier-floating-button').click()
  await expect(page.locator('#pdf-verifier-panel-overlay')).toBeVisible({ timeout: 10_000 })
  await page.close()
})

test('autoVerify off → waits for a click', async () => {
  test.setTimeout(150_000)
  await setAutoVerify(false)
  try {
    const page = await openPdf('hsm-signed-a.pdf')
    const button = page.locator('#pdf-verifier-floating-button')
    await page.waitForTimeout(3_000)
    expect(await button.getAttribute('data-pdf-verifier-state')).toBe('idle')
    await expect(page.locator('#pdf-verifier-panel-overlay')).toHaveCount(0)

    await button.click()
    expect(await finalState(page)).toBe('trusted')
    await page.close()
  } finally {
    await setAutoVerify(true)
  }
})
