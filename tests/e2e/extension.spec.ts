/**
 * End-to-end: load the built extension (.output/chrome-mv3) into Chromium,
 * open PDFs over HTTP and read the verdict from the injected notification bar.
 * Verification starts automatically when a PDF is opened (setting
 * "autoVerifyScope", all sites by default); in Chrome the results panel opens
 * by itself for signed PDFs, and the toolbar badge shows the verdict.
 *
 * Prerequisites: `npm run build` and sample PDFs in PDF_Sample/ (gitignored).
 * Run: npx playwright test --project=chromium --reporter=list
 */
import { test, expect, chromium, type BrowserContext, type Page } from '@playwright/test'
import { createServer, type Server } from 'http'
import { existsSync, readFileSync, mkdtempSync } from 'fs'
import { tmpdir } from 'os'
import { join, resolve } from 'path'
import { fileURLToPath, pathToFileURL } from 'url'

const ROOT = fileURLToPath(new URL('../..', import.meta.url))
const EXTENSION_DIR = resolve(ROOT, '.output/chrome-mv3')
const SAMPLE_DIR = resolve(ROOT, 'PDF_Sample')

const CASES = [
  { file: 'hsm-signed-a.pdf', expected: 'trusted', badge: '✓' },
  { file: 'self-signed.pdf', expected: 'failed', badge: '✗' },
  // TWCA signature trusted (embedded OCSP) + DocuSign co-signature under a foreign root -> document not fully verified
  { file: 'expired-hsm-and-foreign-ca.pdf', expected: 'unknown', badge: '!' },
]
const FINAL_STATES = ['trusted', 'failed', 'unknown', 'error', 'none']

test.skip(!existsSync(EXTENSION_DIR) || !existsSync(SAMPLE_DIR), 'needs npm run build and PDF_Sample/')
test.describe.configure({ mode: 'serial' })

let server: Server
let baseUrl: string
let context: BrowserContext
let extensionId = ''
/** GET count per sample file, to see which document a re-check fetched. */
const requests = new Map<string, number>()

test.beforeAll(async ({}, testInfo) => {
  testInfo.setTimeout(120_000)
  server = createServer((req, res) => {
    const name = decodeURIComponent((req.url ?? '/').slice(1).split('?')[0])
    requests.set(name, (requests.get(name) ?? 0) + 1)
    if (name === 'page.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }).end('<!doctype html><title>page</title><p>Not a PDF</p>')
      return
    }
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

async function openPdf(fileOrUrl: string): Promise<Page> {
  const page = await context.newPage()
  await page.goto(fileOrUrl.includes(':') ? fileOrUrl : `${baseUrl}/${encodeURIComponent(fileOrUrl)}`)
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

/** Run extension APIs from an extension page (tabs, action, storage, messaging). */
async function withExtensionPage<T>(fn: (page: Page) => Promise<T>): Promise<T> {
  if (!extensionId) {
    const worker = context.serviceWorkers()[0] ?? (await context.waitForEvent('serviceworker'))
    extensionId = new URL(worker.url()).host
  }
  const page = await context.newPage()
  await page.goto(`chrome-extension://${extensionId}/popup.html`)
  try {
    return await fn(page)
  } finally {
    await page.close()
  }
}

async function setSettings(settings: Record<string, unknown>) {
  await withExtensionPage((page) =>
    page.evaluate((value) => chrome.storage.local.set({ 'pdf-verifier-settings': value }), settings)
  )
}

async function tabIdOf(page: Page): Promise<number> {
  const url = page.url()
  return withExtensionPage((ext) =>
    ext.evaluate(async (u) => (await chrome.tabs.query({})).find((tab) => tab.url === u)!.id!, url)
  )
}

async function badgeOf(page: Page): Promise<string> {
  const tabId = await tabIdOf(page)
  return withExtensionPage((ext) => ext.evaluate((id) => chrome.action.getBadgeText({ tabId: id }), tabId))
}

for (const { file, expected, badge } of CASES) {
  test(`auto-verify ${file} → ${expected}`, async () => {
    test.setTimeout(120_000)
    const page = await openPdf(file)

    const state = await finalState(page)
    const label = (await page.locator('#pdf-verifier-floating-button').innerText()).trim()
    console.log(`${file}: state=${state} label=${label}`)
    expect(state).toBe(expected)

    // Signed PDF in Chrome: the results panel opens on its own
    await expect(page.locator('#pdf-verifier-panel-overlay')).toBeVisible({ timeout: 10_000 })
    // ... and the toolbar icon shows the verdict for this tab
    expect(await badgeOf(page)).toBe(badge)
    await page.close()
  })
}

test('unsigned PDF → no signatures, no panel, no badge', async () => {
  test.setTimeout(120_000)
  const page = await openPdf('unsigned.pdf')
  expect(await finalState(page)).toBe('none')
  await expect(page.locator('#pdf-verifier-panel-overlay')).toHaveCount(0)
  expect(await badgeOf(page)).toBe('')
  await page.close()
})

test('popup shows the result already verified for the active tab', async () => {
  test.setTimeout(120_000)
  const pdf = await openPdf('hsm-signed-a.pdf')
  expect(await finalState(pdf)).toBe('trusted')
  const pdfTabId = await tabIdOf(pdf)

  // The popup shows the entry of the tab it is opened from. Open it in a tab of
  // its own, then hand that tab the PDF tab's entry (arrives while it is open).
  const popup = await context.newPage()
  await popup.goto(`chrome-extension://${extensionId}/popup.html`)
  await popup.bringToFront()
  await expect(popup.getByText('目前分頁的驗證結果')).toHaveCount(0)
  const popupTabId = await popup.evaluate(async () => (await chrome.tabs.getCurrent())!.id!)
  await popup.evaluate(async ([from, to]) => {
    const entry = (await chrome.storage.session.get(`tab-result:${from}`))[`tab-result:${from}`]
    await chrome.storage.session.set({ [`tab-result:${to}`]: entry })
  }, [pdfTabId, popupTabId] as const)
  // popup language defaults to Traditional Chinese
  await expect(popup.getByText('目前分頁的驗證結果')).toBeVisible({ timeout: 10_000 })
  await expect(popup.getByText('hsm-signed-a.pdf')).toBeVisible()
  await expect(popup.getByText('文件可信').first()).toBeVisible()
  await popup.close()
  await pdf.close()
})

test('a PDF dropped on the bar is verified (online, by the background)', async () => {
  test.setTimeout(150_000)
  const page = await openPdf('unsigned.pdf')
  expect(await finalState(page)).toBe('none')

  const b64 = readFileSync(join(SAMPLE_DIR, 'hsm-signed-b.pdf')).toString('base64')
  const dataTransfer = await page.evaluateHandle((data) => {
    const bytes = Uint8Array.from(atob(data), (c) => c.charCodeAt(0))
    const dt = new DataTransfer()
    dt.items.add(new File([bytes], 'hsm-signed-b.pdf', { type: 'application/pdf' }))
    return dt
  }, b64)
  await page.dispatchEvent('#pdf-verifier-notification-bar', 'drop', { dataTransfer })

  const button = page.locator('#pdf-verifier-floating-button')
  await expect.poll(() => button.getAttribute('data-pdf-verifier-state'), { timeout: 90_000 }).toBe('trusted')
  await expect(page.locator('#pdf-verifier-panel-overlay')).toBeVisible({ timeout: 10_000 })
  // a dropped file cannot be fetched again
  await expect(page.frameLocator('#pdf-verifier-panel-overlay iframe').getByTestId('panel-recheck')).toHaveCount(0)
  expect(await badgeOf(page)).toBe('✓')
  await page.close()
})

test('context menu: the page shows progress, the result panel and errors', async () => {
  test.setTimeout(120_000)
  const page = await context.newPage()
  await page.goto(`${baseUrl}/page.html`)
  const tabId = await tabIdOf(page)

  // what the background sends after the user picks "verify this PDF"
  const notPdf = await withExtensionPage((ext) =>
    ext.evaluate((url) => chrome.runtime.sendMessage({ action: 'verify-pdf-url', url, fileName: 'page.html' }), `${baseUrl}/page.html`)
  )
  // the service worker follows the OS language, pages the emulated one
  expect(notPdf.error).toMatch(/not a PDF|不是 PDF/)

  const verified = await withExtensionPage((ext) =>
    ext.evaluate((url) => chrome.runtime.sendMessage({ action: 'verify-pdf-url', url, fileName: 'hsm-signed-a.pdf' }), `${baseUrl}/hsm-signed-a.pdf`)
  )
  expect(verified.result.status).toBe('trusted')

  // a popup re-check result for a document this tab no longer shows is refused
  const stale = await withExtensionPage((ext) =>
    ext.evaluate(([id, result, url]) => chrome.runtime.sendMessage({
      action: 'tab-state', tabId: id, state: 'trusted', result, source: { url, fileName: 'hsm-signed-a.pdf' },
    }), [tabId, verified.result, `${baseUrl}/hsm-signed-a.pdf`] as const)
  )
  expect(stale).toEqual({ ok: false })
  expect(await badgeOf(page)).toBe('')

  await withExtensionPage((ext) => ext.evaluate((id) => chrome.tabs.sendMessage(id, { action: 'show-verifying' }, { frameId: 0 }), tabId))
  await expect(page.locator('#pdf-verifier-toast')).toBeVisible()
  const source = { url: `${baseUrl}/hsm-signed-a.pdf`, fileName: 'hsm-signed-a.pdf' }
  await withExtensionPage((ext) =>
    ext.evaluate(([id, result, src]) => chrome.tabs.sendMessage(id, { action: 'show-result', result, source: src }, { frameId: 0 }), [tabId, verified.result, source] as const)
  )
  await expect(page.locator('#pdf-verifier-toast')).toHaveCount(0)
  await expect(page.locator('#pdf-verifier-panel-overlay')).toBeVisible({ timeout: 10_000 })

  await withExtensionPage((ext) =>
    ext.evaluate((id) => chrome.tabs.sendMessage(id, { action: 'show-error', error: 'This is not a PDF file' }, { frameId: 0 }), tabId)
  )
  await expect(page.locator('#pdf-verifier-toast')).toHaveText('This is not a PDF file')
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

test('local file:// PDF is verified automatically when file access is allowed', async () => {
  test.setTimeout(120_000)
  // extensions loaded with --load-extension have "Allow access to file URLs" on
  const page = await openPdf(pathToFileURL(join(SAMPLE_DIR, 'hsm-signed-a.pdf')).href)
  expect(await finalState(page)).toBe('trusted')
  await expect(page.locator('#pdf-verifier-panel-overlay')).toBeVisible({ timeout: 10_000 })
  await page.close()
})

test('auto-verify scope: listed sites only', async () => {
  test.setTimeout(180_000)
  try {
    await setSettings({ autoVerifyScope: 'listed', autoVerifySites: ['example.com'] })
    const elsewhere = await openPdf('hsm-signed-a.pdf')
    await elsewhere.waitForTimeout(3_000)
    expect(await elsewhere.locator('#pdf-verifier-floating-button').getAttribute('data-pdf-verifier-state')).toBe('idle')
    await elsewhere.close()

    await setSettings({ autoVerifyScope: 'listed', autoVerifySites: ['127.0.0.1'] })
    const listed = await openPdf('hsm-signed-a.pdf')
    expect(await finalState(listed)).toBe('trusted')
    await listed.close()
  } finally {
    await setSettings({ autoVerifyScope: 'all', autoVerifySites: [] })
  }
})

test('autoVerify off (settings saved by earlier versions) → waits for a click', async () => {
  test.setTimeout(150_000)
  await setSettings({ autoVerify: false })
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
    await setSettings({ autoVerifyScope: 'all', autoVerifySites: [] })
  }
})

test('international CAs: off by default, labelled when turned on', async () => {
  test.setTimeout(180_000)
  try {
    // default: the DocuSign (DigiCert) signature is not trusted, the TWCA one is labelled licensed
    const off = await openPdf('expired-hsm-and-foreign-ca.pdf')
    expect(await finalState(off)).toBe('unknown')
    const offPanel = off.frameLocator('#pdf-verifier-panel-overlay iframe')
    await expect(offPanel.getByTestId('signature-regulation').first()).toContainText('TWCA')
    await off.close()

    await setSettings({ autoVerifyScope: 'all', autoVerifySites: [], trustInternational: true })
    const on = await openPdf('expired-hsm-and-foreign-ca.pdf')
    expect(await finalState(on)).toBe('trusted')
    const onPanel = on.frameLocator('#pdf-verifier-panel-overlay iframe')
    await expect(onPanel.getByTestId('signature-regulation')).toHaveCount(2)
    await expect(onPanel.getByTestId('signature-regulation').nth(1)).toContainText('DigiCert')
    await on.close()
  } finally {
    await setSettings({ autoVerifyScope: 'all', autoVerifySites: [] })
  }
})
