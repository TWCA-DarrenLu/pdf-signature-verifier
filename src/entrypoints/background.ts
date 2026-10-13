import { t, setLocale, detectBrowserLocale } from '@/i18n'
import type { Locale } from '@/i18n'

/**
 * Service worker keep-alive (audit P3-10).
 *
 * MV3 reaps the service worker after ~30s of idle time, which can interrupt
 * a long verification (OCSP fetch waiting on a slow responder, large CRL
 * download, etc.). While a verification is in flight, we keep the worker
 * alive by registering a no-op alarm and tracking active job count.
 */
let activeJobs = 0
const KEEPALIVE_ALARM = 'pdf-verifier-keepalive'

async function startKeepAlive(): Promise<void> {
  activeJobs++
  if (activeJobs === 1) {
    try {
      await chrome.alarms.create(KEEPALIVE_ALARM, { periodInMinutes: 0.5 })
    } catch {
      // alarms permission missing — no-op
    }
  }
}

async function endKeepAlive(): Promise<void> {
  activeJobs = Math.max(0, activeJobs - 1)
  if (activeJobs === 0) {
    try {
      await chrome.alarms.clear(KEEPALIVE_ALARM)
    } catch {
      // ignore
    }
  }
}

export default defineBackground(() => {
  // Initialize locale
  const initLocale = async () => {
    try {
      const result = await chrome.storage.local.get('pdf-verifier-settings')
      const settings = result['pdf-verifier-settings']
      if (settings?.language) {
        setLocale(settings.language as Locale)
      } else {
        setLocale(detectBrowserLocale())
      }
    } catch {
      setLocale(detectBrowserLocale())
    }
  }
  initLocale()

  // Eagerly load the trust store on startup so the first verification doesn't
  // pay parsing cost. Warnings (empty store, fingerprint mismatch, etc.) go
  // to console.warn here so developers see them during dev mode reloads.
  void (async () => {
    const { initializeTrustStore, getTrustStoreWarnings } = await import('@/trust-store/trust-manager')
    await initializeTrustStore()
    const warnings = getTrustStoreWarnings()
    if (warnings.length > 0) {
      console.warn('[PDFtrust] Trust store warnings:')
      for (const w of warnings) console.warn('  -', w)
    }
  })()

  console.log('PDF Signature Verifier background script loaded')

  // No-op alarm listener — its existence keeps the SW awake.
  chrome.alarms.onAlarm.addListener(() => {})

  // Toolbar badge per tab: reset when the tab shows another document, forget closed tabs
  chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status !== 'loading') return
    void (async () => {
      const entry = await getTabEntry(tabId)
      // in-document navigation (#page=2) keeps the result
      if (changeInfo.url && entry?.url && withoutHash(changeInfo.url) === withoutHash(entry.url)) return
      await clearTabState(tabId)
    })()
  })
  chrome.tabs.onRemoved.addListener((tabId) => {
    void chrome.storage.session?.remove(tabKey(tabId)).catch(() => {})
  })

  // Right-click "verify this PDF" on links and embedded documents
  chrome.runtime.onInstalled.addListener(() => {
    void initLocale().then(createContextMenu)
  })
  chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === CONTEXT_MENU_ID) void handleContextMenuVerify(info, tab)
  })
  chrome.storage.onChanged.addListener((changes, area) => {
    const language = changes['pdf-verifier-settings']?.newValue?.language as Locale | undefined
    if (area !== 'local' || !language) return
    setLocale(language)
    chrome.contextMenus.update(CONTEXT_MENU_ID, { title: t('contextMenu.verifyLink') }, () => {
      void chrome.runtime.lastError
    })
  })

  // Handle messages from popup, content scripts, and upload window
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    handleMessage(message, sender)
      .then(sendResponse)
      .catch((err) => {
        sendResponse({ error: err instanceof Error ? err.message : 'Unknown error' })
      })
    return true // Keep channel open for async response
  })
})

async function handleMessage(
  message: { action: string; [key: string]: unknown },
  sender: chrome.runtime.MessageSender
): Promise<unknown> {
  switch (message.action) {
    case 'verify-pdf-url':
      return handlePdfUrlVerification(message.url as string, message.fileName as string, message.fresh === true)

    case 'verify-pdf':
      return handlePdfVerification(
        typeof message.base64 === 'string' ? fromBase64(message.base64) : new Uint8Array(message.data as number[]),
        message.fileName as string,
        message.options as Record<string, unknown> | undefined
      )

    case 'tab-state':
      return handleTabState(message, sender)

    case 'open-panel-window':
      return handleOpenPanelWindow(message.result as unknown)

    case 'open-upload-window':
      return handleOpenUploadWindow()

    case 'open-popup':
      return handleOpenPopup()

    case 'get-trust-store-status':
      return handleGetTrustStoreStatus()

    default:
      return { error: `Unknown action: ${message.action}` }
  }
}

async function handlePdfUrlVerification(
  url: string,
  fileName: string,
  fresh = false
): Promise<{ result: unknown } | { error: string }> {
  await startKeepAlive()
  try {
    const response = await fetch(url)
    if (!response.ok) {
      return { error: t('core.misc.pdfDownloadFailed', { status: String(response.status) }) }
    }
    const bytes = new Uint8Array(await response.arrayBuffer())
    // Links from the context menu can point anywhere (HTML pages, images, ...)
    if (!looksLikePdf(bytes)) {
      return { error: t('content.notPdf') }
    }
    const { verifyPdfSignatures } = await import('@/core/verifier')
    const result = await verifyPdfSignatures(bytes, fileName, { refreshRevocation: fresh })
    return { result }
  } catch (error) {
    return { error: error instanceof Error ? error.message : 'Verification failed' }
  } finally {
    await endKeepAlive()
  }
}

async function handleOpenPanelWindow(
  result?: unknown
): Promise<{ ok: boolean }> {
  // Result may be passed via message (legacy) or pre-stored in chrome.storage.local
  if (result !== undefined && result !== null) {
    await chrome.storage.local.set({ 'pdf-panel-result': result })
  }
  await chrome.windows.create({
    url: chrome.runtime.getURL('/panel.html?source=popup'),
    type: 'popup',
    width: 440,
    height: 700,
  })
  return { ok: true }
}

async function handleOpenUploadWindow(): Promise<{ ok: boolean }> {
  await chrome.windows.create({
    url: chrome.runtime.getURL('/popup.html?source=tab'),
    type: 'popup',
    width: 460,
    height: 500,
  })
  return { ok: true }
}

async function handleOpenPopup(): Promise<{ ok: boolean }> {
  try {
    await chrome.action.openPopup()
  } catch {
    // Fallback: open popup as a window if openPopup() is not supported
    await chrome.windows.create({
      url: chrome.runtime.getURL('/popup.html?source=tab'),
      type: 'popup',
      width: 460,
      height: 500,
    })
  }
  return { ok: true }
}

async function handlePdfVerification(
  data: Uint8Array,
  fileName: string,
  options?: Record<string, unknown>
): Promise<{ result: unknown } | { error: string }> {
  await startKeepAlive()
  try {
    if (!looksLikePdf(data)) {
      return { error: t('content.notPdf') }
    }
    const { verifyPdfSignatures } = await import('@/core/verifier')
    const result = await verifyPdfSignatures(data, fileName, options)
    return { result }
  } catch (error) {
    return { error: error instanceof Error ? error.message : 'Verification failed' }
  } finally {
    await endKeepAlive()
  }
}

async function handleGetTrustStoreStatus(): Promise<{
  isEmpty: boolean
  isTsaEmpty: boolean
  warnings: string[]
  stats: unknown
}> {
  const {
    initializeTrustStore,
    isTrustStoreEmpty,
    isTsaTrustStoreEmpty,
    getTrustStoreWarnings,
    getTrustStoreStats,
  } = await import('@/trust-store/trust-manager')
  await initializeTrustStore()
  return {
    isEmpty: isTrustStoreEmpty(),
    isTsaEmpty: isTsaTrustStoreEmpty(),
    warnings: getTrustStoreWarnings(),
    stats: getTrustStoreStats(),
  }
}

/** A PDF starts with "%PDF-" within its first 1024 bytes. */
function looksLikePdf(bytes: Uint8Array): boolean {
  const head = String.fromCharCode(...bytes.subarray(0, 1024))
  return head.includes('%PDF-')
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

// ─── Per-tab result + toolbar badge ─────────────────────────────

type TabState = 'busy' | 'trusted' | 'unknown' | 'failed' | 'none' | 'error'

interface TabEntry {
  state: TabState
  result: unknown
  source: { url: string; fileName: string } | null
  url?: string
}

const BADGE: Record<TabState, { text: string; color: string; titleKey: string }> = {
  busy: { text: '…', color: '#64748b', titleKey: 'content.verifying' },
  trusted: { text: '✓', color: '#16a34a', titleKey: 'status.trusted' },
  unknown: { text: '!', color: '#d97706', titleKey: 'status.unknown' },
  failed: { text: '✗', color: '#dc2626', titleKey: 'status.failed' },
  none: { text: '', color: '#64748b', titleKey: 'content.noSignatures' },
  error: { text: '?', color: '#64748b', titleKey: 'content.cannotGetPdf' },
}

const tabKey = (tabId: number) => `tab-result:${tabId}`
const withoutHash = (url: string) => url.split('#')[0]

async function getTabEntry(tabId: number): Promise<TabEntry | undefined> {
  try {
    return (await chrome.storage.session.get(tabKey(tabId)))[tabKey(tabId)] as TabEntry | undefined
  } catch {
    return undefined
  }
}

async function setTabBadge(tabId: number, state: TabState): Promise<void> {
  const badge = BADGE[state]
  try {
    await chrome.action.setBadgeText({ tabId, text: badge.text })
    if (badge.text) {
      await chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color })
      await chrome.action.setBadgeTextColor?.({ tabId, color: '#ffffff' })
    }
    await chrome.action.setTitle({ tabId, title: `${chrome.runtime.getManifest().name} — ${t(badge.titleKey)}` })
  } catch {
    // tab closed meanwhile
  }
}

async function clearTabState(tabId: number): Promise<void> {
  try {
    await chrome.action.setBadgeText({ tabId, text: '' })
    await chrome.action.setTitle({ tabId, title: chrome.runtime.getManifest().name })
    await chrome.storage.session.remove(tabKey(tabId))
  } catch {
    // tab closed meanwhile
  }
}

/**
 * The PDF shown in a tab was (re)verified — by the viewer bar (automatic or
 * manual), a dropped file, or the popup's re-check. Only the top document of
 * a tab reports; the popup passes the tab id explicitly.
 */
async function handleTabState(
  message: { [key: string]: unknown },
  sender: chrome.runtime.MessageSender
): Promise<{ ok: boolean }> {
  // Content scripts report for their own tab; extension pages (the popup, also
  // when it is opened in a tab) name the tab explicitly.
  const fromTab = sender.tab?.id !== undefined && !sender.url?.startsWith(chrome.runtime.getURL(''))
  if (fromTab && sender.frameId !== 0) return { ok: false }
  const tabId = fromTab ? sender.tab!.id! : (message.tabId as number | undefined)
  const state = message.state as TabState
  if (tabId === undefined || !(state in BADGE)) return { ok: false }

  let url = sender.tab?.url
  if (!fromTab) {
    // popup re-check: the tab may show another document by now
    const source = message.source as TabEntry['source']
    try {
      url = (await chrome.tabs.get(tabId)).url
    } catch {
      return { ok: false }
    }
    if (!source || !url || withoutHash(url) !== withoutHash(source.url)) return { ok: false }
  }

  await setTabBadge(tabId, state)
  const session = chrome.storage.session
  if (!session) return { ok: true } // Firefox < 115: badge only
  if (message.result) {
    const entry: TabEntry = {
      state,
      result: message.result,
      source: (message.source as TabEntry['source']) ?? null,
      url,
    }
    try {
      await session.set({ [tabKey(tabId)]: entry })
    } catch {
      // storage.session quota is shared with the revocation cache: drop the cache, try once more
      const { clearRevocationCache } = await import('@/core/revocation/revocation-cache')
      await clearRevocationCache()
      await session.set({ [tabKey(tabId)]: entry }).catch(() => {})
    }
  } else if (state !== 'busy') {
    await session.remove(tabKey(tabId)).catch(() => {})
  }
  return { ok: true }
}

// ─── Context menu ───────────────────────────────────────────────

const CONTEXT_MENU_ID = 'pdf-verifier-verify-link'

function createContextMenu(): void {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: CONTEXT_MENU_ID,
      title: t('contextMenu.verifyLink'),
      contexts: ['link', 'frame'],
    }, () => {
      void chrome.runtime.lastError
    })
  })
}

function fileNameFromUrl(url: string): string {
  try {
    return decodeURIComponent(new URL(url).pathname.split('/').pop() || '') || 'document.pdf'
  } catch {
    return 'document.pdf'
  }
}

/**
 * Verify the link / frame the user right-clicked. The page shows progress and
 * the result panel; pages without our content script get the panel window.
 */
async function handleContextMenuVerify(info: chrome.contextMenus.OnClickData, tab?: chrome.tabs.Tab): Promise<void> {
  const url = info.linkUrl ?? info.frameUrl
  if (!url || !/^https?:/i.test(url)) return
  const source = { url, fileName: fileNameFromUrl(url) }
  const tabId = tab?.id
  const tell = async (msg: Record<string, unknown>): Promise<boolean> => {
    if (tabId === undefined) return false
    try {
      await chrome.tabs.sendMessage(tabId, msg, { frameId: 0 })
      return true
    } catch {
      return false
    }
  }

  await tell({ action: 'show-verifying', url })
  const response = await handlePdfUrlVerification(source.url, source.fileName)
  if ('result' in response) {
    // what messaging would deliver: Dates as ISO strings
    const result = JSON.parse(JSON.stringify(response.result))
    if (!(await tell({ action: 'show-result', result, source }))) {
      await chrome.storage.local.set({ 'pdf-panel-result': result, 'pdf-panel-source': source })
      await handleOpenPanelWindow()
    }
  } else if (!(await tell({ action: 'show-error', error: response.error }))) {
    await chrome.storage.local.set({ 'pdf-panel-error': response.error })
    await handleOpenPanelWindow()
  }
}
