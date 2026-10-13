import { t, setLocale, detectBrowserLocale } from '@/i18n'
import type { Locale } from '@/i18n'
import { shouldAutoVerify } from '@/settings/auto-verify'

export default defineContentScript({
  matches: ['<all_urls>'],
  runAt: 'document_idle',

  main() {
    // Initialize locale from settings
    const initLocale = async () => {
      try {
        if (typeof chrome !== 'undefined' && chrome.storage) {
          const result = await chrome.storage.local.get('pdf-verifier-settings')
          const settings = result['pdf-verifier-settings']
          if (settings?.language) {
            setLocale(settings.language as Locale)
          } else {
            setLocale(detectBrowserLocale())
          }
        } else {
          setLocale(detectBrowserLocale())
        }
      } catch {
        setLocale(detectBrowserLocale())
      }
    }
    // Detect PDF files once the language is known: the injected bar and
    // buttons are labelled when they are created.
    void initLocale().then(() => {
      detectPdfLinks()
      detectEmbeddedPdfs()

      // Watch for dynamically added content
      const observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
          if (mutation.addedNodes.length > 0) {
            detectPdfLinks()
            detectEmbeddedPdfs()
          }
        }
      })

      observer.observe(document.body, {
        childList: true,
        subtree: true,
      })
    })

    // Listen for panel messages
    window.addEventListener('message', (event) => {
      if (event.data?.type === 'pdf-panel-close' && panelIframe && event.source === panelIframe.contentWindow) {
        closePanel()
      } else if (event.data?.type === 'pdf-panel-recheck' && panelIframe && event.source === panelIframe.contentWindow) {
        void recheckFromPanel()
      }
    })

    // Right-click "verify this PDF": progress and result come from the background
    chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
      if (message?.action === 'show-verifying') {
        showToast(t('content.verifying'), false)
      } else if (message?.action === 'show-result') {
        hideToast()
        void showPanel(message.result, message.source ?? null).catch(() => {})
      } else if (message?.action === 'show-error') {
        showToast(String(message.error ?? t('content.unknownError')), true)
      } else {
        return
      }
      sendResponse({ ok: true })
    })

    // Listen for language changes from popup/settings
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.onChanged.addListener((changes, area) => {
        if (area === 'local' && changes['pdf-verifier-settings']) {
          const newSettings = changes['pdf-verifier-settings'].newValue
          if (newSettings?.language) {
            setLocale(newSettings.language as Locale)
            refreshIdleButtonLabels()
          }
        }
      })
    }
  },
})

// ─── Panel Management ───────────────────────────────────────────

let panelContainer: HTMLDivElement | null = null
let panelIframe: HTMLIFrameElement | null = null
let pendingResult: unknown = null
type PanelSource = { url: string; fileName: string }
/** Remote PDF behind the result shown in the panel (for "re-check"); null for local files. */
let panelSource: PanelSource | null = null
let panelFallbackTimer: ReturnType<typeof setTimeout> | undefined
let panelReadyHandler: ((event: MessageEvent) => void) | null = null
/** Result shown by the PDF viewer bar (automatic run, click or dropped file) and its source. */
let viewerResult: unknown = null
let viewerSource: PanelSource | null = null
let viewerBusy = false

type VerifyResponse = { result?: unknown; error?: string }

function canEmbedPanel(): boolean {
  // The panel iframe (extension page) loads in Chrome and Edge, incl. their
  // PDF viewers — verified with Chrome 145 and Edge 155 (2026-10-13). Brave is
  // untested and keeps the pop-up window; Firefox has no "Chrome/" in its UA.
  // If the iframe does not load anyway, showPanel falls back to the window.
  return /Chrome\//i.test(navigator.userAgent) && !('brave' in navigator)
}

function sourceFor(url: string): PanelSource | null {
  return isFetchableByBackground(url) ? { url, fileName: getFileName(url) } : null
}

async function showPanel(result: unknown, source: PanelSource | null, auto = false) {
  // Only Chrome reliably supports extension iframes in content scripts.
  // Edge, Brave, and other Chromium forks block them.
  if (!canEmbedPanel()) {
    await openPanelAsPopup(result, source)
    return
  }

  // Close existing panel if open
  closePanel()

  pendingResult = result
  panelSource = source

  // Create overlay container
  panelContainer = document.createElement('div')
  panelContainer.id = 'pdf-verifier-panel-overlay'
  panelContainer.style.cssText = `
    position: fixed;
    top: 0;
    right: 0;
    width: 420px;
    height: 100vh;
    z-index: 2147483647;
    box-shadow: -4px 0 24px rgba(0,0,0,0.15);
    background: white;
    display: flex;
    flex-direction: column;
    transition: transform 0.25s ease;
    transform: translateX(100%);
  `

  // Create iframe pointing to our panel page
  const iframe = document.createElement('iframe')
  panelIframe = iframe
  iframe.src = chrome.runtime.getURL('/panel.html')
  iframe.style.cssText = `
    width: 100%;
    height: 100%;
    border: none;
  `

  // Listen for panel ready signal BEFORE iframe loads to avoid race condition
  const handlePanelReady = (event: MessageEvent) => {
    if (event.data?.type === 'pdf-panel-ready' && event.source === iframe.contentWindow) {
      clearTimeout(panelFallbackTimer)
      iframe.contentWindow?.postMessage(
        { type: 'pdf-verification-result', result: pendingResult, canRecheck: panelSource !== null },
        '*'
      )
      window.removeEventListener('message', handlePanelReady)
      panelReadyHandler = null
    }
  }
  panelReadyHandler = handlePanelReady
  window.addEventListener('message', handlePanelReady)

  // Fallback: if iframe fails to load, open as popup window — never unprompted
  // (automatic runs leave the result on the button instead)
  panelFallbackTimer = setTimeout(() => {
    closePanel()
    if (!auto) void openPanelAsPopup(result, source)
  }, 3000)

  panelContainer.appendChild(iframe)
  document.body.appendChild(panelContainer)

  // Slide in animation
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      if (panelContainer) {
        panelContainer.style.transform = 'translateX(0)'
      }
    })
  })

  // Close on Escape key
  const handleEscape = (e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      closePanel()
      document.removeEventListener('keydown', handleEscape)
    }
  }
  document.addEventListener('keydown', handleEscape)
}

async function openPanelAsPopup(result: unknown, source: PanelSource | null) {
  // Store result directly in storage (avoids large data serialization through messaging)
  await chrome.storage.local.set({ 'pdf-panel-result': result, 'pdf-panel-source': source })
  // Send lightweight message to background to open the panel window
  chrome.runtime.sendMessage({ action: 'open-panel-window' }, () => {
    void chrome.runtime.lastError // suppress console warning
  })
}

function closePanel() {
  clearTimeout(panelFallbackTimer)
  panelFallbackTimer = undefined
  if (panelReadyHandler) {
    window.removeEventListener('message', panelReadyHandler)
    panelReadyHandler = null
  }
  if (panelContainer) {
    panelContainer.style.transform = 'translateX(100%)'
    const container = panelContainer
    setTimeout(() => {
      container.remove()
    }, 250)
    panelContainer = null
  }
  panelIframe = null
  panelSource = null
  pendingResult = null
}

// ─── PDF Detection ──────────────────────────────────────────────

function detectPdfLinks() {
  const links = document.querySelectorAll('a[href$=".pdf"], a[href*=".pdf?"]')

  links.forEach((link) => {
    if (link.hasAttribute('data-pdf-verifier')) {
      return
    }

    link.setAttribute('data-pdf-verifier', 'detected')

    // Add verification button next to PDF links
    const button = createVerifyButton(link as HTMLAnchorElement)
    link.parentNode?.insertBefore(button, link.nextSibling)
  })
}

function isPdfViewerPage(): boolean {
  // Chrome: contentType is application/pdf
  if (document.contentType === 'application/pdf') return true

  // URL path ends with .pdf (ignore query params and hash)
  try {
    const pathname = new URL(window.location.href).pathname
    if (pathname.toLowerCase().endsWith('.pdf')) return true
  } catch { /* ignore */ }

  // Firefox PDF.js viewer: detect by viewer-specific elements
  if (document.querySelector('#outerContainer #viewerContainer')) return true

  return false
}

function detectEmbeddedPdfs() {
  if (isPdfViewerPage()) {
    injectPdfViewerButton()
  }

  // Check for embed/object elements
  const embeds = document.querySelectorAll(
    'embed[type="application/pdf"], object[type="application/pdf"]'
  )

  embeds.forEach((embed) => {
    if (embed.hasAttribute('data-pdf-verifier')) {
      return
    }

    embed.setAttribute('data-pdf-verifier', 'detected')

    const button = createEmbedVerifyButton(embed as HTMLEmbedElement)
    embed.parentNode?.insertBefore(button, embed)
  })
}

// ─── Message Helpers ─────────────────────────────────────────────

// Path building, OCSP/CRL and AIA fetches can take a while on slow networks.
const VERIFY_TIMEOUT_MS = 90_000

function isRemoteUrl(url: string): boolean {
  return url.startsWith('http://') || url.startsWith('https://')
}

/**
 * The background can download this document: web URLs, and the file:// PDF
 * this page shows — the content script only runs on file:// pages when the
 * user allowed file access, which also lets the background read local files.
 */
function isFetchableByBackground(url: string): boolean {
  return isRemoteUrl(url) || (url.startsWith('file:') && window.location.protocol === 'file:')
}

/**
 * Prompt user to pick a PDF file via file input dialog, then read via FileReader.
 * This is the only reliable way to read local files from a content script —
 * XHR and fetch() are blocked by same-origin policy on file:// pages.
 */
function pickAndReadLocalPdf(): Promise<{ bytes: Uint8Array; fileName: string }> {
  return new Promise((resolve, reject) => {
    const input = document.createElement('input')
    input.type = 'file'
    input.accept = '.pdf,application/pdf'
    input.style.display = 'none'

    input.addEventListener('change', () => {
      const file = input.files?.[0]
      input.remove()
      if (!file) {
        reject(new Error(t('content.noFileSelected')))
        return
      }
      file.arrayBuffer().then((buffer) => {
        resolve({ bytes: new Uint8Array(buffer), fileName: file.name })
      }).catch(() => {
        reject(new Error(t('content.fileReadFailed')))
      })
    })

    // User cancelled the dialog
    input.addEventListener('cancel', () => {
      input.remove()
      reject(new Error(t('content.noFileSelected')))
    })

    document.body.appendChild(input)
    input.click()
  })
}

/**
 * Verify a PDF: remote URLs go to background service worker,
 * local files are read via FileReader in content script context.
 */
async function verifyPdfFromUrl(
  url: string,
  fileName: string,
  fresh = false
): Promise<VerifyResponse> {
  if (isFetchableByBackground(url)) {
    return sendMessageWithTimeout<VerifyResponse>({
      action: 'verify-pdf-url',
      url,
      fileName,
      fresh,
    })
  }
  // Local file — must use FileReader (XHR/fetch blocked by same-origin on file://)
  try {
    const picked = await pickAndReadLocalPdf()
    return await verifyBytesInBackground(picked.bytes, picked.fileName)
  } catch (error) {
    return { error: error instanceof Error ? error.message : t('content.unknownError') }
  }
}

/**
 * Local / dropped files are verified by the background too: only it may
 * query OCSP / CRL servers (content-script requests are bound by the page's CORS).
 */
function verifyBytesInBackground(bytes: Uint8Array, fileName: string): Promise<VerifyResponse> {
  let binary = ''
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  }
  return sendMessageWithTimeout<VerifyResponse>({ action: 'verify-pdf', base64: btoa(binary), fileName })
}

/** Tell the background what the bar shows, for the toolbar badge and the popup. */
function reportTabState(state: string, result?: unknown, source?: PanelSource | null): void {
  try {
    chrome.runtime.sendMessage({ action: 'tab-state', state, result, source: source ?? null }, () => {
      void chrome.runtime.lastError
    })
  } catch {
    // extension reloaded — the badge is optional
  }
}

function sendMessageWithTimeout<T>(
  message: Record<string, unknown>,
  timeoutMs: number = VERIFY_TIMEOUT_MS
): Promise<T> {
  return new Promise((resolve, reject) => {
    // Check if extension context is still valid
    if (!chrome.runtime?.id) {
      reject(new Error(t('content.extensionUpdated')))
      return
    }

    const timer = setTimeout(() => {
      reject(new Error(t('content.verifyTimeout')))
    }, timeoutMs)

    try {
      chrome.runtime.sendMessage(message, (response: T) => {
        clearTimeout(timer)
        // Always read lastError to suppress console warning
        const err = chrome.runtime.lastError
        if (err) {
          reject(new Error(err.message))
          return
        }
        resolve(response)
      })
    } catch {
      clearTimeout(timer)
      reject(new Error(t('content.connectionFailed')))
    }
  })
}

// ─── Button Creators ────────────────────────────────────────────

function refreshIdleButtonLabels() {
  document.querySelectorAll<HTMLButtonElement>('[data-pdf-verifier-state="idle"]').forEach((btn) => {
    const labelKey = btn.dataset.pdfVerifierLabel || 'content.verifySignature'
    btn.innerHTML = `${svgSearch()} ${t(labelKey)}`
  })
}

function createVerifyButton(link: HTMLAnchorElement): HTMLButtonElement {
  const button = document.createElement('button')
  button.dataset.pdfVerifierState = 'idle'
  button.dataset.pdfVerifierLabel = 'content.verifySignature'
  button.innerHTML = `${svgSearch()} ${t('content.verifySignature')}`
  button.style.cssText = `
    all: initial;
    margin-left: 8px;
    padding: 2px 8px;
    font-size: 12px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #3b82f6;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    line-height: normal;
    direction: ltr;
    text-decoration: none;
    white-space: nowrap;
    box-sizing: border-box;
  `

  button.addEventListener('click', async (e) => {
    e.preventDefault()
    e.stopPropagation()

    button.dataset.pdfVerifierState = 'busy'
    button.innerHTML = `${svgLoading()} ${t('content.verifying')}`
    button.disabled = true

    try {
      const result = await verifyPdfFromUrl(link.href, getFileName(link.href))

      if (!result || result.error) {
        button.innerHTML = `${svgX()} ${t('content.failed')}`
        button.dataset.pdfVerifierState = 'error'
        button.title = result?.error || t('content.noResponse')
      } else {
        updateButtonWithResult(button, result.result as VerifyResult)
        try { await showPanel(result.result, sourceFor(link.href)) } catch { /* panel display is optional */ }
      }
    } catch (error) {
      button.innerHTML = `${svgX()} ${t('content.error')}`
      button.dataset.pdfVerifierState = 'error'
      button.title = error instanceof Error ? error.message : t('content.unknownError')
    }

    button.disabled = false
  })

  return button
}

function createEmbedVerifyButton(embed: HTMLEmbedElement): HTMLButtonElement {
  const button = document.createElement('button')
  button.dataset.pdfVerifierState = 'idle'
  button.dataset.pdfVerifierLabel = 'content.verifyPdfSignature'
  button.innerHTML = `${svgSearch()} ${t('content.verifyPdfSignature')}`
  button.style.cssText = `
    all: initial;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    margin: 8px 0;
    padding: 4px 12px;
    font-size: 14px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #3b82f6;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    line-height: normal;
    direction: ltr;
    text-decoration: none;
    white-space: nowrap;
    box-sizing: border-box;
  `

  button.addEventListener('click', async () => {
    const src = embed.src || embed.getAttribute('data')
    if (!src) {
      button.innerHTML = `${svgX()} ${t('content.cannotGetPdf')}`
      return
    }

    button.dataset.pdfVerifierState = 'busy'
    button.innerHTML = `${svgLoading()} ${t('content.verifying')}`
    button.disabled = true

    try {
      const result = await verifyPdfFromUrl(src, getFileName(src))

      if (!result || result.error) {
        button.innerHTML = `${svgX()} ${t('content.failed')}`
      } else {
        updateButtonWithResult(button, result.result as VerifyResult)
        try { await showPanel(result.result, sourceFor(src)) } catch { /* panel display is optional */ }
      }
    } catch {
      button.innerHTML = `${svgX()} ${t('content.error')}`
      button.dataset.pdfVerifierState = 'error'
    }

    button.disabled = false
  })

  return button
}

function getPdfViewerToolbarHeight(): number {
  // Chrome's PDF viewer embed element sits below the toolbar;
  // its top offset reveals the actual toolbar height.
  const embed = document.querySelector('embed[type="application/pdf"]')
  if (embed) {
    const top = embed.getBoundingClientRect().top
    if (top > 0) return top
  }

  // Firefox / other viewers: look for common toolbar containers
  for (const sel of ['#toolbarContainer', '#toolbarViewer', '[role="toolbar"]']) {
    const el = document.querySelector(sel)
    if (el) {
      const h = el.getBoundingClientRect().height
      if (h > 0) return h
    }
  }

  // Fallback: typical Chrome PDF viewer toolbar height
  return 44
}

function injectPdfViewerButton() {
  // Only inject once
  if (document.getElementById('pdf-verifier-notification-bar')) {
    return
  }

  const toolbarHeight = getPdfViewerToolbarHeight()

  // Create notification bar container
  const bar = document.createElement('div')
  bar.id = 'pdf-verifier-notification-bar'
  bar.style.cssText = `
    position: fixed;
    top: ${toolbarHeight}px;
    left: 0;
    right: 0;
    z-index: 999999;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 6px 16px;
    background: #eff6ff;
    border-bottom: 1px solid #bfdbfe;
    box-shadow: 0 1px 4px rgba(0,0,0,0.08);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  `

  // Left section: icon + text
  const info = document.createElement('span')
  info.style.cssText = `
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 13px;
    color: #1e40af;
  `
  info.id = 'pdf-verifier-bar-info'
  info.innerHTML = `${svgDoc()} ${t('content.pdfDetected')}`

  // Right section: verify button + close button
  const actions = document.createElement('div')
  actions.style.cssText = `
    display: flex;
    align-items: center;
    gap: 8px;
  `

  // Verify button
  const button = document.createElement('button')
  button.id = 'pdf-verifier-floating-button'
  button.dataset.pdfVerifierState = 'idle'
  button.dataset.pdfVerifierLabel = 'content.verifySignature'
  button.innerHTML = `${svgSearch()} ${t('content.verifySignature')}`
  button.style.cssText = `
    all: initial;
    padding: 4px 14px;
    font-size: 13px;
    line-height: 20px;
    background: #3b82f6;
    color: white;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    direction: ltr;
    text-decoration: none;
    white-space: nowrap;
    box-sizing: border-box;
  `
  button.addEventListener('mouseenter', () => { button.style.background = '#2563eb' })
  button.addEventListener('mouseleave', () => {
    if (button.dataset.pdfVerifierState === 'idle') button.style.background = '#3b82f6'
  })

  button.addEventListener('click', async () => {
    const pdfUrl = window.location.href

    // Already verified (e.g. automatically): show that result instead of verifying again
    if (viewerResult && hasSignatures(viewerResult)) {
      try { await showPanel(viewerResult, viewerSource) } catch { /* panel display is optional */ }
      return
    }

    if (!isRemoteUrl(pdfUrl) && button.dataset.pdfVerifierState === 'error') {
      // Local file the background could not read: the user picks it
      let picked: { bytes: Uint8Array; fileName: string }
      try {
        picked = await pickAndReadLocalPdf()
      } catch {
        return // cancelled
      }
      await runViewerVerification(button, false, () => verifyBytesInBackground(picked.bytes, picked.fileName), null)
      return
    }
    await runViewerVerification(button, false)
  })

  // Close/dismiss button
  const closeBtn = document.createElement('button')
  closeBtn.title = t('content.dismiss')
  closeBtn.innerHTML = svgClose()
  closeBtn.style.cssText = `
    padding: 2px;
    background: none;
    border: none;
    cursor: pointer;
    color: #6b7280;
    display: inline-flex;
    align-items: center;
    border-radius: 4px;
  `
  closeBtn.addEventListener('mouseenter', () => { closeBtn.style.color = '#1f2937' })
  closeBtn.addEventListener('mouseleave', () => { closeBtn.style.color = '#6b7280' })
  closeBtn.addEventListener('click', () => { bar.remove() })

  actions.appendChild(button)
  actions.appendChild(closeBtn)
  bar.appendChild(info)
  bar.appendChild(actions)
  document.body.appendChild(bar)

  // Drop zone: a downloaded / local PDF dropped on the bar is verified right here
  let dragDepth = 0
  let infoBeforeDrag = ''
  const carriesFiles = (event: DragEvent) => Array.from(event.dataTransfer?.types ?? []).includes('Files')
  const setDropActive = (active: boolean) => {
    if (active && !infoBeforeDrag) {
      infoBeforeDrag = info.innerHTML
      info.innerHTML = `${svgDoc()} ${t('content.dropHere')}`
    } else if (!active && infoBeforeDrag) {
      info.innerHTML = infoBeforeDrag
      infoBeforeDrag = ''
    }
    bar.style.background = active ? '#dbeafe' : '#eff6ff'
    bar.style.outline = active ? '2px dashed #3b82f6' : ''
  }
  bar.addEventListener('dragenter', (event) => {
    if (!carriesFiles(event)) return
    event.preventDefault()
    dragDepth++
    setDropActive(true)
  })
  bar.addEventListener('dragover', (event) => {
    if (!carriesFiles(event)) return
    event.preventDefault()
    if (event.dataTransfer) event.dataTransfer.dropEffect = 'copy'
  })
  bar.addEventListener('dragleave', () => {
    dragDepth = Math.max(0, dragDepth - 1)
    if (dragDepth === 0) setDropActive(false)
  })
  bar.addEventListener('drop', (event) => {
    event.preventDefault()
    dragDepth = 0
    setDropActive(false)
    const file = event.dataTransfer?.files?.[0]
    if (!file) return
    void runViewerVerification(button, false, async () => {
      const bytes = new Uint8Array(await file.arrayBuffer())
      return verifyBytesInBackground(bytes, file.name)
    }, null)
  })

  if (isFetchableByBackground(window.location.href)) {
    void isAutoVerifyEnabled().then((enabled) => {
      if (enabled) void runViewerVerification(button, true)
    })
  } else {
    info.innerHTML = `${svgDoc()} ${t('content.pdfDetected')} — ${t('content.localFileHint')}`
  }
}

async function isAutoVerifyEnabled(): Promise<boolean> {
  try {
    const stored = await chrome.storage.local.get('pdf-verifier-settings')
    return shouldAutoVerify(stored['pdf-verifier-settings'], window.location.hostname)
  } catch {
    return true
  }
}

function hasSignatures(result: unknown): boolean {
  const signatures = (result as VerifyResult | null)?.signatures
  return Array.isArray(signatures) && signatures.length > 0
}

/**
 * Verify for the viewer bar: by default the PDF shown in the viewer, or a
 * picked / dropped file (`task`, no re-fetchable source). Automatic runs open
 * the side panel only where it can be embedded (Chrome); other browsers would
 * need a pop-up window, which the user opens by clicking the result button.
 */
async function runViewerVerification(
  button: HTMLButtonElement,
  auto: boolean,
  task?: () => Promise<VerifyResponse>,
  taskSource: PanelSource | null = null
): Promise<void> {
  if (viewerBusy) return
  viewerBusy = true
  button.dataset.pdfVerifierState = 'busy'
  button.innerHTML = `${svgLoading()} ${t('content.verifying')}`
  button.style.background = '#3b82f6'
  button.disabled = true
  reportTabState('busy')

  try {
    const pdfUrl = window.location.href
    const source = task ? taskSource : sourceFor(pdfUrl)
    const response = task ? await task() : await verifyPdfFromUrl(pdfUrl, getFileName(pdfUrl))

    if (!response || response.error) {
      button.innerHTML = `${svgX()} ${t('content.cannotGetPdf')}`
      button.dataset.pdfVerifierState = 'error'
      if (task) {
        button.title = response?.error ?? t('content.noResponse')
      } else {
        // The document is fetched again; single-use or expired links fail here.
        button.title = response?.error ? `${t('content.cannotFetchPdf')} (${response.error})` : t('content.cannotFetchPdf')
        setBarHint(isRemoteUrl(window.location.href) ? t('content.dropHint') : t('content.localFileHint'))
      }
      reportTabState('error')
      return
    }

    viewerResult = response.result
    viewerSource = source
    if (!hasSignatures(response.result)) {
      button.dataset.pdfVerifierState = 'none'
      button.innerHTML = `${svgDoc()} ${t('content.noSignatures')}`
      button.style.background = '#64748b'
      button.title = t('content.noSignatures')
      reportTabState('none')
      return
    }

    updateButtonWithResult(button, response.result as VerifyResult)
    reportTabState(button.dataset.pdfVerifierState ?? 'unknown', response.result, source)
    if (!auto || canEmbedPanel()) {
      try { await showPanel(response.result, source, auto) } catch { /* panel display is optional */ }
    } else {
      button.title = `${button.title} | ${t('content.viewResult')}`
    }
  } catch (error) {
    button.innerHTML = `${svgX()} ${t('content.error')}`
    button.dataset.pdfVerifierState = 'error'
    button.title = error instanceof Error ? error.message : t('content.unknownError')
    reportTabState('error')
  } finally {
    viewerBusy = false
    button.disabled = false
  }
}

function setBarHint(text: string): void {
  const info = document.getElementById('pdf-verifier-bar-info')
  if (info) info.innerHTML = `${svgDoc()} ${t('content.pdfDetected')} — ${text}`
}

// ─── Toast (context-menu progress / errors) ─────────────────────

let toastTimer: ReturnType<typeof setTimeout> | undefined

function showToast(text: string, isError: boolean): void {
  let toast = document.getElementById('pdf-verifier-toast')
  if (!toast) {
    toast = document.createElement('div')
    toast.id = 'pdf-verifier-toast'
    toast.style.cssText = `
      position: fixed; top: 16px; right: 16px; z-index: 2147483647;
      max-width: 360px; padding: 10px 14px; border-radius: 8px;
      font: 13px/1.4 -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      color: white; box-shadow: 0 4px 16px rgba(0,0,0,0.2);
    `
    document.body.appendChild(toast)
  }
  toast.textContent = text
  toast.style.background = isError ? '#dc2626' : '#1e40af'
  clearTimeout(toastTimer)
  if (isError) toastTimer = setTimeout(hideToast, 6000)
}

function hideToast(): void {
  clearTimeout(toastTimer)
  document.getElementById('pdf-verifier-toast')?.remove()
}

/** "Re-check" from the side panel: verify the same source again and refresh the panel. */
async function recheckFromPanel(): Promise<void> {
  const iframe = panelIframe
  const source = panelSource
  if (!iframe || !source) {
    iframe?.contentWindow?.postMessage({ type: 'pdf-verification-error', error: t('content.noResponse') }, '*')
    return
  }
  let response: { result?: unknown; error?: string }
  try {
    response = await verifyPdfFromUrl(source.url, source.fileName, true)
  } catch (error) {
    response = { error: error instanceof Error ? error.message : t('content.unknownError') }
  }
  if (response.result) {
    pendingResult = response.result
    if (source.url === window.location.href) {
      viewerResult = response.result
      viewerSource = source
      const viewerButton = document.getElementById('pdf-verifier-floating-button') as HTMLButtonElement | null
      if (viewerButton && hasSignatures(response.result)) {
        updateButtonWithResult(viewerButton, response.result as VerifyResult)
        reportTabState(viewerButton.dataset.pdfVerifierState ?? 'unknown', response.result, source)
      }
    }
    iframe.contentWindow?.postMessage({ type: 'pdf-verification-result', result: response.result, canRecheck: true }, '*')
  } else {
    iframe.contentWindow?.postMessage({ type: 'pdf-verification-error', error: response.error ?? t('content.noResponse') }, '*')
  }
}

// ─── Result Display Helpers ─────────────────────────────────────

interface VerifyResult {
  status: string
  summary: string
  signatures?: Array<{
    signerName: string
    certificateChain?: Array<{ subject: string; isRoot: boolean }>
  }>
}

function updateButtonWithResult(
  button: HTMLButtonElement,
  result: VerifyResult
) {
  const status = result?.status
  button.dataset.pdfVerifierState = status === 'trusted' || status === 'failed' ? status : 'unknown'
  if (status === 'trusted') {
    button.innerHTML = `${svgCheck()} ${t('content.trusted')}`
    button.style.background = '#22c55e'
  } else if (status === 'failed') {
    button.innerHTML = `${svgX()} ${t('content.failed')}`
    button.style.background = '#ef4444'
  } else {
    button.innerHTML = `${svgWarning()} ${t('content.unknown')}`
    button.style.background = '#eab308'
  }

  button.title = buildTooltip(result)
}

function buildTooltip(result: VerifyResult): string {
  const signatures = result?.signatures
  if (!signatures || signatures.length === 0) {
    return result?.summary || ''
  }

  const parts: string[] = []

  const signerNames = signatures.map((s) => s.signerName).filter(Boolean)
  if (signerNames.length > 0) {
    parts.push(t('content.signerLabel', { names: signerNames.join(', ') }))
  }

  const rootCAs = new Set<string>()
  for (const sig of signatures) {
    const rootCert = sig.certificateChain?.find((c) => c.isRoot)
    if (rootCert) {
      const cn = rootCert.subject.match(/CN=([^,]+)/)?.[1]
      if (cn) rootCAs.add(cn)
    }
  }
  if (rootCAs.size > 0) {
    parts.push(t('content.rootCaLabel', { names: [...rootCAs].join(', ') }))
  }

  const statusText =
    result.status === 'trusted'
      ? t('content.allValid')
      : result.status === 'failed'
        ? t('content.failed')
        : t('content.unknown')
  parts.push(t('content.signatureCount', { count: signatures.length, status: statusText }))

  return parts.join(' | ')
}

// ─── Inline SVG Helpers (content script, no React) ──────────────

function svgCheck(): string {
  return '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;flex-shrink:0;"><path d="M3 8.5l3.5 3.5L13 4"/></svg>'
}

function svgX(): string {
  return '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;flex-shrink:0;"><path d="M4 4l8 8M12 4l-8 8"/></svg>'
}

function svgWarning(): string {
  return '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;flex-shrink:0;"><path d="M8 1.5L1 14h14L8 1.5z"/><path d="M8 6v3.5"/><circle cx="8" cy="12" r="0.5" fill="currentColor" stroke="none"/></svg>'
}

function svgSearch(): string {
  return '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;flex-shrink:0;"><circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5L14 14"/></svg>'
}

function svgDoc(): string {
  return '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;flex-shrink:0;"><path d="M9 1.5H4a1.5 1.5 0 00-1.5 1.5v10A1.5 1.5 0 004 14.5h8a1.5 1.5 0 001.5-1.5V6L9 1.5z"/><path d="M9 1.5V6h4.5"/></svg>'
}

function svgClose(): string {
  return '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;flex-shrink:0;"><path d="M4 4l8 8M12 4l-8 8"/></svg>'
}

function svgLoading(): string {
  return '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" style="vertical-align:middle;flex-shrink:0;animation:pdf-verifier-spin 1s linear infinite;"><style>@keyframes pdf-verifier-spin{to{transform:rotate(360deg)}}</style><path d="M8 1.5a6.5 6.5 0 11-6.5 6.5" stroke-linecap="round"/></svg>'
}

function getFileName(url: string): string {
  try {
    const pathname = new URL(url).pathname
    const encoded = pathname.split('/').pop() || 'document.pdf'
    return decodeURIComponent(encoded)
  } catch {
    return 'document.pdf'
  }
}
