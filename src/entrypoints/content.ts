import { t, setLocale, detectBrowserLocale } from '@/i18n'
import type { Locale } from '@/i18n'

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
    initLocale()

    // Detect PDF files in the page
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

    // Listen for panel messages
    window.addEventListener('message', (event) => {
      if (event.data?.type === 'pdf-panel-close') {
        closePanel()
      }
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
let pendingResult: unknown = null

function isChromeBrowser(): boolean {
  // Chrome: has "Chrome/" but NOT "Edg/" (Edge) and NOT "brave" in navigator
  return /\bChrome\//i.test(navigator.userAgent)
    && !/\bEdg\//i.test(navigator.userAgent)
    && !('brave' in navigator)
}

async function showPanel(result: unknown) {
  // Only Chrome reliably supports extension iframes in content scripts.
  // Edge, Brave, and other Chromium forks block them.
  if (!isChromeBrowser()) {
    await openPanelAsPopup(result)
    return
  }

  // Close existing panel if open
  closePanel()

  pendingResult = result

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
  iframe.src = chrome.runtime.getURL('/panel.html')
  iframe.style.cssText = `
    width: 100%;
    height: 100%;
    border: none;
  `

  // Listen for panel ready signal BEFORE iframe loads to avoid race condition
  const handlePanelReady = (event: MessageEvent) => {
    if (event.data?.type === 'pdf-panel-ready') {
      clearTimeout(fallbackTimer)
      iframe.contentWindow?.postMessage(
        { type: 'pdf-verification-result', result: pendingResult },
        '*'
      )
      window.removeEventListener('message', handlePanelReady)
    }
  }
  window.addEventListener('message', handlePanelReady)

  // Fallback: if iframe fails to load, open as popup window
  const fallbackTimer = setTimeout(() => {
    window.removeEventListener('message', handlePanelReady)
    closePanel()
    openPanelAsPopup(result)
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

async function openPanelAsPopup(result: unknown) {
  // Store result directly in storage (avoids large data serialization through messaging)
  await chrome.storage.local.set({ 'pdf-panel-result': result })
  // Send lightweight message to background to open the panel window
  chrome.runtime.sendMessage({ action: 'open-panel-window' }, () => {
    void chrome.runtime.lastError // suppress console warning
  })
}

function closePanel() {
  if (panelContainer) {
    panelContainer.style.transform = 'translateX(100%)'
    const container = panelContainer
    setTimeout(() => {
      container.remove()
    }, 250)
    panelContainer = null
  }
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
  fileName: string
): Promise<{ result?: unknown; error?: string }> {
  if (isRemoteUrl(url)) {
    return sendMessageWithTimeout<{ result?: unknown; error?: string }>({
      action: 'verify-pdf-url',
      url,
      fileName,
    })
  }
  // Local file — must use FileReader (XHR/fetch blocked by same-origin on file://)
  try {
    const picked = await pickAndReadLocalPdf()
    const { verifyPdfSignatures } = await import('@/core/verifier')
    const result = await verifyPdfSignatures(picked.bytes, picked.fileName)
    return { result }
  } catch (error) {
    return { error: error instanceof Error ? error.message : t('content.unknownError') }
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
        try { await showPanel(result.result) } catch { /* panel display is optional */ }
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
        try { await showPanel(result.result) } catch { /* panel display is optional */ }
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

    if (!isRemoteUrl(pdfUrl)) {
      // Local file — open the extension popup (same as clicking the icon)
      chrome.runtime.sendMessage({ action: 'open-popup' }, () => {
        void chrome.runtime.lastError
      })
      return
    }

    button.dataset.pdfVerifierState = 'busy'
    button.innerHTML = `${svgLoading()} ${t('content.verifying')}`
    button.disabled = true

    try {
      const fileName = getFileName(pdfUrl)
      const result = await verifyPdfFromUrl(pdfUrl, fileName)

      if (!result || result.error) {
        button.innerHTML = `${svgX()} ${t('content.failed')}`
        button.dataset.pdfVerifierState = 'error'
        button.title = result?.error || t('content.noResponse')
      } else {
        updateButtonWithResult(button, result.result as VerifyResult)
        try { await showPanel(result.result) } catch { /* panel display is optional */ }
      }
    } catch (error) {
      button.innerHTML = `${svgX()} ${t('content.error')}`
      button.dataset.pdfVerifierState = 'error'
      button.title = error instanceof Error ? error.message : t('content.unknownError')
    }

    button.disabled = false
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
