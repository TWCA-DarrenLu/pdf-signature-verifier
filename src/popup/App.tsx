import { useState, useEffect } from 'react'
import { StatusBadge, SignatureList, DropZone, LoadingSpinner, ExportButton } from './components'
import { useVerification } from './hooks/useVerification'
import { useSettings } from './hooks/useSettings'
import { DocumentIcon, XIcon } from './components/icons'
import { t, setLocale, detectBrowserLocale, resolveSummary } from '@/i18n'
import { parseSiteList, type AutoVerifyScope } from '@/settings/auto-verify'
import { getInternationalVendors } from '@/trust-store/international-roots'
import type { VerificationResult } from '@/types'
import { restoreDates } from './restore-dates'

/** Result the page reported for a tab (shown by the toolbar badge). */
interface TabEntry {
  tabId: number
  result: VerificationResult
  source: { url: string; fileName: string } | null
}

const isFirefox = /Firefox\//i.test(navigator.userAgent)
const isTabMode = typeof window !== 'undefined' && window.location.search.includes('source=tab')

function getQueryParam(name: string): string | null {
  try {
    return new URLSearchParams(window.location.search).get(name)
  } catch {
    return null
  }
}

export function App() {
  const { result, isLoading, error, verify, reset } = useVerification()
  const { settings, updateSettings, isLoading: settingsLoading } = useSettings()
  const [showSettings, setShowSettings] = useState(false)
  const [, forceUpdate] = useState(0)
  const [pdfTabUrl, setPdfTabUrl] = useState<string | null>(getQueryParam('pdfUrl'))
  const [verifyingPdfTab, setVerifyingPdfTab] = useState(false)
  const [lastFile, setLastFile] = useState<File | null>(null)
  const [tabEntry, setTabEntry] = useState<TabEntry | null>(null)
  const [rechecking, setRechecking] = useState(false)
  const [recheckError, setRecheckError] = useState<string | null>(null)
  const [sitesText, setSitesText] = useState('')
  const [fileAccessMissing, setFileAccessMissing] = useState(false)

  // Local PDF tab: without "Allow access to file URLs" nothing can read it
  useEffect(() => {
    if (!pdfTabUrl?.startsWith('file:')) return
    chrome.extension?.isAllowedFileSchemeAccess?.()
      .then((allowed) => setFileAccessMissing(!allowed))
      .catch(() => {})
  }, [pdfTabUrl])

  // fill the editor once the stored settings are loaded; afterwards it keeps what is typed
  useEffect(() => {
    if (!settingsLoading) setSitesText(settings.autoVerifySites.join('\n'))
  }, [settingsLoading])

  // Show what the badge shows: the result verified for the active tab — also
  // when it arrives while the popup is open (badge still "…")
  useEffect(() => {
    if (isTabMode || isFirefox) return
    let listener: ((changes: Record<string, chrome.storage.StorageChange>, area: string) => void) | null = null
    let closed = false
    const show = (tabId: number, entry: { result?: VerificationResult; source?: TabEntry['source'] } | undefined) => {
      if (entry?.result) setTabEntry({ tabId, result: restoreDates(entry.result), source: entry.source ?? null })
    }
    try {
      chrome.tabs?.query?.({ active: true, currentWindow: true }, (tabs) => {
        const tabId = tabs?.[0]?.id
        if (closed || tabId === undefined || !chrome.storage?.session) return
        const key = `tab-result:${tabId}`
        chrome.storage.session.get(key).then((stored) => show(tabId, stored[key])).catch(() => {})
        listener = (changes, area) => {
          if (area === 'session' && changes[key]) show(tabId, changes[key].newValue)
        }
        chrome.storage.onChanged.addListener(listener)
      })
    } catch { /* ignore */ }
    return () => {
      closed = true
      if (listener) chrome.storage.onChanged.removeListener(listener)
    }
  }, [])

  useEffect(() => {
    if (settings.language) {
      setLocale(settings.language)
    } else {
      const detected = detectBrowserLocale()
      setLocale(detected)
      updateSettings({ language: detected })
    }
    forceUpdate(n => n + 1)
  }, [settings.language])

  // Firefox: popup can't handle file picker or drag-drop, so immediately
  // open a dedicated window and close the popup.
  useEffect(() => {
    if (!isFirefox || isTabMode) return

    // Use callback style for maximum Firefox MV2 compatibility
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs?.[0]
      let windowUrl = '/popup.html?source=tab'

      if (tab?.url) {
        try {
          const pathname = new URL(tab.url).pathname.toLowerCase()
          if (pathname.endsWith('.pdf')) {
            windowUrl += '&pdfUrl=' + encodeURIComponent(tab.url)
          }
        } catch { /* ignore */ }
      }

      // Position near top-right corner
      const screenW = window.screen.availWidth
      const left = Math.max(0, screenW - 470)
      const top = 80

      chrome.windows.create({
        url: chrome.runtime.getURL(windowUrl),
        type: 'popup',
        width: 460,
        height: 500,
        left,
        top,
      }, () => {
        window.close()
      })
    })
  }, [])

  // Chrome: detect if current tab is a PDF for the popup
  useEffect(() => {
    if (isTabMode || isFirefox) return
    try {
      chrome.tabs?.query?.({ active: true, currentWindow: true }, (tabs) => {
        const tab = tabs?.[0]
        if (tab?.url) {
          try {
            const pathname = new URL(tab.url).pathname.toLowerCase()
            if (pathname.endsWith('.pdf')) {
              setPdfTabUrl(tab.url)
            }
          } catch { /* ignore */ }
        }
      })
    } catch { /* ignore */ }
  }, [])

  const handleVerifyCurrentPdf = async () => {
    if (!pdfTabUrl) return
    setVerifyingPdfTab(true)

    try {
      const fileName = decodeURIComponent(
        new URL(pdfTabUrl).pathname.split('/').pop() || 'document.pdf'
      )

      // Fetch PDF directly in popup context, then reuse the same verify flow as DropZone
      const response = await fetch(pdfTabUrl)
      if (!response.ok) {
        setVerifyingPdfTab(false)
        return
      }
      const buffer = await response.arrayBuffer()
      const file = new File([buffer], fileName, { type: 'application/pdf' })
      setVerifyingPdfTab(false)
      await handleFileSelect(file)
    } catch {
      setVerifyingPdfTab(false)
    }
  }

  const handleFileSelect = async (file: File, fresh = false) => {
    setLastFile(file)
    setTabEntry(null)
    await verify(file, {
      checkOnlineRevocation: true,
      refreshRevocation: fresh,
      trustInternational: settings.trustInternational,
    })
  }

  /** Re-check the active tab's PDF: fetch it again, ask OCSP/CRL again, update the badge. */
  const handleRecheckTab = async () => {
    const entry = tabEntry
    if (!entry?.source || rechecking) return
    setRechecking(true)
    setRecheckError(null)
    try {
      const response = (await chrome.runtime.sendMessage({
        action: 'verify-pdf-url',
        url: entry.source.url,
        fileName: entry.source.fileName,
        fresh: true,
      })) as { result?: VerificationResult; error?: string } | undefined
      if (!response?.result) {
        setRecheckError(response?.error ?? t('verification.noResult'))
        return
      }
      const fresh = response.result
      const state = fresh.signatures.length === 0 ? 'none' : fresh.status
      await chrome.runtime.sendMessage({ action: 'tab-state', tabId: entry.tabId, state, result: fresh, source: entry.source })
      setTabEntry({ ...entry, result: restoreDates(fresh) })
    } catch (err) {
      setRecheckError(err instanceof Error ? err.message : String(err))
    } finally {
      setRechecking(false)
    }
  }

  const shown = result ?? tabEntry?.result ?? null
  const canRecheck = result ? lastFile !== null : Boolean(tabEntry?.source)


  return (
    <div className={`${isTabMode ? 'max-w-[500px] mx-auto' : 'w-[400px]'} min-h-[300px] bg-white`}>
      {/* Header */}
      <header className="flex items-center justify-between px-4 py-3 border-b border-gray-200">
        <h1 className="text-lg font-semibold text-gray-900">{t('app.title')}</h1>
        <div className="flex items-center gap-2">
          <a
            href="mailto:business@darrenlu.com"
            className="inline-flex items-center gap-1 px-2 py-1 text-xs text-gray-500 bg-gray-100 rounded-md hover:bg-gray-200 transition-colors"
            title={t('app.businessContact')}
          >
            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
            business@darrenlu.com
          </a>
          <button
            onClick={() => setShowSettings(!showSettings)}
            className="p-1.5 rounded-md hover:bg-gray-100 transition-colors"
            title={t('settings.title')}
          >
            <svg className="w-5 h-5 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
          </button>
        </div>
      </header>

      {/* Settings Panel */}
      {showSettings && (
        <div className="px-4 py-3 border-b border-gray-200 bg-gray-50">
          <div className="space-y-3">
            <div className="space-y-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm text-gray-700">{t('settings.autoVerify')}</span>
                <select
                  value={settings.autoVerifyScope}
                  onChange={(e) => updateSettings({ autoVerifyScope: e.target.value as AutoVerifyScope })}
                  data-testid="auto-verify-scope"
                  className="text-sm border border-gray-300 rounded px-2 py-1"
                >
                  <option value="all">{t('settings.scopeAll')}</option>
                  <option value="listed">{t('settings.scopeListed')}</option>
                  <option value="off">{t('settings.scopeOff')}</option>
                </select>
              </div>
              {settings.autoVerifyScope === 'listed' && (
                <textarea
                  value={sitesText}
                  onChange={(e) => {
                    setSitesText(e.target.value)
                    void updateSettings({ autoVerifySites: parseSiteList(e.target.value) })
                  }}
                  placeholder={t('settings.sitesPlaceholder')}
                  rows={3}
                  data-testid="auto-verify-sites"
                  className="w-full text-sm border border-gray-300 rounded px-2 py-1 font-mono"
                />
              )}
            </div>
            {getInternationalVendors().length > 0 && (
              <label className="flex items-start gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={settings.trustInternational}
                  onChange={(e) => updateSettings({ trustInternational: e.target.checked })}
                  data-testid="trust-international"
                  className="mt-0.5 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="text-sm text-gray-700">
                  {t('settings.trustInternational')}
                  <span className="block text-xs text-gray-500">
                    {t('settings.trustInternationalHint', { vendors: getInternationalVendors().join('、') })}
                  </span>
                </span>
              </label>
            )}
            <div className="flex items-center gap-2">
              <span className="text-sm text-gray-700">{t('settings.language')}</span>
              <select
                value={settings.language}
                onChange={(e) => {
                  const lang = e.target.value as 'zh-TW' | 'en'
                  updateSettings({ language: lang })
                  setLocale(lang)
                }}
                className="text-sm border border-gray-300 rounded px-2 py-1"
              >
                <option value="zh-TW">{t('settings.langZhTW')}</option>
                <option value="en">{t('settings.langEn')}</option>
              </select>
            </div>
          </div>
        </div>
      )}

      {/* Main Content */}
      <main className="p-4">
        {isLoading || verifyingPdfTab ? (
          <LoadingSpinner />
        ) : error ? (
          <div className="text-center py-6">
            <div className="flex justify-center mb-2">
              <XIcon className="w-10 h-10 text-red-500" />
            </div>
            <div className="text-red-600 font-medium mb-1">{t('verification.errorTitle')}</div>
            <div className="text-sm text-gray-500">{error}</div>
            <button
              onClick={reset}
              className="mt-4 px-4 py-2 bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200 transition-colors text-sm"
            >
              {t('verification.retryButton')}
            </button>
          </div>
        ) : shown ? (
          <div className="space-y-4">
            {!result && tabEntry && (
              <div className="text-xs text-gray-500">{t('popup.currentTabResult')}</div>
            )}
            {/* File Info */}
            <div className="flex items-center gap-3">
              <DocumentIcon className="w-6 h-6 text-gray-500 flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="font-medium text-gray-900 truncate">{shown.fileName}</div>
              </div>
            </div>

            {/* Status Summary */}
            <div className="p-4 rounded-lg bg-gray-50 border border-gray-200">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <StatusBadge status={shown.status} size="lg" />
                <div className="flex items-center gap-3 whitespace-nowrap">
                  {canRecheck && (
                    <button
                      onClick={() => (result && lastFile ? handleFileSelect(lastFile, true) : handleRecheckTab())}
                      disabled={rechecking}
                      title={t('verification.recheckHint')}
                      className="text-sm text-gray-600 hover:text-gray-800 disabled:opacity-60"
                    >
                      {rechecking ? t('verification.loading') : t('verification.recheck')}
                    </button>
                  )}
                  <ExportButton result={shown} />
                  <button
                    onClick={() => { reset(); setTabEntry(null) }}
                    className="text-sm text-blue-600 hover:text-blue-700"
                  >
                    {t('verification.verifyOther')}
                  </button>
                </div>
              </div>
              <div className="mt-2 text-sm text-gray-600">{resolveSummary(shown)}</div>
              {recheckError && <div className="mt-1 text-xs text-red-600">{recheckError}</div>}
            </div>

            {/* Signature List */}
            <SignatureList signatures={shown.signatures} />
          </div>
        ) : (
          <div className="space-y-4">
            {/* PDF tab detected — show verify button */}
            {pdfTabUrl && (
              <div className="p-3 rounded-lg bg-blue-50 border border-blue-200">
                <div className="text-sm text-blue-800 mb-2 flex items-center gap-2">
                  <DocumentIcon className="w-4 h-4 flex-shrink-0" />
                  {t('content.pdfDetected')}
                </div>
                {fileAccessMissing ? (
                  <div className="space-y-2">
                    <div className="text-xs text-blue-900">{t('popup.fileAccessHint')}</div>
                    <button
                      onClick={() => chrome.tabs.create({
                        url: `${/\bEdg\//.test(navigator.userAgent) ? 'edge' : 'chrome'}://extensions/?id=${chrome.runtime.id}`,
                      })}
                      className="w-full px-3 py-2 bg-white border border-blue-300 text-blue-700 text-sm rounded-md hover:bg-blue-100 transition-colors"
                    >
                      {t('popup.openExtensionSettings')}
                    </button>
                  </div>
                ) : (
                  <button
                    onClick={handleVerifyCurrentPdf}
                    className="w-full px-3 py-2 bg-blue-500 text-white text-sm rounded-md hover:bg-blue-600 transition-colors"
                  >
                    {t('content.verifySignature')}
                  </button>
                )}
              </div>
            )}

            <DropZone onFileSelect={handleFileSelect} />
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="px-4 py-2 text-center text-xs text-gray-400 border-t border-gray-100 space-y-1">
        <div>{t('app.footerTech')}</div>
        <div>
          <a href="https://www.buymeacoffee.com/darrenlu" target="_blank" rel="noopener noreferrer">
            <img
              src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=darrenlu&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff"
              alt="Buy me a coffee"
              className="inline-block h-7"
            />
          </a>
        </div>
      </footer>
    </div>
  )
}

export default App
