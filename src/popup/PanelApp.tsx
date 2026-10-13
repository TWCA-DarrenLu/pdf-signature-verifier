import { useState, useEffect, useRef } from 'react'
import type { VerificationResult } from '@/types'
import { StatusBadge, SignatureList, ExportButton } from './components'
import { DocumentIcon } from './components/icons'
import { t, setLocale, detectBrowserLocale, resolveSummary } from '@/i18n'
import { restoreDates } from './restore-dates'

export function PanelApp() {
  const [result, setResult] = useState<VerificationResult | null>(null)
  const [loading, setLoading] = useState(true)
  const [rechecking, setRechecking] = useState(false)
  const [recheckError, setRecheckError] = useState<string | null>(null)
  /** Inline mode: the page says whether the result can be fetched again (not for local files). */
  const [inlineCanRecheck, setInlineCanRecheck] = useState(false)
  /** Popup-window mode: why there is no result (right-click verify that failed). */
  const [windowError, setWindowError] = useState<string | null>(null)
  /** Popup-window mode: the remote PDF behind the result, used for re-checking. */
  const sourceRef = useRef<{ url: string; fileName: string } | null>(null)

  useEffect(() => {
    const initLocale = async () => {
      try {
        if (typeof chrome !== 'undefined' && chrome.storage) {
          const stored = await chrome.storage.local.get('pdf-verifier-settings')
          const settings = stored['pdf-verifier-settings']
          if (settings?.language) {
            setLocale(settings.language)
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
  }, [])

  useEffect(() => {
    const isPopupWindow = window.location.search.includes('source=popup')

    if (isPopupWindow) {
      // Opened as popup window — read result from local storage
      chrome.storage.local.get(['pdf-panel-result', 'pdf-panel-source', 'pdf-panel-error']).then((stored: Record<string, unknown>) => {
        const raw = stored['pdf-panel-result'] as VerificationResult | undefined
        if (typeof stored['pdf-panel-error'] === 'string') {
          setWindowError(stored['pdf-panel-error'])
          chrome.storage.local.remove('pdf-panel-error')
        }
        sourceRef.current = (stored['pdf-panel-source'] as { url: string; fileName: string } | null) ?? null
        if (raw) {
          setResult(restoreDates(raw))
          chrome.storage.local.remove(['pdf-panel-result', 'pdf-panel-source'])
        }
        setLoading(false)
      }).catch(() => {
        setLoading(false)
      })
      return
    }

    // Embedded as iframe — listen for verification results from the content script
    const handleMessage = (event: MessageEvent) => {
      if (event.source !== window.parent) return
      if (event.data?.type === 'pdf-verification-result') {
        const raw = event.data.result as VerificationResult
        // Restore Date objects from serialized JSON
        const restored = restoreDates(raw)
        setResult(restored)
        setInlineCanRecheck(event.data.canRecheck === true)
        setLoading(false)
        setRechecking(false)
        setRecheckError(null)
      } else if (event.data?.type === 'pdf-verification-error') {
        setRechecking(false)
        setRecheckError(String(event.data.error ?? ''))
      }
    }

    window.addEventListener('message', handleMessage)

    // Signal that the panel is ready to receive data
    window.parent.postMessage({ type: 'pdf-panel-ready' }, '*')

    // Timeout: stop loading spinner after 15s if no result received
    const timeout = setTimeout(() => {
      setLoading(false)
    }, 15_000)

    return () => {
      window.removeEventListener('message', handleMessage)
      clearTimeout(timeout)
    }
  }, [])

  const isPopupWindow = window.location.search.includes('source=popup')
  // Inline panels re-check through the page; popup windows need the stored source URL
  const canRecheck = isPopupWindow ? sourceRef.current !== null : inlineCanRecheck

  const handleRecheck = async () => {
    if (rechecking) return
    setRechecking(true)
    setRecheckError(null)
    if (!isPopupWindow) {
      window.parent.postMessage({ type: 'pdf-panel-recheck' }, '*')
      return
    }
    const source = sourceRef.current
    if (!source) return
    try {
      const response = (await chrome.runtime.sendMessage({
        action: 'verify-pdf-url',
        url: source.url,
        fileName: source.fileName,
        fresh: true,
      })) as { result?: VerificationResult; error?: string } | undefined
      if (response?.result) {
        setResult(restoreDates(response.result))
      } else {
        setRecheckError(response?.error ?? t('verification.noResult'))
      }
    } catch (error) {
      setRecheckError(error instanceof Error ? error.message : String(error))
    } finally {
      setRechecking(false)
    }
  }

  const handleClose = () => {
    const isPopupWindow = window.location.search.includes('source=popup')
    if (isPopupWindow) {
      window.close()
    } else {
      window.parent.postMessage({ type: 'pdf-panel-close' }, '*')
    }
  }

  if (loading) {
    return (
      <div className="h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full mx-auto mb-3" />
          <div className="text-sm text-gray-500">{t('verification.loadingPanel')}</div>
        </div>
      </div>
    )
  }

  if (!result) {
    return (
      <div className="h-screen flex items-center justify-center">
        <div className="text-center text-gray-500">
          <div className="flex justify-center mb-2">
            <DocumentIcon className="w-10 h-10 text-gray-400" />
          </div>
          <div>{t('verification.noResult')}</div>
          {windowError && <div className="mt-2 text-sm text-red-600">{windowError}</div>}
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-white">
      {/* Header */}
      <header className="sticky top-0 z-10 flex items-center justify-between px-4 py-3 border-b border-gray-200 bg-white">
        <h1 className="text-base font-semibold text-gray-900">{t('panel.title')}</h1>
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
            onClick={handleClose}
            className="p-1 rounded hover:bg-gray-100 transition-colors"
            title={t('panel.close')}
          >
            <svg className="w-5 h-5 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      </header>

      {/* Content */}
      <main className="p-4 space-y-4">
        {/* File Info */}
        <div className="flex items-center gap-3">
          <DocumentIcon className="w-5 h-5 text-gray-500 flex-shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="font-medium text-gray-900 truncate text-sm">{result.fileName}</div>
          </div>
        </div>

        {/* Status Summary */}
        <div className="p-3 rounded-lg bg-gray-50 border border-gray-200">
          <div className="flex items-center justify-between">
            <StatusBadge status={result.status} size="lg" />
            <div className="flex items-center gap-2">
              {canRecheck && (
                <button
                  onClick={handleRecheck}
                  disabled={rechecking}
                  data-testid="panel-recheck"
                  title={t('verification.recheckHint')}
                  className="inline-flex items-center gap-1 px-2 py-1 text-xs text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-60 transition-colors"
                >
                  <svg className={`w-3.5 h-3.5 ${rechecking ? 'animate-spin' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  </svg>
                  {rechecking ? t('verification.loading') : t('verification.recheck')}
                </button>
              )}
              <ExportButton result={result} />
            </div>
          </div>
          <div className="mt-2 text-sm text-gray-600">{resolveSummary(result)}</div>
          {recheckError && <div className="mt-1 text-xs text-red-600">{recheckError}</div>}
        </div>

        {/* Signature List */}
        <SignatureList signatures={result.signatures} />
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
