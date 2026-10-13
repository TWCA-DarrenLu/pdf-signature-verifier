/**
 * Shared network helper.
 *
 * In MV3, the background service worker can fetch() cross-origin without
 * host_permissions. OCSP/CRL requests are made from the background context.
 *
 * Audit P3-10: every outbound request has a timeout (AbortController) and
 * is retried with exponential backoff. The service worker may be reaped
 * mid-fetch, so we keep retries bounded and the timeout tight.
 */

const DEFAULT_TIMEOUT_MS = 10_000
const MAX_RETRIES = 2
const BACKOFF_BASE_MS = 500

interface FetchOptions extends RequestInit {
  /** Per-attempt timeout. Default 10s. */
  timeoutMs?: number
  /** Number of retries on transient failure (network error / 5xx). Default 2. */
  retries?: number
}

async function fetchWithTimeout(url: string, opts: FetchOptions): Promise<Response> {
  const { timeoutMs = DEFAULT_TIMEOUT_MS, ...init } = opts
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    return await fetch(url, { ...init, signal: ctrl.signal })
  } finally {
    clearTimeout(timer)
  }
}

function isRetryable(status: number): boolean {
  // 408 request timeout, 425 too early, 429 too many requests, 5xx server errors
  return status === 408 || status === 425 || status === 429 || (status >= 500 && status <= 599)
}

async function fetchBytesWithRetry(url: string, opts: FetchOptions = {}): Promise<Uint8Array | null> {
  const retries = opts.retries ?? MAX_RETRIES
  let lastErr: unknown
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetchWithTimeout(url, opts)
      if (!res.ok) {
        if (isRetryable(res.status) && attempt < retries) {
          await delay(BACKOFF_BASE_MS * Math.pow(2, attempt))
          continue
        }
        return null
      }
      const buf = await res.arrayBuffer()
      return new Uint8Array(buf)
    } catch (err) {
      lastErr = err
      // AbortError = timeout
      const transient = err instanceof Error && (err.name === 'AbortError' || err.name === 'TypeError')
      if (transient && attempt < retries) {
        await delay(BACKOFF_BASE_MS * Math.pow(2, attempt))
        continue
      }
      return null
    }
  }
  void lastErr
  return null
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/**
 * Fetch arbitrary binary data (CRL, certificate, etc.)
 */
export async function fetchBinary(url: string): Promise<Uint8Array | null> {
  return fetchBytesWithRetry(url)
}

const certificateCache = new Map<string, Uint8Array>()
const MAX_CACHED_CERTIFICATES = 100

/**
 * Fetch a certificate by URL (AIA caIssuers). Successful downloads are kept in
 * memory: issuer certificates are static and paths may be built more than once.
 */
export async function fetchCertificateBytes(url: string): Promise<Uint8Array | null> {
  const cached = certificateCache.get(url)
  if (cached) return cached
  const bytes = await fetchBytesWithRetry(url)
  if (bytes) {
    if (certificateCache.size >= MAX_CACHED_CERTIFICATES) {
      certificateCache.delete(certificateCache.keys().next().value as string)
    }
    certificateCache.set(url, bytes)
  }
  return bytes
}

/**
 * Send an OCSP request and return the raw response bytes.
 */
export async function fetchOcspResponse(
  url: string,
  requestBytes: Uint8Array
): Promise<Uint8Array | null> {
  return fetchBytesWithRetry(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/ocsp-request' },
    body: requestBytes as unknown as BodyInit,
  })
}
