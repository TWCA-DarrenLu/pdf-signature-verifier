/**
 * The store calls needed to update an extension that is already listed:
 * upload a package and submit it for review. No dependencies (Node 22+).
 *
 * Chrome Web Store API v2 (v1.1 is retired on 2026-10-15)
 *   https://developer.chrome.com/docs/webstore/using-api
 *   https://developer.chrome.com/docs/webstore/service-accounts
 * Microsoft Edge Add-ons API v1.1 (API key + client ID)
 *   https://learn.microsoft.com/microsoft-edge/extensions/update/api/addons-api-reference
 *
 * Errors carry the store's response, never the credentials.
 */
import { createSign } from 'node:crypto'

export const CWS_BASE = 'https://chromewebstore.googleapis.com'
export const EDGE_BASE = 'https://api.addons.microsoftedge.microsoft.com'
const CWS_SCOPE = 'https://www.googleapis.com/auth/chromewebstore'
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'

const POLL_MS = 5_000
const TIMEOUT_MS = 10 * 60_000

export class StoreError extends Error {
  constructor(message, status, body) {
    super(`${message} (HTTP ${status}): ${typeof body === 'string' ? body : JSON.stringify(body)}`)
    this.status = status
    this.body = body
  }
}

const defaults = (opts) => ({
  fetch: opts.fetch ?? globalThis.fetch,
  sleep: opts.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms))),
  pollMs: opts.pollMs ?? POLL_MS,
  timeoutMs: opts.timeoutMs ?? TIMEOUT_MS,
  now: opts.now ?? (() => Date.now()),
})

async function readBody(res) {
  const text = await res.text()
  try {
    return text ? JSON.parse(text) : {}
  } catch {
    return text
  }
}

// ─── Google service account → access token ─────────────────────

/** RS256 JWT for the OAuth 2.0 JWT-bearer grant (exp at most 1 h after iat). */
export function signServiceAccountJwt({ clientEmail, privateKey, scope = CWS_SCOPE, now = Date.now() }) {
  const iat = Math.floor(now / 1000)
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url')
  const unsigned = `${encode({ alg: 'RS256', typ: 'JWT' })}.${encode({
    iss: clientEmail,
    scope,
    aud: GOOGLE_TOKEN_URL,
    iat,
    exp: iat + 3600,
  })}`
  const signature = createSign('RSA-SHA256').update(unsigned).sign(privateKey).toString('base64url')
  return `${unsigned}.${signature}`
}

/** `serviceAccount` is the JSON key file of the service account (client_email, private_key). */
export async function googleAccessToken(serviceAccount, opts = {}) {
  const { fetch, now } = defaults(opts)
  const assertion = signServiceAccountJwt({
    clientEmail: serviceAccount.client_email,
    privateKey: serviceAccount.private_key,
    now: now(),
  })
  const res = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion }).toString(),
  })
  const body = await readBody(res)
  if (!res.ok || !body.access_token) throw new StoreError('Google token request failed', res.status, body)
  return body.access_token
}

// ─── Chrome Web Store ───────────────────────────────────────────

const cwsItem = ({ publisherId, itemId }) => `publishers/${publisherId}/items/${itemId}`

export async function chromeFetchStatus({ token, publisherId, itemId }, opts = {}) {
  const { fetch } = defaults(opts)
  const res = await fetch(`${CWS_BASE}/v2/${cwsItem({ publisherId, itemId })}:fetchStatus`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  const body = await readBody(res)
  if (!res.ok) throw new StoreError('Chrome fetchStatus failed', res.status, body)
  return body
}

/** Upload a new package (its manifest version must be higher than the listed one). */
export async function chromeUpload({ token, publisherId, itemId, zip }, opts = {}) {
  const o = defaults(opts)
  // As in the official example (curl -T): the package is the raw request body.
  const res = await o.fetch(`${CWS_BASE}/upload/v2/${cwsItem({ publisherId, itemId })}:upload`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
    body: zip,
  })
  const body = await readBody(res)
  if (!res.ok) throw new StoreError('Chrome upload failed', res.status, body)

  let state = body.uploadState
  const deadline = o.now() + o.timeoutMs
  // the guide calls it UPLOAD_IN_PROGRESS, the UploadState enum IN_PROGRESS
  while (state === 'IN_PROGRESS' || state === 'UPLOAD_IN_PROGRESS') {
    if (o.now() > deadline) throw new StoreError('Chrome upload still processing after timeout', res.status, body)
    await o.sleep(o.pollMs)
    state = (await chromeFetchStatus({ token, publisherId, itemId }, opts)).lastAsyncUploadState
  }
  if (state !== 'SUCCEEDED') throw new StoreError(`Chrome upload ended in state ${state ?? 'unknown'}`, res.status, body)
  return { crxVersion: body.crxVersion }
}

/**
 * Submit the uploaded package for review. DEFAULT_PUBLISH goes live after
 * approval; STAGED_PUBLISH waits for a manual publish in the dashboard.
 */
export async function chromePublish({ token, publisherId, itemId, publishType = 'DEFAULT_PUBLISH' }, opts = {}) {
  const { fetch } = defaults(opts)
  const res = await fetch(`${CWS_BASE}/v2/${cwsItem({ publisherId, itemId })}:publish`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ publishType }),
  })
  const body = await readBody(res)
  if (!res.ok) throw new StoreError('Chrome publish failed', res.status, body)
  if (body.state === 'REJECTED' || body.state === 'CANCELLED') {
    throw new StoreError(`Chrome submission ${body.state}`, res.status, body)
  }
  return { state: body.state, warnings: body.warningInfo?.warnings ?? [] }
}

// ─── Microsoft Edge Add-ons ─────────────────────────────────────

const edgeHeaders = ({ clientId, apiKey }) => ({ Authorization: `ApiKey ${apiKey}`, 'X-ClientID': clientId })

/** The Location header holds the operation ID (accept a full URL as well). */
function operationId(res, what) {
  const location = res.headers.get('location')
  if (!location) throw new StoreError(`Edge ${what}: no operation ID in the Location header`, res.status, '')
  return location.split('/').filter(Boolean).pop()
}

async function pollEdgeOperation(url, headers, what, o) {
  const deadline = o.now() + o.timeoutMs
  for (;;) {
    const res = await o.fetch(url, { headers })
    const body = await readBody(res)
    if (!res.ok) throw new StoreError(`Edge ${what} status check failed`, res.status, body)
    if (body.status === 'Succeeded') return body
    if (body.status !== 'InProgress') {
      throw new StoreError(`Edge ${what} failed${body.errorCode ? ` [${body.errorCode}]` : ''}: ${body.message ?? ''}`, res.status, body)
    }
    if (o.now() > deadline) throw new StoreError(`Edge ${what} still in progress after timeout`, res.status, body)
    await o.sleep(o.pollMs)
  }
}

/** Upload a package into the product's draft submission and wait for validation. */
export async function edgeUpload({ clientId, apiKey, productId, zip }, opts = {}) {
  const o = defaults(opts)
  const headers = edgeHeaders({ clientId, apiKey })
  const res = await o.fetch(`${EDGE_BASE}/v1/products/${productId}/submissions/draft/package`, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/zip' },
    body: zip,
  })
  if (res.status !== 202) throw new StoreError('Edge upload failed', res.status, await readBody(res))
  const id = operationId(res, 'upload')
  return pollEdgeOperation(`${EDGE_BASE}/v1/products/${productId}/submissions/draft/package/operations/${id}`, headers, 'upload', o)
}

/** Submit the draft for certification, with notes for the reviewers. */
export async function edgePublish({ clientId, apiKey, productId, notes = '' }, opts = {}) {
  const o = defaults(opts)
  const headers = edgeHeaders({ clientId, apiKey })
  const res = await o.fetch(`${EDGE_BASE}/v1/products/${productId}/submissions`, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({ notes }),
  })
  if (res.status !== 202) throw new StoreError('Edge publish failed', res.status, await readBody(res))
  const id = operationId(res, 'publish')
  return pollEdgeOperation(`${EDGE_BASE}/v1/products/${productId}/submissions/operations/${id}`, headers, 'publish', o)
}
