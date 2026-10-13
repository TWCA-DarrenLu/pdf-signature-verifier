// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { generateKeyPairSync, createVerify } from 'node:crypto'
import {
  signServiceAccountJwt,
  googleAccessToken,
  chromeUpload,
  chromePublish,
  edgeUpload,
  edgePublish,
  CWS_BASE,
  EDGE_BASE,
} from '../../scripts/release/store-api.mjs'

/** Records requests and answers them in order. */
function fakeFetch(responses: Array<{ status?: number; body?: unknown; headers?: Record<string, string> }>) {
  const calls: Array<{ url: string; init: RequestInit }> = []
  const fetch = async (url: string, init: RequestInit = {}) => {
    calls.push({ url, init })
    const next = responses.shift()
    if (!next) throw new Error(`unexpected request ${url}`)
    return new Response(next.body === undefined ? '' : JSON.stringify(next.body), {
      status: next.status ?? 200,
      headers: next.headers,
    })
  }
  return { fetch, calls }
}
const fast = { sleep: async () => {}, pollMs: 0 }
const zip = new Uint8Array([0x50, 0x4b, 3, 4])

describe('Google service account token', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()

  it('signs an RS256 JWT for the Chrome Web Store scope', () => {
    const jwt = signServiceAccountJwt({ clientEmail: 'ci@project.iam.gserviceaccount.com', privateKey: pem, now: 1_700_000_000_000 })
    const [header, claims, signature] = jwt.split('.')
    expect(JSON.parse(Buffer.from(header, 'base64url').toString())).toEqual({ alg: 'RS256', typ: 'JWT' })
    expect(JSON.parse(Buffer.from(claims, 'base64url').toString())).toEqual({
      iss: 'ci@project.iam.gserviceaccount.com',
      scope: 'https://www.googleapis.com/auth/chromewebstore',
      aud: 'https://oauth2.googleapis.com/token',
      iat: 1_700_000_000,
      exp: 1_700_003_600,
    })
    const ok = createVerify('RSA-SHA256').update(`${header}.${claims}`).verify(publicKey, Buffer.from(signature, 'base64url'))
    expect(ok).toBe(true)
  })

  it('exchanges the JWT with the jwt-bearer grant', async () => {
    const { fetch, calls } = fakeFetch([{ body: { access_token: 'ya29.token', expires_in: 3600 } }])
    const token = await googleAccessToken({ client_email: 'ci@x', private_key: pem }, { fetch })
    expect(token).toBe('ya29.token')
    const form = new URLSearchParams(String(calls[0].init.body))
    expect(calls[0].url).toBe('https://oauth2.googleapis.com/token')
    expect(form.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:jwt-bearer')
    expect(form.get('assertion')?.split('.')).toHaveLength(3)
  })

  it('reports a rejected key without leaking it', async () => {
    const { fetch } = fakeFetch([{ status: 400, body: { error: 'invalid_grant' } }])
    await expect(googleAccessToken({ client_email: 'ci@x', private_key: pem }, { fetch })).rejects.toThrow(/invalid_grant/)
    await expect(googleAccessToken({ client_email: 'ci@x', private_key: pem }, { fetch: fakeFetch([{ status: 400, body: {} }]).fetch }))
      .rejects.not.toThrow(/PRIVATE KEY/)
  })
})

describe('Chrome Web Store API v2', () => {
  const ids = { token: 't', publisherId: 'pub-1', itemId: 'abcdef' }

  it('uploads the package and waits while it is processed', async () => {
    const { fetch, calls } = fakeFetch([
      { body: { uploadState: 'IN_PROGRESS', crxVersion: '1.0.5' } },
      { body: { lastAsyncUploadState: 'IN_PROGRESS' } },
      { body: { lastAsyncUploadState: 'SUCCEEDED' } },
    ])
    const result = await chromeUpload({ ...ids, zip }, { fetch, ...fast })
    expect(result.crxVersion).toBe('1.0.5')
    expect(calls[0].url).toBe(`${CWS_BASE}/upload/v2/publishers/pub-1/items/abcdef:upload`)
    expect(calls[0].init.method).toBe('POST')
    expect((calls[0].init.headers as Record<string, string>).Authorization).toBe('Bearer t')
    expect(calls[1].url).toBe(`${CWS_BASE}/v2/publishers/pub-1/items/abcdef:fetchStatus`)
  })

  it('fails when the upload is rejected', async () => {
    const { fetch } = fakeFetch([{ body: { uploadState: 'FAILED' } }])
    await expect(chromeUpload({ ...ids, zip }, { fetch, ...fast })).rejects.toThrow(/state FAILED/)
  })

  it('submits for review with the chosen publish type', async () => {
    const { fetch, calls } = fakeFetch([{ body: { state: 'PENDING_REVIEW' } }])
    const result = await chromePublish({ ...ids, publishType: 'STAGED_PUBLISH' }, { fetch })
    expect(result.state).toBe('PENDING_REVIEW')
    expect(calls[0].url).toBe(`${CWS_BASE}/v2/publishers/pub-1/items/abcdef:publish`)
    expect(JSON.parse(String(calls[0].init.body))).toEqual({ publishType: 'STAGED_PUBLISH' })
  })

  it('treats a rejected or cancelled submission as a failure', async () => {
    const { fetch } = fakeFetch([{ body: { state: 'REJECTED' } }])
    await expect(chromePublish(ids, { fetch })).rejects.toThrow(/REJECTED/)
  })
})

describe('Edge Add-ons API v1.1', () => {
  const ids = { clientId: 'client-1', apiKey: 'key-1', productId: 'prod-1' }

  it('uploads with ApiKey + X-ClientID and polls the operation from the Location header', async () => {
    const { fetch, calls } = fakeFetch([
      { status: 202, headers: { Location: 'op-42' } },
      { body: { status: 'InProgress' } },
      { body: { status: 'Succeeded', message: 'Successfully updated package' } },
    ])
    await edgeUpload({ ...ids, zip }, { fetch, ...fast })
    const headers = calls[0].init.headers as Record<string, string>
    expect(calls[0].url).toBe(`${EDGE_BASE}/v1/products/prod-1/submissions/draft/package`)
    expect(headers).toMatchObject({ Authorization: 'ApiKey key-1', 'X-ClientID': 'client-1', 'Content-Type': 'application/zip' })
    expect(calls[1].url).toBe(`${EDGE_BASE}/v1/products/prod-1/submissions/draft/package/operations/op-42`)
  })

  it('accepts a Location header that is a full URL', async () => {
    const { fetch, calls } = fakeFetch([
      { status: 202, headers: { Location: `${EDGE_BASE}/v1/products/prod-1/submissions/operations/op-7` } },
      { body: { status: 'Succeeded' } },
    ])
    await edgePublish({ ...ids, notes: 'n' }, { fetch, ...fast })
    expect(calls[1].url).toBe(`${EDGE_BASE}/v1/products/prod-1/submissions/operations/op-7`)
    expect(JSON.parse(String(calls[0].init.body))).toEqual({ notes: 'n' })
  })

  it('reports why a submission was refused', async () => {
    const { fetch } = fakeFetch([
      { status: 202, headers: { Location: 'op-9' } },
      { body: { status: 'Failed', errorCode: 'InProgressSubmission', message: 'submission is in progress' } },
    ])
    await expect(edgePublish(ids, { fetch, ...fast })).rejects.toThrow(/InProgressSubmission/)
  })
})
