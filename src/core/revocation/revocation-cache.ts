import type { RevocationEvidence } from './revocation-validator'

/**
 * Cache for online revocation answers (OCSP responses, CRLs), keyed by what
 * was asked. An entry lives until the answer's nextUpdate, at most 24 hours;
 * callers re-validate the bytes on every use, so the cache only saves the
 * network round trip — it never decides a status by itself.
 *
 * Kept in memory and, where the context allows it (service worker,
 * extension pages), in chrome.storage.session so it survives service-worker
 * restarts. Content scripts cannot use storage.session and stay memory-only.
 */

const MAX_TTL_MS = 24 * 60 * 60 * 1000
const MAX_MEMORY_ENTRIES = 200
const MAX_PERSISTED_BYTES = 512 * 1024
const STORAGE_PREFIX = 'rev-cache:'

interface Entry {
  bytes: Uint8Array
  expiresAt: number
}

interface PersistedEntry {
  b64: string
  expiresAt: number
}

const memory = new Map<string, Entry>()
let sessionUsable = true

function sessionStorage(): chrome.storage.StorageArea | null {
  if (!sessionUsable) return null
  try {
    return typeof chrome !== 'undefined' && chrome.storage?.session ? chrome.storage.session : null
  } catch {
    return null
  }
}

export async function getCachedRevocation(key: string, now = Date.now()): Promise<Uint8Array | null> {
  const hit = memory.get(key)
  if (hit) {
    if (hit.expiresAt > now) return hit.bytes
    memory.delete(key)
  }
  const session = sessionStorage()
  if (!session) return null
  let stored: PersistedEntry | undefined
  try {
    stored = (await session.get(STORAGE_PREFIX + key))[STORAGE_PREFIX + key] as PersistedEntry | undefined
  } catch {
    sessionUsable = false // e.g. content script: no access to storage.session
    return null
  }
  if (!stored) return null
  try {
    if (stored.expiresAt <= now) throw new Error('expired')
    const bytes = fromBase64(stored.b64)
    remember(key, { bytes, expiresAt: stored.expiresAt })
    return bytes
  } catch {
    await session.remove(STORAGE_PREFIX + key).catch(() => {})
    return null
  }
}

export async function putCachedRevocation(
  key: string,
  bytes: Uint8Array,
  evidence: Pick<RevocationEvidence, 'thisUpdate' | 'nextUpdate'>,
  now = Date.now()
): Promise<void> {
  const validUntil = evidence.nextUpdate?.getTime() ?? evidence.thisUpdate.getTime() + MAX_TTL_MS
  const expiresAt = Math.min(validUntil, now + MAX_TTL_MS)
  if (expiresAt <= now) return
  remember(key, { bytes, expiresAt })

  const session = sessionStorage()
  if (!session || bytes.length > MAX_PERSISTED_BYTES) return
  try {
    await session.set({ [STORAGE_PREFIX + key]: { b64: toBase64(bytes), expiresAt } satisfies PersistedEntry })
  } catch {
    // quota exceeded or no access — the memory copy still helps
  }
}

export async function clearRevocationCache(): Promise<void> {
  memory.clear()
  const session = sessionStorage()
  if (!session) return
  try {
    const all = await session.get(null)
    const keys = Object.keys(all).filter((k) => k.startsWith(STORAGE_PREFIX))
    if (keys.length > 0) await session.remove(keys)
  } catch {
    // ignore
  }
}

function remember(key: string, entry: Entry): void {
  memory.delete(key)
  memory.set(key, entry)
  while (memory.size > MAX_MEMORY_ENTRIES) {
    memory.delete(memory.keys().next().value as string)
  }
}

function toBase64(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  }
  return btoa(binary)
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}
