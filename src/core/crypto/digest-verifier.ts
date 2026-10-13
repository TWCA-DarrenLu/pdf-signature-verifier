import type { DigestResult, DigestAlgorithm } from '@/types'
import { asBufferSource } from '../bytes'

/**
 * Compute digest of data using Web Crypto API
 */
export async function computeDigest(
  algorithm: DigestAlgorithm,
  data: Uint8Array
): Promise<Uint8Array> {
  const hashBuffer = await crypto.subtle.digest(algorithm, asBufferSource(data))
  return new Uint8Array(hashBuffer)
}

/**
 * Verify that computed digest matches expected value
 */
export async function verifyDigest(
  algorithm: DigestAlgorithm,
  data: Uint8Array,
  expected: Uint8Array
): Promise<DigestResult> {
  const digest = await computeDigest(algorithm, data)

  const matches = compareBytes(digest, expected)

  return {
    algorithm,
    digest,
    expected,
    matches,
  }
}

/**
 * Compare two byte arrays for equality
 */
export function compareBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false
  }

  // Constant-time comparison to prevent timing attacks
  let result = 0
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i]
  }

  return result === 0
}

/**
 * Map algorithm OID to Web Crypto algorithm name
 */
export function oidToDigestAlgorithm(oid: string): DigestAlgorithm {
  const mapping: Record<string, DigestAlgorithm> = {
    '1.3.14.3.2.26': 'SHA-1',
    '2.16.840.1.101.3.4.2.1': 'SHA-256',
    '2.16.840.1.101.3.4.2.2': 'SHA-384',
    '2.16.840.1.101.3.4.2.3': 'SHA-512',
  }

  const algorithm = mapping[oid]
  if (!algorithm) {
    throw new Error(`Unsupported digest algorithm OID: ${oid}`)
  }

  return algorithm
}

/**
 * Map algorithm name to Web Crypto algorithm name
 */
export function normalizeDigestAlgorithm(name: string): DigestAlgorithm {
  const normalized = name.toUpperCase().replace(/[^A-Z0-9]/g, '')

  const mapping: Record<string, DigestAlgorithm> = {
    SHA1: 'SHA-1',
    SHA256: 'SHA-256',
    SHA384: 'SHA-384',
    SHA512: 'SHA-512',
  }

  const algorithm = mapping[normalized]
  if (!algorithm) {
    throw new Error(`Unsupported digest algorithm: ${name}`)
  }

  return algorithm
}

/**
 * Get the expected digest length for an algorithm
 */
export function getDigestLength(algorithm: DigestAlgorithm): number {
  const lengths: Record<DigestAlgorithm, number> = {
    'SHA-1': 20,
    'SHA-256': 32,
    'SHA-384': 48,
    'SHA-512': 64,
  }

  return lengths[algorithm]
}

/**
 * Format digest as hex string
 */
export function formatDigest(digest: Uint8Array): string {
  return Array.from(digest)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Parse hex string to bytes
 */
export function parseHexDigest(hex: string): Uint8Array {
  const cleanHex = hex.replace(/[^0-9A-Fa-f]/g, '')
  const bytes = new Uint8Array(cleanHex.length / 2)

  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16)
  }

  return bytes
}

/**
 * Verify message digest from signed attributes
 */
export async function verifyMessageDigest(
  signedBytes: Uint8Array,
  messageDigest: Uint8Array,
  algorithm: string
): Promise<{ valid: boolean; computed: Uint8Array; expected: Uint8Array }> {
  const digestAlgorithm = normalizeDigestAlgorithm(algorithm)
  const computed = await computeDigest(digestAlgorithm, signedBytes)

  return {
    valid: compareBytes(computed, messageDigest),
    computed,
    expected: messageDigest,
  }
}
