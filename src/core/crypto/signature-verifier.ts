import * as pkijs from 'pkijs'
import type { SignatureVerificationResult, SignatureAlgorithm } from '@/types'
import type { ParsedCertificate } from '@/types'
import { normalizeDigestAlgorithm } from './digest-verifier'
import { asBufferSource } from '../bytes'

/**
 * Verify a digital signature using Web Crypto API
 */
export async function verifySignature(
  signatureValue: Uint8Array,
  signedData: Uint8Array,
  certificate: ParsedCertificate,
  signatureAlgorithm: string,
  digestAlgorithm: string
): Promise<SignatureVerificationResult> {
  try {
    const publicKey = certificate.publicKey
    if (!publicKey) {
      return {
        isValid: false,
        algorithm: signatureAlgorithm,
        error: 'Failed to extract public key from certificate',
      }
    }

    const algorithm = getVerifyAlgorithm(signatureAlgorithm, digestAlgorithm)
    if (!algorithm) {
      return {
        isValid: false,
        algorithm: signatureAlgorithm,
        error: `Unsupported signature algorithm: ${signatureAlgorithm}`,
      }
    }

    const isValid = await crypto.subtle.verify(
      algorithm,
      publicKey,
      asBufferSource(signatureValue),
      asBufferSource(signedData)
    )

    return {
      isValid,
      algorithm: signatureAlgorithm,
      keySize: await getKeySize(publicKey),
    }
  } catch (error) {
    return {
      isValid: false,
      algorithm: signatureAlgorithm,
      error: error instanceof Error ? error.message : 'Signature verification failed',
    }
  }
}

/**
 * Verify signature using pkijs SignedData verification
 */
export async function verifyPkcs7Signature(
  signedData: pkijs.SignedData,
  signedBytes: Uint8Array,
  signerIndex: number = 0
): Promise<SignatureVerificationResult> {
  try {
    const result = await signedData.verify({
      signer: signerIndex,
      data: signedBytes.buffer as ArrayBuffer,
      checkChain: false, // We'll check the chain separately
    })

    const signerInfo = signedData.signerInfos[signerIndex]
    const algorithm = getAlgorithmName(signerInfo.signatureAlgorithm.algorithmId)

    return {
      isValid: result,
      algorithm,
    }
  } catch (error) {
    return {
      isValid: false,
      algorithm: 'unknown',
      error: error instanceof Error ? error.message : 'Signature verification failed',
    }
  }
}

/**
 * Get Web Crypto algorithm parameters for verification
 */
function getVerifyAlgorithm(
  signatureAlgorithm: string,
  digestAlgorithm: string
): AlgorithmIdentifier | RsaPssParams | EcdsaParams | null {
  const normalizedDigest = normalizeDigestAlgorithm(digestAlgorithm)

  // Check for RSA-PSS
  if (signatureAlgorithm.includes('PSS') || signatureAlgorithm === 'RSA-PSS') {
    return {
      name: 'RSA-PSS',
      saltLength: getSaltLength(normalizedDigest),
    }
  }

  // Check for ECDSA
  if (signatureAlgorithm.includes('ECDSA')) {
    return {
      name: 'ECDSA',
      hash: normalizedDigest,
    }
  }

  // Default to RSASSA-PKCS1-v1_5
  if (signatureAlgorithm.includes('RSA') || signatureAlgorithm.includes('rsa')) {
    return {
      name: 'RSASSA-PKCS1-v1_5',
    }
  }

  return null
}

/**
 * Get salt length for RSA-PSS based on hash algorithm
 */
function getSaltLength(hashAlgorithm: string): number {
  const lengths: Record<string, number> = {
    'SHA-1': 20,
    'SHA-256': 32,
    'SHA-384': 48,
    'SHA-512': 64,
  }
  return lengths[hashAlgorithm] || 32
}

/**
 * Get key size from CryptoKey
 */
async function getKeySize(key: CryptoKey): Promise<number | undefined> {
  try {
    const keyData = await crypto.subtle.exportKey('spki', key)
    // Approximate key size from SPKI length
    // This is a rough estimate
    const bytes = keyData.byteLength
    if (bytes > 500) return 4096
    if (bytes > 300) return 2048
    if (bytes > 200) return 1024
    return bytes * 8
  } catch {
    return undefined
  }
}

/**
 * Map algorithm OID to name
 */
function getAlgorithmName(oid: string): string {
  const names: Record<string, string> = {
    '1.2.840.113549.1.1.1': 'RSA',
    '1.2.840.113549.1.1.5': 'SHA1withRSA',
    '1.2.840.113549.1.1.11': 'SHA256withRSA',
    '1.2.840.113549.1.1.12': 'SHA384withRSA',
    '1.2.840.113549.1.1.13': 'SHA512withRSA',
    '1.2.840.113549.1.1.10': 'RSA-PSS',
    '1.2.840.10045.4.1': 'SHA1withECDSA',
    '1.2.840.10045.4.3.2': 'SHA256withECDSA',
    '1.2.840.10045.4.3.3': 'SHA384withECDSA',
    '1.2.840.10045.4.3.4': 'SHA512withECDSA',
  }
  return names[oid] || oid
}

/**
 * Extract signature algorithm type
 */
export function getSignatureAlgorithmType(algorithm: string): SignatureAlgorithm {
  if (algorithm.includes('PSS')) {
    return 'RSA-PSS'
  }
  if (algorithm.includes('ECDSA')) {
    return 'ECDSA'
  }
  return 'RSASSA-PKCS1-v1_5'
}

/**
 * Check if signature algorithm is supported
 */
export function isSignatureAlgorithmSupported(algorithm: string): boolean {
  const supported = [
    'RSA',
    'SHA1withRSA',
    'SHA256withRSA',
    'SHA384withRSA',
    'SHA512withRSA',
    'RSA-PSS',
    'SHA1withECDSA',
    'SHA256withECDSA',
    'SHA384withECDSA',
    'SHA512withECDSA',
    'RSASSA-PKCS1-v1_5',
    'ECDSA',
  ]

  return supported.some((s) =>
    algorithm.toUpperCase().includes(s.toUpperCase())
  )
}
