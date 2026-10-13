import type { ParsedCertificate, CertificateChain } from '@/types'
import { parseCertificateFromBytes, parseCertificatesFromBundle } from './cert-utils'
import {
  getTrustAnchors,
  getTsaTrustAnchors,
  getKnownIntermediates,
  getKnownRoots,
} from '@/trust-store/trust-manager'
import { verifyCertSignature } from '../crypto/pki-verify'

export type AnchorStore = 'signing' | 'tsa'

export interface ChainBuildOptions {
  /** Fetch missing issuers from the AIA caIssuers URL. */
  fetchMissing?: boolean
  /** Extra DER certificates (e.g. the PDF's DSS /Certs). */
  additionalCertBytes?: Uint8Array[]
  /** Which trust store terminates the path. Default: signing. */
  anchorStore?: AnchorStore
  /** Also trust the selected international roots (user option). Default false. */
  trustInternational?: boolean
}

/** Max certificates in a path, leaf and anchor included. */
const MAX_PATH_LENGTH = 8

/**
 * Build a certification path from `endEntityCert` to a trust anchor.
 *
 * Candidate issuers come from the signature's embedded certificates, the
 * PDF's DSS, the bundled Taiwan intermediates, the anchors themselves and —
 * optionally — AIA downloads. None of these sources is trusted: a candidate
 * only joins the path when
 *   - its subject equals the child's issuer (and AKI/SKI agree when present),
 *   - it is a CA (basicConstraints cA, keyCertSign, pathLenConstraint), and
 *   - the child's signature verifies with its public key.
 * The path is trusted only when it ends at an anchor matched by SHA-256
 * fingerprint. Same-name candidates (e.g. GRCA G1/G2, TWCA Root CA SHA-1 /
 * SHA-256) are tried in turn (backtracking).
 *
 * A self-signed end-entity certificate is never trusted.
 */
export async function buildCertificateChain(
  endEntityCert: ParsedCertificate,
  intermediateCerts: ParsedCertificate[],
  options: ChainBuildOptions = {}
): Promise<CertificateChain> {
  const { fetchMissing = false, additionalCertBytes = [], anchorStore = 'signing', trustInternational = false } = options

  if (isSelfIssued(endEntityCert) || (await verifyCertSignature(endEntityCert, endEntityCert))) {
    return {
      certificates: [endEntityCert],
      root: endEntityCert,
      isComplete: true,
      isTrusted: false,
      selfSignedLeaf: true,
    }
  }

  const anchors = anchorStore === 'tsa' ? getTsaTrustAnchors(trustInternational) : getTrustAnchors(trustInternational)
  const anchorFps = new Set(anchors.map((a) => a.fingerprint.toLowerCase()))
  const isAnchor = (c: ParsedCertificate) => anchorFps.has(c.fingerprint.toLowerCase())

  const pool = new Map<string, ParsedCertificate>()
  const addToPool = (c: ParsedCertificate) => {
    if (!pool.has(c.fingerprint)) pool.set(c.fingerprint, c)
  }
  intermediateCerts.forEach(addToPool)
  for (const bytes of additionalCertBytes) {
    try {
      addToPool(await parseCertificateFromBytes(bytes))
    } catch {
      // ignore unparsable DSS entries
    }
  }
  getKnownIntermediates().forEach(addToPool)
  // every bundled root completes paths; only `anchors` make them trusted
  getKnownRoots().forEach(addToPool)
  anchors.forEach(addToPool)

  const triedUrls = new Set<string>()
  let longest: ParsedCertificate[] = [endEntityCert]
  let untrustedComplete: ParsedCertificate[] | null = null

  const extend = async (path: ParsedCertificate[]): Promise<ParsedCertificate[] | null> => {
    const current = path[path.length - 1]
    if (path.length > longest.length) longest = path

    if (isAnchor(current)) return path
    if (isSelfIssued(current)) {
      if (!untrustedComplete) untrustedComplete = path
      return null
    }
    if (path.length >= MAX_PATH_LENGTH) return null

    let candidates = issuerCandidates(current, [...pool.values()], path)
    if (candidates.length === 0 && fetchMissing) {
      for (const url of current.authorityInfoAccess?.caIssuers ?? []) {
        if (triedUrls.has(url)) continue
        triedUrls.add(url)
        ;(await fetchIssuerCertificates(url)).forEach(addToPool)
      }
      candidates = issuerCandidates(current, [...pool.values()], path)
    }
    candidates.sort((a, b) => Number(isAnchor(b)) - Number(isAnchor(a)))

    // Number of CA certificates already below the candidate (leaf excluded).
    const casBelow = path.length - 1
    for (const candidate of candidates) {
      if (!canIssue(candidate, casBelow)) continue
      if (!(await verifyCertSignature(current, candidate))) continue
      const found = await extend([...path, candidate])
      if (found) return found
    }
    return null
  }

  const trustedPath = await extend([endEntityCert])
  if (trustedPath) {
    return {
      certificates: trustedPath,
      root: trustedPath[trustedPath.length - 1],
      isComplete: true,
      isTrusted: true,
    }
  }

  const fallback: ParsedCertificate[] = untrustedComplete ?? longest
  const top = fallback[fallback.length - 1]
  return {
    certificates: fallback,
    root: isSelfIssued(top) ? top : null,
    isComplete: isSelfIssued(top),
    isTrusted: false,
  }
}

function isSelfIssued(cert: ParsedCertificate): boolean {
  return cert.subject === cert.issuer
}

function issuerCandidates(
  cert: ParsedCertificate,
  pool: ParsedCertificate[],
  path: ParsedCertificate[]
): ParsedCertificate[] {
  return pool.filter((candidate) => {
    if (candidate.subject !== cert.issuer) return false
    if (path.some((p) => p.fingerprint === candidate.fingerprint)) return false
    if (cert.authorityKeyIdentifier && candidate.subjectKeyIdentifier) {
      return cert.authorityKeyIdentifier === candidate.subjectKeyIdentifier
    }
    return true
  })
}

/**
 * RFC 5280 §6.1.4 essentials for an issuing certificate.
 */
function canIssue(candidate: ParsedCertificate, casBelow: number): boolean {
  if (!candidate.isCA) return false
  if (candidate.keyUsagePresent && !candidate.keyUsage.keyCertSign) return false
  if (
    typeof candidate.pathLenConstraint === 'number' &&
    !isSelfIssued(candidate) &&
    casBelow > candidate.pathLenConstraint
  ) {
    return false
  }
  return true
}

async function fetchIssuerCertificates(url: string): Promise<ParsedCertificate[]> {
  try {
    const { fetchCertificateBytes } = await import('../network')
    const data = await fetchCertificateBytes(url)
    return data ? await parseCertificatesFromBundle(data) : []
  } catch {
    return []
  }
}

/**
 * Verify that one certificate issued another (name chaining + signature).
 */
export async function verifyIssuedBy(
  subject: ParsedCertificate,
  issuer: ParsedCertificate
): Promise<boolean> {
  if (subject.issuer !== issuer.subject) return false
  if (subject.authorityKeyIdentifier && issuer.subjectKeyIdentifier) {
    if (subject.authorityKeyIdentifier !== issuer.subjectKeyIdentifier) return false
  }
  return verifyCertSignature(subject, issuer)
}

/**
 * Get certificate chain as array of DER bytes
 */
export function chainToDer(chain: CertificateChain): Uint8Array[] {
  return chain.certificates.map((cert) => new Uint8Array(cert.raw.toSchema().toBER()))
}

/**
 * Get certificate chain summary
 */
export function getChainSummary(chain: CertificateChain): string[] {
  return chain.certificates.map((cert, index) => {
    const prefix = index === 0 ? '[EE]' : index === chain.certificates.length - 1 ? '[Root]' : '[CA]'
    const trustMark = chain.isTrusted && index === chain.certificates.length - 1 ? ' [Trusted]' : ''
    return `${prefix} ${cert.subject}${trustMark}`
  })
}
