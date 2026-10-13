import type {
  EmbeddedRevocationInfo,
  RevocationResult,
  ParsedCertificate,
  CrlInfo,
} from '@/types'
import { t } from '@/i18n'
import { parseEmbeddedOcspResponse } from './ocsp-client'
import { parseEmbeddedCrl, isSerialInCrl } from './crl-client'

/**
 * Check revocation status using embedded PDF revocation info
 */
export function checkEmbeddedRevocationStatus(
  certificate: ParsedCertificate,
  embeddedInfo: EmbeddedRevocationInfo | null
): RevocationResult {
  if (!embeddedInfo) {
    return {
      status: 'unknown',
      checkedAt: new Date(),
      method: 'embedded',
      details: t('core.revocation.noEmbeddedInfo'),
      detailsI18nKey: 'core.revocation.noEmbeddedInfo',
    }
  }

  // Try OCSP responses first (they're more specific)
  // Only use OCSP responses whose certID serial matches the target certificate
  for (const ocspData of embeddedInfo.ocspResponses) {
    try {
      const result = parseEmbeddedOcspResponse(ocspData)
      if (result.targetSerial && normalizeSerial(result.targetSerial) !== normalizeSerial(certificate.serialNumber)) {
        continue
      }
      if (result.status === 'good' || result.status === 'revoked') {
        return result
      }
    } catch {
      continue
    }
  }

  // Try CRLs
  // For embedded/LTV CRLs, skip expiry check — the timestamp proves
  // the CRL was valid at signing time. That's the whole point of LTV.
  // Only use CRLs whose issuer matches the certificate's issuer.
  const serialNumber = certificate.serialNumber
  for (const crlData of embeddedInfo.crls) {
    try {
      const crlInfo = parseEmbeddedCrl(crlData)

      if (normalizeDN(crlInfo.issuer) !== normalizeDN(certificate.issuer)) {
        continue
      }

      if (isSerialInCrl(serialNumber, crlInfo)) {
        return {
          status: 'revoked',
          checkedAt: new Date(),
          method: 'embedded',
          details: t('core.revocation.inEmbeddedCrl', { issuer: crlInfo.issuer }),
          detailsI18nKey: 'core.revocation.inEmbeddedCrl',
          detailsI18nParams: { issuer: crlInfo.issuer },
        }
      }

      // Cert not in CRL — good (LTV: trust embedded CRL regardless of expiry)
      return {
        status: 'good',
        checkedAt: new Date(),
        method: 'embedded',
        details: t('core.revocation.notInEmbeddedCrl', { issuer: crlInfo.issuer }),
        detailsI18nKey: 'core.revocation.notInEmbeddedCrl',
        detailsI18nParams: { issuer: crlInfo.issuer },
      }
    } catch {
      continue
    }
  }

  return {
    status: 'unknown',
    checkedAt: new Date(),
    method: 'embedded',
    details: t('core.revocation.cannotDetermineFromEmbedded'),
    detailsI18nKey: 'core.revocation.cannotDetermineFromEmbedded',
  }
}

/**
 * Extract embedded revocation info statistics
 */
export function getEmbeddedRevocationStats(
  embeddedInfo: EmbeddedRevocationInfo | null
): {
  hasOcsp: boolean
  hasCrl: boolean
  ocspCount: number
  crlCount: number
  crlInfos: CrlInfo[]
} {
  if (!embeddedInfo) {
    return {
      hasOcsp: false,
      hasCrl: false,
      ocspCount: 0,
      crlCount: 0,
      crlInfos: [],
    }
  }

  const crlInfos: CrlInfo[] = []
  for (const crlData of embeddedInfo.crls) {
    try {
      crlInfos.push(parseEmbeddedCrl(crlData))
    } catch {
      continue
    }
  }

  return {
    hasOcsp: embeddedInfo.ocspResponses.length > 0,
    hasCrl: embeddedInfo.crls.length > 0,
    ocspCount: embeddedInfo.ocspResponses.length,
    crlCount: embeddedInfo.crls.length,
    crlInfos,
  }
}

/**
 * Check if embedded revocation info is sufficient for LTV
 */
export function isLtvComplete(
  chain: ParsedCertificate[],
  embeddedInfo: EmbeddedRevocationInfo | null
): { complete: boolean; missing: string[] } {
  const missing: string[] = []

  if (!embeddedInfo) {
    for (const cert of chain) {
      if (!cert.isSelfSigned) {
        missing.push(t('core.revocation.missingRevocationInfo', { name: getCommonName(cert.subject) }))
      }
    }
    return { complete: false, missing }
  }

  // For each non-root certificate, we need revocation info
  for (let i = 0; i < chain.length - 1; i++) {
    const cert = chain[i]
    const result = checkEmbeddedRevocationStatus(cert, embeddedInfo)

    if (result.status === 'unknown' || result.status === 'error') {
      missing.push(t('core.revocation.missingRevocationInfo', { name: getCommonName(cert.subject) }))
    }
  }

  return {
    complete: missing.length === 0,
    missing,
  }
}

/**
 * Get revocation info validity window.
 * Combines both CRL and OCSP time windows:
 *   validFrom  = latest start across all sources (most restrictive)
 *   validUntil = earliest end across all sources (most restrictive)
 */
export function getRevocationInfoValidity(
  embeddedInfo: EmbeddedRevocationInfo | null
): { validFrom: Date | null; validUntil: Date | null } {
  if (!embeddedInfo) {
    return { validFrom: null, validUntil: null }
  }

  let validFrom: Date | null = null
  let validUntil: Date | null = null

  // Check CRLs for validity windows
  for (const crlData of embeddedInfo.crls) {
    try {
      const crlInfo = parseEmbeddedCrl(crlData)

      if (!validFrom || crlInfo.thisUpdate > validFrom) {
        validFrom = crlInfo.thisUpdate
      }

      if (crlInfo.nextUpdate) {
        if (!validUntil || crlInfo.nextUpdate < validUntil) {
          validUntil = crlInfo.nextUpdate
        }
      }
    } catch {
      continue
    }
  }

  // Check OCSP responses for validity windows
  for (const ocspData of embeddedInfo.ocspResponses) {
    try {
      const result = parseEmbeddedOcspResponse(ocspData)

      // Use thisUpdate (or producedAt as fallback) as the start of validity
      const ocspStart = result.thisUpdate || result.producedAt
      if (ocspStart) {
        if (!validFrom || ocspStart > validFrom) {
          validFrom = ocspStart
        }
      }

      if (result.nextUpdate) {
        if (!validUntil || result.nextUpdate < validUntil) {
          validUntil = result.nextUpdate
        }
      }
    } catch {
      continue
    }
  }

  return { validFrom, validUntil }
}

function getCommonName(subject: string): string {
  const match = subject.match(/CN=([^,]+)/)
  return match ? match[1] : subject
}

/**
 * Normalize a DN string for comparison: lowercase, remove extra spaces,
 * sort RDN components so order doesn't matter, and normalize OID aliases.
 */
function normalizeDN(dn: string): string {
  const normalized = dn
    .replace(/\s*=\s*/g, '=')
    .replace(/\s*,\s*/g, ',')
    .toLowerCase()
    .trim()

  // Sort RDN components so order differences don't cause mismatches
  return normalized.split(',').sort().join(',')
}

/**
 * Normalize a serial number for comparison: lowercase, strip leading zeros
 */
function normalizeSerial(serial: string): string {
  return serial.toLowerCase().replace(/^0+/, '')
}
