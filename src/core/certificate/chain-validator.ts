import type { CertificateChain, CheckResult } from '@/types'
import { createPassedCheck, createFailedCheck } from '@/types'
import { verifyIssuedBy } from './chain-builder'

export interface ChainValidationResult {
  isValid: boolean
  checks: ChainValidationChecks
  errors: string[]
  warnings: string[]
}

export interface ChainValidationChecks {
  chainComplete: CheckResult
  signaturesValid: CheckResult
  datesValid: CheckResult
  keyUsageValid: CheckResult
  trustAnchor: CheckResult
}

export interface ValidationOptions {
  validationTime?: Date
  requireTrustAnchor?: boolean
  checkRevocation?: boolean
}

/**
 * Validate a certificate chain
 */
export async function validateCertificateChain(
  chain: CertificateChain,
  options: ValidationOptions = {}
): Promise<ChainValidationResult> {
  const {
    validationTime = new Date(),
    requireTrustAnchor = true,
  } = options

  const errors: string[] = []
  const warnings: string[] = []
  const checks: ChainValidationChecks = {
    chainComplete: createFailedCheck('Chain completeness not verified'),
    signaturesValid: createFailedCheck('Signatures not verified'),
    datesValid: createFailedCheck('Validity dates not verified'),
    keyUsageValid: createFailedCheck('Key usage not verified'),
    trustAnchor: createFailedCheck('Trust anchor not verified'),
  }

  // Check chain completeness
  if (chain.isComplete) {
    checks.chainComplete = createPassedCheck('Certificate chain is complete')
  } else {
    checks.chainComplete = createFailedCheck(
      'Certificate chain is incomplete',
      'Could not build chain to a root certificate'
    )
    errors.push('Incomplete certificate chain')
  }

  // Check trust anchor
  if (chain.isTrusted) {
    checks.trustAnchor = createPassedCheck(
      'Chain terminates at trusted root',
      `Root: ${chain.root?.subject || 'Unknown'}`
    )
  } else if (requireTrustAnchor) {
    checks.trustAnchor = createFailedCheck(
      'Chain does not terminate at trusted root',
      'The root certificate is not in the trust store'
    )
    errors.push('Untrusted root certificate')
  } else {
    checks.trustAnchor = createPassedCheck(
      'Trust anchor verification skipped',
      'requireTrustAnchor is false'
    )
    warnings.push('Trust anchor verification was skipped')
  }

  // Validate signatures in chain
  const sigResult = await validateChainSignatures(chain)
  if (sigResult.valid) {
    checks.signaturesValid = createPassedCheck('All certificate signatures are valid')
  } else {
    checks.signaturesValid = createFailedCheck(
      'Certificate signature verification failed',
      sigResult.error
    )
    errors.push(sigResult.error || 'Signature verification failed')
  }

  // Validate dates
  const dateResult = validateChainDates(chain, validationTime)
  if (dateResult.valid) {
    checks.datesValid = createPassedCheck(
      'All certificates are within validity period',
      `Validated at: ${validationTime.toISOString()}`
    )
  } else {
    checks.datesValid = createFailedCheck(
      'Certificate validity period check failed',
      dateResult.error
    )
    if (dateResult.isExpired) {
      errors.push(dateResult.error || 'Certificate expired')
    } else {
      warnings.push(dateResult.error || 'Certificate not yet valid')
    }
  }

  // Validate key usage
  const keyUsageResult = validateChainKeyUsage(chain)
  if (keyUsageResult.valid) {
    checks.keyUsageValid = createPassedCheck('Key usage constraints are satisfied')
  } else {
    checks.keyUsageValid = createFailedCheck(
      'Key usage constraint violation',
      keyUsageResult.error
    )
    warnings.push(keyUsageResult.error || 'Key usage issue')
  }

  const isValid = errors.length === 0

  return {
    isValid,
    checks,
    errors,
    warnings,
  }
}

/**
 * Validate all signatures in the chain
 */
async function validateChainSignatures(
  chain: CertificateChain
): Promise<{ valid: boolean; error?: string }> {
  const certs = chain.certificates

  for (let i = 0; i < certs.length - 1; i++) {
    const subject = certs[i]
    const issuer = certs[i + 1]

    const isValid = await verifyIssuedBy(subject, issuer)
    if (!isValid) {
      return {
        valid: false,
        error: `Certificate "${subject.subject}" signature not verified by "${issuer.subject}"`,
      }
    }
  }

  // For self-signed root, verify self-signature
  if (chain.root && chain.root.subject === chain.root.issuer) {
    const isValid = await verifyIssuedBy(chain.root, chain.root)
    if (!isValid) {
      return {
        valid: false,
        error: `Root certificate "${chain.root.subject}" self-signature is invalid`,
      }
    }
  }

  return { valid: true }
}

/**
 * Validate validity periods for all certificates
 */
function validateChainDates(
  chain: CertificateChain,
  validationTime: Date
): { valid: boolean; isExpired?: boolean; error?: string } {
  for (const cert of chain.certificates) {
    if (validationTime < cert.notBefore) {
      return {
        valid: false,
        isExpired: false,
        error: `Certificate "${cert.subject}" is not yet valid (starts ${cert.notBefore.toISOString()})`,
      }
    }

    if (validationTime > cert.notAfter) {
      return {
        valid: false,
        isExpired: true,
        error: `Certificate "${cert.subject}" has expired (ended ${cert.notAfter.toISOString()})`,
      }
    }
  }

  return { valid: true }
}

/**
 * Validate key usage for all certificates in chain
 */
function validateChainKeyUsage(
  chain: CertificateChain
): { valid: boolean; error?: string } {
  const certs = chain.certificates

  // End entity certificate should have digitalSignature or nonRepudiation
  if (certs.length > 0) {
    const endEntity = certs[0]
    if (!endEntity.keyUsage.digitalSignature && !endEntity.keyUsage.nonRepudiation) {
      return {
        valid: false,
        error: `End entity certificate lacks digitalSignature or nonRepudiation key usage`,
      }
    }
  }

  // Intermediate and root certificates should have keyCertSign
  for (let i = 1; i < certs.length; i++) {
    const cert = certs[i]
    if (!cert.keyUsage.keyCertSign && cert.isCA) {
      return {
        valid: false,
        error: `CA certificate "${cert.subject}" lacks keyCertSign key usage`,
      }
    }
  }

  return { valid: true }
}

/**
 * Check if certificate chain allows document signing
 */
export function canChainSignDocuments(chain: CertificateChain): boolean {
  if (chain.certificates.length === 0) {
    return false
  }

  const endEntity = chain.certificates[0]

  // Must not be a CA certificate
  if (endEntity.isCA) {
    return false
  }

  // Must have appropriate key usage
  if (!endEntity.keyUsage.digitalSignature && !endEntity.keyUsage.nonRepudiation) {
    return false
  }

  return true
}

/**
 * Get validation summary for display
 */
export function getValidationSummary(result: ChainValidationResult): string {
  if (result.isValid) {
    return 'Certificate chain is valid and trusted'
  }

  if (result.errors.length > 0) {
    return result.errors[0]
  }

  if (result.warnings.length > 0) {
    return result.warnings[0]
  }

  return 'Unknown validation issue'
}
