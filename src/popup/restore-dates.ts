import type { VerificationResult } from '@/types'

/**
 * Restore Date objects in a result that crossed postMessage / runtime
 * messaging / chrome.storage (dates arrive as ISO strings).
 */
export function restoreDates(result: VerificationResult): VerificationResult {
  return {
    ...result,
    signatures: result.signatures.map((sig) => ({
      ...sig,
      signedAt: sig.signedAt ? new Date(sig.signedAt) : null,
      validationTime: sig.validationTime ? new Date(sig.validationTime) : undefined,
      certificateChain: sig.certificateChain.map((cert) => ({
        ...cert,
        notBefore: new Date(cert.notBefore),
        notAfter: new Date(cert.notAfter),
      })),
      timestampInfo: sig.timestampInfo
        ? {
            ...sig.timestampInfo,
            time: new Date(sig.timestampInfo.time),
          }
        : undefined,
    })),
  }
}
