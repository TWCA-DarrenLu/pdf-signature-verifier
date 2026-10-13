import type {
  VerificationResult,
  SignatureResult,
  CertificateInfo,
  CertificateChain,
  TimestampInfo,
  PdfSignatureField,
  EmbeddedRevocationInfo,
  ParsedCertificate,
  CheckResult,
  VerificationStatus,
} from '@/types'
import {
  createPassedCheck,
  createFailedCheck,
  createSkippedCheck,
  determineOverallStatus,
} from '@/types'

import { t, getLocale } from '@/i18n'
import { parsePdf } from './pdf/parser'
import { extractSignedBytes, validateByteRange } from './pdf/byte-range'
import { parsePkcs7 } from './crypto/pkcs7-parser'
import { computeDigest, compareBytes, normalizeDigestAlgorithm } from './crypto/digest-verifier'
import { verifyCmsSignerInfo, getEncapsulatedContentBytes } from './crypto/pki-verify'
import { buildCertificateChain } from './certificate/chain-builder'
import { getCommonName, isCertificateValid } from './certificate/cert-utils'
import { checkCertificateRevocation, type CertRevocationOutcome, type RevocationContext } from './revocation/revocation-checker'
import { verifyTimestampForData, type TimestampFailure } from './timestamp/tst-verifier'
import { checkLtvCompleteness } from './ltv/ltv-checker'
import { createChangeAnalyzer, type ChangeAnalyzer, type ChangePolicy } from './pdf/incremental-update'
import { initializeTrustStore, isTrustStoreEmpty, getAnchorCategory } from '@/trust-store/trust-manager'
import { ensurePkijsEngine } from './crypto/pkijs-engine'

export interface VerificationOptions {
  /** Allow OCSP / CRL / AIA network access. Default true. */
  checkOnlineRevocation?: boolean
  /** Ask OCSP / CRL servers again instead of using cached answers ("re-check"). */
  refreshRevocation?: boolean
  /** Verify embedded RFC 3161 timestamps. Default true. */
  validateTimestamp?: boolean
  /** Kept for API compatibility; a trusted root is always required. */
  requireTrustedRoot?: boolean
}

interface DocContext {
  pdfData: Uint8Array
  allFields: PdfSignatureField[]
  dss: EmbeddedRevocationInfo | null
  options: VerificationOptions
  /** Compares each signed revision with the final document. */
  changes: ChangeAnalyzer
  /** DocMDP permission level of the certification signature, if any. */
  docMdpLevel: 1 | 2 | 3 | null
  /** Verified DocTimeStamp results, by field. */
  docTimestamps: Map<PdfSignatureField, DocTimestampOutcome>
}

interface DocTimestampOutcome {
  result: SignatureResult
  trusted: boolean
  ltvCovered: boolean
}

/**
 * Verify all signatures in a PDF document
 */
export async function verifyPdfSignatures(
  pdfData: ArrayBuffer | Uint8Array,
  fileName: string,
  options: VerificationOptions = {}
): Promise<VerificationResult> {
  // Wire PKI.js to Web Crypto (idempotent) and load trust store.
  ensurePkijsEngine()
  await initializeTrustStore()

  const pdf = await parsePdf(pdfData)

  if (pdf.signatureFields.length === 0) {
    return {
      status: 'unknown',
      fileName,
      signatures: [],
      summary: t('core.summary.noSignatures'),
      summaryI18nKey: 'core.summary.noSignatures',
    }
  }

  const ctx: DocContext = {
    pdfData: pdf.data,
    allFields: pdf.signatureFields,
    dss: pdf.dssRevocationInfo,
    options,
    changes: createChangeAnalyzer(pdf.data),
    // Only the first signature of the document can be a certification signature.
    docMdpLevel:
      [...pdf.signatureFields].sort(
        (a, b) => a.byteRange.start2 + a.byteRange.length2 - (b.byteRange.start2 + b.byteRange.length2)
      )[0]?.docMdp?.permissionLevel ?? null,
    docTimestamps: new Map(),
  }

  // Document timestamps first: approval signatures use them for B-LTA.
  for (let i = 0; i < pdf.signatureFields.length; i++) {
    const field = pdf.signatureFields[i]
    if (field.isDocTimeStamp) {
      ctx.docTimestamps.set(field, await verifyDocTimeStamp(field, i, ctx))
    }
  }

  const signatures: SignatureResult[] = []
  for (let i = 0; i < pdf.signatureFields.length; i++) {
    const field = pdf.signatureFields[i]
    const docTs = ctx.docTimestamps.get(field)
    signatures.push(docTs ? docTs.result : await verifySingleSignature(field, i, ctx))
  }

  const status = determineOverallStatus(signatures)
  const summaryKey =
    status === 'trusted'
      ? 'core.summary.allTrusted'
      : status === 'failed'
      ? 'core.summary.someFailed'
      : 'core.summary.cannotFullyVerify'
  const summaryParams = status === 'trusted' ? { count: signatures.length } : undefined

  return {
    status,
    fileName,
    signatures,
    summary: t(summaryKey, summaryParams),
    summaryI18nKey: summaryKey,
    summaryI18nParams: summaryParams,
  }
}

// ─── Status policy ───────────────────────────────────────────────

export interface SignatureStatusInput {
  integrityPassed: boolean
  selfSignedSigner: boolean
  /** Signer certificate not intended for signing (CA cert, keyUsage, EKU). */
  signerCertUnsuitable?: boolean
  chainTrusted: boolean
  validityPassed: boolean
  revocation: 'good' | 'revoked' | 'unknown'
  /** Set when a timestamp is present but did not verify. */
  timestampFailure?: TimestampFailure | null
  docMdpViolation: boolean
  /** Content changed after the last signature (not just LTV material). */
  unexplainedChanges: boolean
}

/**
 * Status policy (default: Taiwan PKI, no self-signed certificates):
 *   failed  — broken integrity, self-signed signer, revoked certificate,
 *             DocMDP violation, or a timestamp whose imprint/signature is invalid
 *   unknown — anything not proven: untrusted/incomplete chain, validity not
 *             established, revocation status unknown, untrusted TSA,
 *             unexplained changes after the last signature
 *   trusted — everything above proven
 */
export function determineSignatureStatus(input: SignatureStatusInput): VerificationStatus {
  const brokenTimestamp =
    input.timestampFailure === 'imprintMismatch' ||
    input.timestampFailure === 'signatureInvalid' ||
    input.timestampFailure === 'tsaRevoked'
  if (
    !input.integrityPassed ||
    input.selfSignedSigner ||
    input.signerCertUnsuitable ||
    input.revocation === 'revoked' ||
    input.docMdpViolation ||
    brokenTimestamp
  ) {
    return 'failed'
  }
  if (
    !input.chainTrusted ||
    !input.validityPassed ||
    input.revocation !== 'good' ||
    input.timestampFailure ||
    input.unexplainedChanges
  ) {
    return 'unknown'
  }
  return 'trusted'
}

// ─── Approval / certification signatures ─────────────────────────

async function verifySingleSignature(
  sigField: PdfSignatureField,
  index: number,
  ctx: DocContext
): Promise<SignatureResult> {
  const notVerified = () =>
    createSkippedCheck(t('core.check.skipped'), t('core.check.skippedDetails'), {
      key: 'core.check.skipped',
      detailsKey: 'core.check.skippedDetails',
    })
  const checks: SignatureResult['checks'] = {
    integrity: notVerified(),
    certificateChain: notVerified(),
    trustRoot: notVerified(),
    validity: notVerified(),
    revocation: notVerified(),
    timestamp: null,
    ltv: notVerified(),
  }

  let signerName = t('core.chain.unknownSigner')
  let signedAt: Date | null = null
  let certificateChain: CertificateInfo[] = []
  const fail = () => createSignatureResult(index, signerName, signedAt, 'failed', checks, certificateChain)

  try {
    // 1. ByteRange structure
    const byteRangeValidation = validateByteRange(ctx.pdfData, sigField.byteRange)
    if (!byteRangeValidation.isValid) {
      checks.integrity = createFailedCheck(
        t('core.integrity.byteRangeFailed'),
        byteRangeValidation.errors.join('; '),
        { key: 'core.integrity.byteRangeFailed' }
      )
      return fail()
    }

    // 2. CMS structure
    const pkcs7 = await parsePkcs7(sigField.contents)
    const signerInfo = pkcs7.signerInfos[0]
    const rawSignerInfo = pkcs7.signedData.signerInfos[0]
    if (!signerInfo || !rawSignerInfo) {
      checks.integrity = createFailedCheck(t('core.integrity.noSignerInfo'), undefined, { key: 'core.integrity.noSignerInfo' })
      return fail()
    }
    const signerCert = signerInfo.signerCertificate
    if (!signerCert) {
      checks.integrity = createFailedCheck(t('core.chain.signerCertNotFound'), undefined, { key: 'core.chain.signerCertNotFound' })
      checks.certificateChain = createFailedCheck(t('core.chain.signerCertNotFound'), undefined, { key: 'core.chain.signerCertNotFound' })
      return fail()
    }
    signerName = getCommonName(signerCert)
    signedAt = signerInfo.signingTime ?? pkcs7.embeddedTimestamp?.time ?? null

    // 3. Integrity: messageDigest over the signed byte ranges + CMS signature
    const integrity = await verifyIntegrity(ctx.pdfData, sigField, pkcs7, rawSignerInfo, signerCert, signerInfo)
    checks.integrity = integrity.check
    if (!integrity.passed) {
      // An algorithm we cannot verify is "cannot tell", not "invalid".
      if (integrity.unsupported) {
        checks.integrity = { ...checks.integrity, level: 'warning' }
        return createSignatureResult(index, signerName, signedAt, 'unknown', checks, certificateChain)
      }
      return fail()
    }

    const revInfo = mergeRevocationInfo(pkcs7.embeddedRevocationInfo, ctx.dss)
    const allowNetwork = ctx.options.checkOnlineRevocation !== false

    // 4–5. Certification path + trust anchor
    const chain = await buildCertificateChain(signerCert, pkcs7.certificates, {
      fetchMissing: allowNetwork,
      additionalCertBytes: revInfo?.certs ?? [],
    })
    certificateChain = toCertificateInfo(chain)
    const chainChecks = describeChain(chain)
    checks.certificateChain = chainChecks.certificateChain
    checks.trustRoot = chainChecks.trustRoot

    const unsuitableKey = signingUsageProblem(signerCert)
    if (unsuitableKey && !chain.selfSignedLeaf) {
      checks.certificateChain = createFailedCheck(t(unsuitableKey), undefined, { key: unsuitableKey })
      return createSignatureResult(index, signerName, signedAt, 'failed', checks, certificateChain)
    }

    if (chain.selfSignedLeaf) {
      checks.validity = notVerified()
      checks.revocation = notVerified()
      checks.ltv = notVerified()
      return createSignatureResult(index, signerName, signedAt, 'failed', checks, certificateChain)
    }

    // 6. Signature timestamp (RFC 3161 over the signature value)
    let timestampInfo: TimestampInfo | undefined
    let timestampFailure: TimestampFailure | null = null
    let tsaRevocation: ChainRevocation | null = null
    if (pkcs7.embeddedTimestamp && ctx.options.validateTimestamp !== false) {
      const ts = await verifyTimestampForData(pkcs7.embeddedTimestamp.raw, signerInfo.signatureValue, {
        extraCertBytes: revInfo?.certs ?? [],
        fetchMissing: allowNetwork,
      })
      // The TSA path must be proven unrevoked at genTime before its time is used.
      if (ts.valid && ts.info && ts.tsaChain) {
        tsaRevocation = await checkChainRevocation(ts.tsaChain, {
          embedded: revInfo,
          allowOnline: allowNetwork,
          freshOnline: ctx.options.refreshRevocation,
          atTime: ts.info.time,
          atTimeTrusted: true,
        })
      }
      // genTime is the TSA's own claim: if its key was compromised, any time
      // it states is suspect, so such a revocation invalidates every token.
      const tsaKeyCompromised =
        !!tsaRevocation?.leaf.revokedAfterSigning &&
        ['keyCompromise', 'caCompromise', 'unspecified', undefined].includes(tsaRevocation.leaf.evidence?.reason)
      const tsaRevocationFailure: TimestampFailure | null =
        tsaRevocation?.status === 'revoked' || tsaKeyCompromised
          ? 'tsaRevoked'
          : tsaRevocation?.status === 'unknown'
            ? 'tsaRevocationUnknown'
            : null
      if (ts.valid && ts.info && !tsaRevocationFailure) {
        timestampInfo = ts.info
        signedAt = ts.info.time
        checks.timestamp = createPassedCheck(
          t('core.timestamp.verified'),
          t('core.timestamp.timeLabel', { time: ts.info.time.toISOString() }),
          { key: 'core.timestamp.verified', detailsKey: 'core.timestamp.timeLabel', detailsParams: { time: ts.info.time.toISOString() } }
        )
      } else if (tsaRevocationFailure) {
        timestampFailure = tsaRevocationFailure
        const detailsKey =
          tsaRevocationFailure === 'tsaRevoked' ? 'core.timestampVerifier.tsaRevoked' : 'core.timestampVerifier.tsaRevocationUnknown'
        checks.timestamp = createFailedCheck(t('core.timestamp.verificationFailed'), t(detailsKey, { tsa: ts.info?.issuer ?? '' }), {
          key: 'core.timestamp.verificationFailed',
          detailsKey,
          detailsParams: { tsa: ts.info?.issuer ?? '' },
        })
      } else {
        timestampFailure = ts.failure ?? 'parse'
        checks.timestamp = createFailedCheck(t('core.timestamp.verificationFailed'), ts.check.message, {
          key: 'core.timestamp.verificationFailed',
        })
      }
    } else if (!pkcs7.embeddedTimestamp) {
      checks.timestamp = createFailedCheck(t('core.timestamp.noTimestamp'), t('core.timestamp.noRfc3161'), {
        key: 'core.timestamp.noTimestamp',
        detailsKey: 'core.timestamp.noRfc3161',
      })
    }

    // Validation time: a trusted timestamp, otherwise "now". The signer's own
    // signingTime attribute is a claim, not evidence.
    const trustedTime = timestampInfo?.time ?? null
    const validationTime = trustedTime ?? new Date()

    // 7. Validity of every certificate in the path at the validation time
    checks.validity = describeValidity(chain, signerCert, trustedTime, validationTime)

    // 8. Revocation (signer + issuing CAs)
    const revCtx: RevocationContext = {
      embedded: revInfo,
      allowOnline: allowNetwork,
      freshOnline: ctx.options.refreshRevocation,
      atTime: validationTime,
      atTimeTrusted: trustedTime !== null,
    }
    const revocation = chain.isTrusted ? await checkChainRevocation(chain, revCtx) : null
    checks.revocation = describeRevocation(revocation, chain, signerCert)

    // 9. LTV (signer chain + TSA chain must be covered by validated embedded data)
    const coverage = [...(revocation?.coverage ?? []), ...(trustedTime && tsaRevocation ? tsaRevocation.coverage : [])]
    const archive = archiveTimestampsAfter(sigField, ctx)
    const ltvResult = checkLtvCompleteness(chain.certificates, revInfo, timestampInfo ?? null, {
      archiveTimestampCount: archive.length,
      archiveTimestampsHaveLtv: archive.map((a) => a.ltvCovered),
      revocationCoverage: chain.isTrusted ? coverage : [{ name: signerName, covered: false }],
    })
    checks.ltv = ltvResult.check

    // Expired signer certificate: validity rests on the trusted timestamp;
    // revocation must then come from embedded (LTV) data — online sources are
    // not consulted for expired certificates (see revocation-checker.ts).
    const signerExpiredNow = new Date() > signerCert.notAfter
    if (signerExpiredNow && checks.validity.passed && revocation?.leaf.source === 'embedded' && revocation.status === 'good') {
      checks.validity = createPassedCheck(t('core.validity.expiredWithLtv'), t('core.ltv.signedWithinValidity'), {
        key: 'core.validity.expiredWithLtv',
        detailsKey: 'core.ltv.signedWithinValidity',
      })
    }

    // Changes after signing (later revisions compared with this one)
    const changes = await assessChanges(sigField, ctx)
    const { docMdpViolation, unexplainedChanges } = changes
    checks.integrity = applyChangeAssessment(checks.integrity, changes)

    const status = determineSignatureStatus({
      integrityPassed: checks.integrity.passed,
      selfSignedSigner: false,
      chainTrusted: chain.isTrusted,
      validityPassed: checks.validity.passed,
      revocation: revocation?.status ?? 'unknown',
      timestampFailure,
      docMdpViolation,
      unexplainedChanges,
    })

    const rootCategory = chain.isTrusted && chain.root ? getAnchorCategory(chain.root) ?? undefined : undefined
    return createSignatureResult(index, signerName, signedAt, status, applyLevels(checks, timestampFailure), certificateChain, timestampInfo, sigField.reason, {
      rootCategory,
      validationTime,
      validationTimeSource: trustedTime ? 'timestamp' : 'current',
      type: sigField.docMdp ? 'certification' : 'approval',
      docMdp: sigField.docMdp,
      ltvLevel: ltvResult.level,
      subsequentChanges: changes.hasChanges
        ? [{ signatureIndex: -1, byteOffset: sigField.byteRange.start2 + sigField.byteRange.length2, permittedByDocMdp: !docMdpViolation }]
        : undefined,
    })
  } catch (error) {
    checks.integrity = createFailedCheck(
      t('core.error.verificationError'),
      error instanceof Error ? error.message : t('core.error.unknownError'),
      { key: 'core.error.verificationError' }
    )
    return fail()
  }
}

async function verifyIntegrity(
  pdfData: Uint8Array,
  sigField: PdfSignatureField,
  pkcs7: Awaited<ReturnType<typeof parsePkcs7>>,
  rawSignerInfo: Awaited<ReturnType<typeof parsePkcs7>>['signedData']['signerInfos'][number],
  signerCert: ParsedCertificate,
  signerInfo: Awaited<ReturnType<typeof parsePkcs7>>['signerInfos'][number]
): Promise<{ passed: boolean; unsupported?: boolean; check: CheckResult }> {
  const signedBytes = extractSignedBytes(pdfData, sigField.byteRange)

  // adbe.pkcs7.sha1: the encapsulated content is SHA-1(signed bytes).
  let content = signedBytes
  const eContent = getEncapsulatedContentBytes(pkcs7.signedData)
  if (eContent && eContent.length > 0) {
    const sha1 = await computeDigest('SHA-1', signedBytes)
    if (!compareBytes(sha1, eContent)) {
      return {
        passed: false,
        check: createFailedCheck(t('core.integrity.documentModified'), t('core.integrity.digestMismatch'), {
          key: 'core.integrity.documentModified',
          detailsKey: 'core.integrity.digestMismatch',
        }),
      }
    }
    content = eContent
  }

  const result = await verifyCmsSignerInfo(rawSignerInfo, signerCert.raw, content)
  if (!result.valid) {
    if (result.failure === 'digestMismatch') {
      return {
        passed: false,
        check: createFailedCheck(t('core.integrity.documentModified'), t('core.integrity.digestMismatch'), {
          key: 'core.integrity.documentModified',
          detailsKey: 'core.integrity.digestMismatch',
        }),
      }
    }
    const unsupported = result.failure === 'unsupportedDigest' || result.failure === 'unsupportedAlgorithm'
    const detailsKey = unsupported ? 'core.integrity.unsupportedDigest' : 'core.integrity.cryptoMismatch'
    return {
      passed: false,
      unsupported,
      check: createFailedCheck(t('core.integrity.signatureVerificationFailed'), t(detailsKey), {
        key: 'core.integrity.signatureVerificationFailed',
        detailsKey,
      }),
    }
  }

  // CAdES / ESS signing-certificate binding (protects against signer cert substitution)
  if (signerInfo.signingCertificateHash) {
    const algorithm = normalizeDigestAlgorithm(signerInfo.signingCertificateHashAlgorithm ?? 'SHA-256')
    const certDer = signerCert.der ?? new Uint8Array(signerCert.raw.toSchema().toBER())
    const actual = Array.from(await computeDigest(algorithm, certDer))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
    if (actual !== signerInfo.signingCertificateHash.toLowerCase()) {
      return {
        passed: false,
        check: createFailedCheck(
          t('core.integrity.signingCertMismatch'),
          t('core.integrity.cadesHashDetails', { expected: signerInfo.signingCertificateHash, actual }),
          {
            key: 'core.integrity.signingCertMismatch',
            detailsKey: 'core.integrity.cadesHashDetails',
            detailsParams: { expected: signerInfo.signingCertificateHash, actual },
          }
        ),
      }
    }
  }

  return {
    passed: true,
    check: createPassedCheck(t('core.integrity.integrityAndSignatureVerified'), undefined, {
      key: 'core.integrity.integrityAndSignatureVerified',
    }),
  }
}

// ─── Chain / validity / revocation descriptions ──────────────────

const NON_SIGNING_EKUS = new Set(['serverAuth', 'timeStamping', 'ocspSigning', 'codeSigning'])

/**
 * The signer certificate must be an end-entity certificate meant for
 * signatures: not a CA, keyUsage (if present) allows digitalSignature or
 * nonRepudiation, and the EKU (if present) is not limited to purposes such as
 * TLS servers, time-stamping or OCSP signing.
 */
export function signingUsageProblem(cert: ParsedCertificate): string | null {
  if (cert.isCA) return 'core.chain.signerIsCa'
  if (cert.keyUsagePresent && !cert.keyUsage.digitalSignature && !cert.keyUsage.nonRepudiation) {
    return 'core.chain.keyUsageNotForSigning'
  }
  if (cert.extKeyUsage.length > 0 && cert.extKeyUsage.every((eku) => NON_SIGNING_EKUS.has(eku))) {
    return 'core.chain.ekuNotForSigning'
  }
  return null
}

function describeChain(chain: CertificateChain): { certificateChain: CheckResult; trustRoot: CheckResult } {
  const count = chain.certificates.length
  if (chain.selfSignedLeaf) {
    return {
      certificateChain: createFailedCheck(t('core.chain.selfSignedNotSupported'), undefined, {
        key: 'core.chain.selfSignedNotSupported',
      }),
      trustRoot: createFailedCheck(t('core.trust.rootUntrusted'), t('core.trust.selfSignedNotSupported'), {
        key: 'core.trust.rootUntrusted',
        detailsKey: 'core.trust.selfSignedNotSupported',
      }),
    }
  }
  if (chain.isTrusted && chain.root) {
    const rootName = getCommonName(chain.root)
    return {
      certificateChain: createPassedCheck(
        t('core.chain.chainCompleteAndVerified'),
        t('core.chain.chainCompleteWithCount', { count }),
        { key: 'core.chain.chainCompleteAndVerified', detailsKey: 'core.chain.chainCompleteWithCount', detailsParams: { count } }
      ),
      trustRoot: createPassedCheck(t('core.trust.trusted'), t('core.chain.rootCa', { name: rootName }), {
        key: 'core.trust.trusted',
        detailsKey: 'core.chain.rootCa',
        detailsParams: { name: rootName },
      }),
    }
  }
  if (chain.isComplete && chain.root) {
    const rootName = getCommonName(chain.root)
    const empty = isTrustStoreEmpty()
    return {
      certificateChain: createFailedCheck(
        t('core.chain.chainVerifiedUntrustedRoot'),
        t('core.chain.chainCompleteWithCount', { count }),
        { key: 'core.chain.chainVerifiedUntrustedRoot', detailsKey: 'core.chain.chainCompleteWithCount', detailsParams: { count } }
      ),
      trustRoot: createFailedCheck(
        t('core.trust.rootUntrusted'),
        empty ? t('core.trust.storeEmpty') : t('core.trust.rootNotInStore', { name: rootName }),
        {
          key: 'core.trust.rootUntrusted',
          detailsKey: empty ? 'core.trust.storeEmpty' : 'core.trust.rootNotInStore',
          detailsParams: empty ? undefined : { name: rootName },
        }
      ),
    }
  }
  return {
    certificateChain: createFailedCheck(t('core.chain.chainIncomplete'), t('core.chain.cannotBuildChain'), {
      key: 'core.chain.chainIncomplete',
      detailsKey: 'core.chain.cannotBuildChain',
    }),
    trustRoot: createFailedCheck(t('core.trust.chainIncomplete'), t('core.trust.cannotBuildChain'), {
      key: 'core.trust.chainIncomplete',
      detailsKey: 'core.trust.cannotBuildChain',
    }),
  }
}

function describeValidity(
  chain: CertificateChain,
  signerCert: ParsedCertificate,
  trustedTime: Date | null,
  validationTime: Date
): CheckResult {
  const period = {
    from: signerCert.notBefore.toLocaleDateString(getLocale()),
    to: signerCert.notAfter.toLocaleDateString(getLocale()),
  }
  if (!isCertificateValid(signerCert, validationTime)) {
    if (validationTime < signerCert.notBefore) {
      return createFailedCheck(t('core.validity.notYetValid'), t('core.validity.validityPeriod', period), {
        key: 'core.validity.notYetValid',
        detailsKey: 'core.validity.validityPeriod',
        detailsParams: period,
      })
    }
    const key = trustedTime ? 'core.validity.notValidAtTimestamp' : 'core.validity.expiredNoTimestamp'
    return createFailedCheck(t(key), t('core.validity.validityPeriod', period), {
      key,
      detailsKey: 'core.validity.validityPeriod',
      detailsParams: period,
    })
  }
  for (const ca of chain.certificates.slice(1)) {
    if (!isCertificateValid(ca, validationTime)) {
      const name = getCommonName(ca)
      return createFailedCheck(t('core.validity.caNotValid', { name }), undefined, {
        key: 'core.validity.caNotValid',
        params: { name },
      })
    }
  }
  const key = trustedTime ? 'core.validity.validAtTimestamp' : 'core.validity.currentlyValid'
  return createPassedCheck(t(key), t('core.validity.validityPeriod', period), {
    key,
    detailsKey: 'core.validity.validityPeriod',
    detailsParams: period,
  })
}

interface ChainRevocation {
  status: 'good' | 'revoked' | 'unknown'
  leaf: CertRevocationOutcome
  revokedCa?: ParsedCertificate
  /** First issuing CA whose status could not be established. */
  unknownCa?: ParsedCertificate
  coverage: Array<{ name: string; covered: boolean }>
}

/**
 * Revocation for every non-anchor certificate of a trusted path.
 */
async function checkChainRevocation(chain: CertificateChain, ctx: RevocationContext): Promise<ChainRevocation> {
  const certs = chain.certificates
  const outcomes = await Promise.all(
    certs.slice(0, -1).map((cert, i) => checkCertificateRevocation(cert, certs[i + 1], ctx))
  )
  const coverage = outcomes.map((o, i) => ({ name: getCommonName(certs[i]), covered: !!o.embeddedEvidence && o.status === 'good' }))
  const revokedIndex = outcomes.findIndex((o) => o.status === 'revoked')
  const leaf = outcomes[0]
  if (revokedIndex >= 0) {
    return { status: 'revoked', leaf, revokedCa: revokedIndex > 0 ? certs[revokedIndex] : undefined, coverage }
  }
  // Every certificate of the path must be proven unrevoked.
  const unknownIndex = outcomes.findIndex((o, i) => i > 0 && o.status !== 'good')
  if (leaf.status === 'good' && unknownIndex > 0) {
    return { status: 'unknown', leaf, unknownCa: certs[unknownIndex], coverage }
  }
  return { status: leaf.status, leaf, coverage }
}

function describeRevocation(
  revocation: ChainRevocation | null,
  chain: CertificateChain,
  signerCert: ParsedCertificate
): CheckResult {
  if (!revocation) {
    return createFailedCheck(t('core.revocation.cannotVerify'), t('core.revocation.chainNotTrusted'), {
      key: 'core.revocation.cannotVerify',
      detailsKey: 'core.revocation.chainNotTrusted',
    })
  }
  if (revocation.status === 'revoked') {
    if (revocation.revokedCa) {
      const name = getCommonName(revocation.revokedCa)
      return createFailedCheck(t('core.revocation.revoked'), t('core.revocation.caRevoked', { name }), {
        key: 'core.revocation.revoked',
        detailsKey: 'core.revocation.caRevoked',
        detailsParams: { name },
      })
    }
    const date = revocation.leaf.evidence?.revokedAt?.toISOString() ?? '-'
    return createFailedCheck(t('core.revocation.revoked'), t('core.revocation.revokedAt', { date }), {
      key: 'core.revocation.revoked',
      detailsKey: 'core.revocation.revokedAt',
      detailsParams: { date },
    })
  }
  const leaf = revocation.leaf
  if (revocation.unknownCa) {
    const name = getCommonName(revocation.unknownCa)
    return createFailedCheck(t('core.revocation.cannotVerify'), t('core.revocation.caUnknown', { name }), {
      key: 'core.revocation.cannotVerify',
      detailsKey: 'core.revocation.caUnknown',
      detailsParams: { name },
    })
  }
  if (leaf.status === 'good' && leaf.evidence) {
    const kind = leaf.evidence.kind === 'ocsp' ? 'OCSP' : 'CRL'
    const evidenceParams = { kind, signer: leaf.evidence.signerName }
    if (leaf.revokedAfterSigning) {
      const date = leaf.evidence.revokedAt?.toISOString() ?? '-'
      return createPassedCheck(t('core.revocation.notRevokedMethod', { method: kind }), t('core.revocation.revokedAfterSigning', { date }), {
        key: 'core.revocation.notRevokedMethod',
        params: { method: kind },
        detailsKey: 'core.revocation.revokedAfterSigning',
        detailsParams: { date },
      })
    }
    if (leaf.source === 'embedded') {
      return createPassedCheck(t('core.revocation.notRevokedEmbedded'), t('core.revocation.evidence', evidenceParams), {
        key: 'core.revocation.notRevokedEmbedded',
        detailsKey: 'core.revocation.evidence',
        detailsParams: evidenceParams,
      })
    }
    return createPassedCheck(t('core.revocation.notRevokedMethod', { method: kind }), t('core.revocation.evidence', evidenceParams), {
      key: 'core.revocation.notRevokedMethod',
      params: { method: kind },
      detailsKey: 'core.revocation.evidence',
      detailsParams: evidenceParams,
    })
  }
  const expired = new Date() > signerCert.notAfter
  const detailsKey = expired && chain.isTrusted ? 'core.revocation.expiredNeedsLtv' : 'core.revocation.allFailed'
  return createFailedCheck(t('core.revocation.cannotVerify'), t(detailsKey), {
    key: 'core.revocation.cannotVerify',
    detailsKey,
  })
}

function toCertificateInfo(chain: CertificateChain): CertificateInfo[] {
  return chain.certificates.map((cert, i) => ({
    subject: cert.subject,
    issuer: cert.issuer,
    serialNumber: cert.serialNumber,
    notBefore: cert.notBefore,
    notAfter: cert.notAfter,
    isRoot: i === chain.certificates.length - 1 && cert.subject === cert.issuer,
    isTrusted: chain.isTrusted,
    fingerprint: cert.fingerprint,
  }))
}

// ─── Document timestamps (ETSI.RFC3161) ──────────────────────────

/**
 * Verify a DocTimeStamp: the TST imprint must equal the hash of the ByteRange
 * content, the TSA signature must verify and the TSA path must reach a TSA
 * trust anchor.
 */
async function verifyDocTimeStamp(
  sigField: PdfSignatureField,
  index: number,
  ctx: DocContext
): Promise<DocTimestampOutcome> {
  const label = () =>
    createSkippedCheck(t('core.check.skipped'), t('core.check.skippedDetails'), {
      key: 'core.check.skipped',
      detailsKey: 'core.check.skippedDetails',
    })
  const checks: SignatureResult['checks'] = {
    integrity: label(),
    certificateChain: label(),
    trustRoot: label(),
    validity: label(),
    revocation: label(),
    timestamp: null,
    ltv: label(),
  }
  const failedOutcome = (): DocTimestampOutcome => ({
    result: createSignatureResult(index, 'DocTimeStamp', null, 'failed', checks, []),
    trusted: false,
    ltvCovered: false,
  })

  try {
    const byteRangeValidation = validateByteRange(ctx.pdfData, sigField.byteRange)
    if (!byteRangeValidation.isValid) {
      checks.integrity = createFailedCheck(t('core.docTimestamp.byteRangeFailed'), byteRangeValidation.errors.join('; '), {
        key: 'core.docTimestamp.byteRangeFailed',
      })
      return failedOutcome()
    }

    const allowNetwork = ctx.options.checkOnlineRevocation !== false
    const signedBytes = extractSignedBytes(ctx.pdfData, sigField.byteRange)
    const ts = await verifyTimestampForData(sigField.contents, signedBytes, {
      extraCertBytes: ctx.dss?.certs ?? [],
      fetchMissing: allowNetwork,
    })
    const tsaName = ts.info?.issuer || 'DocTimeStamp'
    const signerName = `DocTimeStamp (${tsaName})`
    const tsaChain = ts.tsaChain
    const certificateChain = tsaChain ? toCertificateInfo(tsaChain) : []

    if (ts.failure === 'imprintMismatch' || ts.failure === 'signatureInvalid' || ts.failure === 'parse' || !ts.info) {
      checks.integrity = createFailedCheck(t('core.docTimestamp.verificationFailed'), ts.check.message, {
        key: 'core.docTimestamp.verificationFailed',
      })
      checks.timestamp = ts.check
      return {
        result: createSignatureResult(index, signerName, ts.info?.time ?? null, 'failed', checks, certificateChain),
        trusted: false,
        ltvCovered: false,
      }
    }

    const time = ts.info.time.toISOString()
    checks.integrity = createPassedCheck(t('core.docTimestamp.verified'), t('core.docTimestamp.tsaTime', { tsa: tsaName, time }), {
      key: 'core.docTimestamp.verified',
      detailsKey: 'core.docTimestamp.tsaTime',
      detailsParams: { tsa: tsaName, time },
    })
    checks.timestamp = ts.valid
      ? createPassedCheck(t('core.docTimestamp.timestampVerified'), t('core.docTimestamp.timeLabel', { time }), {
          key: 'core.docTimestamp.timestampVerified',
          detailsKey: 'core.docTimestamp.timeLabel',
          detailsParams: { time },
        })
      : ts.check

    if (tsaChain) {
      const chainChecks = describeChain(tsaChain)
      checks.certificateChain = chainChecks.certificateChain
      checks.trustRoot = chainChecks.trustRoot
    } else {
      checks.certificateChain = ts.check
      checks.trustRoot = ts.check
    }
    checks.validity =
      ts.failure === 'tsaCertNotValidAtTime' || ts.failure === 'tsaNotTimestampingCert'
        ? ts.check
        : tsaChain
        ? describeValidity(tsaChain, tsaChain.certificates[0], ts.info.time, ts.info.time)
        : ts.check

    let revocationStatus: 'good' | 'revoked' | 'unknown' = 'unknown'
    let ltvCovered = false
    if (ts.valid && tsaChain?.isTrusted) {
      const revCtx: RevocationContext = {
        embedded: ctx.dss,
        allowOnline: allowNetwork,
        freshOnline: ctx.options.refreshRevocation,
        atTime: ts.info.time,
        atTimeTrusted: true,
      }
      const revocation = await checkChainRevocation(tsaChain, revCtx)
      revocationStatus = revocation.status
      ltvCovered = revocation.coverage.every((c) => c.covered)
      checks.revocation = describeRevocation(revocation, tsaChain, tsaChain.certificates[0])
      checks.ltv = ltvCovered
        ? createPassedCheck(t('core.ltv.ltvComplete'), t('core.ltv.canLongTermVerify'), { key: 'core.ltv.ltvComplete', detailsKey: 'core.ltv.canLongTermVerify' })
        : createFailedCheck(t('core.ltv.ltvIncomplete'), t('core.ltv.missing', { items: revocation.coverage.filter((c) => !c.covered).map((c) => c.name).join(', ') }), {
            key: 'core.ltv.ltvIncomplete',
          })
    } else {
      checks.revocation = createFailedCheck(t('core.revocation.cannotVerify'), t('core.revocation.chainNotTrusted'), {
        key: 'core.revocation.cannotVerify',
        detailsKey: 'core.revocation.chainNotTrusted',
      })
    }

    const changes = await assessChanges(sigField, ctx)
    checks.integrity = applyChangeAssessment(checks.integrity, changes)
    const status = determineSignatureStatus({
      integrityPassed: checks.integrity.passed,
      selfSignedSigner: !!tsaChain?.selfSignedLeaf,
      chainTrusted: !!tsaChain?.isTrusted && ts.valid,
      validityPassed: checks.validity.passed,
      revocation: revocationStatus,
      timestampFailure: ts.valid ? null : ts.failure ?? 'parse',
      docMdpViolation: changes.docMdpViolation,
      unexplainedChanges: changes.unexplainedChanges,
    })

    return {
      result: createSignatureResult(index, signerName, ts.info.time, status, applyLevels(checks, ts.valid ? null : ts.failure ?? 'parse'), certificateChain, ts.info, undefined, {
        type: 'timestamp',
        rootCategory: tsaChain?.isTrusted && tsaChain.root ? getAnchorCategory(tsaChain.root) ?? undefined : undefined,
        validationTime: ts.info.time,
        validationTimeSource: 'timestamp',
      }),
      trusted: status === 'trusted',
      ltvCovered,
    }
  } catch (error) {
    checks.integrity = createFailedCheck(
      t('core.docTimestamp.verificationError'),
      error instanceof Error ? error.message : t('core.error.unknownError'),
      { key: 'core.docTimestamp.verificationError' }
    )
    return failedOutcome()
  }
}

const BROKEN_TIMESTAMP: Array<TimestampFailure | null> = ['imprintMismatch', 'signatureInvalid', 'tsaRevoked']

/**
 * Display severity for checks that did not pass:
 *   error (default) — leads to "failed",
 *   'warning'       — could not be confirmed, leads to "unknown",
 *   'info'          — advisory only (missing timestamp, LTV completeness).
 */
function applyLevels(checks: SignatureResult['checks'], timestampFailure: TimestampFailure | null): SignatureResult['checks'] {
  const withLevel = (c: CheckResult, level: 'warning' | 'info'): CheckResult => ({ ...c, level })
  const out = { ...checks }
  const pending = (c: CheckResult | null): c is CheckResult => !!c && !c.passed && !c.skipped

  if (out.integrity.passed && out.integrity.detailsI18nKey === 'core.integrity.unpermittedChanges') {
    out.integrity = withLevel(out.integrity, 'warning')
  } else if (pending(out.integrity) && out.integrity.detailsI18nKey === 'core.integrity.unsupportedDigest') {
    out.integrity = withLevel(out.integrity, 'warning')
  }
  if (pending(out.certificateChain) && ['core.chain.chainVerifiedUntrustedRoot', 'core.chain.chainIncomplete'].includes(out.certificateChain.i18nKey ?? '')) {
    out.certificateChain = withLevel(out.certificateChain, 'warning')
  }
  if (pending(out.trustRoot) && out.trustRoot.detailsI18nKey !== 'core.trust.selfSignedNotSupported') {
    out.trustRoot = withLevel(out.trustRoot, 'warning')
  }
  if (pending(out.validity)) out.validity = withLevel(out.validity, 'warning')
  if (pending(out.revocation) && out.revocation.i18nKey !== 'core.revocation.revoked') {
    out.revocation = withLevel(out.revocation, 'warning')
  }
  if (pending(out.timestamp)) {
    if (out.timestamp.i18nKey === 'core.timestamp.noTimestamp') out.timestamp = withLevel(out.timestamp, 'info')
    else if (!BROKEN_TIMESTAMP.includes(timestampFailure)) out.timestamp = withLevel(out.timestamp, 'warning')
  }
  if (pending(out.ltv)) out.ltv = withLevel(out.ltv, 'info')
  return out
}

interface ChangeAssessment {
  hasChanges: boolean
  docMdpViolation: boolean
  unexplainedChanges: boolean
  reason?: string
}

/**
 * Compare this signature's revision with the final document.
 * Permitted changes follow the certification signature's DocMDP level
 * (P1 → LTV/doc timestamps only, P2 → + signatures, P3 → + annotations);
 * without a certification signature, signatures and LTV data are permitted.
 * Not permitted → failed under DocMDP, unknown otherwise; changes that cannot
 * be analysed → unknown.
 */
async function assessChanges(sigField: PdfSignatureField, ctx: DocContext): Promise<ChangeAssessment> {
  const end = sigField.byteRange.start2 + sigField.byteRange.length2
  const policy: ChangePolicy = ctx.docMdpLevel === 1 ? 'ltv' : ctx.docMdpLevel === 3 ? 'annotations' : 'signing'
  const analysis = await ctx.changes.changesSince(end, policy)
  if (!analysis.hasChanges) return { hasChanges: false, docMdpViolation: false, unexplainedChanges: false }
  if (analysis.analysable && analysis.violations.length === 0) {
    return { hasChanges: true, docMdpViolation: false, unexplainedChanges: false }
  }
  const reason = analysis.violations.slice(0, 3).join('; ')
  if (analysis.analysable && ctx.docMdpLevel !== null) {
    return { hasChanges: true, docMdpViolation: true, unexplainedChanges: false, reason }
  }
  return { hasChanges: true, docMdpViolation: false, unexplainedChanges: true, reason }
}

function applyChangeAssessment(integrity: CheckResult, changes: ChangeAssessment): CheckResult {
  if (!changes.hasChanges || !integrity.passed) return integrity
  if (changes.docMdpViolation) {
    return createFailedCheck(t('core.integrity.docMdpViolation'), t('core.integrity.unpermittedChanges', { reason: changes.reason ?? '' }), {
      key: 'core.integrity.docMdpViolation',
      detailsKey: 'core.integrity.unpermittedChanges',
      detailsParams: { reason: changes.reason ?? '' },
    })
  }
  if (changes.unexplainedChanges) {
    return {
      ...integrity,
      details: t('core.integrity.unpermittedChanges', { reason: changes.reason ?? '' }),
      detailsI18nKey: 'core.integrity.unpermittedChanges',
      detailsI18nParams: { reason: changes.reason ?? '' },
    }
  }
  return { ...integrity, details: t('core.integrity.subsequentSignatures'), detailsI18nKey: 'core.integrity.subsequentSignatures' }
}

/** Trusted DocTimeStamps that cover this signature (archive timestamps, B-LTA). */
function archiveTimestampsAfter(sigField: PdfSignatureField, ctx: DocContext): DocTimestampOutcome[] {
  const end = sigField.byteRange.start2 + sigField.byteRange.length2
  const out: DocTimestampOutcome[] = []
  for (const [field, outcome] of ctx.docTimestamps) {
    if (outcome.trusted && field.byteRange.start2 + field.byteRange.length2 > end) out.push(outcome)
  }
  return out
}

// ─── helpers ─────────────────────────────────────────────────────

/**
 * Merge per-signature embedded revocation info with document-level DSS data.
 */
function mergeRevocationInfo(
  signatureInfo: EmbeddedRevocationInfo | null,
  dssInfo: EmbeddedRevocationInfo | null
): EmbeddedRevocationInfo | null {
  if (!signatureInfo && !dssInfo) {
    return null
  }

  return {
    ocspResponses: [...(signatureInfo?.ocspResponses || []), ...(dssInfo?.ocspResponses || [])],
    crls: [...(signatureInfo?.crls || []), ...(dssInfo?.crls || [])],
    certs: [...(signatureInfo?.certs || []), ...(dssInfo?.certs || [])],
  }
}

function createSignatureResult(
  index: number,
  signerName: string,
  signedAt: Date | null,
  status: SignatureResult['status'],
  checks: SignatureResult['checks'],
  certificateChain: CertificateInfo[],
  timestampInfo?: TimestampInfo,
  reason?: string,
  extras?: Partial<
    Pick<
      SignatureResult,
      'type' | 'docMdp' | 'ltvLevel' | 'subsequentChanges' | 'rootCategory' | 'validationTime' | 'validationTimeSource'
    >
  >
): SignatureResult {
  return {
    index,
    signerName,
    signedAt,
    reason,
    status,
    checks,
    certificateChain,
    timestampInfo,
    ...extras,
  }
}
