import { useState } from 'react'
import { getCheckState, type SignatureResult } from '@/types'
import { t, getLocale, resolveCheck } from '@/i18n'
import { VerificationDetails } from './VerificationDetails'
import { CertificateChain } from './CertificateChain'
import { CheckIcon, XIcon, WarningIcon } from './icons'

interface SignatureCardProps {
  signature: SignatureResult
}

function getSignatureStatusLabel(status: 'trusted' | 'unknown' | 'failed'): string {
  switch (status) {
    case 'trusted': return t('signature.valid')
    case 'unknown': return t('signature.statusUnknown')
    case 'failed': return t('signature.invalid')
  }
}

const statusConfig = {
  trusted: {
    Icon: CheckIcon,
    badgeBg: 'bg-green-100',
    badgeText: 'text-green-800',
    borderColor: 'border-green-300',
    headerBg: 'bg-green-50',
  },
  unknown: {
    Icon: WarningIcon,
    badgeBg: 'bg-yellow-100',
    badgeText: 'text-yellow-800',
    borderColor: 'border-yellow-300',
    headerBg: 'bg-yellow-50',
  },
  failed: {
    Icon: XIcon,
    badgeBg: 'bg-red-100',
    badgeText: 'text-red-800',
    borderColor: 'border-red-300',
    headerBg: 'bg-red-50',
  },
} as const

export function SignatureCard({ signature }: SignatureCardProps) {
  const [expanded, setExpanded] = useState(true)

  const config = statusConfig[signature.status]
  const { Icon } = config

  const formatDate = (date: Date | null) => {
    if (!date) return t('signature.unknown')
    return date.toLocaleString(getLocale(), {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  // Checks that explain a "not fully verified" or "invalid" verdict
  const reasonLabels: Record<string, string> = {
    integrity: t('checks.integrity'),
    certificateChain: t('checks.signerIdentity'),
    trustRoot: t('checks.rootCert'),
    validity: t('checks.validity'),
    revocation: t('checks.revocation'),
    timestamp: t('checks.timestamp'),
  }
  const reasons =
    signature.status === 'trusted'
      ? []
      : Object.entries(signature.checks)
          .filter(([key, check]) => check && key in reasonLabels && ['error', 'warning'].includes(getCheckState(check)))
          .sort(([, a], [, b]) => Number(getCheckState(a!) !== 'error') - Number(getCheckState(b!) !== 'error'))
          .slice(0, 2)
          .map(([key, check]) => `${reasonLabels[key]}：${resolveCheck(check!).message}`)

  // Regulatory status of the trusted root (shown after the chain is verified)
  const regulation = signature.rootCategory
    ? signature.rootCategory === 'international'
      ? { licensed: false, text: t('signature.esaNotLicensed', { vendor: signature.rootVendor ?? '' }) }
      : { licensed: true, text: t('signature.esaLicensed', { vendor: signature.rootVendor ?? '' }) }
    : null

  const validationBasis = signature.validationTimeSource
    ? signature.validationTimeSource === 'timestamp' && signature.validationTime
      ? t('signature.validationByTimestamp', { time: formatDate(signature.validationTime) })
      : t('signature.validationByCurrent')
    : null

  const getRootCA = () => {
    const rootCert = signature.certificateChain.find((c) => c.isRoot)
    if (rootCert) {
      const cn = rootCert.subject.match(/CN=([^,]+)/)?.[1]
      return cn || rootCert.subject.split(',')[0]
    }
    return null
  }

  return (
    <div className={`border ${config.borderColor} rounded-lg overflow-hidden shadow-sm`}>
      {/* Header - always visible summary */}
      <button
        onClick={() => setExpanded(!expanded)}
        className={`w-full px-4 py-3 ${config.headerBg} text-left`}
      >
        <div className="flex items-center gap-3">
          {/* Status badge */}
          <span
            className={`inline-flex items-center gap-1.5 ${config.badgeBg} ${config.badgeText} px-3 py-1 rounded-full text-sm font-bold flex-shrink-0`}
          >
            <Icon className="inline-block" />
            <span>{getSignatureStatusLabel(signature.status)}</span>
          </span>

          <div className="flex-1" />

          <svg
            className={`w-5 h-5 text-gray-500 transition-transform flex-shrink-0 ${expanded ? 'rotate-180' : ''}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>

        {/* Signer info - always visible */}
        <div className="mt-2 space-y-0.5 text-sm">
          <div className="text-gray-800">
            <span className="text-gray-500">{t('signature.signer')}</span>
            <span className="font-medium">{signature.signerName}</span>
          </div>
          <div className="text-gray-600">
            <span className="text-gray-500">{t('signature.signedAt')}</span>
            {formatDate(signature.signedAt)}
          </div>
          {signature.reason && (
            <div className="text-gray-600">
              <span className="text-gray-500">{t('signature.reason')}</span>
              {signature.reason}
            </div>
          )}
          {signature.location && (
            <div className="text-gray-600">
              <span className="text-gray-500">{t('signature.location')}</span>
              {signature.location}
            </div>
          )}
          {validationBasis && (
            <div className="text-gray-600">
              <span className="text-gray-500">{t('signature.validationBasis')}</span>
              {validationBasis}
            </div>
          )}
          {regulation && (
            <div className={regulation.licensed ? 'text-green-700' : 'text-slate-600'} data-testid="signature-regulation">
              {regulation.text}
            </div>
          )}
          {reasons.length > 0 && (
            <div className={signature.status === 'failed' ? 'text-red-700' : 'text-amber-700'}>
              <span className="font-medium">{t('signature.reasons')}</span>
              {reasons.join('；')}
            </div>
          )}
        </div>
      </button>

      {/* Expanded details */}
      {expanded && (
        <div className="border-t border-gray-200">
          {/* Verification checks */}
          <div className="px-4 py-3">
            <VerificationDetails
              checks={signature.checks}
              chainLength={signature.certificateChain.length}
              rootCA={getRootCA()}
              rootCategory={signature.rootCategory}
            />
          </div>

          {/* Certificate chain */}
          {signature.certificateChain.length > 0 && (
            <div className="border-t border-gray-100 px-4 py-3">
              <CertificateChain certificates={signature.certificateChain} />
            </div>
          )}

          {/* Timestamp info */}
          {signature.timestampInfo && (
            <div className="border-t border-gray-100 px-4 py-3">
              <div className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">
                {t('timestamp.title')}
              </div>
              <div className="bg-gray-50 rounded-lg p-3 text-sm space-y-1.5">
                <div className="flex items-start gap-2">
                  <span className="text-gray-400 flex-shrink-0">{t('timestamp.time')}</span>
                  <span className="text-gray-800 font-mono text-xs">
                    {signature.timestampInfo.time.toLocaleString(getLocale(), {
                      year: 'numeric',
                      month: '2-digit',
                      day: '2-digit',
                      hour: '2-digit',
                      minute: '2-digit',
                      second: '2-digit',
                      fractionalSecondDigits: 3,
                    } as Intl.DateTimeFormatOptions)}
                  </span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="text-gray-400 flex-shrink-0">{t('timestamp.tsa')}</span>
                  <span className="text-gray-800">{signature.timestampInfo.issuer}</span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="text-gray-400 flex-shrink-0">{t('timestamp.hashAlgorithm')}</span>
                  <span className="text-gray-800">{signature.timestampInfo.hashAlgorithm}</span>
                </div>
                {signature.timestampInfo.serialNumber && (
                  <div className="flex items-start gap-2">
                    <span className="text-gray-400 flex-shrink-0">{t('timestamp.serial')}</span>
                    <span className="text-gray-800 font-mono text-[10px] break-all">
                      {signature.timestampInfo.serialNumber}
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
