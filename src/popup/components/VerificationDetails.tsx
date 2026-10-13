import { useState } from 'react'
import { getCheckState, type CheckResult, type CheckState, type SignatureResult } from '@/types'
import { t, resolveCheck } from '@/i18n'
import { CheckIcon, XIcon, WarningIcon, InfoIcon, MinusIcon, ChevronRightIcon, ChevronDownIcon } from './icons'

interface VerificationDetailsProps {
  checks: SignatureResult['checks']
  chainLength?: number
  rootCA?: string | null
  rootCategory?: SignatureResult['rootCategory']
}

interface CheckRowProps {
  label: string
  check: CheckResult
  summary?: string
  badge?: string
}

// green ✓ / red ✗ / amber ⚠ / grey ⓘ / grey —
const stateStyle: Record<CheckState, { Icon: typeof CheckIcon; color: string }> = {
  pass: { Icon: CheckIcon, color: 'text-green-600' },
  error: { Icon: XIcon, color: 'text-red-600' },
  warning: { Icon: WarningIcon, color: 'text-amber-600' },
  info: { Icon: InfoIcon, color: 'text-slate-500' },
  skipped: { Icon: MinusIcon, color: 'text-gray-400' },
}

function CheckRow({ label, check, summary, badge }: CheckRowProps) {
  const [expanded, setExpanded] = useState(false)
  const resolved = resolveCheck(check)
  const { Icon: StatusIcon, color } = stateStyle[getCheckState(check)]
  const hasDetails = Boolean(resolved.details)
  const text = summary || resolved.message

  return (
    <div className="border-b border-gray-100 last:border-b-0">
      <button
        onClick={() => hasDetails && setExpanded(!expanded)}
        className={`w-full flex items-start gap-2 px-2 py-1.5 text-left text-sm ${
          hasDetails ? 'hover:bg-gray-50 cursor-pointer' : 'cursor-default'
        }`}
      >
        {/* Expand indicator */}
        <span className="text-gray-400 w-3 flex-shrink-0 mt-0.5">
          {hasDetails ? (
            expanded ? <ChevronDownIcon className="w-3 h-3" /> : <ChevronRightIcon className="w-3 h-3" />
          ) : (
            <span className="inline-block w-3" />
          )}
        </span>

        {/* Label */}
        <span className="text-gray-700 flex-shrink-0">{label}</span>

        {/* Summary on the right: wraps instead of truncating */}
        <span className={`${color} flex-1 min-w-0 text-xs font-medium flex items-start justify-end gap-1 text-right`} title={text}>
          <StatusIcon className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
          <span className="break-words">{text}</span>
          {badge && (
            <span className="ml-1 flex-shrink-0 rounded bg-blue-50 px-1.5 text-[10px] font-medium text-blue-700">{badge}</span>
          )}
        </span>
      </button>

      {/* Expanded details */}
      {expanded && resolved.details && (
        <div className="px-7 pb-2 text-xs text-gray-500 leading-relaxed whitespace-pre-wrap">
          {resolved.details}
        </div>
      )}
    </div>
  )
}

export function VerificationDetails({ checks, chainLength, rootCA, rootCategory }: VerificationDetailsProps) {
  const getSummary = (key: string, check: CheckResult): string => {
    if (check.skipped) return t('checks.skipped')
    if (!check.passed || check.level) {
      return resolveCheck(check).message
    }

    switch (key) {
      case 'integrity':
        return t('checks.verified')
      case 'certificateChain':
        return chainLength ? t('checks.chainComplete', { count: chainLength }) : t('checks.verified')
      case 'trustRoot':
        return rootCA ?? t('checks.trusted')
      case 'validity':
        return t('checks.valid')
      case 'revocation':
        return t('checks.notRevoked')
      case 'timestamp':
        return t('checks.verified')
      case 'ltv':
        return t('checks.complete')
      default:
        return resolveCheck(check).message
    }
  }

  const checkItems: { key: keyof typeof checks; label: string }[] = [
    { key: 'integrity', label: t('checks.integrity') },
    { key: 'certificateChain', label: t('checks.signerIdentity') },
    { key: 'trustRoot', label: t('checks.rootCert') },
    { key: 'validity', label: t('checks.validity') },
    { key: 'revocation', label: t('checks.revocation') },
    { key: 'timestamp', label: t('checks.timestamp') },
    { key: 'ltv', label: t('checks.ltv') },
  ]

  return (
    <div>
      <div className="border border-gray-200 rounded-lg overflow-hidden bg-white">
        {checkItems.map(({ key, label }) => {
          const check = checks[key]
          if (!check) return null
          const badge = key === 'trustRoot' && check.passed && rootCategory ? t(`trust.${rootCategory}`) : undefined
          return <CheckRow key={key} label={label} check={check} summary={getSummary(key, check)} badge={badge} />
        })}
      </div>
    </div>
  )
}
