import { getCheckState, type VerificationResult, type SignatureResult, type CertificateInfo, type CheckResult } from '@/types'
import { t, getLocale, resolveCheck, resolveSummary } from '@/i18n'

function formatDate(date: Date | null | undefined): string {
  if (!date) return '-'
  try {
    return new Date(date).toLocaleString(getLocale(), {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    })
  } catch {
    return String(date)
  }
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function statusColor(status: string): string {
  switch (status) {
    case 'trusted':
      return '#16a34a'
    case 'failed':
      return '#dc2626'
    default:
      return '#d97706'
  }
}

function statusLabel(status: string): string {
  switch (status) {
    case 'trusted':
      return 'TRUSTED'
    case 'failed':
      return 'FAILED'
    default:
      return 'UNKNOWN'
  }
}

function statusLabelZh(status: string): string {
  switch (status) {
    case 'trusted':
      return t('report.statusTrusted')
    case 'failed':
      return t('report.statusFailed')
    default:
      return t('report.statusUnknown')
  }
}

function checkIcon(passed: boolean): string {
  if (passed) {
    return '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="#16a34a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;vertical-align:middle;"><path d="M3 8.5l3.5 3.5L13 4"/></svg>'
  }
  return '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="#dc2626" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;vertical-align:middle;"><path d="M4 4l8 8M12 4l-8 8"/></svg>'
}

/** Same states as the panel: skipped, warning and info are not failures. */
function checkStateIcon(check: CheckResult): string {
  const svg = (color: string, path: string) =>
    `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;vertical-align:middle;">${path}</svg>`
  switch (getCheckState(check)) {
    case 'skipped': return svg('#9ca3af', '<path d="M4 8h8"/>')
    case 'warning': return svg('#d97706', '<path d="M8 2L1.5 13.5h13L8 2z"/><path d="M8 6.5v3M8 11.5v.01"/>')
    case 'info': return svg('#64748b', '<circle cx="8" cy="8" r="6.5"/><path d="M8 7.5v4M8 5v.01"/>')
    case 'pass': return checkIcon(true)
    default: return checkIcon(false)
  }
}

function renderCheckRow(label: string, check: CheckResult | null): string {
  if (!check) return ''
  const resolved = resolveCheck(check)
  return `
    <tr>
      <td style="padding:6px 12px;border:1px solid #e5e7eb;">${checkStateIcon(check)}</td>
      <td style="padding:6px 12px;border:1px solid #e5e7eb;">${escapeHtml(label)}</td>
      <td style="padding:6px 12px;border:1px solid #e5e7eb;">${escapeHtml(resolved.message)}${resolved.details ? `<br><span style="color:#6b7280;font-size:0.85em;">${escapeHtml(resolved.details)}</span>` : ''}</td>
    </tr>`
}

function renderCertRow(cert: CertificateInfo): string {
  return `
    <div class="cert-row" style="padding:8px 12px;border:1px solid #e5e7eb;border-top:none;font-size:0.85em;display:flex;gap:8px;">
      <div style="flex:2;min-width:0;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(cert.subject)}</div>
      <div style="flex:2;min-width:0;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(cert.issuer)}</div>
      <div style="flex:1;white-space:nowrap;">${formatDate(cert.notBefore)}</div>
      <div style="flex:1;white-space:nowrap;">${formatDate(cert.notAfter)}</div>
      <div style="width:60px;text-align:center;">${cert.isRoot ? 'Root' : ''} ${cert.isTrusted ? checkIcon(true) : checkIcon(false)}</div>
    </div>`
}

function renderCertTable(certs: CertificateInfo[]): string {
  if (certs.length === 0) return `<p style="color:#6b7280;">${t('report.noCertChain')}</p>`

  const header = `
    <div style="display:flex;gap:8px;background:#f3f4f6;padding:6px 12px;border:1px solid #e5e7eb;font-size:0.85em;font-weight:600;">
      <div style="flex:2;">${t('report.certSubject')}</div>
      <div style="flex:2;">${t('report.certIssuer')}</div>
      <div style="flex:1;">${t('report.certNotBefore')}</div>
      <div style="flex:1;">${t('report.certNotAfter')}</div>
      <div style="width:60px;text-align:center;">${t('report.certTrust')}</div>
    </div>`

  const rows = certs.map((cert) => renderCertRow(cert)).join('')

  return `<div style="margin-top:8px;">${header}${rows}</div>`
}

function renderSignature(sig: SignatureResult, index: number): string {
  const checks = sig.checks

  // Each check row is its own block to avoid cutting
  const checkRows = [
    { label: t('report.integrity'), check: checks.integrity },
    { label: t('report.certificateChain'), check: checks.certificateChain },
    { label: t('report.trustRoot'), check: checks.trustRoot },
    { label: t('report.validityPeriod'), check: checks.validity },
    { label: t('report.revocationStatus'), check: checks.revocation },
    { label: t('report.timestampLabel'), check: checks.timestamp },
    { label: t('report.longTermValidation'), check: checks.ltv },
  ]
    .filter(({ check }) => check !== null)
    .map(({ label, check }) => renderCheckRow(label, check))
    .join('')

  return `
    <div class="sig-section">
      <h3 style="font-size:1.1em;margin:0 0 12px 0;padding-bottom:8px;border-bottom:2px solid ${statusColor(sig.status)};">
        ${t('report.signatureNumber', { index: index + 1 })}
        <span style="float:right;color:${statusColor(sig.status)};font-weight:600;">${statusLabelZh(sig.status)}</span>
      </h3>

      <div class="sig-meta">
        <table style="width:100%;border-collapse:collapse;margin-bottom:12px;">
          <tr>
            <td style="padding:4px 0;color:#6b7280;width:100px;">${t('report.signer')}</td>
            <td style="padding:4px 0;font-weight:500;">${escapeHtml(sig.signerName)}</td>
          </tr>
          <tr>
            <td style="padding:4px 0;color:#6b7280;">${t('report.signedTime')}</td>
            <td style="padding:4px 0;">${formatDate(sig.signedAt)}</td>
          </tr>
          ${sig.reason ? `<tr><td style="padding:4px 0;color:#6b7280;">${t('report.signReason')}</td><td style="padding:4px 0;">${escapeHtml(sig.reason)}</td></tr>` : ''}
          ${sig.location ? `<tr><td style="padding:4px 0;color:#6b7280;">${t('report.signLocation')}</td><td style="padding:4px 0;">${escapeHtml(sig.location)}</td></tr>` : ''}
          ${sig.rootCategory ? `<tr><td style="padding:4px 0;color:#6b7280;">${t('report.regulation')}</td><td style="padding:4px 0;">${escapeHtml(t(sig.rootCategory === 'international' ? 'report.esaNotLicensed' : 'report.esaLicensed', { vendor: sig.rootVendor ?? '' }))}</td></tr>` : ''}
        </table>
      </div>

      <h4 style="font-size:0.95em;margin:16px 0 8px 0;">${t('report.verificationResult')}</h4>
      <table class="check-table" style="width:100%;border-collapse:collapse;font-size:0.9em;">
        <thead>
          <tr style="background:#f3f4f6;">
            <th style="padding:6px 12px;border:1px solid #e5e7eb;width:30px;"></th>
            <th style="padding:6px 12px;border:1px solid #e5e7eb;text-align:left;width:120px;">${t('report.checkItem')}</th>
            <th style="padding:6px 12px;border:1px solid #e5e7eb;text-align:left;">${t('report.checkDescription')}</th>
          </tr>
        </thead>
        <tbody>
          ${checkRows}
        </tbody>
      </table>

      <h4 style="font-size:0.95em;margin:16px 0 8px 0;">${t('report.certChainSection')}</h4>
      ${renderCertTable(sig.certificateChain)}

      ${
        sig.timestampInfo
          ? `
        <div class="ts-section">
          <h4 style="font-size:0.95em;margin:16px 0 8px 0;">${t('report.timestampInfo')}</h4>
          <table style="width:100%;border-collapse:collapse;font-size:0.9em;">
            <tr>
              <td style="padding:4px 0;color:#6b7280;width:120px;">${t('report.timestampTime')}</td>
              <td style="padding:4px 0;">${formatDate(sig.timestampInfo.time)}</td>
            </tr>
            <tr>
              <td style="padding:4px 0;color:#6b7280;">${t('report.timestampIssuer')}</td>
              <td style="padding:4px 0;">${escapeHtml(sig.timestampInfo.issuer)}</td>
            </tr>
            <tr>
              <td style="padding:4px 0;color:#6b7280;">${t('report.timestampHashAlg')}</td>
              <td style="padding:4px 0;">${escapeHtml(sig.timestampInfo.hashAlgorithm)}</td>
            </tr>
            <tr>
              <td style="padding:4px 0;color:#6b7280;">${t('report.timestampStatus')}</td>
              <td style="padding:4px 0;">${sig.timestampInfo.isValid ? checkIcon(true) + ' ' + t('report.timestampValid') : checkIcon(false) + ' ' + t('report.timestampInvalid')}</td>
            </tr>
          </table>
        </div>`
          : ''
      }
    </div>`
}

export function generateVerificationReport(result: VerificationResult): string {
  const now = formatDate(new Date())
  const color = statusColor(result.status)

  const signaturesHtml = result.signatures.map((sig, i) => renderSignature(sig, i)).join('')

  return `<!DOCTYPE html>
<html lang="${getLocale()}"
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${t('report.title')} - ${escapeHtml(result.fileName)}</title>
  <style>
    @media print {
      body { margin: 0; padding: 20px; }
      .no-print { display: none !important; }
      @page { size: A4; margin: 15mm; }
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft JhengHei", "PingFang TC", sans-serif;
      color: #1f2937;
      line-height: 1.6;
      max-width: 800px;
      margin: 0 auto;
      padding: 40px 24px;
      background: #fff;
    }
    h1 { font-size: 1.5em; margin: 0; }
    h2 { font-size: 1.2em; margin: 32px 0 16px 0; padding-bottom: 8px; border-bottom: 1px solid #e5e7eb; }

    /* Prevent page-break inside these blocks */
    .sig-section { margin-bottom: 24px; }
    .sig-meta,
    .check-table,
    .cert-row,
    .ts-section,
    .summary-box {
      break-inside: avoid;
      page-break-inside: avoid;
    }
    .check-table tr {
      break-inside: avoid;
      page-break-inside: avoid;
    }
  </style>
</head>
<body>
  <div style="text-align:center;margin-bottom:32px;">
    <h1>${t('report.title')}</h1>
    <p style="color:#6b7280;margin:8px 0 0 0;font-size:0.9em;">${t('report.subtitle')}</p>
  </div>

  <div class="summary-box" style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:16px 20px;margin-bottom:24px;">
    <table style="width:100%;border-collapse:collapse;">
      <tr>
        <td style="padding:4px 0;color:#6b7280;width:100px;">${t('report.fileName')}</td>
        <td style="padding:4px 0;font-weight:500;">${escapeHtml(result.fileName)}</td>
      </tr>
      <tr>
        <td style="padding:4px 0;color:#6b7280;">${t('report.verifyTime')}</td>
        <td style="padding:4px 0;">${now}</td>
      </tr>
      <tr>
        <td style="padding:4px 0;color:#6b7280;">${t('report.overallStatus')}</td>
        <td style="padding:4px 0;">
          <span style="display:inline-block;padding:2px 12px;border-radius:4px;color:#fff;background:${color};font-weight:600;font-size:0.9em;">
            ${statusLabel(result.status)} - ${statusLabelZh(result.status)}
          </span>
        </td>
      </tr>
      <tr>
        <td style="padding:4px 0;color:#6b7280;">${t('report.signatureCount')}</td>
        <td style="padding:4px 0;">${result.signatures.length}</td>
      </tr>
      <tr>
        <td style="padding:4px 0;color:#6b7280;">${t('report.summary')}</td>
        <td style="padding:4px 0;">${escapeHtml(resolveSummary(result))}</td>
      </tr>
    </table>
  </div>

  <h2>${t('report.signatureDetails')}</h2>
  ${signaturesHtml}

  <div style="margin-top:40px;padding-top:16px;border-top:1px solid #e5e7eb;text-align:center;color:#9ca3af;font-size:0.8em;">
    <p>${t('report.reportGenTime', { time: now })}</p>
    <p>${t('report.reportGenBy')}</p>
  </div>

</body>
</html>`
}
