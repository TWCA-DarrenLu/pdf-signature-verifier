/**
 * Where PDFs are verified automatically when opened in the browser viewer.
 *   all    — every website (default)
 *   listed — only the sites in `autoVerifySites` (subdomains included)
 *   off    — never; the user clicks "verify"
 * Settings saved by earlier versions only have the boolean `autoVerify`.
 */
export type AutoVerifyScope = 'all' | 'listed' | 'off'

export interface AutoVerifySettings {
  autoVerify?: boolean
  autoVerifyScope?: AutoVerifyScope
  autoVerifySites?: string[]
}

export function resolveAutoVerifyScope(settings: AutoVerifySettings | null | undefined): AutoVerifyScope {
  if (settings?.autoVerifyScope) return settings.autoVerifyScope
  return settings?.autoVerify === false ? 'off' : 'all'
}

/** "https://www.Example.com:8443/path" / "*.example.com" → "www.example.com" / "example.com" */
export function normalizeSite(input: string): string {
  let site = input.trim().toLowerCase()
  site = site.replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
  site = site.replace(/[/?#].*$/, '')
  site = site.replace(/:\d+$/, '')
  site = site.replace(/^\*\./, '').replace(/^\.+|\.+$/g, '')
  return site
}

export function parseSiteList(text: string): string[] {
  const sites = text.split(/[\s,，;；]+/).map(normalizeSite).filter(Boolean)
  return [...new Set(sites)]
}

export function shouldAutoVerify(settings: AutoVerifySettings | null | undefined, hostname: string): boolean {
  const scope = resolveAutoVerifyScope(settings)
  if (scope === 'all') return true
  if (scope === 'off') return false
  const host = hostname.toLowerCase()
  return (settings?.autoVerifySites ?? [])
    .map(normalizeSite)
    .some((site) => site !== '' && (host === site || host.endsWith(`.${site}`)))
}
