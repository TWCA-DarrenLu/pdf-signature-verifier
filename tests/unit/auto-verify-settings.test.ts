import { describe, it, expect } from 'vitest'
import { normalizeSite, parseSiteList, resolveAutoVerifyScope, shouldAutoVerify } from '@/settings/auto-verify'

describe('auto-verify scope', () => {
  it('keeps settings saved before the scope existed', () => {
    expect(resolveAutoVerifyScope(undefined)).toBe('all')
    expect(resolveAutoVerifyScope({ autoVerify: true })).toBe('all')
    expect(resolveAutoVerifyScope({ autoVerify: false })).toBe('off')
    expect(resolveAutoVerifyScope({ autoVerify: false, autoVerifyScope: 'listed' })).toBe('listed')
  })

  it('normalizes what people paste as a site', () => {
    expect(normalizeSite(' https://www.TWCA.com.tw:8443/path?q=1 ')).toBe('www.twca.com.tw')
    expect(normalizeSite('*.gov.tw')).toBe('gov.tw')
    expect(parseSiteList('twca.com.tw\nhttps://gov.tw/x, twca.com.tw；moica.nat.gov.tw')).toEqual([
      'twca.com.tw',
      'gov.tw',
      'moica.nat.gov.tw',
    ])
  })

  it('matches listed sites and their subdomains only', () => {
    const settings = { autoVerifyScope: 'listed' as const, autoVerifySites: ['twca.com.tw', 'gov.tw'] }
    expect(shouldAutoVerify(settings, 'twca.com.tw')).toBe(true)
    expect(shouldAutoVerify(settings, 'www.twca.com.tw')).toBe(true)
    expect(shouldAutoVerify(settings, 'moica.nat.gov.tw')).toBe(true)
    expect(shouldAutoVerify(settings, 'nottwca.com.tw')).toBe(false)
    expect(shouldAutoVerify(settings, 'twca.com.tw.evil.example')).toBe(false)
    expect(shouldAutoVerify({ autoVerifyScope: 'listed' }, 'twca.com.tw')).toBe(false)
  })

  it('all / off ignore the list', () => {
    expect(shouldAutoVerify({ autoVerifyScope: 'all', autoVerifySites: [] }, 'example.com')).toBe(true)
    expect(shouldAutoVerify({ autoVerifyScope: 'off', autoVerifySites: ['example.com'] }, 'example.com')).toBe(false)
  })
})
