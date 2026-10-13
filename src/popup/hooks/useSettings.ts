import { useState, useEffect, useCallback } from 'react'
import { resolveAutoVerifyScope, type AutoVerifyScope } from '@/settings/auto-verify'

export interface Settings {
  /** Superseded by autoVerifyScope; kept in sync for older readers. */
  autoVerify: boolean
  autoVerifyScope: AutoVerifyScope
  autoVerifySites: string[]
  checkOnlineRevocation: boolean
  language: 'zh-TW' | 'en'
}

const DEFAULT_SETTINGS: Settings = {
  autoVerify: true,
  autoVerifyScope: 'all',
  autoVerifySites: [],
  checkOnlineRevocation: false,
  language: 'zh-TW',
}

/** Stored settings may predate autoVerifyScope (only the boolean autoVerify). */
function withDefaults(stored: Partial<Settings>): Settings {
  return { ...DEFAULT_SETTINGS, ...stored, autoVerifyScope: resolveAutoVerifyScope(stored) }
}

const STORAGE_KEY = 'pdf-verifier-settings'

export function useSettings() {
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS)
  const [isLoading, setIsLoading] = useState(true)

  // Load settings on mount
  useEffect(() => {
    loadSettings().then((loaded) => {
      setSettings(loaded)
      setIsLoading(false)
    })
  }, [])

  const updateSettings = useCallback(async (updates: Partial<Settings>) => {
    const newSettings = { ...settings, ...updates }
    newSettings.autoVerify = newSettings.autoVerifyScope !== 'off'
    setSettings(newSettings)
    await saveSettings(newSettings)
  }, [settings])

  const resetSettings = useCallback(async () => {
    setSettings(DEFAULT_SETTINGS)
    await saveSettings(DEFAULT_SETTINGS)
  }, [])

  return {
    settings,
    isLoading,
    updateSettings,
    resetSettings,
  }
}

async function loadSettings(): Promise<Settings> {
  try {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      const result = await chrome.storage.local.get(STORAGE_KEY)
      if (result[STORAGE_KEY]) {
        return withDefaults(result[STORAGE_KEY])
      }
    } else {
      const stored = localStorage.getItem(STORAGE_KEY)
      if (stored) {
        return withDefaults(JSON.parse(stored))
      }
    }
  } catch {
    console.warn('Failed to load settings')
  }
  return DEFAULT_SETTINGS
}

async function saveSettings(settings: Settings): Promise<void> {
  try {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      await chrome.storage.local.set({ [STORAGE_KEY]: settings })
    } else {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(settings))
    }
  } catch {
    console.warn('Failed to save settings')
  }
}
