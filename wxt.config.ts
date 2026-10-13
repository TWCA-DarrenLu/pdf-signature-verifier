import { defineConfig } from 'wxt'
import type { Plugin } from 'vite'

/**
 * Strip remote CDN URLs embedded in jsPDF's minified source.
 * Chrome Web Store rejects MV3 extensions that contain references
 * to remotely hosted code, even if the URL is never fetched at runtime.
 */
function stripRemoteCodeReferences(): Plugin {
  return {
    name: 'strip-remote-code-references',
    enforce: 'pre',
    transform(code, id) {
      if (!id.includes('jspdf')) return null
      const cleaned = code.replace(
        /https?:\/\/cdnjs\.cloudflare\.com\/ajax\/libs\/pdfobject\/[^"'\s]*/g,
        ''
      )
      if (cleaned !== code) return { code: cleaned, map: null }
      return null
    },
  }
}

export default defineConfig({
  srcDir: 'src',
  modules: ['@wxt-dev/module-react'],
  vite: () => ({
    plugins: [stripRemoteCodeReferences()],
  }),
  manifest: ({ browser }) => ({
    name: 'PDFtrust - PDF 數位簽章驗證工具',
    description: 'Verify PDF digital signatures — integrity, certificate chain, trust, timestamp, revocation & LTV. Taiwan PKI (GRCA, TWCA, Chunghwa).',
    version: '1.0.4',
    permissions: ['activeTab', 'storage', 'downloads', 'alarms'],
    host_permissions: ['<all_urls>'],
    icons: {
      16: 'icon-16.png',
      32: 'icon-32.png',
      48: 'icon-48.png',
      128: 'icon-128.png',
    },
    web_accessible_resources: [
      {
        resources: ['panel.html', 'chunks/*', 'assets/*'],
        matches: ['http://*/*', 'https://*/*', 'file://*/*'],
      },
    ],
    browser_specific_settings: browser === 'firefox'
      ? {
          gecko: {
            id: 'pdftrust@darrenlu.com',
            strict_min_version: '109.0',
            data_collection_permissions: {
              required: ['none'],
            },
          },
        }
      : undefined,
  }),
  runner: {
    startUrls: ['https://example.com'],
  },
})
