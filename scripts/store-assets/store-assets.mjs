// Usage: node scripts/store-assets/store-assets.mjs <repoRoot> <outDir>
// Store icon 128, Edge logo 300, small promo tiles 440x280 (zh-TW / en) from src/public/icon.svg.
import { createRequire } from 'node:module'
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'

const [repo, outDir] = process.argv.slice(2)
const require = createRequire(join(repo, 'package.json'))
const { chromium } = require('@playwright/test')
mkdirSync(outDir, { recursive: true })
const icon = `data:image/svg+xml;base64,${readFileSync(join(repo, 'src/public/icon.svg')).toString('base64')}`

const browser = await chromium.launch({ channel: 'chromium' })
const page = await browser.newPage({ deviceScaleFactor: 1 })

async function raster(size, padding, out) {
  const png = await page.evaluate(({ src, size, padding }) => new Promise((resolve) => {
    const img = new Image()
    img.onload = () => {
      const c = document.createElement('canvas'); c.width = size; c.height = size
      c.getContext('2d').drawImage(img, padding, padding, size - 2 * padding, size - 2 * padding)
      resolve(c.toDataURL('image/png').split(',')[1])
    }
    img.src = src
  }), { src: icon, size, padding })
  writeFileSync(join(outDir, out), Buffer.from(png, 'base64'))
}
await raster(128, 16, 'chrome-store-icon-128.png') // 96px artwork + 16px transparent padding
await raster(300, 20, 'edge-logo-300.png')

const tiles = {
  'zh-TW': { name: 'PDFtrust', line: 'PDF 數位簽章驗證', sub: '開啟即驗證・台灣 PKI・LTV' },
  en: { name: 'PDFtrust', line: 'PDF signature verifier', sub: 'Verify on open · Taiwan PKI · LTV' },
}
for (const [lang, t] of Object.entries(tiles)) {
  await page.setViewportSize({ width: 440, height: 280 })
  await page.setContent(`<!doctype html><meta charset="utf-8"><style>
    body{margin:0;width:440px;height:280px;display:flex;align-items:center;gap:22px;padding:0 34px;box-sizing:border-box;
      background:linear-gradient(135deg,#ffffff,#dbeafe);font-family:"Microsoft JhengHei","Segoe UI",sans-serif;color:#0f172a}
    img{width:120px;height:120px;filter:drop-shadow(0 6px 14px rgba(30,58,138,.25))}
    .n{font-size:38px;font-weight:700;letter-spacing:.5px}.l{font-size:21px;margin-top:4px;color:#1e3a8a}.s{font-size:14px;margin-top:10px;color:#475569}
  </style><img src="${icon}"><div><div class="n">${t.name}</div><div class="l">${t.line}</div><div class="s">${t.sub}</div></div>`)
  await page.waitForTimeout(300)
  await page.screenshot({ path: join(outDir, `promo-small-440x280-${lang}.png`) })
}
await browser.close()
console.log('done')
