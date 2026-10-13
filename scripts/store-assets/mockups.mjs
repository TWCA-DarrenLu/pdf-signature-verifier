// Usage: node scripts/store-assets/mockups.mjs <repoRoot> <outDir>
// Needs `npm run build` and PDF_Sample/hsm-signed-a.pdf + foreign-tsa.pdf (gitignored samples);
// their real verification results are shown with fictional names. See docs/release.md.
// Store screenshots as illustrated mock-ups (1280x800, zh-TW + en): a drawn browser
// window with a fictional document; the extension's real panel/popup UI rendered
// with fictional verification results (signer names and file names replaced).
import { createRequire } from 'node:module'
import { createServer } from 'node:http'
import { existsSync, readFileSync, mkdtempSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const [repo, outDir] = process.argv.slice(2)
const require = createRequire(join(repo, 'package.json'))
const { chromium } = require('@playwright/test')
const ext = join(repo, '.output', 'chrome-mv3')
mkdirSync(outDir, { recursive: true })
const icon = `data:image/svg+xml;base64,${readFileSync(join(repo, 'src/public/icon.svg')).toString('base64')}`

const server = createServer((req, res) => {
  const p = join(repo, 'PDF_Sample', decodeURIComponent((req.url ?? '/').slice(1).split('?')[0]))
  if (!existsSync(p)) return res.writeHead(404).end()
  res.writeHead(200, { 'Content-Type': 'application/pdf' }).end(readFileSync(p))
})
await new Promise((r) => server.listen(0, '127.0.0.1', r))
const base = `http://127.0.0.1:${server.address().port}`

// Fictional names per language (replace the real ones from the sample results)
const L = {
  'zh-TW': {
    trustedFile: '服務合約.pdf', partialFile: '報價單.pdf',
    signerA: '範例科技股份有限公司', signerB: '王小明', signerC: '範例顧問有限公司',
    docTitle: '服務合約', docTitle2: '報價單', party: '簽署人：範例科技股份有限公司', seal: '範例',
    detected: '偵測到 PDF 文件', trusted: '文件可信', unknown: '無法完整驗證',
    h1: '開啟 PDF 即自動驗證簽章', s1: '結果顯示在側邊面板，Chrome 與 Edge 皆可',
    h2: '無法完整驗證時，清楚列出原因', s2: '每項檢查以綠／紅／黃／灰標示，可一鍵重新檢查',
    h3a: '點工具列圖示，查看目前分頁的結果', s3a: '圖示直接標示 ✓ 文件可信／! 無法完整驗證／✗ 驗證失敗',
    h3b: '自動驗證範圍與國際憑證機構', s3b: '可限定網站；預設只信任台灣憑證，可選擇開啟國際精選憑證機構',
    h4: '拖放或按右鍵，也能驗證', s4: '已下載的 PDF 拖到通知列；網頁連結按右鍵選「驗證此 PDF 的數位簽章」',
    dropHere: '放開以驗證此 PDF', ctxItems: ['在新分頁中開啟連結', '另存連結為…', '複製連結網址'], ctxOurs: '驗證此 PDF 的數位簽章',
    linkPage: '文件下載', link1: '採購合約（PDF）', link2: '保密協議（PDF）',
  },
  en: {
    trustedFile: 'service-agreement.pdf', partialFile: 'quotation.pdf',
    signerA: 'Example Technology Co., Ltd.', signerB: 'Alex Chen', signerC: 'Example Consulting Ltd.',
    docTitle: 'Service Agreement', docTitle2: 'Quotation', party: 'Signed by: Example Technology Co., Ltd.', seal: 'SEAL',
    detected: 'PDF document detected', trusted: 'Trusted', unknown: 'Not fully verified',
    h1: 'Signatures are verified when you open a PDF', s1: 'Results appear in a side panel, in Chrome and Edge',
    h2: 'When a signature cannot be fully verified, you see why', s2: 'Every check is marked green / red / amber / grey, with one-click re-check',
    h3a: "Click the toolbar icon for this tab's result", s3a: 'The icon shows ✓ trusted / ! not fully verified / ✗ failed',
    h3b: 'Where to verify, which CAs to trust', s3b: 'Limit automatic verification to listed sites; Taiwan CAs by default, selected international CAs optional',
    h4: 'Drop a file or right-click a link', s4: 'Drop a downloaded PDF on the bar, or right-click a link: "Verify the digital signatures of this PDF"',
    dropHere: 'Drop to verify this PDF', ctxItems: ['Open link in new tab', 'Save link as…', 'Copy link address'], ctxOurs: 'Verify the digital signatures of this PDF',
    linkPage: 'Documents', link1: 'Purchase agreement (PDF)', link2: 'Non-disclosure agreement (PDF)',
  },
}

const ctx = await chromium.launchPersistentContext(mkdtempSync(join(tmpdir(), 'pdftrust-mock-')), {
  channel: 'chromium',
  viewport: { width: 1280, height: 800 },
  deviceScaleFactor: 1,
  args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
})
const worker = ctx.serviceWorkers()[0] ?? (await ctx.waitForEvent('serviceworker'))
const extId = new URL(worker.url()).host
const extPage = async () => {
  const p = await ctx.newPage()
  await p.goto(`chrome-extension://${extId}/popup.html`)
  return p
}

// Real verification results of two samples, then anonymised per language
const helper = await extPage()
const verify = (file) => helper.evaluate(([url, name]) => chrome.runtime.sendMessage({ action: 'verify-pdf-url', url, fileName: name }), [`${base}/${file}`, file])
const realTrusted = (await verify('hsm-signed-a.pdf')).result
const realPartial = (await verify('foreign-tsa.pdf')).result
if (realTrusted.status !== 'trusted' || realPartial.status !== 'unknown') throw new Error(`unexpected verdicts ${realTrusted.status} / ${realPartial.status}`)
await helper.close()

function anonymise(result, pairs) {
  let json = JSON.stringify(result)
  for (const [from, to] of pairs) json = json.split(from).join(to)
  return JSON.parse(json)
}

async function settings(language, extra = {}) {
  const p = await extPage()
  await p.evaluate((v) => chrome.storage.local.set({ 'pdf-verifier-settings': v }), {
    language, autoVerify: true, autoVerifyScope: 'all', autoVerifySites: [], checkOnlineRevocation: false, ...extra,
  })
  await p.close()
}

/** The real side panel showing `result`, as a PNG (420 wide). */
async function panelShot(result, height, collapseText) {
  const p = await ctx.newPage()
  await p.setViewportSize({ width: 420, height })
  await p.goto(`chrome-extension://${extId}/panel.html`)
  await p.evaluate((r) => window.postMessage({ type: 'pdf-verification-result', result: r, canRecheck: true }, '*'), result)
  await p.getByText(result.fileName).first().waitFor({ timeout: 10_000 })
  if (collapseText) await p.getByText(collapseText).first().click()
  await p.waitForTimeout(500)
  const png = await p.screenshot()
  await p.close()
  return png.toString('base64')
}

/** The real popup showing `result` as the current tab's result. */
async function popupResultShot(result) {
  const p = await extPage()
  await p.setViewportSize({ width: 400, height: 760 })
  const tabId = await p.evaluate(async () => (await chrome.tabs.getCurrent()).id)
  await p.evaluate(async ([id, r]) => {
    await chrome.storage.session.set({ [`tab-result:${id}`]: { state: r.status, result: r, source: { url: 'https://example.com/doc.pdf', fileName: r.fileName } } })
  }, [tabId, result])
  await p.getByText(result.fileName).first().waitFor({ timeout: 10_000 })
  await p.waitForTimeout(500)
  const png = await p.screenshot({ clip: { x: 0, y: 0, width: 400, height: 560 } })
  await p.close()
  return png.toString('base64')
}

async function settingsShot(lang) {
  await settings(lang, { autoVerifyScope: 'listed', autoVerifySites: ['example.com', 'gov.tw'] })
  const p = await extPage()
  await p.setViewportSize({ width: 400, height: 760 })
  await p.waitForTimeout(600)
  await p.locator('header button').last().click()
  await p.waitForTimeout(600)
  const png = await p.screenshot({ clip: { x: 0, y: 0, width: 400, height: 300 } })
  await p.close()
  await settings(lang)
  return png.toString('base64')
}

const CSS = `
  *{box-sizing:border-box} body{margin:0;width:1280px;height:800px;overflow:hidden;font-family:"Microsoft JhengHei","Segoe UI",sans-serif;background:linear-gradient(135deg,#eff6ff,#dbeafe);color:#0f172a}
  .head{position:absolute;left:48px;top:26px;right:48px} .head h2{margin:0;font-size:28px} .head p{margin:6px 0 0;font-size:16px;color:#334155}
  .win{position:absolute;left:48px;top:108px;width:1184px;height:672px;border-radius:12px;overflow:hidden;box-shadow:0 18px 50px rgba(15,23,42,.28);background:#525659}
  .tabs{height:34px;background:#dee1e6;display:flex;align-items:flex-end;padding-left:70px;gap:6px}
  .dots{position:absolute;left:14px;top:12px;display:flex;gap:7px}.dots i{width:11px;height:11px;border-radius:50%;display:block}
  .tab{height:28px;width:220px;background:#fff;border-radius:8px 8px 0 0;font-size:12px;padding:7px 12px;color:#334155;white-space:nowrap;overflow:hidden}
  .addr{height:38px;background:#fff;display:flex;align-items:center;gap:10px;padding:0 12px;border-bottom:1px solid #e5e7eb}
  .url{flex:1;height:26px;border-radius:13px;background:#f1f3f4;font-size:12.5px;color:#475569;padding:5px 14px}
  .ic{position:relative;width:20px;height:20px}.ic img{width:20px;height:20px}
  .bd{position:absolute;right:-7px;bottom:-5px;min-width:12px;height:12px;border-radius:3px;color:#fff;font:bold 9px/12px Arial;text-align:center;padding:0 2px}
  .bar{height:34px;background:#eff6ff;border-bottom:1px solid #bfdbfe;display:flex;align-items:center;justify-content:space-between;padding:0 14px;font-size:13px;color:#1e40af}
  .btn{color:#fff;border-radius:6px;padding:4px 12px;font-size:12.5px}
  .viewer{position:absolute;top:106px;left:0;right:0;bottom:0;display:flex;justify-content:center;padding-top:22px}
  .page{width:470px;height:600px;background:#fff;padding:46px 50px;box-shadow:0 2px 10px rgba(0,0,0,.35);margin-right:330px}
  .page h1{font-size:30px;margin:0 0 22px;text-align:center;letter-spacing:4px}
  .ln{height:9px;background:#e2e8f0;border-radius:4px;margin:11px 0}
  .sig{margin-top:34px;display:flex;align-items:center;justify-content:space-between}
  .sig .who{font-size:12.5px;color:#334155}
  .seal{width:66px;height:66px;border:3px solid #dc2626;border-radius:50%;color:#dc2626;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:15px;transform:rotate(-12deg);opacity:.85}
  .panel{position:absolute;top:106px;right:0;width:420px;bottom:0;box-shadow:-4px 0 24px rgba(0,0,0,.18);background:#fff;overflow:hidden}
  .panel img{width:420px;display:block}
`

function browser({ title, url, badge, barButton, page, panelPng, extra = '' }) {
  const [bt, bc] = badge
  return `<div class="win">
    <div class="dots"><i style="background:#ef4444"></i><i style="background:#f59e0b"></i><i style="background:#22c55e"></i></div>
    <div class="tabs"><div class="tab">${title}</div></div>
    <div class="addr"><div class="url">${url}</div><div class="ic"><img src="${icon}">${bt ? `<div class="bd" style="background:${bc}">${bt}</div>` : ''}</div></div>
    ${barButton}
    <div class="viewer">${page}</div>
    ${panelPng ? `<div class="panel"><img src="data:image/png;base64,${panelPng}"></div>` : ''}
    ${extra}
  </div>`
}

const docPage = (t, title) => `<div class="page"><h1>${title}</h1>
  ${[100, 96, 92, 98, 70, 0, 100, 94, 97, 60, 0, 99, 88].map((w) => (w ? `<div class="ln" style="width:${w}%"></div>` : '<div style="height:14px"></div>')).join('')}
  <div class="sig"><div class="who">${t.party}</div><div class="seal">${t.seal}</div></div></div>`

const bar = (t, label, color, extraStyle = '') => `<div class="bar" style="${extraStyle}"><span>📄 ${t.detected}</span><span class="btn" style="background:${color}">${label}</span></div>`

async function render(file, html) {
  const p = await ctx.newPage()
  await p.setViewportSize({ width: 1280, height: 800 })
  await p.setContent(`<!doctype html><meta charset="utf-8"><style>${CSS}</style>${html}`)
  await p.waitForTimeout(400)
  await p.screenshot({ path: join(outDir, file) })
  await p.close()
}

for (const lang of ['zh-TW', 'en']) {
  const t = L[lang]
  await settings(lang)
  const trusted = anonymise(realTrusted, [
    ['hsm-signed-a.pdf', t.trustedFile],
    ['70759028-00-00-C3::HSMT132', t.signerA],
    ['MyTWES 臺灣電子簽章中心', t.signerB],
  ])
  const partial = anonymise(realPartial, [
    ['foreign-tsa.pdf', t.partialFile],
    ['70759028-AATL-RD', t.signerC],
  ])

  // 1. verified on open
  await render(`${lang}-1-verify-on-open.png`, `<div class="head"><h2>${t.h1}</h2><p>${t.s1}</p></div>` + browser({
    title: t.trustedFile, url: `https://example.com/docs/${t.trustedFile}`, badge: ['✓', '#16a34a'],
    barButton: bar(t, `✓ ${t.trusted}`, '#22c55e'), page: docPage(t, t.docTitle), panelPng: await panelShot(trusted, 566),
  }))

  // 2. not fully verified, with reasons
  await render(`${lang}-2-not-fully-verified.png`, `<div class="head"><h2>${t.h2}</h2><p>${t.s2}</p></div>` + browser({
    title: t.partialFile, url: `https://example.com/docs/${t.partialFile}`, badge: ['!', '#d97706'],
    barButton: bar(t, `⚠ ${t.unknown}`, '#f59e0b'), page: docPage({ ...t, party: t.party.replace(t.signerA, t.signerC) }, t.docTitle2), panelPng: await panelShot(partial, 566),
  }))

  // 3. toolbar result + settings
  const resultPng = await popupResultShot(trusted)
  const settingsPng = await settingsShot(lang)
  const badges = [['✓', '#16a34a'], ['!', '#d97706'], ['✗', '#dc2626']]
    .map(([c, bg]) => `<div class="ic" style="width:28px;height:28px"><img src="${icon}" style="width:28px;height:28px"><div class="bd" style="background:${bg};min-width:15px;height:15px;font-size:12px;line-height:15px;right:-9px;bottom:-6px">${c}</div></div>`).join('')
  await render(`${lang}-3-toolbar-and-settings.png`, `
    <div style="display:flex;gap:64px;justify-content:center;align-items:center;height:800px">
      <div style="display:flex;flex-direction:column;gap:10px;width:540px">
        <div style="display:flex;gap:22px;background:#f1f3f4;border-radius:10px;padding:10px 18px;width:max-content;box-shadow:0 2px 8px rgba(0,0,0,.08)">${badges}</div>
        <h2 style="margin:0;font-size:26px">${t.h3a}</h2><p style="margin:0 0 6px;font-size:17px;color:#334155">${t.s3a}</p>
        <img src="data:image/png;base64,${resultPng}" style="width:372px;border-radius:12px;box-shadow:0 12px 40px rgba(15,23,42,.25)">
      </div>
      <div style="display:flex;flex-direction:column;gap:10px;width:540px">
        <h2 style="margin:0;font-size:26px">${t.h3b}</h2><p style="margin:0 0 6px;font-size:17px;color:#334155">${t.s3b}</p>
        <img src="data:image/png;base64,${settingsPng}" style="width:400px;border-radius:12px;box-shadow:0 12px 40px rgba(15,23,42,.25)">
      </div>
    </div>`)

  // 4. drop on the bar + right-click a link (drawn)
  const dropBar = `<div class="bar" style="background:#dbeafe;outline:2px dashed #3b82f6;outline-offset:-2px"><span>📄 ${t.dropHere}</span><span class="btn" style="background:#3b82f6">🔍</span></div>`
  const fileChip = `<div style="position:absolute;top:118px;left:520px;display:flex;align-items:center;gap:8px;background:#fff;border-radius:8px;padding:8px 12px;box-shadow:0 8px 24px rgba(0,0,0,.3);font-size:13px">📄 ${t.trustedFile} <span style="font-size:18px">⤵</span></div>`
  const linkPage = `<div style="width:640px;height:560px;background:#fff;border-radius:6px;padding:30px 36px;margin-right:0;position:relative">
    <h3 style="margin:0 0 18px;font-size:22px">${t.linkPage}</h3>
    <div style="font-size:15px;color:#1d4ed8;text-decoration:underline;margin:12px 0">📄 ${t.link1}</div>
    <div style="font-size:15px;color:#1d4ed8;text-decoration:underline;margin:12px 0;background:#e0e7ff;width:max-content">📄 ${t.link2}</div>
    <div style="position:absolute;left:250px;top:112px;width:300px;background:#fff;border:1px solid #d1d5db;border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.2);padding:6px 0;font-size:13.5px">
      ${t.ctxItems.map((x) => `<div style="padding:7px 16px;color:#334155">${x}</div>`).join('')}
      <div style="border-top:1px solid #e5e7eb;margin:4px 0"></div>
      <div style="padding:7px 16px;background:#dbeafe;display:flex;gap:8px;align-items:center"><img src="${icon}" style="width:16px;height:16px">${t.ctxOurs}</div>
    </div></div>`
  await render(`${lang}-4-drop-and-right-click.png`, `<div class="head"><h2>${t.h4}</h2><p>${t.s4}</p></div>
    <div style="position:absolute;left:48px;top:108px;width:560px;height:672px;border-radius:12px;overflow:hidden;box-shadow:0 18px 50px rgba(15,23,42,.28);background:#525659">
      <div class="tabs" style="padding-left:20px"><div class="tab">${t.partialFile}</div></div>
      <div class="addr"><div class="url">https://example.com/…/${t.partialFile}</div></div>
      ${dropBar}
      <div style="display:flex;justify-content:center;padding-top:22px"><div class="page" style="margin:0;width:380px;height:480px;padding:36px"><h1 style="font-size:24px">${t.docTitle2}</h1>${[100, 92, 96, 70, 0, 98, 90].map((w) => (w ? `<div class="ln" style="width:${w}%"></div>` : '<div style="height:12px"></div>')).join('')}</div></div>
      ${fileChip.replace('left:520px', 'left:150px')}
    </div>
    <div style="position:absolute;left:640px;top:108px;width:592px;height:672px;border-radius:12px;overflow:hidden;box-shadow:0 18px 50px rgba(15,23,42,.28);background:#f8fafc">
      <div class="tabs" style="padding-left:20px"><div class="tab">${t.linkPage}</div></div>
      <div class="addr"><div class="url">https://example.com/documents</div></div>
      <div style="padding:20px 0 0 0;display:flex;justify-content:center">${linkPage.replace('width:640px', 'width:540px')}</div>
    </div>`)
}
await ctx.close()
server.close()
console.log('done')
