#!/usr/bin/env node
/**
 * Upload the built package to the Chrome Web Store and Microsoft Edge
 * Add-ons and submit it for review. Used by .github/workflows/release.yml;
 * see docs/release.md for the one-time setup.
 *
 *   node scripts/release/publish.mjs --zip .output/<name>-<version>-chrome.zip
 *        [--store all|chrome|edge] [--publish-type DEFAULT_PUBLISH|STAGED_PUBLISH]
 *        [--notes "text for Edge reviewers"] [--check]
 *
 * --check only verifies the setup: package and environment present, and the
 * Chrome credentials can read the item's status. Nothing is uploaded.
 *
 * Environment (GitHub Environment "store" secrets):
 *   CWS_PUBLISHER_ID, CWS_EXTENSION_ID, CWS_SERVICE_ACCOUNT_JSON
 *   EDGE_PRODUCT_ID, EDGE_CLIENT_ID, EDGE_API_KEY
 */
import { readFileSync, existsSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'
import {
  googleAccessToken,
  chromeFetchStatus,
  chromeUpload,
  chromePublish,
  edgeUpload,
  edgePublish,
} from './store-api.mjs'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const ENV = {
  chrome: ['CWS_PUBLISHER_ID', 'CWS_EXTENSION_ID', 'CWS_SERVICE_ACCOUNT_JSON'],
  edge: ['EDGE_PRODUCT_ID', 'EDGE_CLIENT_ID', 'EDGE_API_KEY'],
}

const { values: args } = parseArgs({
  options: {
    zip: { type: 'string' },
    store: { type: 'string', default: 'all' },
    'publish-type': { type: 'string', default: 'DEFAULT_PUBLISH' },
    notes: { type: 'string', default: '' },
    check: { type: 'boolean', default: false },
  },
})

function fail(message) {
  console.error(`✗ ${message}`)
  process.exit(1)
}

const stores = args.store === 'all' ? ['chrome', 'edge'] : [args.store]
if (!stores.every((s) => s in ENV)) fail(`--store must be all, chrome or edge (got ${args.store})`)
if (!['DEFAULT_PUBLISH', 'STAGED_PUBLISH'].includes(args['publish-type'])) fail('--publish-type must be DEFAULT_PUBLISH or STAGED_PUBLISH')

// The package must be the version in package.json (the single source of the version).
const version = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).version
if (!args.zip || !existsSync(args.zip)) fail(`package not found: ${args.zip ?? '(missing --zip)'}`)
if (!basename(args.zip).includes(`-${version}-`)) fail(`${basename(args.zip)} is not version ${version} (package.json)`)

const missing = stores.flatMap((s) => ENV[s].filter((name) => !process.env[name]))
if (missing.length > 0) fail(`missing environment variables: ${missing.join(', ')}`)

let serviceAccount
if (stores.includes('chrome')) {
  try {
    serviceAccount = JSON.parse(process.env.CWS_SERVICE_ACCOUNT_JSON)
  } catch {
    fail('CWS_SERVICE_ACCOUNT_JSON is not valid JSON (paste the whole service-account key file)')
  }
  if (!serviceAccount.client_email || !serviceAccount.private_key) fail('CWS_SERVICE_ACCOUNT_JSON lacks client_email / private_key')
}

const zip = readFileSync(args.zip)
const chromeIds = { publisherId: process.env.CWS_PUBLISHER_ID, itemId: process.env.CWS_EXTENSION_ID }
const edgeIds = {
  productId: process.env.EDGE_PRODUCT_ID,
  clientId: process.env.EDGE_CLIENT_ID,
  apiKey: process.env.EDGE_API_KEY,
}
console.log(`PDFtrust ${version}: ${basename(args.zip)} (${zip.length} bytes) → ${stores.join(', ')}${args.check ? ' [check only]' : ''}`)

const steps = {
  async chrome() {
    const token = await googleAccessToken(serviceAccount)
    const status = await chromeFetchStatus({ token, ...chromeIds })
    const listed = status.publishedItemRevisionStatus?.distributionChannels?.[0]?.crxVersion ?? '?'
    const pending = status.submittedItemRevisionStatus?.state
    console.log(`  Chrome: listed ${listed}${pending ? `, submission ${pending}` : ''}`)
    if (args.check) return
    const upload = await chromeUpload({ token, ...chromeIds, zip })
    console.log(`  Chrome: uploaded ${upload.crxVersion ?? version}`)
    const published = await chromePublish({ token, ...chromeIds, publishType: args['publish-type'] })
    for (const w of published.warnings) console.log(`  Chrome warning: ${w.reason} — ${w.description}`)
    console.log(`  Chrome: submitted for review (${args['publish-type']}), state ${published.state ?? '?'}`)
  },
  async edge() {
    // Edge has no read-only call: --check stops after the local checks.
    if (args.check) {
      console.log('  Edge: credentials present (Edge offers no read-only API to test them)')
      return
    }
    await edgeUpload({ ...edgeIds, zip })
    console.log('  Edge: package uploaded and validated')
    const notes = args.notes || `PDFtrust ${version}. See the listing description for what changed.`
    await edgePublish({ ...edgeIds, notes })
    console.log('  Edge: submitted for certification')
  },
}

let failed = false
for (const store of stores) {
  try {
    await steps[store]()
  } catch (error) {
    failed = true
    console.error(`✗ ${store}: ${error instanceof Error ? error.message : String(error)}`)
  }
}
process.exit(failed ? 1 : 0)
