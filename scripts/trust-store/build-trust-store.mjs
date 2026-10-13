// Regenerates src/trust-store/generated-anchors.ts from manifest.json + certs/.
// Usage: node scripts/trust-store/build-trust-store.mjs
//
// Refuses to write anything unless every certificate:
//   - matches the SHA-256 recorded in manifest.json,
//   - (roots) is self-signed and its self-signature verifies,
//   - (intermediates) is signed by one of the listed roots.
import { readFileSync, writeFileSync } from 'node:fs'
import { X509Certificate } from 'node:crypto'
import { join, dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(here, '../..')
const manifest = JSON.parse(readFileSync(join(here, 'manifest.json'), 'utf8'))

const fail = (msg) => {
  console.error(`build-trust-store: ${msg}`)
  process.exit(1)
}

function load(entry) {
  const der = readFileSync(join(here, 'certs', entry.file))
  const cert = new X509Certificate(der)
  const fp = cert.fingerprint256.replace(/:/g, '')
  if (fp !== entry.sha256) fail(`${entry.file}: SHA-256 ${fp} != manifest ${entry.sha256}`)
  return { entry, cert, der }
}

const roots = manifest.roots.map(load)
for (const { entry, cert } of roots) {
  if (cert.subject !== cert.issuer || !cert.verify(cert.publicKey)) {
    fail(`${entry.file}: root is not a valid self-signed certificate`)
  }
}

const intermediates = manifest.intermediates.map(load)
for (const { entry, cert } of intermediates) {
  const issuer = roots.find((r) => r.cert.subject === cert.issuer && cert.verify(r.cert.publicKey))
  if (!issuer) fail(`${entry.file}: not signed by any listed root`)
}

const toPem = (der) =>
  `-----BEGIN CERTIFICATE-----\n${der.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`

const fmtFp = (hex) => hex.toLowerCase().match(/.{2}/g).join(':')

function render({ entry, cert, der }) {
  const notes = `${cert.subject.replace(/\n/g, ', ')}; valid ${new Date(cert.validFrom).toISOString().slice(0, 10)} → ${new Date(cert.validTo).toISOString().slice(0, 10)}`
  return `  {
    name: ${JSON.stringify(entry.name)},
    category: '${entry.category}',
    pem: \`${toPem(der)}\`,
    expectedFingerprint: '${fmtFp(entry.sha256)}',
    source: ${JSON.stringify(entry.source)},
    notes: ${JSON.stringify(notes)},
  },`
}

const out = `/**
 * GENERATED FILE — do not edit by hand.
 * Source of truth: scripts/trust-store/manifest.json + scripts/trust-store/certs/
 * Regenerate with: node scripts/trust-store/build-trust-store.mjs
 */
import type { TrustAnchorEntry } from './taiwan-roots'

/** Self-signed Taiwan root CAs (government + private). */
export const GENERATED_ROOTS: TrustAnchorEntry[] = [
${roots.map(render).join('\n')}
]

/**
 * Known Taiwan intermediate CAs. NOT trust anchors — only offered to the
 * path builder so chains can be completed offline. Every path must still be
 * cryptographically verified up to a root in GENERATED_ROOTS.
 */
export const GENERATED_INTERMEDIATES: TrustAnchorEntry[] = [
${intermediates.map(render).join('\n')}
]
`

const target = join(repoRoot, 'src/trust-store/generated-anchors.ts')
writeFileSync(target, out)
console.log(`wrote ${target}: ${roots.length} roots, ${intermediates.length} intermediates`)
