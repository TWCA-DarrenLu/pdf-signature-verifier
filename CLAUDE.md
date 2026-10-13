# CLAUDE.md - PDF Signature Verifier

## Project Overview

Browser extension that verifies PDF digital signatures with X.509 certificate support. Built as a Chrome MV3 extension using WXT framework. Supports Traditional Chinese (zh-TW) and English (en) with automatic language detection and manual switching.

## Tech Stack

- **Framework**: WXT 0.19 (browser extension framework)
- **UI**: React 18 + Tailwind CSS 3
- **Language**: TypeScript (strict mode, ESNext target)
- **Crypto**: asn1js + pkijs (ASN.1 parsing, PKCS#7, X.509)
- **State**: Zustand
- **Build**: Vite (via WXT)
- **Test**: Vitest (unit/integration) + Playwright (e2e)
- **Target**: Chrome MV3 (also supports Firefox)

## Key Directories

```
src/
  entrypoints/         # WXT entry points (background.ts, content.ts)
  core/                # Verification engine (pure logic, no UI)
    pdf/               # PDF parser, xref, byte-range, signature extractor
    crypto/            # PKCS#7 parser, digest & signature verification
    certificate/       # Chain building, validation, cert utilities
    revocation/        # OCSP client, CRL client, embedded reader
    timestamp/         # RFC 3161 timestamp verification
    ltv/               # Long-Term Validation checks
    report/            # HTML verification report generator (zero npm deps)
    verifier.ts        # Main orchestrator - ties all steps together
  types/               # TypeScript interfaces (verification, certificate, signature)
  trust-store/         # Taiwan root CA certificates + trust manager
  popup/               # React UI components and hooks
    components/        # StatusBadge, SignatureCard, CertificateChain, DropZone, ExportButton, etc.
    hooks/             # useVerification, useSettings
  i18n/                # zh-TW.json, en.json, translation utilities
tests/
  unit/                # Unit tests
  integration/         # Integration tests
  e2e/                 # Playwright E2E tests
  fixtures/            # Test PDF samples
```

## Build Commands

```bash
npm run dev              # Dev mode (Chrome)
npm run dev:firefox      # Dev mode (Firefox)
npm run build            # Production build (Chrome)
npm run build:firefox    # Production build (Firefox)
npm run build:all        # Build both browsers
npm run compile          # TypeScript type check (no emit)
npm run test             # Vitest watch mode
npm run test:unit        # Vitest single run
npm run test:coverage    # Vitest with v8 coverage (80% threshold)
npm run test:e2e         # Playwright E2E
```

## Architecture: Verification Pipeline

The main entry point is `verifyPdfSignatures()` in `src/core/verifier.ts`. For each signature field found in the PDF, it runs these steps in order:

1. **ByteRange validation** - Verify the byte range covers the document correctly
2. **PKCS#7 parsing** - Parse the CMS/PKCS#7 SignedData structure
3. **Integrity check** - Verify message digest, then cryptographic signature over signed attributes
4. **Certificate chain** - `chain-builder.ts`: every link signature-verified (pkijs), CA/keyCertSign/pathLen enforced, backtracks across same-name issuers
5. **Trust root** - Path must end at an anchor matched by SHA-256 fingerprint only; self-signed signer certificates are rejected
6. **Timestamp** - Verify embedded RFC 3161 timestamp (hash of signatureValue bytes)
7. **Validity** - Validation time = trusted timestamp time, else now
8. **Revocation** - `revocation-checker.ts` / `revocation-validator.ts`: OCSP and CRL signatures and responder authorization verified; embedded first, online only for unexpired certs
9. **LTV** - Check Long-Term Validation completeness (embedded revocation + timestamp)

Overall per-signature status comes from `determineSignatureStatus()` (structured inputs, never message text). Changes after each signature are found by `pdf/incremental-update.ts` (xref-based revision diff + reachability from the page tree, DocMDP-aware); TSA path revocation must be proven before a timestamp's time is used.

Each step produces a `CheckResult` (`{ passed, message, details, i18nKey?, i18nParams?, detailsI18nKey?, detailsI18nParams? }`). The overall status is `trusted | unknown | failed`.

CheckResult stores both pre-rendered strings and i18n keys. Core modules run in the background service worker where the locale may differ from the UI. At render time, UI components call `resolveCheck(check)` and `resolveSummary(result)` (from `src/i18n/index.ts`) to re-resolve strings in the current locale.

## Extension Architecture

- **background.ts** - Service worker handling network requests (OCSP, CRL, certificate fetch, PDF fetch) and delegating verification
- **Trust store** - Taiwan roots (category government/private) are always anchors; international roots (category international, vendor, usage signing/timestamping) only with `VerificationOptions.trustInternational` (user setting `pdf-verifier-settings.trustInternational`, default false, read by background.ts per verification). Disabled international roots still complete paths so the UI can say "international CA, not enabled". `rootCategory`/`rootVendor` drive the Electronic Signatures Act label (licensed vs not licensed in Taiwan)
- **Releases** - `.github/workflows/release.yml` + `scripts/release/` (store-api.mjs: Chrome Web Store API v2 with a service account, Edge Add-ons API v1.1). Version single source: `package.json` (wxt.config.ts has no version). Icons live in `src/public/` (WXT publicDir with srcDir 'src'; the root `public/` is not packaged). Setup: docs/release.md
- **Store listing** - texts in `store/` (Chrome zh-TW short version, Edge en). Never list vendor/brand names in store descriptions (Chrome rejected 1.0.4 for keyword spam). Screenshots are illustrated mock-ups from `scripts/store-assets/`; rules in docs/release.md
- **content.ts** - Detects PDF links/embeds on pages, injects verify buttons, manages side panel (iframe) for results. In the PDF viewer it verifies automatically per `pdf-verifier-settings.autoVerifyScope` (src/settings/auto-verify.ts; http(s) and, with file access allowed, file://), reports each verdict to the background (`tab-state`) for the toolbar badge, and accepts dropped PDFs on its bar (verified by the background via `verify-pdf`). The panel's "re-check" posts `pdf-panel-recheck`; context-menu results arrive as `show-verifying` / `show-result` / `show-error`
- **background.ts** - Downloads and verifies PDFs (`verify-pdf-url`, `verify-pdf`), keeps the per-tab result in `chrome.storage.session` (`tab-result:<tabId>`) with the toolbar badge, and owns the right-click menu. Online OCSP/CRL answers are cached by src/core/revocation/revocation-cache.ts; `fresh` / `refreshRevocation` bypasses it
- **popup/** - React components for the popup UI and verification result panel

Messages flow: content script -> background (via `chrome.runtime.sendMessage`) -> core verifier -> result back to content -> panel iframe.

## i18n Architecture

- **Locales**: `zh-TW` (Traditional Chinese), `en` (English). Translation files: `src/i18n/zh-TW.json`, `src/i18n/en.json`.
- **Auto-detection**: `detectBrowserLocale()` selects language based on `navigator.language`. Chinese → `zh-TW`, otherwise → `en`.
- **Manual switching**: Settings panel dropdown. Persisted in `chrome.storage.local` under `pdf-verifier-settings.language`.
- **Multi-context sync**: Each JS context (popup, background, content script) has its own i18n state. Language changes propagate via `chrome.storage.onChanged`:
  - **Popup/Panel**: `useEffect` on `settings.language` calls `setLocale()`.
  - **Content script**: `chrome.storage.onChanged` listener updates locale and refreshes idle button labels.
  - **Background**: Initializes locale on startup; verification results store i18n keys for render-time resolution.
- **Render-time resolution**: `resolveCheck()` and `resolveSummary()` re-resolve stored i18n keys at render time, ensuring correct language regardless of when verification ran.
- **All user-facing strings** use `t(key, params?)` — no hardcoded Chinese/English in `.ts`/`.tsx` files.

## Conventions

- **Immutability**: Create new objects, never mutate. See `mergeRevocationInfo()` pattern.
- **Small files**: Each module handles one concern (e.g., `digest-verifier.ts`, `chain-builder.ts`, `ocsp-client.ts`).
- **Path alias**: `@/` maps to `src/` (configured in tsconfig and vitest).
- **Error handling**: Always catch and wrap errors with descriptive messages via `t()`.
- **Trust store**: generated file `src/trust-store/generated-anchors.ts` — never edit by hand; change `scripts/trust-store/manifest.json` + `certs/` and run `node scripts/trust-store/build-trust-store.mjs`.

## Key Dependencies

| Package | Purpose |
|---------|---------|
| `asn1js` | ASN.1 DER/BER encoding/decoding |
| `pkijs` | X.509 certificates, CMS/PKCS#7, OCSP, CRL |
| `pvutils` | Buffer/ArrayBuffer utility helpers for pkijs |
| `zustand` | Lightweight React state management |

## Testing

- Coverage threshold: 80% (lines, functions, branches, statements)
- Test environment: jsdom
- Setup file: `tests/setup.ts`
- Test pattern: `tests/**/*.{test,spec}.{ts,tsx}`
- Existing tests cover: byte-range, digest verification, i18n, trust store/policy, chain building with real signatures (`tests/helpers/test-pki.ts`), timestamp trust, incremental updates, sample PDF verification (needs `PDF_Sample/`)
- E2E: `npm run build` then `npx playwright test --project=chromium --reporter=list` (loads `.output/chrome-mv3`)

## Browser Extension Rules

Migrated from `~/.claude/rules/browser-extensions.md` (project-scoped).

### Manifest Format
- Chrome and Firefox manifests differ — always validate per target browser
- Chrome MV3 vs Firefox MV2/MV3 differences must be checked
- Firefox `data_collection_permissions` format: verify against MDN docs

### Icons
- Chrome/Brave do NOT support SVG icons — use PNG only
- Provide icons at 16, 32, 48, 128

### Build and Test
- Always test with a fresh build, not stale output
- After ANY build change (manifest, webpack, CSS, content scripts), rebuild and reload
- Never assume changes take effect without a fresh build
- Load unpacked extension to verify before submission
- Test in both Chrome and Firefox if targeting both
