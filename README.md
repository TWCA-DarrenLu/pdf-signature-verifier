# PDF Signature Verifier

A browser extension that verifies digital signatures in PDF documents, with built-in support for Taiwan's PKI infrastructure (TWCA, GCA, MOICA root certificates).

> **Trust policy** — by default only Taiwan PKI roots are trusted (government
> GRCA G1/G2/G3; private TWCA and Chunghwa Telecom roots). Every anchor is pinned
> by SHA-256 (`scripts/trust-store/manifest.json`). Self-signed signer
> certificates are always rejected, and a signature is reported as *trusted*
> only when integrity, the certification path, validity, revocation and (if
> present) the timestamp are all proven. Versions up to 1.0.3 shipped an empty
> trust store and accepted any self-signed root.

## Features

- **Full PDF signature verification** -- parses PDF structure, extracts PKCS#7/CMS signatures, and validates every step of the chain
- **Taiwan PKI support** -- pre-loaded trust anchors for TWCA (commercial), GCA (government), and MOICA (citizen digital certificates)
- **Automatic PDF detection** -- injects "Verify Signature" buttons next to PDF links and embedded PDFs on any webpage
- **Built-in PDF viewer integration** -- notification bar below the toolbar when viewing a PDF directly in the browser; verification starts automatically (setting: all sites / listed sites only / off)
- **Toolbar badge** -- the extension icon shows ✓ / ! / ✗ for the PDF in each tab; clicking it shows that result
- **Side panel results** -- verification results displayed in a slide-in panel without leaving the page (Chrome and Edge), with a "Re-check" button that asks OCSP/CRL servers again
- **Drop to verify** -- drop a downloaded or local PDF on the notification bar
- **Right-click "Verify the digital signatures of this PDF"** -- on any link or embedded document, also links without `.pdf` in the URL
- **Local PDFs** -- verified automatically once "Allow access to file URLs" is on in the extension details; otherwise pick or drop the file
- **Revocation cache** -- OCSP / CRL answers are reused until their nextUpdate (at most 24 h) instead of being fetched for every PDF
  - Limits: the extension downloads the PDF again, so single-use links may fail (drop the downloaded file instead); Brave is untested and opens the results in a window
- **Comprehensive checks**:
  - Document integrity (message digest + cryptographic signature)
  - Certificate chain building and validation
  - Trust root verification
  - Certificate validity period (with LTV fallback for expired certificates)
  - Revocation checking (embedded OCSP/CRL, online OCSP, online CRL)
  - RFC 3161 timestamp verification
  - Long-Term Validation (LTV) completeness
- **Offline-capable** -- verifies embedded revocation data without requiring network access
- **Multi-language UI** -- Traditional Chinese (primary) and English
- **Cross-browser** -- Chrome (MV3) and Firefox support

## Installation

### From Source

1. Clone the repository:
   ```bash
   git clone https://github.com/darrenlu86/pdf-signature-verifier.git
   cd pdf-signature-verifier
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Build the extension:
   ```bash
   npm run build
   ```

4. Load in Chrome:
   - Navigate to `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked"
   - Select the `.output/chrome-mv3` directory

5. Load in Firefox:
   - Navigate to `about:debugging#/runtime/this-firefox`
   - Click "Load Temporary Add-on"
   - Select any file in the `.output/firefox-mv2` directory

## Development

### Prerequisites

- Node.js 18+
- npm

### Setup

```bash
npm install
npm run dev          # Start dev mode with hot reload (Chrome)
npm run dev:firefox  # Start dev mode (Firefox)
```

### Commands

| Command | Description |
|---------|-------------|
| `npm run dev` | Development mode with HMR (Chrome) |
| `npm run dev:firefox` | Development mode (Firefox) |
| `npm run build` | Production build (Chrome) |
| `npm run build:firefox` | Production build (Firefox) |
| `npm run build:all` | Build for both browsers |
| `npm run zip` | Build and package for Chrome Web Store |
| `npm run compile` | TypeScript type checking |
| `npm run test` | Run tests in watch mode |
| `npm run test:unit` | Run tests once |
| `npm run test:coverage` | Run tests with coverage report |
| `npm run test:e2e` | Run Playwright E2E tests |

### Testing

Tests use Vitest (unit/integration) and Playwright (E2E). Coverage threshold is 80%.

```bash
npm run test:unit       # Fast unit tests
npm run test:coverage   # With coverage report
npm run test:e2e        # End-to-end browser tests
```

Real signed PDFs go in `PDF_Sample/` (gitignored). With samples present,
`tests/unit/verify-sample-pdfs.test.ts` runs offline end-to-end checks, and the
Playwright suite (`npm run build` first, then
`npx playwright test --project=chromium --reporter=list`) loads the built
extension into Chromium and verifies PDFs opened over HTTP. A per-check report
is available with `PDF_SAMPLE_REPORT=1 npx vitest run tests/samples`.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Browser Extension                        │
├──────────────┬──────────────────────┬───────────────────────┤
│ Content      │   Background         │  Panel / Popup        │
│ Script       │   Service Worker     │  (React UI)           │
│              │                      │                       │
│ - Detect PDF │ - PDF fetch +        │ - DropZone            │
│   links      │   verify by URL     │ - SignatureList        │
│ - Inject     │ - Delegates to       │ - SignatureCard        │
│   buttons    │   core verifier      │ - CertificateChain    │
│ - Side panel │                      │ - VerificationDetails │
│   (iframe)   │                      │ - StatusBadge         │
│              │                      │                       │
└──────┬───────┴──────────┬───────────┴───────────────────────┘
       │                  │
       │    chrome.runtime.sendMessage
       │                  │
       ▼                  ▼
┌─────────────────────────────────────────────────────────────┐
│                    Core Verification Engine                   │
│                    (src/core/verifier.ts)                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────┐  ┌──────────┐  ┌────────────┐  ┌───────────┐  │
│  │  PDF     │  │  Crypto  │  │Certificate │  │Revocation │  │
│  │  Parser  │  │  Engine  │  │  Chain     │  │  Checker  │  │
│  │         │  │          │  │           │  │           │  │
│  │- xref   │  │- PKCS#7  │  │- builder  │  │- embedded │  │
│  │- byte   │  │- digest  │  │- validator │  │- OCSP     │  │
│  │  range  │  │- sig     │  │- utils    │  │- CRL      │  │
│  │- extract│  │  verify  │  │           │  │           │  │
│  └────┬────┘  └────┬─────┘  └─────┬─────┘  └─────┬─────┘  │
│       │            │              │              │          │
│  ┌────┴────┐  ┌────┴─────┐  ┌─────┴─────┐                  │
│  │Timestamp│  │  Trust   │  │    LTV    │                  │
│  │Verifier │  │  Store   │  │  Checker  │                  │
│  │         │  │          │  │           │                  │
│  │- RFC    │  │- Taiwan  │  │- complete │                  │
│  │  3161   │  │  roots   │  │  -ness    │                  │
│  │- TST    │  │- manager │  │- expired  │                  │
│  │  verify │  │          │  │  cert LTV │                  │
│  └─────────┘  └──────────┘  └───────────┘                  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Verification Pipeline

For each signature found in a PDF:

1. **Parse PDF** -- extract signature fields, byte ranges, and PKCS#7 data
2. **Validate byte range** -- ensure the signed region covers the document correctly
3. **Parse PKCS#7** -- decode the CMS SignedData structure (certificates, signer info, timestamps)
4. **Verify integrity** -- compute and compare message digest, then verify cryptographic signature
5. **Build certificate chain** -- from signer certificate through intermediates to root CA
6. **Check trust root** -- every link signature-verified up to a pinned Taiwan root; self-signed signers rejected
7. **Verify timestamp** -- validate RFC 3161 embedded timestamp (imprint = hash of signature value)
8. **Check validity** -- certificates valid at the trusted timestamp time (or now, without one)
9. **Check revocation** -- only signature-verified OCSP/CRL: embedded first, then online (unexpired certs only)
10. **Assess LTV** -- verify Long-Term Validation data is complete for archival trust

### Taiwan PKI Trust Roots

Trust anchors (self-signed roots, pinned by SHA-256):

| Category | Roots | Typical certificates |
|---|---|---|
| Government | GRCA G1, GRCA G2, GRCA G3 | MOICA (自然人), MOEACA (工商), XCA (組織及團體), GCA (政府機關) |
| Private | TWCA Root CA (SHA-1 and SHA-256), TWCA Global Root CA, TWCA CYBER Root CA, TWCA Information XML Plus Root CA | TWCA document signing, MyTWES, IXML, TWCA TSA |
| Private | Chunghwa Telecom ePKI Root CA, ePKI Root CA - G2, HiPKI Root CA - G1 | Chunghwa Telecom certificates |

The same roots anchor RFC 3161 timestamps; a TSA certificate must also carry
the `timeStamping` extended key usage. Known government intermediates (MOICA G2,
MOEACA G2/G3, XCA G2/G3, GCA G2/G3) are bundled for offline path building but
are **not** anchors.

Sources and fingerprints: `scripts/trust-store/manifest.json` (Mozilla CCADB,
Microsoft Trusted Root Program, the TWCA repository, grca.nat.gov.tw and the
GPKI CA repositories). A root is only added when an official source publishes
it. Foreign TSAs (e.g. for AATL documents) are not trusted by default.
To change the store, update the manifest and DER files, then run
`node scripts/trust-store/build-trust-store.mjs` — it refuses to write unless
every fingerprint matches, every root self-verifies and every intermediate is
signed by a listed root.

### Status rules

| Status | When |
|---|---|
| failed | integrity broken, self-signed signer, signer certificate not meant for signing (CA / keyUsage / EKU), revoked certificate, DocMDP violation, timestamp imprint/signature invalid, TSA revoked before the timestamp |
| unknown | path not trusted, validity not established, revocation of any path certificate not proven, TSA not trusted or its revocation not proven, unsupported algorithm, changes after signing not permitted (no DocMDP) or not analysable |
| trusted | everything above proven |

Validation time is the trusted timestamp when present, otherwise *now*. A
timestamp is only trusted when the TSA path is also proven unrevoked. An
expired signer certificate therefore needs a trusted timestamp **and** embedded
(LTV) revocation evidence. Online OCSP/CRL is not used for expired certificates.
OCSP responses must be signed by the CA or an authorized responder; CRLs must
be signed by the issuer and cover the certificate (IssuingDistributionPoint
partitions are matched against the certificate's CRL distribution points;
delta and indirect CRLs are not used).

### Changes after signing

For every signature the signed revision and the final document are rebuilt
from their cross-reference data (classic tables, xref streams, object streams)
and compared object by object (`src/core/pdf/incremental-update.ts`). Changes
that cannot affect rendering (DSS / VRI / XMP / Info) are always accepted;
anything reachable from the page tree must be permitted by DocMDP:
P1 → document timestamps only, P2 or no DocMDP → signature fields, P3 →
also annotations. A violation fails a certified document and makes an
approval-only document *unknown*.

### Known limitations

- Encrypted PDFs: streams cannot be decrypted, so embedded revocation data and
  object streams may be unreadable — such documents end up *unknown*.
- FieldMDP locks are not enforced; a permitted new signature widget's
  appearance can still overlay page content (as in other validators).
- SHA-1 digests are still accepted for legacy Taiwan documents.
- Documents that embed revocation data for the signer path but not for the
  TSA verify as *trusted* online and *unknown* offline.

## Tech Stack

- [WXT](https://wxt.dev/) -- Browser extension framework (Vite-based)
- [React](https://react.dev/) -- UI components
- [Tailwind CSS](https://tailwindcss.com/) -- Utility-first styling
- [PKI.js](https://pkijs.org/) -- X.509, CMS/PKCS#7, OCSP, TSP
- [ASN1.js](https://github.com/nicktomlin/nicktomlin.github.io) -- ASN.1 schema and parsing
- [Zustand](https://zustand.docs.pmnd.rs/) -- State management
- [Vitest](https://vitest.dev/) -- Unit and integration testing
- [Playwright](https://playwright.dev/) -- End-to-end testing

## License

MIT
