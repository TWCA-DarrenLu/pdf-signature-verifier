# PDFtrust - PDF Digital Signature Verifier

Open a PDF in your browser and its digital signatures are verified automatically — no uploads, everything runs locally. Trusts Taiwan government and private certificate authorities by default, with timestamp and long-term validation (LTV) support.

## Features

- **Verify on open** — PDFs opened in the browser are verified automatically and the result appears in a side panel (Chrome, Edge); choose all sites, listed sites only, or off
- **Toolbar status** — the extension icon shows ✓ trusted / ! not fully verified / ✗ failed; click it for the details
- **Taiwan PKI trust list** — government: certificates under the Government Root Certification Authority (GRCA): citizen (MOICA), government agency (GCA), organization (XCA) and business (MOEACA) certificates; private: TWCA and Chunghwa Telecom. Self-signed certificates are not accepted
- **Selected international CAs (optional)** — only Taiwan certificates are trusted by default; turn on the document-signing and timestamping roots of DigiCert, GlobalSign, Sectigo, IdenTrust and SSL.com in settings
- **Regulatory label** — after the certificate chain is verified, each signature shows whether its CA is licensed under Taiwan's Electronic Signatures Act; international CAs are marked as not licensed in Taiwan
- **Integrity check** — confirms the document was not altered after signing and detects changes the signer did not allow
- **Certificate chain and revocation** — validates every link of the chain and checks revocation with embedded or online OCSP / CRL data
- **Timestamps and LTV** — verifies RFC 3161 timestamps (issued by a Taiwan PKI timestamp authority), uses the timestamp time for expired certificates, and checks whether long-term validation data is complete
- **Clear results** — every check is marked green / red / amber / grey; when a signature cannot be fully verified the main reasons are listed, with one-click re-check
- **Several ways to verify** — drop a PDF on the notification bar or the extension window, right-click a link and choose "Verify the digital signatures of this PDF", or use the verify button next to PDF links
- **Local files** — after turning on "Allow access to file URLs" in the extension details, local PDFs are verified automatically too
- **Report export** — export a full verification report as PDF

## How It Works

1. Open a PDF in the browser — verification starts automatically
2. See the result in the side panel or by clicking the toolbar icon, including certificate chain, timestamp and revocation status
3. Re-check when needed, or export the verification report

## Privacy

Your PDF files are never uploaded to any server; verification runs locally in your browser. Revocation checks only ask the certificate authority's OCSP / CRL service about the certificate — the document is never sent. Answers are cached briefly to avoid repeated requests.

## Supported Signatures

- CMS / PKCS#7 (adbe.pkcs7.detached, adbe.pkcs7.sha1)
- RSA, ECDSA, RSA-PSS signature algorithms
- SHA-256, SHA-384, SHA-512, SHA-1 hash algorithms
- PAdES (PDF Advanced Electronic Signatures)

## Languages

English and Traditional Chinese (繁體中文). Automatically detected from browser language, or manually switch in settings.
