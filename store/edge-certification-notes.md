# Edge Partner Center: Notes for certification

Submitted with 1.0.4 (2026-10-13). Update "What's new" for each release; keep under 2,000 characters.

```text
PDFtrust 1.0.4 verifies the digital signatures of PDF documents locally in the browser.

What's new in 1.0.4
- PDFs opened in the browser are verified automatically; the result appears in a side panel and as a toolbar badge.
- Right-click a link and choose "Verify the digital signatures of this PDF" (new contextMenus permission).
- Drop a PDF on the notification bar to verify it.
- Optional setting to also trust selected international certificate authorities (default: Taiwan CAs only).
- OCSP / CRL answers are cached briefly to avoid repeated requests.

How to test
1. Open a digitally signed PDF in Edge. A bar appears below the toolbar and verification starts automatically; the side panel shows the result.
2. Click the extension icon to see the result for the current tab.
3. Right-click a link to a PDF and choose "Verify the digital signatures of this PDF".
4. Settings (gear icon in the popup): automatic verification scope, international CAs, language.
Note: by default only Taiwan certificate authorities are trusted, so signatures from other CAs show "Not fully verified" unless "Trust selected international CAs" is turned on in settings.

Permissions
- Host permissions: detect PDFs on pages, download the PDF the user opened to verify it, and query the CAs' OCSP / CRL services.
- contextMenus: the right-click verify item.
- storage: settings, per-tab results (session) and a short OCSP / CRL cache.
- downloads: save the exported verification report.
- alarms: keep the service worker alive during a verification.
- activeTab: let the popup verify the PDF in the current tab.

Privacy: no user data is collected or transmitted, PDFs are never uploaded, and no remote code is used.
```
