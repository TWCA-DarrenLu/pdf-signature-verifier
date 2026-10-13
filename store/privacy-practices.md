# Store dashboard: permission justifications

Paste into the Chrome Web Store "Privacy practices" tab (Edge Partner Center asks for the same in its submission notes). `contextMenus` is new in 1.0.4.

**Single purpose**: Verify the digital signatures of PDF documents in the browser.

| Permission | Justification |
|---|---|
| `host_permissions: <all_urls>` | Detect PDFs on any page (viewer bar, verify buttons next to PDF links), download the PDF the user opened in order to verify it, and query the certificate authorities' OCSP / CRL services for revocation status. |
| `contextMenus` | Adds "Verify the digital signatures of this PDF" to the right-click menu of links and embedded documents. |
| `storage` | Saves the user's settings (language, automatic verification scope, international CA option), the verification result shown for each tab (session only), and briefly caches OCSP / CRL answers (session only). |
| `downloads` | Saves the verification report the user exports as a PDF file. |
| `alarms` | Keeps the service worker alive while a verification is running so long OCSP / CRL requests are not interrupted. |
| `activeTab` | Lets the popup offer verification of the PDF in the current tab. |

**Data usage**: No user data is collected or transmitted. PDF files are processed locally and never uploaded; OCSP / CRL requests contain only certificate identifiers.
