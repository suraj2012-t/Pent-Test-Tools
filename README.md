# 🛡️ Firefox Pen-Testing Toolkit

A growing suite of Firefox WebExtensions that streamline **web-application penetration testing**.  
Current modules focus on reconnaissance and quick-look vulnerability checks that you can run straight from the browser.

## 🚀 Current Extensions

| ID | Extension | Purpose | Quick Highlights |
|----|-----------|---------|------------------|
| 1  | **Google Dork Assistant** | Build and fire advanced Google search (dork) queries from the toolbar. | – One-click dork templates (site:, inurl:, intitle:, filetype:)  
– Bookmark favourite dorks  
– Copy or open in new tab |
| 2  | **OWASP Security Header Scanner** | Inspect the response headers of the active tab and flag missing or weak security headers. | – Checks CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy  
– Traffic-light badge (green/orange/red) + detailed panel  
– Copy report as Markdown |
| 3  | **Clickjacking Tester** | Detect and demonstrate clickjacking issues by overlaying the page in an `<iframe>`. | – One toggle to inject a transparent frame  
– Visual preview of the vulnerable page  
– Saves screenshots for reports |

> More modules are planned (see Roadmap) and PRs are welcome!

## ✨ Key Features

- **Modular Design** – Each tool lives in its own folder but shares build scripts for easy packaging.
- **Zero External Back-ends** – Everything runs client-side inside Firefox.
- **Permissions Minimalism** – Each extension requests only the APIs it actually needs.
- **TypeScript + Web-Ext** build pipeline for fast dev reloads and signed `.xpi` output.
- **Open Source** – MIT-licensed; inspect, fork, contribute.
