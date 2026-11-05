# 🛡️ Web Security & Misconfiguration Scanner

An advanced, asynchronous Node.js CLI utility designed to audit web applications for missing security headers, dangerous CORS policies, and exposed sensitive directories.

## ✨ Features
* **Concurrency Worker Engine:** Scans multiple sensitive paths concurrently for fast target inspection.
* **CORS Vulnerability Check:** Detects risky wildcard origins combined with credential flags.
* **Security Headers Audit:** Verifies implementation of CSP, HSTS, X-Frame-Options, and more.
* **JSON Export:** Easily export machine-readable reports for automated CI/CD security pipelines.

---

## 🚀 Installation & Usage

### For Local Development:
1. Navigate to your project folder:
   ```bash
   cd web-sec-scanner
2. Install dependencies:
   npm install
3. Run a security scan: 
   node cli.js [https://example.com]
4. Export to JSON:
   node cli.js [https://example.com]([https://example.com]) --json



   