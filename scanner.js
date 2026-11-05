import fetch from "node-fetch";

// 1. Advanced Security Headers, TLS & CORS Audit
export async function auditTarget(targetUrl) {
  if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
    targetUrl = "https://" + targetUrl;
  }

  const report = {
    url: targetUrl,
    timestamp: new Date().toISOString(),
    status: null,
    secure: targetUrl.startsWith("https://"),
    headersFound: {},
    missingHeaders: [],
    corsVulnerable: false,
    sensitiveFiles: []
  };

  const requiredHeaders = [
    { name: "strict-transport-security", label: "HSTS (Strict-Transport-Security)" },
    { name: "content-security-policy", label: "CSP (Content-Security-Policy)" },
    { name: "x-frame-options", label: "X-Frame-Options (Clickjacking defense)" },
    { name: "x-content-type-options", label: "X-Content-Type-Options (MIME-sniffing defense)" },
    { name: "permissions-policy", label: "Permissions-Policy" }
  ];

  try {
    const response = await fetch(targetUrl, { 
      method: "GET", 
      redirect: "follow",
      headers: { "Origin": "https://malicious-origin-test.com" },
      signal: AbortSignal.timeout(6000)
    });
    
    report.status = response.status;

    // Check Security Headers
    for (const h of requiredHeaders) {
      const val = response.headers.get(h.name);
      if (val) {
        report.headersFound[h.label] = val;
      } else {
        report.missingHeaders.push(h.label);
      }
    }

    // 2. Check for Dangerous CORS Misconfigurations
    const acao = response.headers.get("access-control-allow-origin");
    const acac = response.headers.get("access-control-allow-credentials");
    if (acao === "*" && acac === "true") {
      report.corsVulnerable = true;
    }

  } catch (error) {
    report.error = `Connection failed: ${error.message}`;
    return report;
  }

  // 3. High-Speed Concurrent Path Fuzzing
  const sensitivePaths = [
    "/robots.txt", "/sitemap.xml", "/.git/config", "/.env", 
    "/admin/", "/api/v1/users", "/backup.zip", "/config.json",
    "/graphql", "/swagger-ui.html", "/phpinfo.php", "/server-status"
  ];

  // Run checks concurrently in batches of 5 for maximum performance
  const batchSize = 5;
  for (let i = 0; i < sensitivePaths.length; i += batchSize) {
    const batch = sensitivePaths.slice(i, i + batchSize);
    const promises = batch.map(async (path) => {
      try {
        const target = new URL(path, targetUrl).toString();
        const res = await fetch(target, { 
          method: "GET", 
          redirect: "manual",
          signal: AbortSignal.timeout(4000) 
        });

        if (res.status === 200 || res.status === 403) {
          return {
            path,
            status: res.status,
            risk: res.status === 200 ? "HIGH - Exposed Publicly" : "LOW - Forbidden (Protected)"
          };
        }
      } catch (err) {
        // Timeout or network drop
      }
      return null;
    });

    const results = await Promise.all(promises);
    results.filter(Boolean).forEach(r => report.sensitiveFiles.push(r));
  }

  return report;
}