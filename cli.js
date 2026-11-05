#!/usr/bin/env node
import { auditTarget } from "./scanner.js";
import ora from "ora";
import fs from "fs";

async function main() {
  const args = process.argv.slice(2);
  const target = args[0];
  const jsonExport = args.includes("--json");

  if (!target || args.includes("--help") || args.includes("-h")) {
    console.log(`
  🛡️ Enterprise Web Security & Misconfiguration Scanner
  Usage:
    node cli.js <url> [--json]
  Example:
    node cli.js https://example.com
    node cli.js https://example.com --json
    `);
    process.exit(0);
  }

  const spinner = ora(`Initializing security probe against ${target}...`).start();
  
  const report = await auditTarget(target);

  if (report.error) {
    spinner.fail(`Scan aborted: ${report.error}`);
    process.exit(1);
  }

  spinner.succeed(`Scan completed successfully for ${report.url}`);

  if (jsonExport) {
    fs.writeFileSync("security-audit-report.json", JSON.stringify(report, null, 2));
    console.log(`\n💾 Report exported successfully to security-audit-report.json\n`);
    return;
  }

  console.log(`\n============================================================`);
  console.log(`          PENTEST AUDIT REPORT: ${report.url}              `);
  console.log(`============================================================`);
  console.log(` Status Code   : ${report.status}`);
  console.log(` HTTPS Secure  : ${report.secure ? "✅ Enforced" : "❌ Plaintext HTTP"}`);
  console.log(` CORS Wildcard : ${report.corsVulnerable ? "🚨 VULNERABLE (Allow-Origin: * with Credentials)" : "✅ Secure"}`);
  console.log(`------------------------------------------------------------`);
  console.log(` 🔒 Security Headers Found: ${Object.keys(report.headersFound).length}`);
  console.log(` ⚠️ Missing Security Headers: ${report.missingHeaders.length}`);
  report.missingHeaders.forEach(h => console.log(`    - ❌ [Missing] ${h}`));
  
  console.log(`------------------------------------------------------------`);
  console.log(` 📂 Exposed Endpoints & Sensitive Paths (${report.sensitiveFiles.length}):`);
  if (report.sensitiveFiles.length === 0) {
    console.log(`    🛡️ No sensitive configurations or paths detected.`);
  } else {
    report.sensitiveFiles.forEach(f => {
      console.log(`    - [HTTP ${f.status}] ${f.path} ➔ ${f.risk}`);
    });
  }
  console.log(`============================================================\n`);
}

main();