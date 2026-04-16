// process-findings.mjs
// parses SARIF output from Trivy + CodeQL, creates GitHub issues, assigns Copilot

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

const SARIF_LEVEL_MAP = {
  error: "HIGH",
  warning: "MEDIUM",
  note: "LOW",
  none: "UNKNOWN",
};

const config = {
  token: process.env.GITHUB_TOKEN,
  repo: process.env.GITHUB_REPOSITORY,
  threshold: process.env.SEVERITY_THRESHOLD || "MEDIUM",
  assignCopilot: process.env.ASSIGN_COPILOT === "true",
  label: process.env.ISSUE_LABEL || "security",
  dryRun: process.env.DRY_RUN === "true",
  sarifDir: process.env.SARIF_DIR || "sarif-results",
};

const [owner, repo] = config.repo.split("/");
const thresholdIndex = SEVERITY_ORDER.indexOf(config.threshold);

// -- github api helpers --

async function ghApi(path, options = {}) {
  const url = path.startsWith("https")
    ? path
    : `https://api.github.com${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      Authorization: `token ${config.token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      ...options.headers,
    },
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`GitHub API ${res.status}: ${body}`);
  }

  return res.status === 204 ? null : res.json();
}

async function getExistingIssues() {
  const issues = [];
  let page = 1;

  while (true) {
    const batch = await ghApi(
      `/repos/${owner}/${repo}/issues?labels=${config.label}&state=open&per_page=100&page=${page}`
    );
    issues.push(...batch);
    if (batch.length < 100) break;
    page++;
  }

  return issues;
}

async function ensureLabel() {
  try {
    await ghApi(`/repos/${owner}/${repo}/labels/${config.label}`);
  } catch {
    await ghApi(`/repos/${owner}/${repo}/labels`, {
      method: "POST",
      body: JSON.stringify({
        name: config.label,
        color: "d73a4a",
        description: "Security vulnerability finding",
      }),
    });
    console.log(`Created label: ${config.label}`);
  }
}

async function createIssue(finding) {
  const body = buildIssueBody(finding);

  // try with copilot assignment first, fall back to unassigned
  if (config.assignCopilot) {
    try {
      return await ghApi(`/repos/${owner}/${repo}/issues`, {
        method: "POST",
        body: JSON.stringify({
          title: finding.title,
          body,
          labels: [config.label],
          assignees: ["copilot"],
        }),
      });
    } catch (err) {
      if (err.message.includes("422")) {
        console.log(
          "  copilot not available as assignee, creating without assignment"
        );
      } else {
        throw err;
      }
    }
  }

  return await ghApi(`/repos/${owner}/${repo}/issues`, {
    method: "POST",
    body: JSON.stringify({
      title: finding.title,
      body,
      labels: [config.label],
    }),
  });
}

// -- sarif parsing --

function findSarifFiles(dir) {
  const files = [];

  try {
    const entries = readdirSync(dir);
    for (const entry of entries) {
      const full = join(dir, entry);
      const stat = statSync(full);
      if (stat.isDirectory()) {
        files.push(...findSarifFiles(full));
      } else if (entry.endsWith(".sarif")) {
        files.push(full);
      }
    }
  } catch {
    // directory might not exist if a scan was skipped
  }

  return files;
}

function parseSarif(filePath) {
  const raw = JSON.parse(readFileSync(filePath, "utf-8"));
  const findings = [];

  for (const run of raw.runs || []) {
    const toolName = run.tool?.driver?.name || "unknown";
    const rules = new Map();

    for (const rule of run.tool?.driver?.rules || []) {
      rules.set(rule.id, rule);
    }

    for (const result of run.results || []) {
      const rule = rules.get(result.ruleId) || {};
      const severity = resolveSeverity(result, rule);
      const severityIndex = SEVERITY_ORDER.indexOf(severity);

      // filter by threshold
      if (severityIndex > thresholdIndex) continue;

      const location = result.locations?.[0]?.physicalLocation;
      const fileLoc = location?.artifactLocation?.uri || "unknown";
      const line = location?.region?.startLine || 0;

      const finding = {
        id: result.ruleId || "unknown",
        tool: toolName,
        severity,
        message:
          result.message?.text || rule.shortDescription?.text || "No details",
        file: fileLoc,
        line,
        helpUri: rule.helpUri || "",
        help: rule.help?.text || rule.fullDescription?.text || "",
      };

      // build a stable title for dedup
      finding.title = `[${severity}] ${finding.id}: ${truncate(finding.message, 80)}`;
      finding.dedupKey = `${finding.id}::${finding.file}`;

      findings.push(finding);
    }
  }

  return findings;
}

function resolveSeverity(result, rule) {
  // check rule properties for severity
  const secSeverity =
    rule.properties?.["security-severity"] ||
    result.properties?.["security-severity"];

  if (secSeverity) {
    const score = parseFloat(secSeverity);
    if (score >= 9.0) return "CRITICAL";
    if (score >= 7.0) return "HIGH";
    if (score >= 4.0) return "MEDIUM";
    if (score >= 0.1) return "LOW";
    return "UNKNOWN";
  }

  // fall back to SARIF level
  const level = result.level || "warning";
  return SARIF_LEVEL_MAP[level] || "MEDIUM";
}

function truncate(str, max) {
  if (str.length <= max) return str;
  return str.slice(0, max - 3) + "...";
}

// -- issue body builder --

function buildIssueBody(finding) {
  const severityBadge = {
    CRITICAL: "🔴 Critical",
    HIGH: "🟠 High",
    MEDIUM: "🟡 Medium",
    LOW: "🔵 Low",
  };

  const lines = [
    `## ${severityBadge[finding.severity] || finding.severity} Security Finding`,
    "",
    `**Scanner:** ${finding.tool}`,
    `**Rule:** \`${finding.id}\``,
    `**Severity:** ${finding.severity}`,
    `**File:** \`${finding.file}\`${finding.line ? `:${finding.line}` : ""}`,
    "",
    "### Description",
    "",
    finding.message,
    "",
  ];

  if (finding.help) {
    lines.push("### Remediation Guidance", "", finding.help, "");
  }

  if (finding.helpUri) {
    lines.push(`### References`, "", `- ${finding.helpUri}`, "");
  }

  lines.push(
    "---",
    "",
    "_This issue was automatically created by [repo-sentinel](https://github.com/codywilliamson/repo-sentinel). " +
      (config.assignCopilot
        ? "Assigned to Copilot for an automated fix attempt._"
        : "Review and fix manually._")
  );

  return lines.join("\n");
}

// -- main --

async function main() {
  console.log(`repo-sentinel: processing findings for ${config.repo}`);
  console.log(
    `  threshold: ${config.threshold}, copilot: ${config.assignCopilot}, dry-run: ${config.dryRun}`
  );

  // find all sarif files
  const sarifFiles = findSarifFiles(config.sarifDir);
  console.log(`  found ${sarifFiles.length} SARIF file(s)`);

  if (sarifFiles.length === 0) {
    console.log("  no SARIF files found, nothing to process");
    return;
  }

  // parse all findings
  const allFindings = [];
  for (const file of sarifFiles) {
    console.log(`  parsing: ${file}`);
    const findings = parseSarif(file);
    allFindings.push(...findings);
  }

  console.log(
    `  ${allFindings.length} finding(s) at ${config.threshold}+ severity`
  );

  if (allFindings.length === 0) {
    console.log("  no findings above threshold");
    return;
  }

  // deduplicate by key
  const unique = new Map();
  for (const f of allFindings) {
    if (!unique.has(f.dedupKey)) {
      unique.set(f.dedupKey, f);
    }
  }

  const findings = [...unique.values()];
  console.log(`  ${findings.length} unique finding(s) after dedup`);

  if (config.dryRun) {
    console.log("\n  [DRY RUN] would create issues for:");
    for (const f of findings) {
      console.log(`    - ${f.title}`);
    }
    return;
  }

  // check existing issues to avoid duplicates
  await ensureLabel();
  const existingIssues = await getExistingIssues();
  const existingTitles = new Set(existingIssues.map((i) => i.title));

  let created = 0;
  let skipped = 0;

  for (const finding of findings) {
    if (existingTitles.has(finding.title)) {
      console.log(`  skip (exists): ${finding.title}`);
      skipped++;
      continue;
    }

    try {
      const issue = await createIssue(finding);
      console.log(`  created #${issue.number}: ${finding.title}`);
      created++;
    } catch (err) {
      console.error(`  failed to create issue: ${finding.title}`, err.message);
    }
  }

  console.log(
    `\n  done: ${created} created, ${skipped} skipped (already exist)`
  );
}

main().catch((err) => {
  console.error("repo-sentinel: fatal error", err);
  process.exit(1);
});
