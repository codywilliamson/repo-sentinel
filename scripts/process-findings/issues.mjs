import { createHash } from "node:crypto";

function digest(value) {
  return createHash("sha256").update(value).digest("hex").slice(0, 20);
}

function sortedCsv(value, fallback) {
  return String(value || fallback).split(",").map((part) => part.trim()).filter(Boolean).sort();
}

export function getIssueProfilePrefix(config) {
  const profile = JSON.stringify({
    threshold: config.threshold || "MEDIUM",
    trivyScanners: sortedCsv(config.trivyScanners, "vuln,secret,misconfig"),
    trivySkipDirs: sortedCsv(config.trivySkipDirs, ""),
    codeqlLanguages: sortedCsv(config.codeqlLanguages, "javascript-typescript"),
  });
  return `<!-- repo-sentinel:issue:${digest(profile)}:`;
}

export function getIssueMarker(config, finding) {
  return `${getIssueProfilePrefix(config)}${digest(`${finding.id}::${finding.file}::${finding.tool}`)} -->`;
}

export function buildIssueBody(finding, { assignCopilot = false, issueMarker = "" } = {}) {
  const severityBadge = {
    CRITICAL: "🔴 Critical",
    HIGH: "🟠 High",
    MEDIUM: "🟡 Medium",
    LOW: "🔵 Low",
  };

  const lines = [
    ...(issueMarker ? [issueMarker, ""] : []),
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
    lines.push("### References", "", `- ${finding.helpUri}`, "");
  }

  lines.push(
    "---",
    "",
    "_This issue was automatically created by [repo-sentinel](https://github.com/codywilliamson/repo-sentinel). " +
      (assignCopilot
        ? "Assigned to Copilot for an automated fix attempt._"
        : "Review and fix manually._")
  );

  return lines.join("\n");
}
