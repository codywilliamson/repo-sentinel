export function buildIssueBody(finding, { assignCopilot = false } = {}) {
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
