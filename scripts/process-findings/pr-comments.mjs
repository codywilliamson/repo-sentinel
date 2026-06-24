import { SEVERITY_ORDER } from "./sarif.mjs";

export const PR_COMMENT_MARKER = "<!-- repo-sentinel:pr-comment -->";

const PR_COMMENT_FINDING_LIMIT = 20;

function formatFindingLocation(finding) {
  return finding.line ? `${finding.file}:${finding.line}` : finding.file;
}

function escapeTableCell(value) {
  return String(value).replaceAll("|", "\\|");
}

export function buildPullRequestComment(findings, config) {
  const lines = [
    PR_COMMENT_MARKER,
    "## repo-sentinel PR findings",
    "",
    `Threshold: \`${config.threshold}+\``,
    "",
  ];

  if (findings.length === 0) {
    lines.push(
      `No findings at \`${config.threshold}+\` severity were detected for this pull request.`,
      "",
      "_This comment is updated automatically on each PR scan run._"
    );

    return lines.join("\n");
  }

  const summary = summarizeFindings(findings);
  const displayedFindings = findings.slice(0, PR_COMMENT_FINDING_LIMIT);
  const noun = findings.length === 1 ? "finding" : "findings";

  lines.push(
    `Detected ${findings.length} unique ${noun}.`,
    "",
    `Severity summary: ${summary}`,
    "",
    "| Severity | Rule | File | Scanner |",
    "| --- | --- | --- | --- |"
  );

  for (const finding of displayedFindings) {
    lines.push(
      `| ${finding.severity} | \`${escapeTableCell(finding.id)}\` | \`${escapeTableCell(formatFindingLocation(finding))}\` | ${escapeTableCell(finding.tool)} |`
    );
  }

  if (displayedFindings.length < findings.length) {
    lines.push(
      "",
      `Showing the first ${displayedFindings.length} of ${findings.length} findings.`
    );
  }

  lines.push(
    "",
    "Review the workflow run artifacts and the repository Security tab for full details."
  );

  if (config.prCommentCopilotTag) {
    lines.push(
      "",
      "@copilot please help remediate the findings called out above in this pull request."
    );
  }

  lines.push("", "_This comment is updated automatically on each PR scan run._");

  return lines.join("\n");
}

export function summarizeFindings(findings) {
  const counts = new Map();

  for (const severity of SEVERITY_ORDER) {
    counts.set(severity, 0);
  }

  for (const finding of findings) {
    counts.set(finding.severity, (counts.get(finding.severity) || 0) + 1);
  }

  return SEVERITY_ORDER.filter((severity) => counts.get(severity) > 0)
    .map((severity) => `${counts.get(severity)} ${severity}`)
    .join(", ");
}

export function isPullRequestContext(config) {
  return Number.isInteger(config.pullRequestNumber) && config.pullRequestNumber > 0;
}
