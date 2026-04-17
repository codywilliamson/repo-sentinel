import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

export const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
export const PR_COMMENT_MARKER = "<!-- repo-sentinel:pr-comment -->";

const SARIF_LEVEL_MAP = {
  error: "HIGH",
  warning: "MEDIUM",
  note: "LOW",
  none: "UNKNOWN",
};

const PR_COMMENT_FINDING_LIMIT = 20;

function parseBoolean(value, defaultValue = false) {
  if (value === undefined || value === null || value === "") {
    return defaultValue;
  }

  return value === "true";
}

function thresholdToIndex(threshold) {
  const index = SEVERITY_ORDER.indexOf(threshold);
  return index === -1 ? SEVERITY_ORDER.indexOf("MEDIUM") : index;
}

function formatFindingLocation(finding) {
  return finding.line ? `${finding.file}:${finding.line}` : finding.file;
}

function escapeTableCell(value) {
  return String(value).replaceAll("|", "\\|");
}

export function getConfig(env = process.env) {
  return {
    token: env.GITHUB_TOKEN,
    repo: env.GITHUB_REPOSITORY,
    threshold: env.SEVERITY_THRESHOLD || "MEDIUM",
    assignCopilot: parseBoolean(env.ASSIGN_COPILOT, true),
    label: env.ISSUE_LABEL || "security",
    dryRun: parseBoolean(env.DRY_RUN, false),
    sarifDir: env.SARIF_DIR || "sarif-results",
    createIssues: parseBoolean(env.CREATE_ISSUES, true),
    commentOnPr: parseBoolean(env.COMMENT_ON_PR, true),
    prCommentCopilotTag: parseBoolean(env.PR_COMMENT_COPILOT_TAG, false),
    pullRequestNumber: Number.parseInt(env.PULL_REQUEST_NUMBER || "", 10) || 0,
  };
}

export function findSarifFiles(dir) {
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
    // The directory may not exist if a scan was skipped.
  }

  return files;
}

export function parseSarif(filePath, threshold = "MEDIUM") {
  const raw = JSON.parse(readFileSync(filePath, "utf-8"));
  const findings = [];
  const thresholdIndex = thresholdToIndex(threshold);

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

      if (severityIndex > thresholdIndex) {
        continue;
      }

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

      finding.title = `[${severity}] ${finding.id}: ${truncate(finding.message, 80)}`;
      finding.dedupKey = `${finding.id}::${finding.file}`;

      findings.push(finding);
    }
  }

  return findings;
}

export function resolveSeverity(result, rule) {
  const secSeverity =
    rule.properties?.["security-severity"] ||
    result.properties?.["security-severity"];

  if (secSeverity) {
    const score = Number.parseFloat(secSeverity);
    if (score >= 9.0) return "CRITICAL";
    if (score >= 7.0) return "HIGH";
    if (score >= 4.0) return "MEDIUM";
    if (score >= 0.1) return "LOW";
    return "UNKNOWN";
  }

  const level = result.level || "warning";
  return SARIF_LEVEL_MAP[level] || "MEDIUM";
}

export function truncate(value, max) {
  if (value.length <= max) {
    return value;
  }

  return `${value.slice(0, max - 3)}...`;
}

export function dedupeFindings(findings) {
  const unique = new Map();

  for (const finding of findings) {
    if (!unique.has(finding.dedupKey)) {
      unique.set(finding.dedupKey, finding);
    }
  }

  return [...unique.values()];
}

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

export function createGitHubClient(config) {
  if (!config.token) {
    throw new Error("GITHUB_TOKEN is required");
  }

  if (!config.repo) {
    throw new Error("GITHUB_REPOSITORY is required");
  }

  const [owner, repo] = config.repo.split("/");
  const encodedLabel = encodeURIComponent(config.label);

  async function ghApi(path, options = {}) {
    const url = path.startsWith("https")
      ? path
      : `https://api.github.com${path}`;
    const response = await fetch(url, {
      ...options,
      headers: {
        Authorization: `token ${config.token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        ...options.headers,
      },
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`GitHub API ${response.status}: ${body}`);
    }

    return response.status === 204 ? null : response.json();
  }

  return {
    async ensureLabel() {
      try {
        await ghApi(`/repos/${owner}/${repo}/labels/${encodedLabel}`);
      } catch {
        await ghApi(`/repos/${owner}/${repo}/labels`, {
          method: "POST",
          body: JSON.stringify({
            name: config.label,
            color: "d73a4a",
            description: "Security vulnerability finding",
          }),
        });
      }
    },
    async getExistingIssues() {
      const issues = [];
      let page = 1;

      while (true) {
        const batch = await ghApi(
          `/repos/${owner}/${repo}/issues?labels=${encodedLabel}&state=open&per_page=100&page=${page}`
        );

        issues.push(...batch);

        if (batch.length < 100) {
          break;
        }

        page += 1;
      }

      return issues;
    },
    async createIssue(finding) {
      const body = buildIssueBody(finding, {
        assignCopilot: config.assignCopilot,
      });

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
        } catch (error) {
          if (error.message.includes("422")) {
            return ghApi(`/repos/${owner}/${repo}/issues`, {
              method: "POST",
              body: JSON.stringify({
                title: finding.title,
                body,
                labels: [config.label],
              }),
            });
          }

          throw error;
        }
      }

      return ghApi(`/repos/${owner}/${repo}/issues`, {
        method: "POST",
        body: JSON.stringify({
          title: finding.title,
          body,
          labels: [config.label],
        }),
      });
    },
    async listPullRequestComments(pullRequestNumber) {
      const comments = [];
      let page = 1;

      while (true) {
        const batch = await ghApi(
          `/repos/${owner}/${repo}/issues/${pullRequestNumber}/comments?per_page=100&page=${page}`
        );

        comments.push(...batch);

        if (batch.length < 100) {
          break;
        }

        page += 1;
      }

      return comments;
    },
    async createPullRequestComment(pullRequestNumber, body) {
      return ghApi(`/repos/${owner}/${repo}/issues/${pullRequestNumber}/comments`, {
        method: "POST",
        body: JSON.stringify({ body }),
      });
    },
    async updatePullRequestComment(commentId, body) {
      return ghApi(`/repos/${owner}/${repo}/issues/comments/${commentId}`, {
        method: "PATCH",
        body: JSON.stringify({ body }),
      });
    },
  };
}

export async function processFindings(config, deps = {}) {
  const logger = deps.logger || console;
  const github = deps.github || createGitHubClient(config);

  logger.log(`repo-sentinel: processing findings for ${config.repo}`);
  logger.log(
    `  threshold: ${config.threshold}, create-issues: ${config.createIssues}, pr-comment: ${config.commentOnPr}, dry-run: ${config.dryRun}`
  );

  const sarifFiles = findSarifFiles(config.sarifDir);
  logger.log(`  found ${sarifFiles.length} SARIF file(s)`);

  if (sarifFiles.length === 0) {
    logger.log("  no SARIF files found, nothing to process");
    return {
      findingsCount: 0,
      createdIssues: 0,
      skippedIssues: 0,
      prCommentAction: "skipped",
    };
  }

  const allFindings = [];
  for (const file of sarifFiles) {
    logger.log(`  parsing: ${file}`);
    allFindings.push(...parseSarif(file, config.threshold));
  }

  const findings = dedupeFindings(allFindings);
  logger.log(
    `  ${findings.length} unique finding(s) at ${config.threshold}+ severity`
  );

  if (config.dryRun) {
    if (findings.length > 0) {
      logger.log("\n  [DRY RUN] would create/update records for:");
      for (const finding of findings) {
        logger.log(`    - ${finding.title}`);
      }
    }

    if (config.commentOnPr && isPullRequestContext(config)) {
      logger.log(
        `  [DRY RUN] would upsert PR comment on #${config.pullRequestNumber}`
      );
    }

    return {
      findingsCount: findings.length,
      createdIssues: 0,
      skippedIssues: 0,
      prCommentAction: "dry-run",
    };
  }

  let createdIssues = 0;
  let skippedIssues = 0;

  if (config.createIssues && findings.length > 0) {
    await github.ensureLabel();
    const existingIssues = await github.getExistingIssues();
    const existingTitles = new Set(existingIssues.map((issue) => issue.title));

    for (const finding of findings) {
      if (existingTitles.has(finding.title)) {
        logger.log(`  skip (exists): ${finding.title}`);
        skippedIssues += 1;
        continue;
      }

      try {
        const issue = await github.createIssue(finding);
        logger.log(`  created #${issue.number}: ${finding.title}`);
        createdIssues += 1;
      } catch (error) {
        logger.error(
          `  failed to create issue: ${finding.title}`,
          error.message
        );
      }
    }
  }

  let prCommentAction = "skipped";

  if (config.commentOnPr && isPullRequestContext(config)) {
    const body = buildPullRequestComment(findings, config);
    const comments = await github.listPullRequestComments(config.pullRequestNumber);
    const existingComment = comments.find((comment) =>
      comment.body?.includes(PR_COMMENT_MARKER)
    );

    if (existingComment) {
      await github.updatePullRequestComment(existingComment.id, body);
      prCommentAction = "updated";
      logger.log(`  updated sticky PR comment on #${config.pullRequestNumber}`);
    } else {
      await github.createPullRequestComment(config.pullRequestNumber, body);
      prCommentAction = "created";
      logger.log(`  created sticky PR comment on #${config.pullRequestNumber}`);
    }
  }

  logger.log(
    `\n  done: ${createdIssues} issue(s) created, ${skippedIssues} skipped, PR comment ${prCommentAction}`
  );

  return {
    findingsCount: findings.length,
    createdIssues,
    skippedIssues,
    prCommentAction,
  };
}
