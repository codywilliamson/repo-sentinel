import { createGitHubClient, isGitHubIntegrationPermissionError } from "./github-client.mjs";
import { buildPullRequestComment, isPullRequestContext, PR_COMMENT_MARKER } from "./pr-comments.mjs";
import { groupDependencyFindings } from "./group.mjs";
import { getIssueMarker, getIssueProfilePrefix } from "./issues.mjs";
import { dedupeFindings, findSarifFiles, parseSarif } from "./sarif.mjs";

function getWarnLogger(logger) {
  return logger.warn ? logger.warn.bind(logger) : logger.log.bind(logger);
}

function logRunConfig(logger, config) {
  logger.log(`repo-sentinel: processing findings for ${config.repo}`);
  logger.log(
    `  threshold: ${config.threshold}, create-issues: ${config.createIssues}, pr-comment: ${config.commentOnPr}, dry-run: ${config.dryRun}`
  );
}

function collectFindings(config, logger) {
  const sarifFiles = findSarifFiles(config.sarifDir);
  logger.log(`  found ${sarifFiles.length} SARIF file(s)`);

  if (sarifFiles.length === 0) {
    return { sarifFiles, findings: [] };
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

  return { sarifFiles, findings };
}

function buildNoSarifResult() {
  return {
    findingsCount: 0,
    createdIssues: 0,
    skippedIssues: 0,
    closedIssues: 0,
    prCommentAction: "skipped",
  };
}

function buildDryRunResult(config, findings, logger) {
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
    closedIssues: 0,
    prCommentAction: "dry-run",
  };
}

const NOT_PLANNED = "not_planned";
const FOREIGN_MARKER_PREFIX = "<!-- repo-sentinel:issue:";

function isClosed(issue) {
  return issue.state === "closed";
}

function isOpen(issue) {
  return !isClosed(issue);
}

function isSuppressed(issue) {
  return isClosed(issue) && issue.state_reason === NOT_PLANNED;
}

function includesAnyMarker(issue, markers) {
  return markers.some((marker) => issue.body?.includes(marker));
}

// grouped findings also recognise the per-cve markers that v0.3.4 filed
function findLegacyIssues(config, issues, finding) {
  const markers = (finding.vulnerabilities || []).map((vuln) =>
    getIssueMarker(config, { id: vuln.id, file: finding.file, tool: finding.tool })
  );
  const legacy = issues.filter((issue) => includesAnyMarker(issue, markers));
  const usable = legacy.filter((issue) => isOpen(issue) || !isSuppressed(issue));
  const chosen = usable.find(isOpen) || usable[0] || legacy[0];

  return { issue: chosen, duplicates: legacy.filter((issue) => isOpen(issue) && issue !== chosen) };
}

// newest-first list: prefer an open match, else the newest closed one
function findIssueForFinding(config, issues, finding) {
  const byMarker = issues.filter((issue) => includesAnyMarker(issue, [getIssueMarker(config, finding)]));
  if (byMarker.length > 0) {
    return { issue: byMarker.find(isOpen) || byMarker[0], duplicates: [] };
  }

  const legacy = findLegacyIssues(config, issues, finding);
  if (legacy.issue) return legacy;

  const byTitle = issues.filter((issue) => issue.title === finding.title && !issue.body?.includes(FOREIGN_MARKER_PREFIX));
  return { issue: byTitle.find(isOpen) || byTitle[0], duplicates: [] };
}

async function closeDuplicates(github, duplicates, issue, logger, counts) {
  for (const duplicate of duplicates) {
    await github.commentOnIssue(duplicate.number, `Superseded by the grouped dependency issue #${issue.number}.`);
    await github.closeIssue(duplicate.number);
    duplicate.state = "closed";
    logger.log(`  closed #${duplicate.number} as duplicate of #${issue.number}`);
    counts.closedIssues += 1;
  }
}

async function syncFinding(config, github, issues, finding, logger, counts, claimed) {
  const { issue, duplicates } = findIssueForFinding(config, issues, finding);

  if (!issue) {
    const created = await github.createIssue(finding);
    logger.log(`  created #${created.number}: ${finding.title}`);
    counts.createdIssues += 1;
    return;
  }

  claimed.add(issue.number);

  if (isSuppressed(issue)) {
    logger.log(`  skip (closed as not planned #${issue.number}): ${finding.title}`);
    counts.skippedIssues += 1;
    return;
  }

  if (isClosed(issue)) {
    await github.reopenIssue(issue.number);
    logger.log(`  reopened #${issue.number}: ${finding.title}`);
    counts.reopenedIssues += 1;
  }

  if (await github.updateIssue(issue, finding)) {
    logger.log(`  updated #${issue.number}: ${finding.title}`);
    counts.updatedIssues += 1;
  } else if (!isClosed(issue)) {
    logger.log(`  skip (up to date #${issue.number}): ${finding.title}`);
    counts.skippedIssues += 1;
  }

  await closeDuplicates(github, duplicates, issue, logger, counts);
}

async function closeResolvedIssues(config, github, issues, activeMarkers, claimed, logger, counts) {
  const profilePrefix = getIssueProfilePrefix(config);

  for (const issue of issues) {
    if (issue.pull_request || isClosed(issue) || claimed.has(issue.number) || !issue.body?.includes(profilePrefix)) continue;
    if ([...activeMarkers].some((marker) => issue.body.includes(marker))) continue;

    try {
      await github.closeIssue(issue.number);
      logger.log(`  closed resolved issue #${issue.number}`);
      counts.closedIssues += 1;
    } catch (error) {
      logger.error(`  failed to close resolved issue #${issue.number}`, error.message);
    }
  }
}

async function syncIssuesForFindings(config, github, scanFindings, logger) {
  const counts = { createdIssues: 0, skippedIssues: 0, updatedIssues: 0, reopenedIssues: 0, closedIssues: 0 };
  const canClose = config.createIssues && config.closeResolvedIssues &&
    config.fullDefaultBranchScan && !isPullRequestContext(config);

  if (!config.createIssues || (scanFindings.length === 0 && !canClose)) {
    return counts;
  }

  const findings = groupDependencyFindings(scanFindings);

  await github.ensureLabel();
  const issues = (await github.getExistingIssues()).filter((issue) => !issue.pull_request);

  const claimed = new Set();

  for (const finding of findings) {
    try {
      await syncFinding(config, github, issues, finding, logger, counts, claimed);
    } catch (error) {
      logger.error(`  failed to sync issue: ${finding.title}`, error.message);
    }
  }

  if (canClose) {
    const activeMarkers = new Set(findings.map((finding) => getIssueMarker(config, finding)));
    await closeResolvedIssues(config, github, issues, activeMarkers, claimed, logger, counts);
  }

  return counts;
}

async function upsertPullRequestComment(config, github, findings, logger, warn) {
  if (!config.commentOnPr || !isPullRequestContext(config)) {
    return "skipped";
  }

  try {
    const body = buildPullRequestComment(findings, config);
    const comments = await github.listPullRequestComments(config.pullRequestNumber);
    const existingComment = comments.find((comment) =>
      comment.body?.includes(PR_COMMENT_MARKER)
    );

    if (existingComment) {
      await github.updatePullRequestComment(existingComment.id, body);
      logger.log(`  updated sticky PR comment on #${config.pullRequestNumber}`);
      return "updated";
    }

    await github.createPullRequestComment(config.pullRequestNumber, body);
    logger.log(`  created sticky PR comment on #${config.pullRequestNumber}`);
    return "created";
  } catch (error) {
    if (!isGitHubIntegrationPermissionError(error)) {
      throw error;
    }

    warn(
      `  skipped sticky PR comment on #${config.pullRequestNumber}: ${error.message}`
    );
    return "skipped-permissions";
  }
}

export async function processFindings(config, deps = {}) {
  const logger = deps.logger || console;
  const warn = getWarnLogger(logger);

  logRunConfig(logger, config);

  const { sarifFiles, findings } = collectFindings(config, logger);

  if (sarifFiles.length === 0) {
    logger.log("  no SARIF files found, nothing to process");
    return buildNoSarifResult();
  }

  if (config.dryRun) {
    return buildDryRunResult(config, findings, logger);
  }

  const github = deps.github || createGitHubClient(config);
  const issueCounts = await syncIssuesForFindings(config, github, findings, logger);
  const prCommentAction = await upsertPullRequestComment(
    config,
    github,
    findings,
    logger,
    warn
  );

  logger.log(
    `\n  done: ${issueCounts.createdIssues} issue(s) created, ${issueCounts.updatedIssues} updated, ${issueCounts.reopenedIssues} reopened, ${issueCounts.skippedIssues} skipped, ${issueCounts.closedIssues} closed, PR comment ${prCommentAction}`
  );

  return {
    findingsCount: findings.length,
    ...issueCounts,
    prCommentAction,
  };
}
