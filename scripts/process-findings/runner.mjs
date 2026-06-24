import { createGitHubClient, isGitHubIntegrationPermissionError } from "./github-client.mjs";
import { buildPullRequestComment, isPullRequestContext, PR_COMMENT_MARKER } from "./pr-comments.mjs";
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
    prCommentAction: "dry-run",
  };
}

async function createIssuesForFindings(config, github, findings, logger) {
  let createdIssues = 0;
  let skippedIssues = 0;

  if (!config.createIssues || findings.length === 0) {
    return { createdIssues, skippedIssues };
  }

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

  return { createdIssues, skippedIssues };
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
  const { createdIssues, skippedIssues } = await createIssuesForFindings(
    config,
    github,
    findings,
    logger
  );
  const prCommentAction = await upsertPullRequestComment(
    config,
    github,
    findings,
    logger,
    warn
  );

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
