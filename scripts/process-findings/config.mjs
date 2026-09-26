function parseBoolean(value, defaultValue = false) {
  if (value === undefined || value === null || value === "") {
    return defaultValue;
  }

  return value === "true";
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
    closeResolvedIssues: parseBoolean(env.CLOSE_RESOLVED_ISSUES, false),
    fullDefaultBranchScan: parseBoolean(env.FULL_DEFAULT_BRANCH_SCAN, false),
    trivyScanners: env.TRIVY_SCANNERS || "vuln,secret,misconfig",
    trivySkipDirs: env.TRIVY_SKIP_DIRS || "",
    codeqlLanguages: env.CODEQL_LANGUAGES || "javascript-typescript",
    commentOnPr: parseBoolean(env.COMMENT_ON_PR, true),
    prCommentCopilotTag: parseBoolean(env.PR_COMMENT_COPILOT_TAG, false),
    pullRequestNumber: Number.parseInt(env.PULL_REQUEST_NUMBER || "", 10) || 0,
  };
}
