import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { PR_COMMENT_MARKER, processFindings } from "./process-findings-lib.mjs";
import { createGitHubClient } from "./process-findings/github-client.mjs";
import { getIssueMarker } from "./process-findings/issues.mjs";

function createMockGithub() {
  const calls = {
    createIssue: [],
    closeIssue: [],
    createPullRequestComment: [],
    updatePullRequestComment: [],
  };

  return {
    calls,
    async ensureLabel() {},
    existingIssues: [],
    async getExistingIssues() {
      return this.existingIssues;
    },
    async createIssue(finding) {
      calls.createIssue.push(finding);
      return { number: 101 };
    },
    async closeIssue(number) {
      calls.closeIssue.push(number);
    },
    async listPullRequestComments() {
      return [];
    },
    async createPullRequestComment(pullRequestNumber, body) {
      calls.createPullRequestComment.push({ pullRequestNumber, body });
      return { id: 201 };
    },
    async updatePullRequestComment(commentId, body) {
      calls.updatePullRequestComment.push({ commentId, body });
      return { id: commentId };
    },
  };
}

function buildSarifResult({
  ruleId = "js/sql-injection",
  message = "Unsanitized user input reaches a SQL query.",
  severity = "8.1",
  file = "src/db.js",
  line = 42,
} = {}) {
  return {
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "CodeQL",
            rules: [
              {
                id: ruleId,
                shortDescription: { text: "SQL injection" },
                properties: { "security-severity": severity },
                help: { text: "Use parameterized queries." },
                helpUri: "https://example.com/sql-injection",
              },
            ],
          },
        },
        results: [
          {
            ruleId,
            message: { text: message },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: file },
                  region: { startLine: line },
                },
              },
            ],
          },
        ],
      },
    ],
  };
}

async function withSarifDir(sarifPayload, callback) {
  const dir = await mkdtemp(join(tmpdir(), "repo-sentinel-test-"));

  try {
    await writeFile(
      join(dir, "codeql.sarif"),
      JSON.stringify(sarifPayload, null, 2),
      "utf8"
    );

    await callback(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("processFindings dry-run reports findings without constructing a GitHub client", async () => {
  await withSarifDir(buildSarifResult(), async (sarifDir) => {
    const logs = [];
    const result = await processFindings(
      {
        repo: "octo/repo-sentinel",
        threshold: "MEDIUM",
        label: "security",
        dryRun: true,
        assignCopilot: true,
        createIssues: true,
        commentOnPr: true,
        prCommentCopilotTag: false,
        pullRequestNumber: 17,
        sarifDir,
      },
      { logger: { log(message) { logs.push(message); }, error() {} } }
    );

    assert.equal(result.findingsCount, 1);
    assert.equal(result.createdIssues, 0);
    assert.equal(result.prCommentAction, "dry-run");
    assert.ok(logs.some((message) => String(message).includes("[DRY RUN]")));
  });
});

test("processFindings creates a sticky PR comment on pull request runs", async () => {
  const github = createMockGithub();

  await withSarifDir(buildSarifResult(), async (sarifDir) => {
    const result = await processFindings(
      {
        repo: "octo/repo-sentinel",
        threshold: "MEDIUM",
        label: "security",
        dryRun: false,
        assignCopilot: false,
        createIssues: false,
        commentOnPr: true,
        prCommentCopilotTag: false,
        pullRequestNumber: 17,
        sarifDir,
      },
      { github, logger: { log() {}, error() {} } }
    );

    assert.equal(result.findingsCount, 1);
    assert.equal(github.calls.createIssue.length, 0);
    assert.equal(github.calls.createPullRequestComment.length, 1);
    assert.equal(github.calls.updatePullRequestComment.length, 0);

    const [{ pullRequestNumber, body }] = github.calls.createPullRequestComment;
    assert.equal(pullRequestNumber, 17);
    assert.match(body, new RegExp(PR_COMMENT_MARKER.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.match(body, /1 unique finding/);
    assert.doesNotMatch(body, /@copilot/);
  });
});

test("processFindings updates the existing sticky PR comment and can tag Copilot", async () => {
  const github = createMockGithub();
  github.listPullRequestComments = async () => [
    { id: 303, body: `${PR_COMMENT_MARKER}\nold body` },
  ];

  await withSarifDir(buildSarifResult(), async (sarifDir) => {
    await processFindings(
      {
        repo: "octo/repo-sentinel",
        threshold: "MEDIUM",
        label: "security",
        dryRun: false,
        assignCopilot: false,
        createIssues: false,
        commentOnPr: true,
        prCommentCopilotTag: true,
        pullRequestNumber: 21,
        sarifDir,
      },
      { github, logger: { log() {}, error() {} } }
    );

    assert.equal(github.calls.createPullRequestComment.length, 0);
    assert.equal(github.calls.updatePullRequestComment.length, 1);

    const [{ commentId, body }] = github.calls.updatePullRequestComment;
    assert.equal(commentId, 303);
    assert.match(body, /@copilot/);
  });
});

test("processFindings posts a clean PR comment when no findings meet the threshold", async () => {
  const github = createMockGithub();
  const lowSeveritySarif = buildSarifResult({ severity: "0.5" });

  await withSarifDir(lowSeveritySarif, async (sarifDir) => {
    const result = await processFindings(
      {
        repo: "octo/repo-sentinel",
        threshold: "MEDIUM",
        label: "security",
        dryRun: false,
        assignCopilot: false,
        createIssues: false,
        commentOnPr: true,
        prCommentCopilotTag: false,
        pullRequestNumber: 34,
        sarifDir,
      },
      { github, logger: { log() {}, error() {} } }
    );

    assert.equal(result.findingsCount, 0);
    assert.equal(github.calls.createPullRequestComment.length, 1);

    const [{ body }] = github.calls.createPullRequestComment;
    assert.match(body, /No findings at `MEDIUM\+` severity were detected/);
  });
});

test("processFindings skips PR comments when GitHub denies integration access", async () => {
  const github = createMockGithub();
  github.createPullRequestComment = async () => {
    throw new Error(
      'GitHub API 403: {"message":"Resource not accessible by integration","status":"403"}'
    );
  };

  await withSarifDir(buildSarifResult(), async (sarifDir) => {
    const warnings = [];
    const result = await processFindings(
      {
        repo: "octo/repo-sentinel",
        threshold: "MEDIUM",
        label: "security",
        dryRun: false,
        assignCopilot: false,
        createIssues: false,
        commentOnPr: true,
        prCommentCopilotTag: false,
        pullRequestNumber: 55,
        sarifDir,
      },
      {
        github,
        logger: {
          log() {},
          warn(message) {
            warnings.push(message);
          },
          error() {},
        },
      }
    );

    assert.equal(result.findingsCount, 1);
    assert.equal(result.prCommentAction, "skipped-permissions");
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /skipped sticky PR comment on #55/);
    assert.match(warnings[0], /Resource not accessible by integration/);
  });
});

test("issue creation neutralizes scanner-provided mentions", async () => {
  let payload;
  const github = createGitHubClient(
    {
      token: "test-token",
      repo: "octo/repo-sentinel",
      label: "security",
      assignCopilot: false,
    },
    {
      async fetch(url, options) {
        assert.equal(url, "https://api.github.com/repos/octo/repo-sentinel/issues");
        payload = JSON.parse(options.body);

        return {
          ok: true,
          status: 201,
          async json() {
            return { number: 101 };
          },
        };
      },
    }
  );

  await github.createIssue({
    title: "[HIGH] Reported by @scanner-author",
    severity: "HIGH",
    tool: "Trivy",
    id: "CVE-2026-0001",
    file: "pnpm-lock.yaml",
    line: 1,
    message: "Reported by @scanner-author via security@example.com.",
    help: "Credits: &#64;first, &#x40;second, and &commat;third.",
    helpUri: "https://github.com/@url-author/advisory",
  });

  assert.equal(payload.title, "[HIGH] Reported by @\u200bscanner-author");
  assert.doesNotMatch(payload.body, /@(scanner-author|first|second|third)/);
  assert.match(payload.body, /@\u200bscanner-author/);
  assert.match(payload.body, /@\u200bfirst/);
  assert.match(payload.body, /@\u200bsecond/);
  assert.match(payload.body, /@\u200bthird/);
  assert.match(payload.body, /security@example\.com/);
  assert.match(payload.body, /https:\/\/github\.com\/@url-author\/advisory/);
});


test("complete default-branch scan closes only owned issues absent from current findings", async () => {
  const github = createMockGithub();
  const config = {
    repo: "octo/repo-sentinel",
    threshold: "MEDIUM",
    label: "security",
    dryRun: false,
    assignCopilot: false,
    createIssues: true,
    closeResolvedIssues: true,
    fullDefaultBranchScan: true,
    commentOnPr: false,
    pullRequestNumber: 0,
  };
  const active = { id: "js/sql-injection", file: "src/db.js", tool: "CodeQL" };
  const resolved = { id: "js/old-bug", file: "src/old.js", tool: "CodeQL" };
  github.existingIssues = [
    { number: 1, title: "old title for active finding", body: getIssueMarker(config, active) },
    { number: 2, title: "resolved", body: getIssueMarker(config, resolved) },
    { number: 3, title: "manual security issue", body: "No repo-sentinel marker" },
    { number: 4, title: "other scan profile", body: getIssueMarker({ ...config, trivyScanners: "secret" }, resolved) },
    { number: 5, title: "pull request", body: getIssueMarker(config, resolved), pull_request: { url: "https://example.com" } },
    { number: 6, title: "other skipped directories", body: getIssueMarker({ ...config, trivySkipDirs: "docs" }, resolved) },
  ];

  await withSarifDir(buildSarifResult(), async (sarifDir) => {
    const result = await processFindings({ ...config, sarifDir }, {
      github,
      logger: { log() {}, error() {} },
    });
    assert.equal(result.findingsCount, 1);
    assert.equal(result.createdIssues, 0);
    assert.equal(result.skippedIssues, 1);
    assert.equal(result.closedIssues, 1);
    assert.deepEqual(github.calls.closeIssue, [2]);
  });
});

test("clean default-branch scan closes owned issues, but partial and PR scans cannot", async () => {
  const config = {
    repo: "octo/repo-sentinel",
    threshold: "MEDIUM",
    label: "security",
    dryRun: false,
    assignCopilot: false,
    createIssues: true,
    closeResolvedIssues: true,
    fullDefaultBranchScan: true,
    commentOnPr: false,
    pullRequestNumber: 0,
  };
  const oldIssue = {
    number: 42,
    title: "resolved finding",
    body: getIssueMarker(config, { id: "js/old-bug", file: "src/old.js", tool: "CodeQL" }),
  };
  await withSarifDir(buildSarifResult({ severity: "0.5" }), async (sarifDir) => {
    for (const [name, overrides, expectedClosed] of [
      ["full scan", {}, 1],
      ["partial scan", { fullDefaultBranchScan: false }, 0],
      ["PR scan", { pullRequestNumber: 17 }, 0],
      ["disabled", { closeResolvedIssues: false }, 0],
    ]) {
      const github = createMockGithub();
      github.existingIssues = [oldIssue];
      const result = await processFindings({ ...config, ...overrides, sarifDir }, {
        github,
        logger: { log() {}, error() {} },
      });
      assert.equal(result.closedIssues, expectedClosed, name);
      assert.equal(github.calls.closeIssue.length, expectedClosed, name);
    }
  });
});

test("closing a resolved issue uses GitHub's completed state", async () => {
  let request;
  const github = createGitHubClient({
    token: "test-token",
    repo: "octo/repo-sentinel",
    label: "security",
    assignCopilot: false,
  }, {
    async fetch(url, options) {
      request = { url, options };
      return { ok: true, status: 200, async json() { return {}; } };
    },
  });
  await github.closeIssue(42);
  assert.equal(request.url, "https://api.github.com/repos/octo/repo-sentinel/issues/42");
  assert.equal(request.options.method, "PATCH");
  assert.deepEqual(JSON.parse(request.options.body), { state: "closed", state_reason: "completed" });
});
