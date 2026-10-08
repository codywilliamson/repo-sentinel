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
    updateIssue: [],
    reopenIssue: [],
    commentOnIssue: [],
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
    async updateIssue(issue, finding) {
      calls.updateIssue.push({ number: issue.number, finding });
      return true;
    },
    async commentOnIssue(number, body) {
      calls.commentOnIssue.push({ number, body });
    },
    async reopenIssue(number) {
      calls.reopenIssue.push(number);
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
    assert.equal(result.updatedIssues, 1);
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

function buildTrivyPackage(name, version, vulns, file = "package-lock.json") {
  return {
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "Trivy",
          rules: vulns.map(([id, score]) => ({
            id,
            properties: { "security-severity": score },
            helpUri: `https://example.com/${id}`,
          })),
        },
      },
      results: vulns.map(([id, , fixed]) => ({
        ruleId: id,
        message: { text: `Package: ${name}
Installed Version: ${version}
Vulnerability ${id}
Fixed Version: ${fixed}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: file }, region: { startLine: 3 } } }],
      })),
    }],
  };
}

const syncConfig = {
  repo: "octo/repo-sentinel",
  threshold: "MEDIUM",
  label: "security",
  dryRun: false,
  assignCopilot: false,
  createIssues: true,
  commentOnPr: false,
  pullRequestNumber: 0,
};
const quietLogger = { log() {}, error() {} };

async function runWithTrivy(payload, github, overrides = {}) {
  const dir = await mkdtemp(join(tmpdir(), "repo-sentinel-test-"));
  try {
    await writeFile(join(dir, "trivy.sarif"), JSON.stringify(payload), "utf8");
    return await processFindings({ ...syncConfig, ...overrides, sarifDir: dir }, { github, logger: quietLogger });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const undiciScan = buildTrivyPackage("undici", "7.29.0", [
  ["CVE-2026-1", "5.0", "7.30.0"],
  ["CVE-2026-2", "8.0", "7.30.0"],
  ["CVE-2026-3", "5.5", "7.31.0"],
]);

test("dependency findings are grouped into one issue per package and version", async () => {
  const github = createMockGithub();
  const result = await runWithTrivy(undiciScan, github);

  assert.equal(result.createdIssues, 1);
  const [group] = github.calls.createIssue;
  assert.equal(group.title, "[HIGH] undici 7.29.0: 3 vulnerabilities");
  assert.equal(group.severity, "HIGH");
  assert.deepEqual(group.vulnerabilities.map((vuln) => vuln.id), ["CVE-2026-2", "CVE-2026-1", "CVE-2026-3"]);
  assert.equal(group.vulnerabilities[0].fixedVersion, "7.30.0");
});

test("a new package version gets a new fingerprint and the old issue is closed", async () => {
  const config = { ...syncConfig, closeResolvedIssues: true, fullDefaultBranchScan: true };
  const github = createMockGithub();
  github.existingIssues = [{
    number: 7,
    state: "open",
    title: "[HIGH] undici 7.29.0: 3 vulnerabilities",
    body: getIssueMarker(config, { id: "undici@7.29.0", file: "package-lock.json", tool: "Trivy" }),
  }];
  const fixed = buildTrivyPackage("undici", "7.30.0", [["CVE-2026-9", "5.0", "7.31.0"]]);
  const result = await runWithTrivy(fixed, github, config);

  assert.equal(result.createdIssues, 1);
  assert.deepEqual(github.calls.closeIssue, [7]);
});

test("an open grouped issue is updated in place, never duplicated", async () => {
  const github = createMockGithub();
  github.existingIssues = [{
    number: 9,
    state: "open",
    title: "[MEDIUM] undici 7.29.0: 1 vulnerability",
    body: getIssueMarker(syncConfig, { id: "undici@7.29.0", file: "package-lock.json", tool: "Trivy" }),
  }];
  const result = await runWithTrivy(undiciScan, github);

  assert.equal(result.createdIssues, 0);
  assert.equal(result.updatedIssues, 1);
  assert.equal(github.calls.updateIssue[0].number, 9);
});

test("closed as not planned stays closed, closed as completed is reopened", async () => {
  const marker = getIssueMarker(syncConfig, { id: "undici@7.29.0", file: "package-lock.json", tool: "Trivy" });

  const ignored = createMockGithub();
  ignored.existingIssues = [{ number: 5, state: "closed", state_reason: "not_planned", title: "x", body: marker }];
  const ignoredResult = await runWithTrivy(undiciScan, ignored);
  assert.equal(ignoredResult.createdIssues, 0);
  assert.equal(ignoredResult.skippedIssues, 1);
  assert.deepEqual(ignored.calls.reopenIssue, []);
  assert.equal(ignored.calls.updateIssue.length, 0);

  const regressed = createMockGithub();
  regressed.existingIssues = [{ number: 6, state: "closed", state_reason: "completed", title: "x", body: marker }];
  const regressedResult = await runWithTrivy(undiciScan, regressed);
  assert.equal(regressedResult.createdIssues, 0);
  assert.equal(regressedResult.reopenedIssues, 1);
  assert.deepEqual(regressed.calls.reopenIssue, [6]);
  assert.equal(regressed.calls.updateIssue.length, 1);
});

test("codeql findings stay per-alert and honor closed issues, including unmarked legacy ones", async () => {
  const finding = { ruleId: "js/xss-through-dom", message: "DOM text is reinterpreted as HTML." };
  const title = "[MEDIUM] js/xss-through-dom: DOM text is reinterpreted as HTML.";
  const github = createMockGithub();
  github.existingIssues = [
    { number: 128, state: "closed", state_reason: "not_planned", title, body: "legacy body without marker" },
    { number: 124, state: "closed", state_reason: "completed", title, body: "legacy body without marker" },
  ];

  await withSarifDir(buildSarifResult({ ...finding, severity: "5.0" }), async (sarifDir) => {
    const result = await processFindings({ ...syncConfig, sarifDir }, { github, logger: quietLogger });
    assert.equal(result.createdIssues, 0);
    assert.equal(result.skippedIssues, 1);
    assert.equal(github.calls.reopenIssue.length, 0);
  });
});

test("updating an issue skips the write when title and body already match", async () => {
  const requests = [];
  const github = createGitHubClient({ ...syncConfig, token: "test-token" }, {
    async fetch(url, options) {
      requests.push({ url, options });
      return { ok: true, status: 200, async json() { return {}; } };
    },
  });
  const finding = { id: "CVE-1", tool: "Trivy", severity: "HIGH", file: "a.json", line: 1, message: "m", title: "[HIGH] t" };
  const upToDate = {
    number: 3,
    title: "[HIGH] t",
    body: (await (async () => {
      await github.updateIssue({ number: 3, title: "", body: "" }, finding);
      return JSON.parse(requests[0].options.body).body;
    })()),
  };
  requests.length = 0;

  assert.equal(await github.updateIssue(upToDate, finding), false);
  assert.equal(requests.length, 0);
  assert.equal(await github.updateIssue({ ...upToDate, title: "old" }, finding), true);
  assert.equal(requests[0].options.method, "PATCH");
});

const legacyMarker = (id, config = syncConfig) =>
  getIssueMarker(config, { id, file: "package-lock.json", tool: "Trivy" });

test("the same cve in two installed versions of a package yields two grouped issues", async () => {
  const github = createMockGithub();
  const dir = await mkdtemp(join(tmpdir(), "repo-sentinel-test-"));
  try {
    await writeFile(join(dir, "a.sarif"), JSON.stringify(buildTrivyPackage("undici", "6.25.0", [["CVE-2026-1", "5.0", "6.26.0"]])));
    await writeFile(join(dir, "b.sarif"), JSON.stringify(buildTrivyPackage("undici", "7.29.0", [["CVE-2026-1", "5.0", "7.30.0"]])));
    const result = await processFindings({ ...syncConfig, sarifDir: dir }, { github, logger: quietLogger });
    assert.equal(result.createdIssues, 2);
    assert.deepEqual(github.calls.createIssue.map((issue) => issue.id).sort(), ["undici@6.25.0", "undici@7.29.0"]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("legacy per-cve issues: all not planned keeps the group suppressed", async () => {
  const github = createMockGithub();
  github.existingIssues = ["CVE-2026-1", "CVE-2026-2"].map((id, index) => ({
    number: 10 + index, state: "closed", state_reason: "not_planned", title: id, body: legacyMarker(id),
  }));
  const result = await runWithTrivy(undiciScan, github);
  assert.equal(result.createdIssues, 0);
  assert.equal(result.skippedIssues, 1);
  assert.equal(github.calls.updateIssue.length, 0);
});

test("legacy per-cve issues: one open issue is adopted and the other open ones are closed as duplicates", async () => {
  const github = createMockGithub();
  github.existingIssues = [
    { number: 12, state: "open", title: "CVE-2026-3", body: legacyMarker("CVE-2026-3") },
    { number: 11, state: "open", title: "CVE-2026-2", body: legacyMarker("CVE-2026-2") },
    { number: 10, state: "closed", state_reason: "not_planned", title: "CVE-2026-1", body: legacyMarker("CVE-2026-1") },
  ];
  const config = { ...syncConfig, closeResolvedIssues: true, fullDefaultBranchScan: true };
  const result = await runWithTrivy(undiciScan, github, config);

  assert.equal(result.createdIssues, 0);
  assert.equal(result.updatedIssues, 1);
  assert.equal(github.calls.updateIssue[0].number, 12);
  assert.deepEqual(github.calls.closeIssue, [11]);
  assert.match(github.calls.commentOnIssue[0].body, /#12/);
});

test("legacy per-cve issues: a completed-only mix reopens one into the group", async () => {
  const github = createMockGithub();
  github.existingIssues = [
    { number: 21, state: "closed", state_reason: "completed", title: "CVE-2026-2", body: legacyMarker("CVE-2026-2") },
    { number: 20, state: "closed", state_reason: "not_planned", title: "CVE-2026-1", body: legacyMarker("CVE-2026-1") },
  ];
  const result = await runWithTrivy(undiciScan, github);
  assert.equal(result.createdIssues, 0);
  assert.deepEqual(github.calls.reopenIssue, [21]);
});
