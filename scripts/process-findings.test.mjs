import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { PR_COMMENT_MARKER, processFindings } from "./process-findings-lib.mjs";

function createMockGithub() {
  const calls = {
    createIssue: [],
    createPullRequestComment: [],
    updatePullRequestComment: [],
  };

  return {
    calls,
    async ensureLabel() {},
    async getExistingIssues() {
      return [];
    },
    async createIssue(finding) {
      calls.createIssue.push(finding);
      return { number: 101 };
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
