import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const workflowFiles = [
  ["reusable workflow", new URL("../.github/workflows/security-scan.yml", import.meta.url)],
  ["caller template", new URL("../caller-template.yml", import.meta.url)],
];

test("security scan workflows avoid unnecessary pull request write permission", async () => {
  for (const [name, fileUrl] of workflowFiles) {
    const content = await readFile(fileUrl, "utf8");

    assert.doesNotMatch(
      content,
      /^\s*pull-requests:\s*write\s*$/m,
      `${name} should not request pull-requests: write`
    );
    assert.match(
      content,
      /^\s*issues:\s*write\s*$/m,
      `${name} should request issues: write for issues and PR issue comments`
    );
  }
});
