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

test("security scan routes every job through the JSON runner-labels input", async () => {
  const reusable = await readFile(workflowFiles[0][1], "utf8");
  const caller = await readFile(workflowFiles[1][1], "utf8");

  assert.match(reusable, /runner-labels:[\s\S]*default: '\["ubuntu-latest"\]'/);
  assert.equal(
    (reusable.match(/runs-on: \$\{\{ fromJSON\(inputs\.runner-labels\) \}\}/g) || []).length,
    4,
    "Trivy, CodeQL prep, CodeQL matrix, and processing must share runner routing"
  );
  assert.doesNotMatch(reusable, /runs-on:\s+ubuntu-latest/);
  assert.match(caller, /runner-labels: '\["ubuntu-latest"\]'/);
  assert.match(caller, /self-hosted.*Linux.*X64.*homelab.*hp-main/);
  assert.equal(
    (reusable.match(/^\s+if: .*join\(fromJSON\(inputs\.runner-labels\), ','\).*$/gm) || []).length,
    4,
    "fork protection should allow only the known hosted label selections"
  );
});

test("security scan keeps exact tool versions and isolated bounded artifacts", async () => {
  const reusable = await readFile(workflowFiles[0][1], "utf8");

  assert.match(reusable, /TRIVY_VERSION: "0\.69\.3"/);
  assert.match(
    reusable,
    /TRIVY_SHA256: "1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75"/
  );
  assert.match(reusable, /RUNNER_TOOL_CACHE/);
  assert.match(reusable, /cache_root="\$RUNNER_TEMP\/repo-sentinel\/trivy-cache"/);
  assert.match(reusable, /temporary_archive="\$\(mktemp "\$cache_root\/\.trivy-\$\{TRIVY_VERSION\}\.XXXXXX"\)"/);
  assert.match(reusable, /mv -- "\$temporary_archive" "\$archive"/);
  assert.match(reusable, /if \[\[ -f "\$archive" \]\] && ! echo "\$TRIVY_SHA256  \$archive"/);
  assert.equal((reusable.match(/runner\.environment != 'github-hosted'/g) || []).length, 4);
  assert.match(reusable, /skip-setup-trivy: true/);
  assert.match(reusable, /fallback="\$RUNNER_TEMP\/repo-sentinel\/trivy-db"/);
  assert.match(reusable, /id: trivy-cache/);
  assert.match(reusable, /RUNNER_ENVIRONMENT: \$\{\{ runner\.environment \}\}/);
  assert.match(reusable, /CALLER_REPOSITORY_ID: \$\{\{ github\.repository_id \}\}/);
  assert.match(reusable, /candidate="\$RUNNER_TOOL_CACHE\/repo-sentinel\/trivy-db\/\$CALLER_REPOSITORY_ID"/);
  assert.match(reusable, /cache-enabled=\$cache_enabled/);
  assert.match(reusable, /TRIVY_CACHE_DIR=\$cache_dir/);
  assert.match(reusable, /TRIVY_CACHE_ENABLED=\$cache_enabled/);
  assert.match(reusable, /cache-dir: \$\{\{ env\.TRIVY_CACHE_DIR \}\}/);
  assert.match(reusable, /cache: \$\{\{ env\.TRIVY_CACHE_ENABLED \}\}/);
  assert.doesNotMatch(reusable, /TRIVY_SKIP_(?:DB|JAVA_DB)_UPDATE/);
  assert.match(reusable, /node-version: "22\.23\.2"/);
  const analyze = reusable.match(/- name: Perform CodeQL Analysis[\s\S]*?- name: Upload CodeQL SARIF/);
  assert.ok(analyze, "CodeQL analysis step should be present");
  assert.match(analyze[0], /upload: never/);
  assert.doesNotMatch(analyze[0], /continue-on-error/);
  assert.match(reusable, /repository: codywilliamson\/repo-sentinel/);
  assert.equal((reusable.match(/retention-days: 5/g) || []).length, 2);
  assert.equal((reusable.match(/if-no-files-found: error/g) || []).length, 2);
  assert.doesNotMatch(reusable, /pull_request_target/);

  for (const match of reusable.matchAll(/^\s*-?\s*uses:\s+[^\s]+@([^\s#]+)/gm)) {
    assert.match(match[1], /^[0-9a-f]{40}$/, `action is not pinned: ${match[0]}`);
  }
});

test("installers default to releases and preserve existing workflows", async () => {
  const shell = await readFile(new URL("../install.sh", import.meta.url), "utf8");
  const powershell = await readFile(new URL("../install.ps1", import.meta.url), "utf8");
  const version = (await readFile(new URL("../VERSION", import.meta.url), "utf8")).trim();
  const tag = `v${version}`;

  assert.match(shell, new RegExp(`REF="${tag}"`));
  assert.match(shell, /SENTINEL_BRANCH="\$REF"/);
  assert.match(shell, /--update\)/);
  assert.match(shell, /repo-sentinel-backup/);
  assert.match(shell, /refusing to overwrite it/);
  const shellUpdateLine = shell.split("\n").find((line) => line.includes("sed -E -i.bak"));
  assert.ok(shellUpdateLine?.includes("\\\"'"), "Bash updater must exclude both YAML quote characters");
  assert.match(powershell, new RegExp(`\\[string\\]\\$Ref = "${tag}"`));
  assert.match(powershell, /\$Branch = \$Ref/);
  assert.match(powershell, /\[switch\]\$Update/);
  assert.match(powershell, /repo-sentinel-backup/);
  assert.match(powershell, /refusing to overwrite it/);
});

test("private SARIF uploads retain actions read on scanner jobs", async () => {
  const reusable = await readFile(workflowFiles[0][1], "utf8");
  const trivy = reusable.match(/  trivy:[\s\S]*?(?=\n  codeql-prep:)/)?.[0];
  const codeql = reusable.match(/  codeql:[\s\S]*?(?=\n  process-findings:)/)?.[0];

  assert.ok(trivy, "Trivy job should be present");
  assert.ok(codeql, "CodeQL job should be present");
  for (const [name, job] of [["Trivy", trivy], ["CodeQL", codeql]]) {
    assert.match(job, /permissions:\s*\n\s+contents: read\s*\n\s+security-events: write\s*\n\s+actions: read/, `${name} must retain actions: read for private SARIF metadata`);
  }
});

test("release references stay coherent with VERSION", async () => {
  const version = (await readFile(new URL("../VERSION", import.meta.url), "utf8")).trim();
  assert.match(version, /^\d+\.\d+\.\d+$/);
  const tag = `v${version}`;
  const reusable = await readFile(workflowFiles[0][1], "utf8");
  const shell = await readFile(new URL("../install.sh", import.meta.url), "utf8");
  const powershell = await readFile(new URL("../install.ps1", import.meta.url), "utf8");

  assert.match(reusable, new RegExp(`ref: ${tag}\\b`));
  assert.match(shell, new RegExp(`REF="${tag}"`));
  assert.match(powershell, new RegExp(`\\[string\\]\\$Ref = "${tag}"`));
});

test("hosted smoke workflow never enables findings writes", async () => {
  const smoke = await readFile(new URL("../.github/workflows/smoke.yml", import.meta.url), "utf8");

  assert.match(smoke, /uses: \.\/\.github\/workflows\/security-scan\.yml/);
  assert.match(smoke, /create-issues: false/);
  assert.match(smoke, /comment-pr-findings: false/);
  assert.match(smoke, /dry-run: true/);
  assert.match(smoke, /runner-labels: '\["ubuntu-latest"\]'/);
});
