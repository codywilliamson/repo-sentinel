import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const template = join(root, "caller-template.yml");
const tag = `v${(await readFile(join(root, "VERSION"), "utf8")).trim()}`;

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", ...options });
  assert.equal(result.status, 0, `${command} ${args.join(" ")}\n${result.stdout}\n${result.stderr}`);
  return result;
}

async function withMasterRepo(callback) {
  const dir = await mkdtemp(join(tmpdir(), "repo-sentinel-install-"));
  const remote = join(dir, "remote.git");
  const consumer = join(dir, "consumer");
  try {
    run("git", ["init", "--bare", "--initial-branch=master", remote]);
    run("git", ["init", "--initial-branch=master", consumer]);
    run("git", ["-C", consumer, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "--allow-empty", "-m", "init"]);
    run("git", ["-C", consumer, "remote", "add", "origin", remote]);
    run("git", ["-C", consumer, "push", "-u", "origin", "master"]);
    await callback({ dir, consumer });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

function assertMasterTriggers(workflow) {
  assert.equal((workflow.match(/branches: \["master"\]/g) || []).length, 2);
  assert.doesNotMatch(workflow, /__DEFAULT_BRANCH__/);
}

test("PowerShell installer targets the remote default branch and preserves it on update", async (t) => {
  if (spawnSync("pwsh", ["-NoProfile", "-Command", "$PSVersionTable.PSVersion.Major"], { encoding: "utf8" }).status !== 0) {
    t.skip("pwsh unavailable");
  }
  await withMasterRepo(async ({ consumer }) => {
    const env = {
      ...process.env,
      SENTINEL_TEST_TEMPLATE: template,
      SENTINEL_INSTALLER: join(root, "install.ps1"),
    };
    const mock = "function Invoke-WebRequest { param([string]$Uri, [string]$OutFile, [switch]$UseBasicParsing) Copy-Item -LiteralPath $env:SENTINEL_TEST_TEMPLATE -Destination $OutFile }; ";
    run("pwsh", ["-NoProfile", "-NonInteractive", "-Command", `${mock}& $env:SENTINEL_INSTALLER -Ref ${tag}`], { cwd: consumer, env });
    const workflowPath = join(consumer, ".github", "workflows", "security-scan.yml");
    assertMasterTriggers(await readFile(workflowPath, "utf8"));
    run("pwsh", ["-NoProfile", "-NonInteractive", "-Command", `& $env:SENTINEL_INSTALLER -Ref ${tag} -Update`], { cwd: consumer, env });
    assertMasterTriggers(await readFile(workflowPath, "utf8"));
  });
});

test("Bash installer targets the remote default branch and preserves it on update", { skip: process.platform === "win32" }, async () => {
  await withMasterRepo(async ({ dir, consumer }) => {
    const bin = join(dir, "bin");
    await mkdir(bin);
    const curl = join(bin, "curl");
    await writeFile(curl, "#!/usr/bin/env bash\nfor arg; do output=$arg; done\ncp -- \"$SENTINEL_TEST_TEMPLATE\" \"$output\"\n");
    await chmod(curl, 0o755);
    const env = { ...process.env, SENTINEL_TEST_TEMPLATE: template, PATH: `${bin}:${process.env.PATH}` };
    run("bash", [join(root, "install.sh"), "--ref", tag], { cwd: consumer, env });
    const workflowPath = join(consumer, ".github", "workflows", "security-scan.yml");
    assertMasterTriggers(await readFile(workflowPath, "utf8"));
    run("bash", [join(root, "install.sh"), "--ref", tag, "--update"], { cwd: consumer, env });
    assertMasterTriggers(await readFile(workflowPath, "utf8"));
  });
});
