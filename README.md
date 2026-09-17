# repo-sentinel

Reusable GitHub Actions workflow that scans your repos with **Trivy** (dependency vulns, secrets, misconfig) and **CodeQL** (semantic code analysis), then creates GitHub issues for findings and can also keep a sticky PR comment updated on pull request runs. Both issue assignment and PR comments can optionally tag **Copilot** to help remediate findings.

## Install

From your project root:

```bash
# bash / macOS / Linux
curl -sL https://raw.githubusercontent.com/codywilliamson/repo-sentinel/v0.3.2/install.sh | bash

# powershell / Windows
irm https://raw.githubusercontent.com/codywilliamson/repo-sentinel/v0.3.2/install.ps1 | iex
```

Options:

```bash
./install.sh --ref "v0.3.2" --languages "javascript-typescript,csharp" --threshold "HIGH" --pr-comment-copilot
```

This drops a thin caller workflow into `.github/workflows/security-scan.yml` — all scanning logic stays in this repo. Installers pin an exact release by default and also accept a full commit SHA for immutable deployments.

## How it works

```
push/PR/schedule
  ├─ Trivy scan ──────► SARIF ──► GitHub Security tab
  ├─ CodeQL analysis ─► SARIF ──► GitHub Security tab
  └─ Process findings
       ├─ Create/update sticky PR comment on PR runs (optional)
       ├─ Filter by severity threshold (default: MEDIUM+)
       ├─ Deduplicate against existing open issues
       ├─ Create GitHub issues with vuln details + remediation
       └─ Assign/tag Copilot (if enabled)
```

## Configuration

All options are set in the caller workflow (`security-scan.yml` in your repo):

| Input | Default | Description |
|-------|---------|-------------|
| `severity-threshold` | `MEDIUM` | Minimum severity to create issues (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) |
| `codeql-languages` | `javascript-typescript` | Comma-separated CodeQL languages |
| `assign-copilot` | `true` | Auto-assign issues to Copilot Coding Agent |
| `comment-pr-findings` | `true` | Create or update a sticky PR comment on pull request runs |
| `pr-comment-copilot-tag` | `false` | Tag `@copilot` in the PR comment when findings are present |
| `trivy-scanners` | `vuln,secret,misconfig` | Trivy scanner types |
| `trivy-skip-dirs` | `""` | Directories to skip |
| `label` | `security` | Label applied to created issues |
| `dry-run` | `false` | Log findings without creating issues |
| `create-issues` | `true` | Enable/disable issue creation while still allowing PR comments |
| `runner-labels` | `["ubuntu-latest"]` | JSON array of labels that must match the runner; use this to target a self-hosted runner |
| `persistent-trivy-cache` | `false` | Opt into a repository-scoped local Trivy DB on trusted self-hosted runs |

Caller workflows need `issues: write` for issue creation and sticky PR comments. repo-sentinel writes PR summaries through GitHub issue comments, so `pull-requests: write` is not required.

### Self-hosted runners

Pass a JSON array string to `runner-labels`. Every label is matched, so a repository-scoped Linux x64 runner can be selected precisely:

```yaml
with:
  runner-labels: '["self-hosted","Linux","X64","homelab","hp-main"]'
```

Self-hosted selections must be Linux x64 because the verified Trivy archive is Linux x64. They need Node.js 22.23.2, `bash`, `curl`, `tar`, `sha256sum`, and `jq`; CodeQL's supported language toolchains must also be available when autobuild needs them. The workflow installs Trivy 0.69.3 without sudo and verifies the release archive checksum. By default, self-hosted jobs use the existing fresh remote DB cache. Set `persistent-trivy-cache: true` only for a dedicated runner whose trusted jobs do not execute untrusted code; trusted push, schedule, and manual runs then use a writable repository-scoped `RUNNER_TOOL_CACHE` directory, while all pull requests use a temporary path and keep remote caching enabled. The persistent directory prevents cross-repository mixing but cannot isolate same-account workflow code. SARIF files use per-job paths under `runner.temp` and short-lived artifacts (five days).

For safety, fork pull requests are skipped when a custom or self-hosted runner selection is used because their code must not execute on that runner. The recognized GitHub-hosted selections (`ubuntu-latest`, `ubuntu-22.04`, and `ubuntu-24.04`) retain fork coverage; push, schedule, manual, and same-repository pull request scans retain the complete Trivy and CodeQL matrix.

### Supported CodeQL languages

`javascript-typescript`, `python`, `go`, `java-kotlin`, `csharp`, `ruby`, `cpp`, `swift`

## Triggers

The installed workflow runs on:
- Push to `main`
- Pull requests targeting `main`
- Weekly schedule (Monday 6am UTC)
- Manual dispatch from the Actions tab

On pull request runs, repo-sentinel can keep one sticky PR comment updated with the latest findings summary. This avoids comment spam while still making scan results visible in the conversation.

Some GitHub contexts still expose a restricted `GITHUB_TOKEN` even when the workflow requests write permissions, especially forked pull requests and some bot-authored runs. In those cases repo-sentinel now logs a warning and skips the sticky PR comment instead of failing the entire job.

## Upgrade path

Existing installs are easy to update because the caller workflow is intentionally thin.

1. Re-run the installer to create a new workflow. Existing workflows are preserved; pass `--update` or `-Update` to update a repo-sentinel workflow ref. The installer writes a `.repo-sentinel-backup` before an update and refuses to overwrite unrelated workflows.
2. Choose your ref strategy:
   - pin to a release tag such as `@v0.3.2` for reproducible runs
   - pin to a full commit SHA when your policy requires immutable references
   - use Dependabot's GitHub Actions update PRs to review later releases
3. Decide how you want to adopt PR comments:
   - Repos pinned to an older release keep their existing behavior until they move to a newer ref
   - Repos updated to `@v0.3.2` can leave `comment-pr-findings: true` to enable sticky PR comments
   - Set `comment-pr-findings: false` if you want to keep the legacy issue-only behavior after updating
   - Set `pr-comment-copilot-tag: true` if you also want the PR comment to tag `@copilot`

Example pinned upgrade:

```yaml
jobs:
  security-scan:
    uses: codywilliamson/repo-sentinel/.github/workflows/security-scan.yml@v0.3.2
    with:
      comment-pr-findings: true
      pr-comment-copilot-tag: true
```

For release notes and planned changes, see [CHANGELOG.md](CHANGELOG.md).

Fresh installs also receive a minimal `.github/dependabot.yml` entry for weekly GitHub Actions update PRs. Existing Dependabot configuration is left untouched; add a root `github-actions` update entry if it does not already cover the caller workflow.

## Requirements

- Repo must be on GitHub with Actions enabled
- For Copilot auto-fix: enable [Copilot Coding Agent](https://docs.github.com/en/copilot/using-github-copilot/using-copilot-coding-agent) on the repo
- This repo must be **public** (so reusable workflows are accessible cross-repo)

## License

MIT
