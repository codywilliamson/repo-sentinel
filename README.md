# repo-sentinel

Reusable GitHub Actions workflow that scans your repos with **Trivy** (dependency vulns, secrets, misconfig) and **CodeQL** (semantic code analysis), then creates GitHub issues for findings and can also keep a sticky PR comment updated on pull request runs. Both issue assignment and PR comments can optionally tag **Copilot** to help remediate findings.

## Install

From your project root:

```bash
# bash / macOS / Linux
curl -sL https://raw.githubusercontent.com/codywilliamson/repo-sentinel/main/install.sh | bash

# powershell / Windows
irm https://raw.githubusercontent.com/codywilliamson/repo-sentinel/main/install.ps1 | iex
```

Options:

```bash
./install.sh --ref "v0.2.0" --languages "javascript-typescript,csharp" --threshold "HIGH" --pr-comment-copilot
```

This drops a thin caller workflow into `.github/workflows/security-scan.yml` — all scanning logic stays in this repo. Installers support `--ref` / `-Ref` so you can stay on rolling `main` or pin a release tag for controlled upgrades.

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

Caller workflows should grant `pull-requests: write` alongside `issues: write` when `comment-pr-findings` is enabled.

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

1. Re-run the installer and overwrite `.github/workflows/security-scan.yml`, or manually update the `uses:` line in that file.
2. Choose your ref strategy:
   - `@v0.1.0` to stay pinned to the current baseline release
   - `@v0.2.0` to adopt the new sticky PR comment feature set on a pinned release
   - `@main` for rolling updates after `v0.2.0`
3. Decide how you want to adopt PR comments:
   - Repos pinned to `@v0.1.0` keep the legacy issue-only behavior until they move to a newer ref
   - Repos updated to `@v0.2.0` or `@main` can leave `comment-pr-findings: true` to enable sticky PR comments
   - Set `comment-pr-findings: false` if you want to keep the legacy issue-only behavior after updating
   - Set `pr-comment-copilot-tag: true` if you also want the PR comment to tag `@copilot`

Example pinned upgrade:

```yaml
jobs:
  security-scan:
    uses: codywilliamson/repo-sentinel/.github/workflows/security-scan.yml@v0.2.0
    with:
      comment-pr-findings: true
      pr-comment-copilot-tag: true
```

For release notes and planned changes, see [CHANGELOG.md](CHANGELOG.md).

## Requirements

- Repo must be on GitHub with Actions enabled
- For Copilot auto-fix: enable [Copilot Coding Agent](https://docs.github.com/en/copilot/using-github-copilot/using-copilot-coding-agent) on the repo
- This repo must be **public** (so reusable workflows are accessible cross-repo)

## License

MIT
