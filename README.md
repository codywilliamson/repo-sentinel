# repo-sentinel

Reusable GitHub Actions workflow that scans your repos with **Trivy** (dependency vulns, secrets, misconfig) and **CodeQL** (semantic code analysis), then auto-creates GitHub issues for findings and optionally assigns them to **Copilot Coding Agent** for automated fix attempts.

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
./install.sh --languages "javascript-typescript,csharp" --threshold "HIGH" --no-copilot
```

This drops a thin caller workflow into `.github/workflows/security-scan.yml` — all scanning logic stays in this repo.

## How it works

```
push/PR/schedule
  ├─ Trivy scan ──────► SARIF ──► GitHub Security tab
  ├─ CodeQL analysis ─► SARIF ──► GitHub Security tab
  └─ Process findings
       ├─ Filter by severity threshold (default: MEDIUM+)
       ├─ Deduplicate against existing open issues
       ├─ Create GitHub issues with vuln details + remediation
       └─ Assign to Copilot (if enabled)
```

## Configuration

All options are set in the caller workflow (`security-scan.yml` in your repo):

| Input | Default | Description |
|-------|---------|-------------|
| `severity-threshold` | `MEDIUM` | Minimum severity to create issues (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) |
| `codeql-languages` | `javascript-typescript` | Comma-separated CodeQL languages |
| `assign-copilot` | `true` | Auto-assign issues to Copilot Coding Agent |
| `trivy-scanners` | `vuln,secret,misconfig` | Trivy scanner types |
| `trivy-skip-dirs` | `""` | Directories to skip |
| `label` | `security` | Label applied to created issues |
| `dry-run` | `false` | Log findings without creating issues |
| `create-issues` | `true` | Enable/disable issue creation |

### Supported CodeQL languages

`javascript-typescript`, `python`, `go`, `java-kotlin`, `csharp`, `ruby`, `cpp`, `swift`

## Triggers

The installed workflow runs on:
- Push to `main`
- Pull requests targeting `main`
- Weekly schedule (Monday 6am UTC)
- Manual dispatch from the Actions tab

## Requirements

- Repo must be on GitHub with Actions enabled
- For Copilot auto-fix: enable [Copilot Coding Agent](https://docs.github.com/en/copilot/using-github-copilot/using-copilot-coding-agent) on the repo
- This repo must be **public** (so reusable workflows are accessible cross-repo)

## License

MIT
