#Requires -Version 5.1
<#
.SYNOPSIS
    Install repo-sentinel security scanning workflow into the current repository.
.DESCRIPTION
    Downloads the caller template and configures it for your project.
.PARAMETER Languages
    CodeQL languages, comma-separated (default: javascript-typescript)
.PARAMETER Ref
    Workflow git ref to pin, such as v0.3.3 or a full commit SHA (default: v0.3.3)
.PARAMETER Threshold
    Minimum severity to create issues for: LOW, MEDIUM, HIGH, CRITICAL (default: MEDIUM)
.PARAMETER NoCopilot
    Don't auto-assign issues to Copilot
.PARAMETER NoPrComments
    Don't create sticky PR comments on pull request runs
.PARAMETER PrCommentCopilot
    Tag @copilot in PR comments when findings are present
.PARAMETER Update
    Update an existing repo-sentinel workflow ref while preserving its configuration
.EXAMPLE
    irm https://raw.githubusercontent.com/codywilliamson/repo-sentinel/v0.3.3/install.ps1 | iex
.EXAMPLE
    ./install.ps1 -Ref "v0.3.3" -Languages "javascript-typescript,python" -Threshold "HIGH"
#>
param(
    [string]$Ref = "v0.3.3",
    [string]$Languages = "javascript-typescript",
    [string]$Threshold = "MEDIUM",
    [switch]$NoCopilot,
    [switch]$NoPrComments,
    [switch]$PrCommentCopilot,
    [switch]$Update
)

$ErrorActionPreference = "Stop"

$SentinelRepo = "codywilliamson/repo-sentinel"
$Branch = ""
$TemplateUrl = ""
$WorkflowDir = ".github/workflows"
$OutputFile = "$WorkflowDir/security-scan.yml"
$EnablePrComments = (-not $NoPrComments) -or $PrCommentCopilot

if ($Ref -notmatch '^v\d+\.\d+\.\d+$' -and $Ref -notmatch '^[0-9a-fA-F]{40}$') {
    throw "Ref must name an exact release (vMAJOR.MINOR.PATCH) or commit SHA."
}
$Branch = $Ref
$TemplateUrl = "https://raw.githubusercontent.com/$SentinelRepo/$Branch/caller-template.yml"

# check we're in a git repo
try {
    git rev-parse --is-inside-work-tree 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw }
} catch {
    Write-Error "Not a git repository. Run this from your project root."
    exit 1
}

# Preserve an existing workflow unless an explicit update was requested. Updates
# only change the repo-sentinel ref and retain the consumer's configuration.
if (Test-Path $OutputFile) {
    $existing = Get-Content -LiteralPath $OutputFile -Raw
    $sentinelPattern = [regex]::Escape("$SentinelRepo/.github/workflows/security-scan.yml") + '@'
    if (-not $Update) {
        Write-Host "Preserved: $OutputFile already exists (use -Update to change its repo-sentinel ref)."
        exit 0
    }
    if ($existing -notmatch $sentinelPattern) {
        throw "$OutputFile is not a repo-sentinel workflow; refusing to overwrite it."
    }
    $backup = "$OutputFile.repo-sentinel-backup"
    if (-not (Test-Path -LiteralPath $backup)) {
        Copy-Item -LiteralPath $OutputFile -Destination $backup
        Write-Host "Backup: $backup"
    }
    $replacement = '${1}' + $Ref
    $updated = [regex]::Replace(
        $existing,
        "($sentinelPattern)[^\s`"']+",
        $replacement
    )
    Set-Content -LiteralPath $OutputFile -Value $updated -NoNewline
    Write-Host "Updated: $OutputFile (configuration preserved)"
} else {
    New-Item -ItemType Directory -Path $WorkflowDir -Force | Out-Null

    Write-Host "Downloading workflow template..."
    $tempTemplate = Join-Path ([IO.Path]::GetTempPath()) ("repo-sentinel-template-" + [Guid]::NewGuid().ToString("N") + ".yml")
    try {
        Invoke-WebRequest -Uri $TemplateUrl -OutFile $tempTemplate -UseBasicParsing
        Copy-Item -LiteralPath $tempTemplate -Destination $OutputFile
    } finally {
        Remove-Item -LiteralPath $tempTemplate -Force -ErrorAction SilentlyContinue
    }

    # apply user config only when creating a workflow; -Update intentionally
    # leaves existing consumer choices untouched.
    $content = Get-Content -LiteralPath $OutputFile -Raw
    $content = $content -replace '__REPO_SENTINEL_REF__', $Ref

    if ($Languages -ne "javascript-typescript") {
        $content = $content -replace 'codeql-languages: "javascript-typescript"', "codeql-languages: `"$Languages`""
    }

    if ($Threshold -ne "MEDIUM") {
        $content = $content -replace 'severity-threshold: "MEDIUM"', "severity-threshold: `"$Threshold`""
    }

    if ($NoCopilot) {
        $content = $content -replace 'assign-copilot: true', 'assign-copilot: false'
    }

    if (-not $EnablePrComments) {
        $content = $content -replace 'comment-pr-findings: true', 'comment-pr-findings: false'
    }

    if ($PrCommentCopilot) {
        $content = $content -replace '# pr-comment-copilot-tag: true', 'pr-comment-copilot-tag: true'
    }

    Set-Content -LiteralPath $OutputFile -Value $content -NoNewline
    Write-Host "Installed: $OutputFile"
}

$dependabotFile = Join-Path ".github" "dependabot.yml"
$alternateDependabotFile = Join-Path ".github" "dependabot.yaml"
if (-not (Test-Path -LiteralPath $dependabotFile) -and -not (Test-Path -LiteralPath $alternateDependabotFile)) {
    New-Item -ItemType Directory -Path ".github" -Force | Out-Null
    @"
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
"@ | Set-Content -LiteralPath $dependabotFile -Encoding utf8
    Write-Host "Created: $dependabotFile (GitHub Actions update PRs)"
} else {
    Write-Host "Preserved: existing Dependabot configuration"
}

Write-Host ""
Write-Host "Installed: $OutputFile" -ForegroundColor Green
Write-Host "Workflow ref: $Ref"
Write-Host ""
Write-Host "What happens next:"
Write-Host "  1. Commit and push this workflow"
Write-Host "  2. Scans run on push to main, PRs, and weekly"
Write-Host "  3. Findings at $Threshold+ severity create GitHub issues"
if ($EnablePrComments) {
    Write-Host "  4. Pull request runs create or update a sticky PR comment"
}
if (-not $NoCopilot) {
    Write-Host "  5. Issues auto-assigned to Copilot for fix attempts"
}
if ($PrCommentCopilot) {
    Write-Host "  6. PR comments tag @copilot when findings are present"
}
Write-Host ""
Write-Host "Edit $OutputFile to customize further; use -Update for a backup-preserving ref update."
