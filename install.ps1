#Requires -Version 5.1
<#
.SYNOPSIS
    Install repo-sentinel security scanning workflow into the current repository.
.DESCRIPTION
    Downloads the caller template and configures it for your project.
.PARAMETER Languages
    CodeQL languages, comma-separated (default: javascript-typescript)
.PARAMETER Ref
    Workflow git ref to pin, such as main or v0.1.0 (default: main)
.PARAMETER Threshold
    Minimum severity to create issues for: LOW, MEDIUM, HIGH, CRITICAL (default: MEDIUM)
.PARAMETER NoCopilot
    Don't auto-assign issues to Copilot
.PARAMETER NoPrComments
    Don't create sticky PR comments on pull request runs
.PARAMETER PrCommentCopilot
    Tag @copilot in PR comments when findings are present
.EXAMPLE
    irm https://raw.githubusercontent.com/codywilliamson/repo-sentinel/main/install.ps1 | iex
.EXAMPLE
    ./install.ps1 -Ref "v0.1.0" -Languages "javascript-typescript,python" -Threshold "HIGH"
#>
param(
    [string]$Ref = "main",
    [string]$Languages = "javascript-typescript",
    [string]$Threshold = "MEDIUM",
    [switch]$NoCopilot,
    [switch]$NoPrComments,
    [switch]$PrCommentCopilot
)

$ErrorActionPreference = "Stop"

$SentinelRepo = "codywilliamson/repo-sentinel"
$Branch = "main"
$TemplateUrl = "https://raw.githubusercontent.com/$SentinelRepo/$Branch/caller-template.yml"
$WorkflowDir = ".github/workflows"
$OutputFile = "$WorkflowDir/security-scan.yml"
$EnablePrComments = (-not $NoPrComments) -or $PrCommentCopilot

# check we're in a git repo
try {
    git rev-parse --is-inside-work-tree 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw }
} catch {
    Write-Error "Not a git repository. Run this from your project root."
    exit 1
}

# check for existing workflow
if (Test-Path $OutputFile) {
    $confirm = Read-Host "warning: $OutputFile already exists. Overwrite? [y/N]"
    if ($confirm -notin @("y", "Y")) {
        Write-Host "Aborted."
        exit 0
    }
}

New-Item -ItemType Directory -Path $WorkflowDir -Force | Out-Null

Write-Host "Downloading workflow template..."
Invoke-WebRequest -Uri $TemplateUrl -OutFile $OutputFile -UseBasicParsing

# apply user config
$content = Get-Content $OutputFile -Raw
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

Set-Content -Path $OutputFile -Value $content -NoNewline

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
Write-Host "Edit $OutputFile to customize further."
