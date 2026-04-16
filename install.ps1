#Requires -Version 5.1
<#
.SYNOPSIS
    Install repo-sentinel security scanning workflow into the current repository.
.DESCRIPTION
    Downloads the caller template and configures it for your project.
.PARAMETER Languages
    CodeQL languages, comma-separated (default: javascript-typescript)
.PARAMETER Threshold
    Minimum severity to create issues for: LOW, MEDIUM, HIGH, CRITICAL (default: MEDIUM)
.PARAMETER NoCopilot
    Don't auto-assign issues to Copilot
.EXAMPLE
    irm https://raw.githubusercontent.com/codywilliamson/repo-sentinel/main/install.ps1 | iex
.EXAMPLE
    ./install.ps1 -Languages "javascript-typescript,python" -Threshold "HIGH"
#>
param(
    [string]$Languages = "javascript-typescript",
    [string]$Threshold = "MEDIUM",
    [switch]$NoCopilot
)

$ErrorActionPreference = "Stop"

$SentinelRepo = "codywilliamson/repo-sentinel"
$Branch = "main"
$TemplateUrl = "https://raw.githubusercontent.com/$SentinelRepo/$Branch/caller-template.yml"
$WorkflowDir = ".github/workflows"
$OutputFile = "$WorkflowDir/security-scan.yml"

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

if ($Languages -ne "javascript-typescript") {
    $content = $content -replace 'codeql-languages: "javascript-typescript"', "codeql-languages: `"$Languages`""
}

if ($Threshold -ne "MEDIUM") {
    $content = $content -replace 'severity-threshold: "MEDIUM"', "severity-threshold: `"$Threshold`""
}

if ($NoCopilot) {
    $content = $content -replace 'assign-copilot: true', 'assign-copilot: false'
}

Set-Content -Path $OutputFile -Value $content -NoNewline

Write-Host ""
Write-Host "Installed: $OutputFile" -ForegroundColor Green
Write-Host ""
Write-Host "What happens next:"
Write-Host "  1. Commit and push this workflow"
Write-Host "  2. Scans run on push to main, PRs, and weekly"
Write-Host "  3. Findings at $Threshold+ severity create GitHub issues"
if (-not $NoCopilot) {
    Write-Host "  4. Issues auto-assigned to Copilot for fix attempts"
}
Write-Host ""
Write-Host "Edit $OutputFile to customize further."
