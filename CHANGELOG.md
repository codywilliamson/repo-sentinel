# Changelog

## [0.3.1] - Unreleased

### Fixed

- Retained `actions: read` on Trivy and CodeQL jobs so SARIF uploads work in private repositories.

## [0.3.0] - Unreleased

### Added

- Added a JSON-array `runner-labels` input for routing every scan and processing job to GitHub-hosted or repository-scoped self-hosted runners.
- Added verified, no-sudo Trivy 0.69.3 installation with versioned binary caching and fresh Trivy database caching.
- Added per-job temporary SARIF paths, bounded artifact retention, and immutable action references.

### Changed

- Pinned the processor checkout to the release-specific `v0.3.0` ref used by this workflow.
- Installers now default to the v0.3.0 release, preserve existing workflows, and require an explicit backup-preserving update.
- Fresh installs add a minimal Dependabot GitHub Actions schedule when no Dependabot configuration exists.

### Security

- Fork pull requests using custom or self-hosted runner selections are skipped so untrusted code cannot execute on those runners; recognized GitHub-hosted labels retain fork coverage.

## [0.2.3] - 2026-08-24

### Fixed

- Neutralized scanner-provided usernames in generated issues so advisory credits and other untrusted text cannot trigger GitHub mention notifications.

## [0.2.2] - 2026-06-23

### Fixed

- Removed the unnecessary `pull-requests: write` permission from the reusable workflow and caller template. Sticky PR comments use GitHub issue comments and only need `issues: write`.

### Changed

- Split the findings processor into focused modules for config, SARIF parsing, issue body rendering, PR comment rendering, GitHub API access, and orchestration.

## [0.2.1] - 2026-04-22

### Fixed

- Sticky PR comment failures caused by restricted GitHub integration tokens now log a warning and do not fail the findings job.
- The reusable workflow and caller template now request `pull-requests: write` when PR comments are enabled.

## [0.2.0] - 2026-04-17

### Added

- Configurable sticky PR comments for pull request scan runs.
- Optional `@copilot` tag in PR comments to prompt remediation help.
- Installer support for pinning the reusable workflow ref with `--ref` / `-Ref`.

### Changed

- The findings processor is now split into a reusable library plus a thin CLI entrypoint.
- Added automated tests for PR comment behavior and clean-run PR summaries.

## [0.1.0] - 2026-04-17

### Added

- Initial public release of the reusable security scanning workflow.
- Trivy and CodeQL scanning with SARIF upload to GitHub Security.
- Automatic issue creation for findings, with optional Copilot assignment.
