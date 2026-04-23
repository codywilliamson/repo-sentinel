# Changelog

## [Unreleased]

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
