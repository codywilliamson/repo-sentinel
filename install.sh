#!/usr/bin/env bash
set -euo pipefail

# repo-sentinel installer
# usage: curl -sL https://raw.githubusercontent.com/codywilliamson/repo-sentinel/v0.3.2/install.sh | bash
# or:    ./install.sh [--ref "v0.3.2"] [--languages "javascript-typescript,python"] [--threshold "MEDIUM"] [--no-copilot]

SENTINEL_REPO="codywilliamson/repo-sentinel"
SENTINEL_BRANCH=""
TEMPLATE_URL=""
WORKFLOW_DIR=".github/workflows"
OUTPUT_FILE="${WORKFLOW_DIR}/security-scan.yml"
DEPENDABOT_DIR=".github"
DEPENDABOT_FILE="${DEPENDABOT_DIR}/dependabot.yml"

# defaults
REF="v0.3.2"
LANGUAGES="javascript-typescript"
THRESHOLD="MEDIUM"
COPILOT="true"
PR_COMMENTS="true"
PR_COMMENT_COPILOT="false"
UPDATE="false"

replace_in_file() {
  local from="$1"
  local to="$2"
  sed -i.bak "s|$from|$to|g" "$OUTPUT_FILE"
  rm -f "${OUTPUT_FILE}.bak"
}

# parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ref) REF="$2"; shift 2 ;;
    --languages) LANGUAGES="$2"; shift 2 ;;
    --threshold) THRESHOLD="$2"; shift 2 ;;
    --no-copilot) COPILOT="false"; shift ;;
    --no-pr-comments) PR_COMMENTS="false"; shift ;;
    --pr-comment-copilot) PR_COMMENT_COPILOT="true"; shift ;;
    --update) UPDATE="true"; shift ;;
    --help|-h)
      echo "repo-sentinel installer"
      echo ""
      echo "usage: install.sh [options]"
      echo ""
      echo "options:"
      echo "  --ref <git-ref>       Workflow ref to pin (default: v0.3.2)"
      echo "  --languages <langs>   CodeQL languages (default: javascript-typescript)"
      echo "  --threshold <level>   Severity threshold: LOW, MEDIUM, HIGH, CRITICAL (default: MEDIUM)"
      echo "  --no-copilot          Don't auto-assign issues to Copilot"
      echo "  --no-pr-comments      Don't create sticky PR comments on pull request runs"
      echo "  --pr-comment-copilot  Tag @copilot in PR comments when findings are present"
      echo "  --update              Update an existing repo-sentinel workflow (creates a backup)"
      echo "  --help                Show this help"
      exit 0
      ;;
    *) echo "unknown option: $1"; exit 1 ;;
  esac
done

if [[ ! "$REF" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ && ! "$REF" =~ ^[[:xdigit:]]{40}$ ]]; then
  echo "error: --ref must be an exact release tag (vMAJOR.MINOR.PATCH) or commit SHA" >&2
  exit 2
fi
SENTINEL_BRANCH="$REF"
TEMPLATE_URL="https://raw.githubusercontent.com/${SENTINEL_REPO}/${SENTINEL_BRANCH}/caller-template.yml"

if [[ "$PR_COMMENT_COPILOT" == "true" ]]; then
  PR_COMMENTS="true"
fi

# check we're in a git repo
if ! git rev-parse --is-inside-work-tree &>/dev/null; then
  echo "error: not a git repository. run this from your project root."
  exit 1
fi

# Preserve an existing workflow unless an explicit update was requested. Updates
# only change the repo-sentinel ref and retain the consumer's configuration.
if [[ -f "$OUTPUT_FILE" ]]; then
  if [[ "$UPDATE" != "true" ]]; then
    echo "preserved: ${OUTPUT_FILE} already exists (use --update to change its repo-sentinel ref)."
    exit 0
  fi
  if ! grep -Fq "${SENTINEL_REPO}/.github/workflows/security-scan.yml@" "$OUTPUT_FILE"; then
    echo "error: ${OUTPUT_FILE} is not a repo-sentinel workflow; refusing to overwrite it." >&2
    exit 2
  fi
  backup="${OUTPUT_FILE}.repo-sentinel-backup"
  if [[ ! -e "$backup" ]]; then
    cp -- "$OUTPUT_FILE" "$backup"
    echo "backup: ${backup}"
  fi
  sed -E -i.bak "s|(${SENTINEL_REPO}/\.github/workflows/security-scan\.yml@)[^[:space:]\"']+|\1${REF}|g" "$OUTPUT_FILE"
  rm -f -- "${OUTPUT_FILE}.bak"
  echo "updated: ${OUTPUT_FILE} (configuration preserved)"
else
  mkdir -p "$WORKFLOW_DIR"
  temp_template="$(mktemp)"
  trap 'rm -f -- "$temp_template"' EXIT
  echo "downloading workflow template..."
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location --connect-timeout 10 --max-time 60 "$TEMPLATE_URL" -o "$temp_template"
  cp -- "$temp_template" "$OUTPUT_FILE"

  # apply user config only when creating a workflow; --update intentionally
  # leaves existing consumer choices untouched.
  replace_in_file "__REPO_SENTINEL_REF__" "$REF"

  if [[ "$LANGUAGES" != "javascript-typescript" ]]; then
    replace_in_file "codeql-languages: \"javascript-typescript\"" "codeql-languages: \"${LANGUAGES}\""
  fi

  if [[ "$THRESHOLD" != "MEDIUM" ]]; then
    replace_in_file "severity-threshold: \"MEDIUM\"" "severity-threshold: \"${THRESHOLD}\""
  fi

  if [[ "$COPILOT" == "false" ]]; then
    replace_in_file "assign-copilot: true" "assign-copilot: false"
  fi

  if [[ "$PR_COMMENTS" == "false" ]]; then
    replace_in_file "comment-pr-findings: true" "comment-pr-findings: false"
  fi

  if [[ "$PR_COMMENT_COPILOT" == "true" ]]; then
    replace_in_file "# pr-comment-copilot-tag: true" "pr-comment-copilot-tag: true"
  fi

  echo "installed: ${OUTPUT_FILE}"
fi

if [[ ! -e "$DEPENDABOT_FILE" && ! -e "${DEPENDABOT_DIR}/dependabot.yaml" ]]; then
  mkdir -p "$DEPENDABOT_DIR"
  cat > "$DEPENDABOT_FILE" <<'EOF'
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
EOF
  echo "created: ${DEPENDABOT_FILE} (GitHub Actions update PRs)"
else
  echo "preserved: existing Dependabot configuration"
fi

echo ""
echo "workflow ref: ${REF}"
echo ""
echo "what happens next:"
echo "  1. commit and push this workflow"
echo "  2. scans run on push to main, PRs, and weekly"
echo "  3. findings at ${THRESHOLD}+ severity create GitHub issues"
if [[ "$PR_COMMENTS" == "true" ]]; then
  echo "  4. pull request runs create or update a sticky PR comment"
fi
if [[ "$COPILOT" == "true" ]]; then
  echo "  5. issues auto-assigned to Copilot for fix attempts"
fi
if [[ "$PR_COMMENT_COPILOT" == "true" ]]; then
  echo "  6. PR comments tag @copilot when findings are present"
fi
echo ""
echo "edit ${OUTPUT_FILE} to customize further; use --update for a backup-preserving ref update."
