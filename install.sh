#!/usr/bin/env bash
set -euo pipefail

# repo-sentinel installer
# usage: curl -sL https://raw.githubusercontent.com/codywilliamson/repo-sentinel/main/install.sh | bash
# or:    ./install.sh [--ref "main"] [--languages "javascript-typescript,python"] [--threshold "MEDIUM"] [--no-copilot]

SENTINEL_REPO="codywilliamson/repo-sentinel"
SENTINEL_BRANCH="main"
TEMPLATE_URL="https://raw.githubusercontent.com/${SENTINEL_REPO}/${SENTINEL_BRANCH}/caller-template.yml"
WORKFLOW_DIR=".github/workflows"
OUTPUT_FILE="${WORKFLOW_DIR}/security-scan.yml"

# defaults
REF="main"
LANGUAGES="javascript-typescript"
THRESHOLD="MEDIUM"
COPILOT="true"
PR_COMMENTS="true"
PR_COMMENT_COPILOT="false"

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
    --help|-h)
      echo "repo-sentinel installer"
      echo ""
      echo "usage: install.sh [options]"
      echo ""
      echo "options:"
      echo "  --ref <git-ref>       Workflow ref to pin (default: main)"
      echo "  --languages <langs>   CodeQL languages (default: javascript-typescript)"
      echo "  --threshold <level>   Severity threshold: LOW, MEDIUM, HIGH, CRITICAL (default: MEDIUM)"
      echo "  --no-copilot          Don't auto-assign issues to Copilot"
      echo "  --no-pr-comments      Don't create sticky PR comments on pull request runs"
      echo "  --pr-comment-copilot  Tag @copilot in PR comments when findings are present"
      echo "  --help                Show this help"
      exit 0
      ;;
    *) echo "unknown option: $1"; exit 1 ;;
  esac
done

if [[ "$PR_COMMENT_COPILOT" == "true" ]]; then
  PR_COMMENTS="true"
fi

# check we're in a git repo
if ! git rev-parse --is-inside-work-tree &>/dev/null; then
  echo "error: not a git repository. run this from your project root."
  exit 1
fi

# check for existing workflow
if [[ -f "$OUTPUT_FILE" ]]; then
  echo "warning: ${OUTPUT_FILE} already exists"
  read -rp "overwrite? [y/N] " confirm
  if [[ "$confirm" != [yY] ]]; then
    echo "aborted."
    exit 0
  fi
fi

mkdir -p "$WORKFLOW_DIR"

echo "downloading workflow template..."
curl -sL "$TEMPLATE_URL" -o "$OUTPUT_FILE"

# apply user config
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

echo ""
echo "installed: ${OUTPUT_FILE}"
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
echo "edit ${OUTPUT_FILE} to customize further."
