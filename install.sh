#!/usr/bin/env bash
set -euo pipefail

# repo-sentinel installer
# usage: curl -sL https://raw.githubusercontent.com/codywilliamson/repo-sentinel/main/install.sh | bash
# or:    ./install.sh [--languages "javascript-typescript,python"] [--threshold "MEDIUM"] [--no-copilot]

SENTINEL_REPO="codywilliamson/repo-sentinel"
SENTINEL_BRANCH="main"
TEMPLATE_URL="https://raw.githubusercontent.com/${SENTINEL_REPO}/${SENTINEL_BRANCH}/caller-template.yml"
WORKFLOW_DIR=".github/workflows"
OUTPUT_FILE="${WORKFLOW_DIR}/security-scan.yml"

# defaults
LANGUAGES="javascript-typescript"
THRESHOLD="MEDIUM"
COPILOT="true"

# parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --languages) LANGUAGES="$2"; shift 2 ;;
    --threshold) THRESHOLD="$2"; shift 2 ;;
    --no-copilot) COPILOT="false"; shift ;;
    --help|-h)
      echo "repo-sentinel installer"
      echo ""
      echo "usage: install.sh [options]"
      echo ""
      echo "options:"
      echo "  --languages <langs>   CodeQL languages (default: javascript-typescript)"
      echo "  --threshold <level>   Severity threshold: LOW, MEDIUM, HIGH, CRITICAL (default: MEDIUM)"
      echo "  --no-copilot          Don't auto-assign issues to Copilot"
      echo "  --help                Show this help"
      exit 0
      ;;
    *) echo "unknown option: $1"; exit 1 ;;
  esac
done

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
if [[ "$LANGUAGES" != "javascript-typescript" ]]; then
  sed -i "s|codeql-languages: \"javascript-typescript\"|codeql-languages: \"${LANGUAGES}\"|" "$OUTPUT_FILE"
fi

if [[ "$THRESHOLD" != "MEDIUM" ]]; then
  sed -i "s|severity-threshold: \"MEDIUM\"|severity-threshold: \"${THRESHOLD}\"|" "$OUTPUT_FILE"
fi

if [[ "$COPILOT" == "false" ]]; then
  sed -i "s|assign-copilot: true|assign-copilot: false|" "$OUTPUT_FILE"
fi

echo ""
echo "installed: ${OUTPUT_FILE}"
echo ""
echo "what happens next:"
echo "  1. commit and push this workflow"
echo "  2. scans run on push to main, PRs, and weekly"
echo "  3. findings at ${THRESHOLD}+ severity create GitHub issues"
if [[ "$COPILOT" == "true" ]]; then
  echo "  4. issues auto-assigned to Copilot for fix attempts"
fi
echo ""
echo "edit ${OUTPUT_FILE} to customize further."
