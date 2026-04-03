#!/usr/bin/env bash
set -euo pipefail

# Custom secrets scanner -- detects common API keys, tokens, and credentials
# using regex patterns. Respects .secretscanignore for allowlisting false positives.
#
# Environment variables:
#   SCAN_MODE      - "pr" (scan only changed files) or "push" (scan all tracked files)
#   CHANGED_FILES  - newline-separated list of changed files (used when SCAN_MODE=pr)

FINDINGS_FILE="/tmp/secrets-scan-findings.txt"
IGNORE_FILE=".secretscanignore"
FINDING_COUNT=0

> "$FINDINGS_FILE"

# --- Regex patterns ---
# Parallel arrays: name, regex, and whether the pattern needs case-insensitive matching.
# Uses grep -E (extended regex) for portability across macOS and Linux.

PATTERN_NAMES=(
  "AWS Access Key ID"
  "AWS Secret Access Key"
  "GCP API Key"
  "GCP Service Account"
  "Azure Key"
  "GitHub Token"
  "Slack Token"
  "Stripe Key"
  "Private Key"
  "Generic Secret Assignment"
  "Google API Key (alt)"
  "JWT Token"
)

PATTERN_REGEXES=(
  '(AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'
  '(aws_secret_access_key|aws_secret_key|secret_access_key)[[:space:]]*[=:][[:space:]]*['"'"'""]?[A-Za-z0-9/+=]{40}'
  'AIza[0-9A-Za-z_-]{35}'
  '"type"[[:space:]]*:[[:space:]]*"service_account"'
  '(AccountKey|SharedAccessKey|client_secret)[[:space:]]*[=:][[:space:]]*['"'"'""]?[A-Za-z0-9+/=]{20,}'
  '(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})'
  '(xoxb-[0-9]{10,13}-[0-9a-zA-Z]{10,}|xoxp-[0-9]{10,13}-[0-9a-zA-Z]{10,})'
  '[sr]k_(live|test)_[0-9a-zA-Z]{24,}'
  '\-\-\-\-\-BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY\-\-\-\-\-'
  '(password|passwd|secret|api_key|apikey|access_token|auth_token|credentials)[[:space:]]*[=:][[:space:]]*['"'"'""][^[:space:]'"'"'""]{8,}'
  '(google_api_key|google_api_secret)[[:space:]]*[=:][[:space:]]*['"'"'""]?[A-Za-z0-9_-]{20,}'
  'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_.+/=-]{10,}'
)

# 1 = case-insensitive (-i flag), 0 = case-sensitive
PATTERN_ICASE=(
  0  # AWS Access Key ID - prefixes are uppercase by spec
  1  # AWS Secret Access Key
  0  # GCP API Key - AIza prefix is exact
  1  # GCP Service Account
  1  # Azure Key
  0  # GitHub Token - prefixes are exact
  0  # Slack Token - prefixes are exact
  0  # Stripe Key - prefixes are exact
  0  # Private Key - header is exact
  1  # Generic Secret Assignment
  1  # Google API Key (alt)
  0  # JWT Token - eyJ prefix is exact (base64 of {"})
)

# --- Load allowlist ---
declare -a ALLOW_FILES=()
declare -a ALLOW_STRINGS=()

if [ -f "$IGNORE_FILE" ]; then
  while IFS= read -r line; do
    # Skip comments and blank lines
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    # Parse file:string format
    if [[ "$line" == *:* ]]; then
      allow_file="${line%%:*}"
      allow_string="${line#*:}"
      ALLOW_FILES+=("$allow_file")
      ALLOW_STRINGS+=("$allow_string")
    else
      # Global allowlist entry (matches any file)
      ALLOW_FILES+=("*")
      ALLOW_STRINGS+=("$line")
    fi
  done < "$IGNORE_FILE"
fi

# --- Determine files to scan ---
FILES_TO_SCAN=""

if [ "${SCAN_MODE:-push}" = "pr" ]; then
  FILES_TO_SCAN="$CHANGED_FILES"
else
  FILES_TO_SCAN=$(git ls-files 2>/dev/null || find . -type f -not -path './.git/*')
fi

# --- Files/directories to skip ---
SKIP_PATTERN='(package-lock\.json|node_modules/|\.git/|\.png$|\.jpg$|\.jpeg$|\.gif$|\.ico$|\.woff2?$|\.ttf$|\.eot$|\.mp3$|\.mp4$|\.wav$|\.pdf$|\.zip$|\.tar\.gz$|\.secretscanignore$)'

# --- Check if a match is allowlisted ---
is_allowlisted() {
  local file="$1"
  local match_text="$2"

  for j in "${!ALLOW_STRINGS[@]}"; do
    if [[ "${ALLOW_FILES[$j]}" = "*" || "${ALLOW_FILES[$j]}" = "$file" ]]; then
      if [[ "$match_text" == *"${ALLOW_STRINGS[$j]}"* ]]; then
        return 0
      fi
    fi
  done
  return 1
}

# --- Check if a generic-pattern match is a false positive ---
is_generic_false_positive() {
  local match_text="$1"

  # Skip HTML attributes, DOM references, env variable names, regex definitions
  if echo "$match_text" | grep -qEi '(env\.|process\.env|getElementById|querySelector|placeholder|<input|<label|<option|aria-|type=.?password|/\^|/\$)'; then
    return 0
  fi

  # Skip lines that are clearly comments describing secrets (not actual secrets)
  if echo "$match_text" | grep -qE '^[[:space:]]*(//|#|\*|/\*)[[:space:]].*(required|configured|set |needed|must|should|optional)'; then
    return 0
  fi

  return 1
}

# --- Summary table header ---
SUMMARY_TABLE="| # | Pattern | File | Line |\n|---|---------|------|------|\n"

# --- Scan ---
while IFS= read -r file; do
  [[ -z "$file" ]] && continue
  [[ ! -f "$file" ]] && continue
  [[ "$file" =~ $SKIP_PATTERN ]] && continue

  for i in "${!PATTERN_NAMES[@]}"; do
    # Use -i flag for case-insensitive patterns
    if [ "${PATTERN_ICASE[$i]}" = "1" ]; then
      grep_flags="-Eni"
    else
      grep_flags="-En"
    fi

    matches=$(grep $grep_flags "${PATTERN_REGEXES[$i]}" "$file" 2>/dev/null || true)

    while IFS= read -r match_line; do
      [[ -z "$match_line" ]] && continue

      line_num="${match_line%%:*}"
      line_content="${match_line#*:}"

      # Check allowlist
      if [ ${#ALLOW_STRINGS[@]} -gt 0 ] && is_allowlisted "$file" "$line_content"; then
        continue
      fi

      # Apply false-positive filters for the generic pattern
      if [[ "${PATTERN_NAMES[$i]}" == "Generic Secret Assignment" ]] && is_generic_false_positive "$line_content"; then
        continue
      fi

      FINDING_COUNT=$((FINDING_COUNT + 1))

      # Truncate line content for display
      display_content=$(echo "$line_content" | head -c 120)

      SUMMARY_TABLE+="| $FINDING_COUNT | ${PATTERN_NAMES[$i]} | \`$file\` | $line_num |\n"
      echo "${PATTERN_NAMES[$i]} | $file:$line_num | $display_content" >> "$FINDINGS_FILE"
    done <<< "$matches"
  done
done <<< "$FILES_TO_SCAN"

# --- Output results ---
if [ "$FINDING_COUNT" -gt 0 ]; then
  echo "::error::Found $FINDING_COUNT potential secret(s) in the codebase"

  # Write GitHub Actions step summary
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      echo "## Secret Scanning Results"
      echo ""
      echo "**Status:** FAILED -- $FINDING_COUNT potential secret(s) detected"
      echo ""
      echo -e "$SUMMARY_TABLE"
      echo ""
      echo "> Review these findings and either fix the issue or add the string to \`.secretscanignore\` if it is a false positive."
    } >> "$GITHUB_STEP_SUMMARY"
  fi

  echo ""
  echo "=== Findings ==="
  cat "$FINDINGS_FILE"
  echo ""
  echo "To suppress false positives, add entries to .secretscanignore"

  exit 1
else
  echo "No secrets detected."

  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      echo "## Secret Scanning Results"
      echo ""
      echo "**Status:** PASSED -- no secrets detected"
    } >> "$GITHUB_STEP_SUMMARY"
  fi

  exit 0
fi
