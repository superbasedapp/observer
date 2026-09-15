#!/usr/bin/env bash
# w8-claim-inventory.sh
#
# W8 claim-pattern inventory script (docs/plans/cloud-intelligence-divergence-
# remediation-plan-2026-09-01.md §"### W8 — Marketing-copy alignment", F14).
#
# Greps website/pages-src/ for every absolute-privacy-claim inflection named
# in the plan's grounded inventory (2026-09-01) and prints file:line + the
# matched text for each hit. This is a CI-style DRIFT GATE: it exits
# non-zero while any absolute claim still stands in the five pages the plan
# names (index.html, privacy.html, security.html, faq.html, features.html) —
# i.e. it is meant to FAIL today and to be inverted (or simply expected to
# pass) once W8's copy flip ships atomically with the R7 exposure release.
# Re-run any time those pages change so no claim is missed at flip time.
#
# enterprise.html:175 ("Nothing phones home") is about the self-hosted ORG
# server, not the personal cloud-egress product, and the plan says it STAYS
# TRUE. It is therefore scanned separately, reported in an ADVISORY section,
# and never affects the exit code.
#
# NOTE (pipefail/SIGPIPE gotcha — see project memory
# feedback_pipefail_sigpipe_shell_gates): never do `producer | grep -q`.
# grep exits 1 on "no match", and under `set -o pipefail` that would abort
# the whole script via `set -e` even though "no match" is a perfectly valid,
# expected outcome. Every grep call below is captured into a variable with
# `|| true` so a clean (no-hit) file never trips the script early; the
# script's own non-zero exit is a deliberate, explicit decision at the end,
# not an accidental one from a failed pipe.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PAGES_SRC="${REPO_ROOT}/website/pages-src"

# ---------------------------------------------------------------------------
# Pattern list — the single source of truth (F14). Each entry is
# "label|extended-regex" (grep -E syntax), matched case-insensitively.
# Keep this array in sync with the plan's grounded inventory; when a new
# absolute-claim inflection is found on the site, add it HERE first.
# ---------------------------------------------------------------------------
declare -a CLAIM_PATTERNS=(
  "zero telemetry|zero telemetry"
  "100% local|100 ?% local"                          # covers "100% local" and "100 % local"
  "phone home|phone home"
  "phoned home|phoned home"
  "phones home|phones home"
  "0 bytes|0 bytes"
  "0 / bytes|0 */ *bytes"                             # covers "0 / bytes" and "0/bytes"
  "bytes phoned home|bytes phoned home"
  "leaves your machine|leaves your machine"
  "no telemetry|no telemetry"
  "no watcher network calls|no watcher network calls"
  "no network calls|no network calls"                 # broader inflection: faq.html "no network calls in the watcher"
  "no analytics ping|no analytics ping"
  "no cloud component|no cloud component"
  "no outbound|no outbound"                           # privacy.html "makes no outbound HTTPS calls"
  "does not phone home|does not phone home"
  "we never see|we never see"                         # site-analytics scope note; kept for completeness, not a product claim
)

# The five pages the plan's grounded inventory names as needing the flip.
# This is the GATE scope — its findings drive the exit code.
GATE_FILES=(
  "index.html"
  "privacy.html"
  "security.html"
  "faq.html"
  "features.html"
)

# enterprise.html:175 "Nothing phones home" is about the self-hosted org
# server and STAYS TRUE (plan, W8 section). Scanned for visibility only;
# never contributes to the exit code.
ADVISORY_FILES=(
  "enterprise.html"
)

# ---------------------------------------------------------------------------

total_hits=0
declare -A unique_lines=()   # dedupe key: "file:line" -> 1, for the summary count

scan_file() {
  local file="$1" rel="$2"
  local entry label pattern matches line
  for entry in "${CLAIM_PATTERNS[@]}"; do
    label="${entry%%|*}"
    pattern="${entry#*|}"
    # Captured (never piped) so a clean grep miss (exit 1) can't trip -e/pipefail.
    matches="$(grep -inE -- "${pattern}" "${file}" || true)"
    [[ -z "${matches}" ]] && continue
    while IFS= read -r line; do
      [[ -z "${line}" ]] && continue
      local lineno="${line%%:*}"
      local text="${line#*:}"
      printf '  [%s] %s:%s: %s\n' "${label}" "${rel}" "${lineno}" "${text}"
      total_hits=$((total_hits + 1))
      unique_lines["${rel}:${lineno}"]=1
    done <<<"${matches}"
  done
}

echo "W8 claim-pattern inventory (docs/plans/cloud-intelligence-divergence-remediation-plan-2026-09-01.md §W8, F14)"
echo "Scanning: ${PAGES_SRC}"
echo

echo "=== GATE — pages the plan names for the copy flip ==="
# A missing gate page is a HARD FAILURE, not a skip (Sol review F10): silently
# skipping a renamed/moved page would let the gate report zero hits without ever
# scanning the intended source. Fail loudly so the gate can never pass vacuously.
missing_gate=0
for f in "${GATE_FILES[@]}"; do
  path="${PAGES_SRC}/${f}"
  if [[ ! -f "${path}" ]]; then
    echo "  ERROR: gate page ${f} not found under ${PAGES_SRC} — the gate cannot verify a page it cannot read" >&2
    missing_gate=$((missing_gate + 1))
    continue
  fi
  before=${total_hits}
  echo "--- ${f} ---"
  scan_file "${path}" "${f}"
  if [[ ${total_hits} -eq ${before} ]]; then
    echo "  (no absolute-claim pattern matched)"
  fi
  echo
done
gate_hits=${total_hits}

echo "=== ADVISORY — pages/claims that intentionally stay true (not gated) ==="
advisory_start=${total_hits}
for f in "${ADVISORY_FILES[@]}"; do
  path="${PAGES_SRC}/${f}"
  if [[ ! -f "${path}" ]]; then
    echo "  WARNING: ${f} not found under ${PAGES_SRC} — skipping" >&2
    continue
  fi
  before=${total_hits}
  echo "--- ${f} (advisory only — never affects exit code) ---"
  scan_file "${path}" "${f}"
  if [[ ${total_hits} -eq ${before} ]]; then
    echo "  (no absolute-claim pattern matched)"
  fi
  echo
done
advisory_hits=$((total_hits - advisory_start))

unique_gate_lines=0
for key in "${!unique_lines[@]}"; do
  for f in "${GATE_FILES[@]}"; do
    if [[ "${key}" == "${f}:"* ]]; then
      unique_gate_lines=$((unique_gate_lines + 1))
      break
    fi
  done
done

echo "=== SUMMARY ==="
echo "Gate pages scanned:      ${#GATE_FILES[@]} (${GATE_FILES[*]})"
echo "Gate pattern hits:       ${gate_hits}"
echo "Gate unique file:lines:  ${unique_gate_lines}"
echo "Advisory pattern hits:   ${advisory_hits} (enterprise.html — informational, excluded from gate)"
echo

if [[ ${missing_gate} -gt 0 ]]; then
  echo "RESULT: ${missing_gate} gate page(s) were missing — the inventory is INCOMPLETE and cannot be trusted."
  echo "A page named in GATE_FILES was not found under ${PAGES_SRC} (renamed/moved?). Fix GATE_FILES or"
  echo "restore the page before relying on this gate."
  exit 2
fi
if [[ ${gate_hits} -gt 0 ]]; then
  echo "RESULT: ${gate_hits} absolute-privacy-claim match(es) still present across the gated pages."
  echo "This is EXPECTED prior to W8's atomic copy flip (ships with the R7 consented-cloud-egress"
  echo "exposure release). Once that flip lands, this script should report zero gate hits."
  exit 1
else
  echo "RESULT: 0 absolute-privacy-claim matches across the gated pages — flip appears complete."
  exit 0
fi
