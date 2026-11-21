#!/usr/bin/env bash
# n2-seccomp-matrix.sh: the operator's live check for lane N2 (gap G16),
# register rows N2-L1 (native Linux) and N2-L2 (WSL2).
#
# It launches every tool the New Terminal picker offers on the bwrap and
# process_lite rows once, with [terminal.sandbox].seccomp = true, through
# `observer <verb> --observer-sandbox <backend>`, and records for each:
# whether it started, whether one prompt round-tripped (a one-shot prompt
# where the tool has a non-interactive mode, else a note that the operator
# must type one prompt by hand), its exit status, and any line naming the
# filter (seccomp, built_below_plan, "Operation not permitted").
#
# Expected outcomes under the filter (lane FU4 decisions N2-A7 and N2-A8;
# the receipt carries them in "expected_outcomes" so a reviewer reads a
# failure of one of these as decided, not as a defect):
#   - a tool whose OWN sandbox runs bwrap or mounts (Claude Code with its
#     sandbox setting on, any nested bwrap) fails at that step: mount is
#     denied inside a nested user namespace too;
#   - a headless browser (Playwright, Puppeteer) keeps its own sandbox:
#     user namespaces stay open;
#   - `strace <cmd>` (strace on a child it starts) works with strace
#     releases before 6.14 (they fall back to PTRACE_TRACEME) and fails with
#     strace 6.14 and later (its startup check seizes itself, so it never
#     falls back); the receipt records this machine's `strace -V`. `strace -p`
#     and any attach to a process that already exists fail with EPERM on
#     every release, as do profilers that read another process's memory
#     (py-spy, lldb).
#
# Operator-attended. It never reads a credential, never edits
# ~/.observer/config.toml and never touches another machine. Before running:
#   1. [terminal.sandbox] enabled = true, seccomp = true, and backends
#      listing the backend under test (process_lite needs Landlock ABI 9+,
#      native Linux only).
#   2. Each tool installed and signed in as you normally use it.
#
# Usage:
#   scripts/sandbox/n2-seccomp-matrix.sh --backend bwrap|process_lite \
#       [--machine linux|wsl2] [--tools "claude-code codex ..."] [--out DIR]
#
# Receipt: <out>/n2-seccomp-<machine>-<backend>-<UTC date>.json (one JSON
# object per tool in "results"). Hand the receipt back; it holds tool ids,
# exit codes and the filter lines only, never a prompt reply.
set -u

backend=""
machine=""
out="${PWD}/n2-receipts"
only=""
timeout_s="${N2_TIMEOUT:-180}"

while [ $# -gt 0 ]; do
	case "$1" in
	--backend) backend="$2"; shift 2 ;;
	--machine) machine="$2"; shift 2 ;;
	--tools) only="$2"; shift 2 ;;
	--out) out="$2"; shift 2 ;;
	-h|--help) sed -n '2,38p' "$0"; exit 0 ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done

case "$backend" in
bwrap|process_lite) ;;
*) echo "--backend must be bwrap or process_lite" >&2; exit 2 ;;
esac
if [ -z "$machine" ]; then
	if grep -qi microsoft /proc/version 2>/dev/null; then machine=wsl2; else machine=linux; fi
fi
command -v observer >/dev/null || { echo "observer is not on PATH" >&2; exit 2; }

# The tool matrix: tool id | observer launcher verb | one-shot prompt args
# ("-" when the tool has no grounded non-interactive mode; the operator then
# types one prompt and exits by hand). The 26 rows are the tools with a
# sandbox state row (integration.Capability.Sandbox.StateRW) at the lane's
# base, each verb an `observer` subcommand at that base; re-check it against
# `observer --help` if a row fails with "unknown command".
# A one-shot row passes only when the tool prints this sentinel alone on a
# line, so a stray "OK" in an error message never counts as a reply.
sentinel="N2-SANDBOX-REPLY-7F3A"
# shellcheck disable=SC2034 # read when a row's prompt args are eval'd below
N2_PROMPT="Print exactly this line and nothing else: $sentinel"
matrix=$(cat <<'ROWS'
claude-code|claude|-p "$N2_PROMPT"
codex|codex|exec "$N2_PROMPT"
gemini-cli|gemini|-p "$N2_PROMPT"
opencode|opencode|run "$N2_PROMPT"
qwen-code|qwen|-p "$N2_PROMPT"
copilot-cli|copilot-cli|-p "$N2_PROMPT"
aider|aider|--yes --message "$N2_PROMPT"
goose|goose|run -t "$N2_PROMPT"
crush|crush|run "$N2_PROMPT"
cline-cli|cline-cli|-
kilo-code-cli|kilo|-
openclaw|openclaw|-
droid|droid|-
prime-agent|prime-agent|-
kiro-cli|kiro|-
kimi-code|kimi|-
zcode|zcode|-
mistral-code|vibe|-
hermes|hermes|-
pi|pi|-
junie|junie|-
grok|grok|-
open-interpreter|open-interpreter|-
command-code|command-code|-
qoder|qoder|-
muse|muse|-
ROWS
)

mkdir -p "$out"
stamp=$(date -u +%Y-%m-%d)
receipt="$out/n2-seccomp-$machine-$backend-$stamp.json"
logdir=$(mktemp -d)
trap 'rm -rf "$logdir"' EXIT

json_escape() { python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\n")))'; }

results=""
# The rows arrive on fd 3, so a tool reading stdin can never eat them; each
# tool gets its own stdin (/dev/null one-shot, /dev/tty interactive).
while IFS='|' read -r tool verb oneshot <&3; do
	[ -n "$tool" ] || continue
	if [ -n "$only" ] && ! printf ' %s ' "$only" | grep -q " $tool "; then
		continue
	fi
	log="$logdir/$tool.log"
	mode="oneshot"
	start=$(date -u +%s)
	if [ "$oneshot" = "-" ]; then
		mode="manual"
		echo
		echo "== $tool: interactive. Type ONE short prompt, wait for the reply, then exit the tool."
		if command -v script >/dev/null; then
			# script(1) gives the tool a real terminal and still keeps a log.
			script -q -e -c "observer $verb --observer-sandbox $backend" "$log" </dev/tty 3<&-
			code=$?
		else
			eval "observer $verb --observer-sandbox $backend" </dev/tty 3<&- 2>&1 | tee "$log"
			code=${PIPESTATUS[0]}
		fi
	else
		echo "== $tool: one-shot prompt"
		eval "timeout $timeout_s observer $verb --observer-sandbox $backend $oneshot" </dev/null 3<&- >"$log" 2>&1
		code=$?
	fi
	secs=$(( $(date -u +%s) - start ))
	replied=unknown
	if [ "$mode" = "oneshot" ]; then
		if tr -d '\r' <"$log" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | grep -qxF "$sentinel"; then replied=true; else replied=false; fi
	else
		printf 'Did the prompt get a reply? [y/n] '
		read -r ans </dev/tty
		case "$ans" in y|Y) replied=true ;; *) replied=false ;; esac
	fi
	# Started: a reply proves it; a launcher refusal, a missing command
	# (126/127) or a timeout (124) with no reply disproves it; else unknown.
	if [ "$replied" = true ]; then
		started=true
	elif grep -qiE 'refused|not available|not sandbox-launchable|unknown command' "$log" || [ "$code" -eq 126 ] || [ "$code" -eq 127 ] || [ "$code" -eq 124 ]; then
		started=false
	else
		started=unknown
	fi
	filter=$(grep -iE 'seccomp|built_below_plan|operation not permitted' "$log" | head -20 | json_escape)
	row=$(printf '{"tool":"%s","verb":"%s","mode":"%s","started":"%s","replied":"%s","exit_code":%d,"seconds":%d,"filter_lines":%s}' \
		"$tool" "$verb" "$mode" "$started" "$replied" "$code" "$secs" "$filter")
	results="${results:+$results,}$row"
	echo "   -> started=$started replied=$replied exit=$code"
done 3<<EOF2
$matrix
EOF2

kernel=$(uname -r)
arch=$(uname -m)
bwrapv=$(bwrap --version 2>/dev/null | head -1)
obsv=$(observer --version 2>/dev/null | head -1)
stracev=$(strace -V 2>/dev/null | head -1)
expected='["nested bwrap or a tool sandbox that mounts: fails (mount denied, N2-A8)","headless browser sandbox (user namespace only): works (N2-A8)","strace on its own child: works with strace before 6.14 (falls back to PTRACE_TRACEME), fails with EPERM with strace 6.14 and later (its startup check seizes itself); strace -p, py-spy, lldb attach: EPERM on every release (N2-A7)"]'
printf '{"lane":"N2","register":"%s","machine":"%s","backend":"%s","date":"%s","kernel":"%s","arch":"%s","bwrap":"%s","strace":"%s","observer":"%s","expected_outcomes":%s,"results":[%s]}\n' \
	"$([ "$machine" = wsl2 ] && echo N2-L2 || echo N2-L1)" "$machine" "$backend" "$stamp" "$kernel" "$arch" "$bwrapv" "$stracev" "$obsv" "$expected" "$results" >"$receipt"
echo
echo "receipt: $receipt"
