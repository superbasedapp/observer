#!/usr/bin/env bash
# g-l-steps-test.sh: checks the attended live checks' step runner
# (scripts/sandbox/g-l-steps.sh) without any machine: bash -n on every
# script that sources it, then a tiny step table run with an --answers
# file (lane GF1, OB-096). The receipt must record the actor the file
# gives, never "operator"; a step the file does not answer is not_run; a
# not_built step is not_run and runs nothing; an auto step still runs; a
# malformed answers line refuses the run. Needs only bash, grep and
# sha256sum. Exit 0 when every row holds.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
FAILED=0
ok() { printf 'ok    %s\n' "$1"; }
bad() {
	printf 'FAIL  %s\n' "$1"
	FAILED=1
}

for s in "$HERE"/g-l-steps.sh "$HERE"/g-l3-openshell-org-e2e-live.sh "$HERE"/g-l4-openshell-org-enforcement-live.sh "$HERE"/g-l6-openshell-org-clone-live.sh "$HERE"/g-l7-openshell-org-tofu-live.sh; do
	if bash -n "$s"; then ok "bash -n $(basename "$s")"; else bad "bash -n $(basename "$s")"; fi
done

WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT

# run ANSWERS_FILE: a driver that sources the runner and walks one table;
# prints the receipt path's content and returns the driver's exit code.
run() {
	cat >"$WORK/driver.sh" <<EOF
set -uo pipefail
. "$HERE/g-l-steps.sh"
st_init G-LT "observer-g-lt-test/1" g-lt
OUT="$WORK"
RECEIPT="$WORK/receipt.json"
ANSWERS="\$1"
trap 'st_finish \$?' EXIT
STEPS=\$(
	cat <<'TBL'
T-01 | op | an answered pass | look at something
T-02 | op | an answered fail | look at something
T-03 | op | a step the file does not answer | look at something
T-04 | not_built | needs a switch this build lacks | touch $WORK/not-built-ran; the switch is not built
T-05 | auto | an auto step still runs | echo auto-ran
TBL
)
st_run "\$STEPS"
R[completed]=1
exit 0
EOF
	rm -f "$WORK/receipt.json"
	bash "$WORK/driver.sh" "$1" </dev/null >"$WORK/out.txt" 2>&1
}

# The last line has no newline: it must still be read (GF1-A12).
printf '%s\n%s\n%s' '# id | verdict | actor | note' \
	'T-01 | pass | orchestrator-unattended (vm stand-in) | saw the row' \
	'T-02 | fail | orchestrator-unattended (vm stand-in) | saw nothing' >"$WORK/answers"
run "$WORK/answers"
rc=$?
R="$(cat "$WORK/receipt.json" 2>/dev/null)"
want() {
	if printf '%s' "$R" | grep -qF -- "$1"; then ok "$2"; else bad "$2 (receipt lacks $1)"; fi
}
if [ "$rc" = 0 ]; then ok "the driver ran"; else bad "the driver exited $rc: $(cat "$WORK/out.txt")"; fi
want '"check.T-01": "pass"' "an answered pass is a pass"
want '"check.T-01.actor": "orchestrator-unattended (vm stand-in)"' "the receipt records the file's actor"
want '"check.T-01.detail": "orchestrator-unattended (vm stand-in): saw the row"' "the detail names the file's actor"
want '"check.T-01.source": "answers-file"' "a check answered from the file says so (GF1-A1)"
want '"check.T-02": "fail"' "an answered fail is a fail (its last line had no newline)"
want '"check.T-03": "not_run"' "an unanswered op step is not_run"
want '"check.T-04": "not_run"' "a not_built step is not_run"
want '"check.T-05": "pass"' "an auto step still runs"
want '"answers_file": "answers"' "the receipt names the answers file"
want '"result": "fail"' "a failed answer fails the run"
if printf '%s' "$R" | grep -q '"operator'; then bad "the receipt says operator for an unattended answer"; else ok "no operator actor in an unattended receipt"; fi
if [ -e "$WORK/not-built-ran" ]; then bad "a not_built step ran its command"; else ok "a not_built step runs nothing"; fi

# refuses CONTENT MESSAGE WHAT: an answers file that must refuse the run
# (exit 2) with MESSAGE in the output.
refuses() {
	printf '%s\n' "$1" >"$WORK/refuse-answers"
	run "$WORK/refuse-answers"
	local rc=$?
	if [ "$rc" = 2 ] && grep -qF -- "$2" "$WORK/out.txt"; then ok "$3"; else bad "$3 (exit $rc: $(tail -n 1 "$WORK/out.txt"))"; fi
}
refuses 'T-01 | maybe | someone | note' "verdict 'maybe'" "a bad verdict refuses the run"
refuses 'T-01 | pass |  | note' "names no actor" "an answer with no actor refuses the run"
# GF1-A1: an answers file never speaks as the operator, in any case or form.
refuses 'T-01 | pass | operator | ok' "never speaks as the operator" "the actor operator refuses the run"
refuses 'T-01 | pass | Operator | ok' "never speaks as the operator" "the actor Operator refuses the run"
refuses 'T-01 | pass | operator-attended | ok' "never speaks as the operator" "the actor operator-attended refuses the run"
refuses 'T-01 | pass | the OPERATOR (vm) | ok' "never speaks as the operator" "an actor naming the operator as a word refuses the run"
# GF1-A12: an id twice, or one the table does not have, refuses the run.
refuses "$(printf '%s\n%s' 'T-01 | pass | bot | a' 'T-01 | fail | bot | b')" "answered twice" "a duplicate id refuses the run"
refuses 'T-99 | pass | bot | a' "not in this check's step table" "an unknown id refuses the run"
# An actor that merely contains the letters (no word boundary) is allowed.
printf 'T-01 | pass | cooperators-bot | ok\n' >"$WORK/word-answers"
word_rc=0
run "$WORK/word-answers" || word_rc=$?
if [ "$word_rc" = 0 ] && grep -qF '"check.T-01.actor": "cooperators-bot"' "$WORK/receipt.json"; then ok "operator inside a longer word is not the operator"; else bad "a non-operator actor was refused"; fi

# GF1-A14: have checks the verb in the help's Usage line, since cobra
# answers --help on an unknown subcommand with its parent's help and exit 0.
mkdir -p "$WORK/bin"
cat >"$WORK/bin/fakeobs" <<'FAKE'
#!/bin/sh
# Like cobra: known paths print their own Usage, unknown ones the parent's.
case "$*" in
"sandbox org-shell --help") printf 'Org shell\n\nUsage:\n  fakeobs sandbox org-shell [flags]\n  fakeobs sandbox org-shell [command]\n' ;;
"sandbox org-shell opt-in --help") printf 'Usage:\n  fakeobs sandbox org-shell opt-in [flags]\n\nFlags:\n' ;;
*) printf 'Sandboxes\n\nUsage:\n  fakeobs sandbox [flags]\n  fakeobs sandbox [command]\n' ;;
esac
exit 0
FAKE
chmod +x "$WORK/bin/fakeobs"
# shellcheck source=scripts/sandbox/g-l-steps.sh
have_rc() { (. "$HERE/g-l-steps.sh" >/dev/null 2>&1; have "$WORK/bin/fakeobs" "$@"); }
for v in "sandbox org-shell" "sandbox org-shell opt-in"; do
	# shellcheck disable=SC2086 # the verb path is split on purpose
	if have_rc $v; then ok "have finds the built verb: $v"; else bad "have missed the built verb: $v"; fi
done
for v in "sandbox no-such-verb" "sandbox org-shell no-such"; do
	# shellcheck disable=SC2086
	have_rc $v
	rc=$?
	if [ "$rc" = 3 ]; then ok "have records an unknown verb not built: $v"; else bad "have passed an unknown verb (exit $rc): $v"; fi
done

exit "$FAILED"
