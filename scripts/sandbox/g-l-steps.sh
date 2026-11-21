# shellcheck shell=bash
# g-l-steps.sh: the step runner of the org-hosted OpenShell gateway's
# attended live checks G-L3, G-L4 and G-L6 (lane G5; design 11.6). Sourced,
# never run alone.
#
# A check is a table of steps, one per line, fields separated by "|":
#
#   id | kind | what the step proves | command
#
# kind "auto": the runner runs the command (bash -c, on this host) and the
#   step passes when it exits 0; its last output line is the detail. A
#   command that names a verb this build does not have yet exits 3, which
#   records the step not_run (the lanes that build the verb, G2 to G4, are
#   named in the step text).
# kind "op": the runner prints the text (and the command, when one is
#   given, as the thing to run or look at) and asks the operator: p pass,
#   f fail, s skip; then one line of note. With --yes no operator is
#   present, so every op step is recorded not_run.
#   With --answers FILE the answers come from FILE instead of the
#   terminal (lane GF1, OB-096): one line per step id,
#     id | pass|fail|skip | actor | note
#   ("#" lines and blank lines ignored). The actor is recorded as given
#   (check.<id>.actor, and the detail's prefix; check.<id>.source is
#   "answers-file", "interactive" for a terminal answer), for example
#   "orchestrator-unattended (vm stand-in)", and never names the operator
#   (refused); an op step with no line in the
#   file is recorded not_run. An interactive answer's actor is "operator".
# kind "not_built": the step needs something this build does not have (a
#   log, a switch, a client); it is recorded not_run with the command field
#   as the reason, and nothing runs. Never a pass.
#
# The receipt has the shape of the other live scripts (check.<id> pass,
# fail or not_run with check.<id>.detail; refused, exit, completed,
# result). Nothing here reads a key, token or config file, and a note the
# operator types is stored as typed, so the prompt asks for no secret.

declare -A R
FAIL=0
RECEIPT=""
RECEIPT_WRITTEN=0
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$PWD"
YES=0
ONLY=""
ANSWERS=""

st_init() {
	R[schema]="$2"
	R[row]="$1"
	R[started]="$STAMP"
	R[completed]=0
	ST_PREFIX="$3"
	R[observer_version]="$( (observer --version 2>/dev/null || echo unknown) | head -n1)"
	R[observer_org_version]="$( (observer-org --version 2>/dev/null || echo unknown) | head -n1)"
	R[host]="$(uname -sr)"
}

st_json_escape() {
	local s="$1"
	s="${s//\\/\\\\}"
	s="${s//\"/\\\"}"
	s="${s//$'\n'/\\n}"
	s="${s//$'\r'/\\r}"
	s="${s//$'\t'/\\t}"
	s="$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037')"
	printf '"%s"' "$s"
}

st_write_receipt() {
	[ -n "$RECEIPT" ] || RECEIPT="$OUT/$ST_PREFIX-$STAMP.json"
	{ : >"$RECEIPT"; } 2>/dev/null || RECEIPT="$HOME/$(basename "$RECEIPT")"
	{
		echo "{"
		local first=1 k
		for k in $(printf '%s\n' "${!R[@]}" | sort); do
			[ "$first" = 1 ] || echo ","
			first=0
			printf '  %s: %s' "$(st_json_escape "$k")" "$(st_json_escape "${R[$k]}")"
		done
		echo
		echo "}"
	} >"$RECEIPT"
	RECEIPT_WRITTEN=1
	echo "receipt: $RECEIPT"
}

st_judge() {
	R["check.$1"]="$2"
	[ -n "${3:-}" ] && R["check.$1.detail"]="$3"
	[ "$2" = pass ] || FAIL=1
	echo "check $1: $2${3:+ ($3)}"
}

st_refuse() {
	R[refused]="$1"
	echo "refused: $1" >&2
	exit 2
}

st_finish() {
	local rc=$1
	R[exit]="$rc"
	R[result]="$([ "$FAIL" = 0 ] && [ "$rc" = 0 ] && echo pass || echo fail)"
	[ "$RECEIPT_WRITTEN" = 1 ] || st_write_receipt
}

st_common_args() {
	case "$1" in
	--yes) YES=1 ;;
	*) return 1 ;;
	esac
	return 0
}

# have CMD VERB...: exit 3 (not built yet) unless this build has the verb.
# Exit status alone proves nothing: cobra answers `--help` on an unknown
# subcommand with its parent's help and exit 0 (audit GF1-A14, measured on
# this lane's build: `observer sandbox no-such-verb --help` exits 0 and
# prints "observer sandbox [flags]"). So the help's Usage section must name
# the whole verb path: a line "  <program> VERB... [flags]" (or with
# arguments after it).
have() {
	local out want
	out="$("$@" --help 2>&1)" || exit 3
	shift
	want="$*"
	printf '%s\n' "$out" | awk -v want="$want" '
		/^Usage:/ { u = 1; next }
		u && /^[^ ]/ { u = 0 }
		u { sub(/^ +[^ ]+ /, ""); if ($0 == want || index($0, want " ") == 1) found = 1 }
		END { exit found ? 0 : 1 }' || exit 3
}
export -f have

# st_answers_load TABLE: with --answers FILE, read it into ST_ANS (verdict,
# actor, note per step id), refusing (exit 2) a file that is missing or
# holds a line that is not "id | pass|fail|skip | actor | note" with an
# actor, an id the table does not have, an id given twice, or an actor that
# names the operator: "operator" as a word in any case, "operator-attended"
# included (audit GF1-A1, ruling OB-096: an answers file never speaks as
# the operator). A last line with no newline is read too (GF1-A12). The
# file is recorded by name and digest in the receipt.
declare -A ST_ANS_V ST_ANS_ACTOR ST_ANS_NOTE
st_answers_load() {
	[ -n "$ANSWERS" ] || return 0
	[ -r "$ANSWERS" ] || st_refuse "--answers $ANSWERS is not a readable file"
	local id v actor note n=0 tid known=","
	while IFS='|' read -r tid _ || [ -n "$tid" ]; do
		tid="$(printf '%s' "$tid" | tr -d ' ')"
		case "$tid" in '' | \#*) continue ;; esac
		known="$known$tid,"
	done <<<"$1"
	while IFS='|' read -r id v actor note || [ -n "$id" ]; do
		id="$(printf '%s' "$id" | tr -d ' \r')"
		[ -n "$id" ] || continue
		case "$id" in \#*) continue ;; esac
		v="$(printf '%s' "$v" | tr -d ' \r')"
		actor="$(printf '%s' "$actor" | sed 's/^ *//; s/ *$//')"
		note="$(printf '%s' "$note" | tr -d '\r' | sed 's/^ *//; s/ *$//')"
		case "$v" in pass | fail | skip) ;; *) st_refuse "--answers: step $id has verdict '$v' (want pass, fail or skip)" ;; esac
		[ -n "$actor" ] || st_refuse "--answers: step $id names no actor"
		if printf '%s' "$actor" | grep -Eiq '(^|[^[:alnum:]_])operator([^[:alnum:]_]|$)'; then
			st_refuse "--answers: step $id names the actor '$actor'; an answers file never speaks as the operator (OB-096)"
		fi
		case "$known" in *",$id,"*) ;; *) st_refuse "--answers: step $id is not in this check's step table" ;; esac
		[ -z "${ST_ANS_V[$id]:-}" ] || st_refuse "--answers: step $id is answered twice"
		ST_ANS_V[$id]="$v"
		ST_ANS_ACTOR[$id]="$actor"
		ST_ANS_NOTE[$id]="$note"
		n=$((n + 1))
	done <"$ANSWERS"
	R[answers_file]="$(basename "$ANSWERS")"
	R[answers_sha256]="$(sha256sum "$ANSWERS" | cut -d' ' -f1)"
	R[answers_lines]="$n"
}

# st_answer ID: sets ans (p, f or s), actor and note for an op step, from
# the answers file or, without one, from the operator at the terminal.
# Returns 1 when the answers file has no line for ID.
st_answer() {
	local id="$1"
	if [ -n "$ANSWERS" ]; then
		[ -n "${ST_ANS_V[$id]:-}" ] || return 1
		ans="${ST_ANS_V[$id]:0:1}"
		actor="${ST_ANS_ACTOR[$id]}"
		note="${ST_ANS_NOTE[$id]}"
		echo "   answered by $actor (answers file): ${ST_ANS_V[$id]}${note:+, $note}"
		return 0
	fi
	actor=operator
	ans=""
	while :; do
		printf '   result? [p]ass [f]ail [s]kip: '
		read -r ans </dev/tty || ans=s
		case "$ans" in p | f | s) break ;; esac
	done
	printf '   note (what you saw; never a key or token): '
	read -r note </dev/tty || note=""
	return 0
}

# st_run TABLE: run every step of the table (or only --only's ids).
st_run() {
	local id kind text cmd out rc ans note actor src
	st_answers_load "$1"
	while IFS='|' read -r id kind text cmd; do
		id="$(printf '%s' "$id" | tr -d ' ')"
		[ -n "$id" ] || continue
		case "$id" in \#*) continue ;; esac
		if [ -n "$ONLY" ] && ! printf ',%s,' "$ONLY" | grep -q ",$id,"; then
			continue
		fi
		kind="$(printf '%s' "$kind" | tr -d ' ')"
		text="$(printf '%s' "$text" | sed 's/^ *//; s/ *$//')"
		cmd="$(printf '%s' "$cmd" | sed 's/^ *//; s/ *$//')"
		R["step.$id"]="$text"
		echo
		echo "== $id: $text"
		case "$kind" in
		auto)
			# </dev/null: a command that reads stdin (docker exec -i,
			# ssh) must never swallow the rest of the step table (audit
			# G5-A11).
			out="$(bash -c "$cmd" </dev/null 2>&1)"
			rc=$?
			out="$(printf '%s' "$out" | tail -n 1 | head -c 400)"
			case "$rc" in
			0) st_judge "$id" pass "$out" ;;
			3) st_judge "$id" not_run "a verb this step needs is not built yet: ${out:-see the step text}" ;;
			*) st_judge "$id" fail "exit $rc: $out" ;;
			esac
			;;
		op)
			[ -n "$cmd" ] && echo "   run or look at: $cmd"
			if [ "$YES" = 1 ] && [ -z "$ANSWERS" ]; then
				st_judge "$id" not_run "operator step, run without an operator (--yes)"
				continue
			fi
			if ! st_answer "$id"; then
				st_judge "$id" not_run "no answer for this step in the answers file"
				continue
			fi
			R["check.$id.actor"]="$actor"
			src=interactive
			[ -z "$ANSWERS" ] || src=answers-file
			R["check.$id.source"]="$src"
			case "$ans" in
			p) st_judge "$id" pass "$actor: $note" ;;
			f) st_judge "$id" fail "$actor: $note" ;;
			s) st_judge "$id" not_run "$actor skipped: $note" ;;
			esac
			;;
		not_built)
			# Nothing runs: the step needs something this build lacks.
			st_judge "$id" not_run "not built in this build: ${cmd:-see the step text}"
			;;
		*) st_judge "$id" fail "bad step kind $kind" ;;
		esac
	done <<<"$1"
}
