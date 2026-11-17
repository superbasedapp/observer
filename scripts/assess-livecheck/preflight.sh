#!/usr/bin/env bash
# Security assessments live check, HOST side (WSL2 Ubuntu or native Linux).
#
# Operator-attended kit for docs/security-assessments-live-check.md (plan:
# docs/plans/security-assessments-depth-plan-2026-11-14.md section 8). It sets up
# a THROWAWAY node and a scratch copy of the deliberately vulnerable fixture
# (testdata/secassess), runs a loopback canary, and never touches the real
# node, the real home or any real tool config:
#
#   - every observer command runs with HOME set to the scratch home;
#   - the throwaway config sets [observer.hooks] auto_register = false;
#   - the ports differ from the defaults (dashboard 18081, proxy 18820);
#   - the scratch root is refused unless it carries the marker this script wrote.
#
# Usage: scripts/assess-livecheck/preflight.sh <command>
#   check               A. preconditions, one verdict per line (writes nothing under the scratch root)
#   node [--force]      B. throwaway home, config, fixture project, probe project
#   env                 print the exports for a shell that runs the throwaway node
#   daemon start|stop|status   the throwaway node, with the scratch HOME (started in its own
#                       session with setsid, so it outlives the shell that started it)
#   canary start|stop|status   C. host canary listener (a hit means the box reached the host)
#   clean               remove the scratch root (only if it carries the marker; makes a read-only
#                       tree such as a Go module cache writable first)
#
# Environment (all optional):
#   ASSESS_LIVE_ROOT  scratch root (default <real home>/sbo-scratch/assess-live)
#   OBSERVER_BIN      the branch binary built in WSL (default <repo>/bin/observer)
#   DASH_PORT PROXY_PORT CANARY_PORT TARGET_PORT   (18081 18820 18999 3000)
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=${REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}
# The real home comes from the account database, never from $HOME: a shell that
# already exported the throwaway home must not nest the scratch root.
REAL_HOME=$(getent passwd "$(id -un)" | cut -d: -f6)
ROOT=${ASSESS_LIVE_ROOT:-$REAL_HOME/sbo-scratch/assess-live}
TH="$ROOT/home"
MARKER="$ROOT/.assess-live-root"
OBSERVER_BIN=${OBSERVER_BIN:-$REPO_ROOT/bin/observer}
DASH_PORT=${DASH_PORT:-18081}
PROXY_PORT=${PROXY_PORT:-18820}
CANARY_PORT=${CANARY_PORT:-18999}
TARGET_PORT=${TARGET_PORT:-3000}
FIXTURE_APP="$REPO_ROOT/testdata/secassess/app"

PASS=0 FAIL=0 WARN=0
say() { printf '%s\n' "$*"; }
verdict() { # verdict LEVEL text
	case "$1" in
	PASS) PASS=$((PASS + 1)) ;;
	FAIL) FAIL=$((FAIL + 1)) ;;
	WARN) WARN=$((WARN + 1)) ;;
	esac
	printf '%-5s %s\n' "$1" "$2"
}
die() {
	printf 'preflight: %s\n' "$*" >&2
	exit 1
}

# port_free <port>: nothing listens on it on this host.
port_free() { [ -z "$(ss -ltnH sport = ":$1" 2>/dev/null)" ]; }

# have_root: the scratch root exists and carries the marker this script wrote.
have_root() { [ -f "$MARKER" ]; }

require_root() { have_root || die "no scratch root at $ROOT (run: $0 node)"; }

# run_observer <args...>: the branch binary with the scratch HOME, never the real one.
run_observer() { env HOME="$TH" "$OBSERVER_BIN" "$@"; }

cmd_check() {
	say "Security assessments live check: preconditions (plan section 8, A)"
	say "scratch root: $ROOT"
	say "repo: $REPO_ROOT"
	say

	# Platform.
	if grep -qi microsoft /proc/version 2>/dev/null && [ -n "${WSL_DISTRO_NAME:-}" ]; then
		verdict PASS "native WSL2 ($WSL_DISTRO_NAME, kernel $(uname -r))"
	elif [ "$(uname -s)" = Linux ]; then
		verdict WARN "native Linux, not WSL2: allowed, but the register records the host (the plan grounds WSL2 Ubuntu)"
	else
		verdict FAIL "$(uname -s) is not Linux: only the Linux and WSL2 backend is grounded"
	fi

	# bwrap >= 0.4.0 and unprivileged user namespaces.
	if command -v bwrap >/dev/null 2>&1; then
		local ver
		ver=$(bwrap --version 2>/dev/null | awk '{print $2}')
		if [ -n "$ver" ] && [ "$(printf '%s\n%s\n' 0.4.0 "$ver" | sort -V | head -n 1)" = 0.4.0 ]; then
			verdict PASS "bwrap $ver (0.4.0 or newer)"
		else
			verdict FAIL "bwrap version '${ver:-unknown}' is older than 0.4.0"
		fi
		if bwrap --unshare-user --unshare-net --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp true >/dev/null 2>&1; then
			verdict PASS "unprivileged user namespaces with a private network namespace work (the node's probe would not say netns_denied)"
		else
			verdict FAIL "bwrap cannot make a private network namespace here (the node's probe would say netns_denied); see docs/sandboxed-terminals.md"
		fi
	else
		verdict FAIL "bwrap is not installed"
	fi

	# python3 must be a real interpreter the box can see (not a Windows stub, not a home-only install).
	local py resolved
	py=$(command -v python3 2>/dev/null || true)
	if [ -z "$py" ]; then
		verdict FAIL "python3 is not on PATH (the fixture and the helper need it)"
	else
		resolved=$(readlink -f "$py" 2>/dev/null || printf '%s' "$py")
		case "$resolved" in
		/mnt/* | *WindowsApps* | *windowsapps*)
			verdict FAIL "python3 resolves to $resolved, a Windows path or Store stub, not a Linux interpreter"
			;;
		*)
			if python3 -c pass >/dev/null 2>&1; then
				verdict PASS "python3 -c pass works ($(python3 --version 2>&1), $resolved)"
			else
				verdict FAIL "python3 -c pass fails ($resolved)"
			fi
			case "$resolved" in
			/usr/bin/* | /bin/* | /usr/local/bin/*) ;;
			*) verdict WARN "python3 is not under /usr/bin, /bin or /usr/local/bin: the box hides a home-directory install ($resolved)" ;;
			esac
			;;
		esac
	fi

	local tool
	for tool in git curl ss pgrep setsid; do
		if command -v "$tool" >/dev/null 2>&1; then
			verdict PASS "$tool is installed"
		else
			verdict FAIL "$tool is not installed"
		fi
	done
	if command -v jq >/dev/null 2>&1; then
		verdict PASS "jq is installed (collect.sh negative and record use it)"
	else
		verdict WARN "jq is not installed: collect.sh negative and record need it"
	fi

	# The branch binary built in WSL.
	if [ -x "$OBSERVER_BIN" ]; then
		local scratch_home
		scratch_home=$(mktemp -d)
		verdict PASS "branch binary $OBSERVER_BIN ($(env HOME="$scratch_home" "$OBSERVER_BIN" version 2>&1 | head -n 1 || true))"
		rm -rf "$scratch_home"
	else
		verdict FAIL "no branch binary at $OBSERVER_BIN (build it in WSL: make build, or set OBSERVER_BIN)"
	fi
	verdict INFO "a proxy-routed agent must be signed in for box use, and the sign-in refreshed outside the box before each paid run (an expired one idles inside it): an interactive step (docs/security-assessments-live-check.md, B), never checked here"

	# Ports the kit uses must be free; the real node is left alone.
	local p name
	for name in DASH_PORT PROXY_PORT CANARY_PORT TARGET_PORT; do
		p=${!name}
		if port_free "$p"; then
			verdict PASS "$name $p is free on the host"
		else
			verdict FAIL "$name $p is already in use on the host: choose another with $name=..."
		fi
	done
	if [ "$TARGET_PORT" -ne 3000 ] || [ "$DASH_PORT" -eq 8081 ] || [ "$PROXY_PORT" -eq 8820 ]; then
		verdict WARN "ports differ from the plan's example or match the real node's defaults: check before going on"
	fi
	if pgrep -f 'observer start' >/dev/null 2>&1; then
		verdict INFO "a node daemon is running (pid $(pgrep -f 'observer start' | head -n 1)): this kit never touches it; it uses its own HOME and ports"
	fi
	local free_kb
	free_kb=$(df -Pk "$(dirname "$ROOT")" 2>/dev/null | awk 'NR==2 {print $4}' || true)
	if [ -n "${free_kb:-}" ] && [ "$free_kb" -lt 1048576 ]; then
		verdict WARN "less than 1 GiB free under $(dirname "$ROOT")"
	fi
	say
	printf 'result: %d pass, %d fail, %d warn\n' "$PASS" "$FAIL" "$WARN"
	[ "$FAIL" -eq 0 ]
}

write_config() {
	cat >"$TH/.observer/config.toml" <<EOF
# Throwaway node for the security assessments live check (scripts/assess-livecheck).
# Own home, own ports; never the real node. Hooks are never auto-registered.
[observer.hooks]
auto_register = false

[proxy]
enabled = true
port = $PROXY_PORT

[dashboard]
addr = "127.0.0.1:$DASH_PORT"

[terminal]
enabled = true

[terminal.launch]
allow_fresh_agent = true
# Without these two nothing can be launched at all (the live run had to add both by hand): the
# agent the assessment and the confinement proof run, and the folder the scratch projects live in.
allowed_project_roots = ["$ROOT/projects"]
allowed_tools = ["claude-code"]

[terminal.sandbox]
enabled = true
backend = "bwrap"
egress = "proxy_only"

[guard]
mode = "observe"
EOF
}

# copy_fixture <dest>: the application files only, never truth/ golden/ or the README.
copy_fixture() {
	local dest=$1
	[ -d "$FIXTURE_APP" ] || die "no fixture at $FIXTURE_APP"
	mkdir -p "$dest"
	cp -R "$FIXTURE_APP/." "$dest/"
	find "$dest" -name '__pycache__' -type d -prune -exec rm -rf {} +
	[ ! -e "$dest/truth" ] && [ ! -e "$dest/golden" ] && [ ! -e "$dest/README.md" ] || die "the copy would carry answer-key material"
}

# init_repo <dir> <message>: one commit under a throwaway identity.
init_repo() {
	(
		cd "$1"
		git init -q
		git config user.name "assess-live"
		git config user.email "assess-live@notes.invalid"
		git config commit.gpgsign false
		git add -A
		git commit -q -m "$2"
	)
}

cmd_node() {
	local force=0
	[ "${1:-}" = "--force" ] && force=1
	case "$ROOT" in
	*/sbo-scratch/assess-live*) ;;
	*) [ -n "${ASSESS_LIVE_ROOT:-}" ] || die "refusing a scratch root outside sbo-scratch/assess-live: $ROOT" ;;
	esac
	if [ -e "$TH/.observer/config.toml" ] && [ "$force" -ne 1 ]; then
		die "a throwaway node already exists at $ROOT (use --force to rewrite its config)"
	fi
	mkdir -p "$TH/.observer" "$ROOT/projects" "$ROOT/receipts" "$ROOT/results" "$ROOT/canary-www"
	printf 'security assessments live check scratch root; written by preflight.sh node\n' >"$MARKER"
	write_config
	say "wrote $TH/.observer/config.toml (hooks auto_register = false, dashboard $DASH_PORT, proxy $PROXY_PORT, allowed_project_roots = $ROOT/projects, allowed_tools = claude-code)"

	local proj="$ROOT/projects/notesapp"
	if [ ! -d "$proj/.git" ]; then
		copy_fixture "$proj"
		mkdir -p "$proj/.claude"
		cat >"$proj/.claude/launch.json" <<EOF
{
  "version": "0.0.1",
  "configurations": [
    {
      "name": "notes",
      "runtimeExecutable": "env",
      "runtimeArgs": ["OBSERVER_SECASSESS_FIXTURE=1", "python3", "server.py"],
      "port": $TARGET_PORT
    }
  ]
}
EOF
		init_repo "$proj" "initial commit"
		say "fixture copied to $proj (neutral name, one commit, start command in .claude/launch.json)"
	else
		say "kept the existing fixture project at $proj"
	fi

	local probe="$ROOT/projects/confine-probe"
	if [ ! -d "$probe/.git" ]; then
		mkdir -p "$probe"
		cp "$SCRIPT_DIR/collect.sh" "$probe/collect.sh"
		chmod +x "$probe/collect.sh"
		init_repo "$probe" "confinement probe"
		say "probe project at $probe (carries collect.sh for the in-box confinement proof)"
	else
		# The probe carries a copy of the kit's script, so a kit that changed must reach it.
		cp "$SCRIPT_DIR/collect.sh" "$probe/collect.sh"
		say "kept the probe project at $probe (collect.sh refreshed from the kit)"
	fi

	local env_files
	env_files=$(find "$proj" -maxdepth 1 -name '.env*' -type f | wc -l | tr -d ' ')
	say "note: $env_files .env* file(s) in the fixture project are readable inside the box (plan W4.4); expected: the fixture has only .env.example"
	say
	say "next:"
	say "  eval \"\$($0 env)\"                 # in the shell that runs the throwaway node"
	say "  $0 daemon start                  # the throwaway node, own HOME and ports"
	say "  sign in once inside the throwaway home, in the fixture project folder (see the doc, B)"
}

cmd_env() {
	require_root
	cat <<EOF
export ASSESS_LIVE_ROOT='$ROOT'
export HOME='$TH'
export OBSERVER_DASH='http://127.0.0.1:$DASH_PORT'
export DASH_PORT='$DASH_PORT' PROXY_PORT='$PROXY_PORT' CANARY_PORT='$CANARY_PORT' TARGET_PORT='$TARGET_PORT'
export OBSERVER_BIN='$OBSERVER_BIN'
# Everything run in this shell now uses the throwaway home. Open a new shell to leave it.
EOF
}

daemon_pid() { cat "$ROOT/daemon.pid" 2>/dev/null || true; }

# spawn_detached <pidfile> <logfile> <command...>: start the command in a session of its own, so it
# survives the shell that started it. A one-shot `wsl.exe -- bash -c ...` kills everything left in
# its session when it exits, which `nohup ... &` did not survive (live run, 2026-11-15). setsid -f
# does not report the pid, so a small wrapper writes its own pid and then execs the command: the
# pid file holds the command's own pid. Returns 1 when no pid was written within two seconds.
spawn_detached() {
	local pidfile=$1 log=$2 i
	shift 2
	rm -f "$pidfile"
	setsid -f bash -c 'echo $$ >"$1"; shift; exec "$@"' _ "$pidfile" "$@" >"$log" 2>&1 </dev/null
	for i in 1 2 3 4 5 6 7 8 9 10; do
		[ -s "$pidfile" ] && return 0
		sleep 0.2
	done
	return 1
}

cmd_daemon() {
	require_root
	local pidfile="$ROOT/daemon.pid" log="$ROOT/daemon.log" pid
	case "${1:-}" in
	start)
		pid=$(daemon_pid)
		if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
			die "the throwaway node is already running (pid $pid)"
		fi
		[ -x "$OBSERVER_BIN" ] || die "no branch binary at $OBSERVER_BIN"
		port_free "$DASH_PORT" || die "dashboard port $DASH_PORT is in use"
		port_free "$PROXY_PORT" || die "proxy port $PROXY_PORT is in use"
		spawn_detached "$pidfile" "$log" env HOME="$TH" "$OBSERVER_BIN" start || die "the throwaway node did not start (no pid written); see $log"
		pid=$(daemon_pid)
		sleep 1
		if ! kill -0 "$pid" 2>/dev/null; then
			rm -f "$pidfile"
			die "the throwaway node exited at once; see $log"
		fi
		say "throwaway node started (pid $pid), log $log"
		say "dashboard http://127.0.0.1:$DASH_PORT/"
		;;
	stop)
		pid=$(daemon_pid)
		if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
			kill "$pid"
			say "stopped the throwaway node (pid $pid); no route points at it, so nothing is cut off"
		else
			say "the throwaway node is not running"
		fi
		rm -f "$pidfile"
		;;
	status)
		pid=$(daemon_pid)
		if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
			say "running (pid $pid); dashboard http://127.0.0.1:$DASH_PORT/"
		else
			say "not running"
		fi
		;;
	*) die "daemon takes start, stop or status" ;;
	esac
}

canary_hits() {
	local n=0
	[ -f "$ROOT/canary.log" ] && n=$(grep -c '"GET ' "$ROOT/canary.log" || true)
	printf '%s' "${n:-0}"
}

cmd_canary() {
	require_root
	local pidfile="$ROOT/canary.pid" log="$ROOT/canary.log" pid
	pid=$(cat "$pidfile" 2>/dev/null || true)
	case "${1:-}" in
	start)
		if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
			die "the canary is already running (pid $pid)"
		fi
		port_free "$CANARY_PORT" || die "canary port $CANARY_PORT is in use"
		spawn_detached "$pidfile" "$log" python3 -m http.server "$CANARY_PORT" --bind 127.0.0.1 --directory "$ROOT/canary-www" || die "the canary did not start (no pid written); see $log"
		pid=$(cat "$pidfile")
		sleep 0.5
		if ! kill -0 "$pid" 2>/dev/null; then
			rm -f "$pidfile"
			die "the canary exited at once; see $log"
		fi
		say "canary listening on 127.0.0.1:$CANARY_PORT (pid $pid), log $log"
		say "a request from inside the box that reaches it means the host loopback is NOT isolated"
		;;
	stop)
		if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
			kill "$pid"
			say "canary stopped (pid $pid)"
		else
			say "the canary is not running"
		fi
		rm -f "$pidfile"
		;;
	status)
		if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
			say "running (pid $pid); requests seen: $(canary_hits)"
		else
			say "not running; requests seen: $(canary_hits)"
		fi
		;;
	*) die "canary takes start, stop or status" ;;
	esac
}

# cmd_clean: remove the scratch root. Both guards (the marker, the sbo-scratch/assess-live path)
# run before anything is stopped, changed or removed.
#
# Go writes its module cache read-only (directories r-x, files r--), and the throwaway HOME can
# hold one ($HOME/go/pkg/mod, from an agent or a build run in the box), so a bare rm -rf stops with
# "Permission denied" part-way through (live run, 2026-11-16: the canary and the node were already
# stopped, the root half removed). The tree is made writable first (chmod -R u+rwX never follows a
# symlink, so it cannot reach outside the root); `go clean -modcache` would cover only Go and needs
# a go binary with that HOME, so it is not used. The children go first and the marker last: a pass
# that fails part-way leaves the marker, so a second `clean` still works instead of refusing a
# half-removed root. A failure exits non-zero and names what is left.
cmd_clean() {
	have_root || die "no scratch root at $ROOT, or it lacks the marker: nothing removed"
	case "$ROOT" in
	*/sbo-scratch/assess-live*) ;;
	*) die "refusing to remove $ROOT: not under sbo-scratch/assess-live" ;;
	esac
	[ ! -L "$ROOT" ] || die "refusing to remove $ROOT: it is a symbolic link"
	cmd_canary stop || true
	cmd_daemon stop || true
	if ! chmod -R u+rwX -- "$ROOT" 2>/dev/null; then
		say "warning: could not make every entry under $ROOT writable (not owned by this user?); removing what can be removed"
	fi
	if find "$ROOT" -mindepth 1 -maxdepth 1 ! -name "$(basename "$MARKER")" -exec rm -rf -- {} + &&
		rm -f -- "$MARKER" && rmdir -- "$ROOT"; then
		say "removed $ROOT"
	else
		local left
		left=$(find "$ROOT" -mindepth 1 2>/dev/null | wc -l | tr -d ' ')
		say "NOT fully removed: $left entries remain under $ROOT (the first ten follow)" >&2
		find "$ROOT" -mindepth 1 2>/dev/null | head -n 10 >&2 || true
		die "clean failed; the marker is kept, so after fixing the cause (ownership, an immutable file, a mount) run clean again"
	fi
}

# Sourced (scripts/assess-livecheck/test-kit.sh does that), nothing is dispatched.
if [ "${BASH_SOURCE[0]}" != "$0" ]; then
	return 0
fi

case "${1:-}" in
check) cmd_check ;;
node) shift && cmd_node "$@" ;;
env) cmd_env ;;
daemon) shift && cmd_daemon "$@" ;;
canary) shift && cmd_canary "$@" ;;
clean) cmd_clean ;;
*)
	sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2
	exit 2
	;;
esac
