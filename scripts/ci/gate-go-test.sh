#!/usr/bin/env bash
# gate-go-test.sh: run one `go test` gate of the pre-merge tier and judge a
# failure against the known-red list (scripts/ci/known-red.txt), instead of
# re-running the failing tests on a base worktree to prove they were red
# before the merge (item 4 of the test-time plan, TESTCI audit M2).
#
#   scripts/ci/gate-go-test.sh <go test arguments...>
#   e.g. scripts/ci/gate-go-test.sh -race -count=1 ./internal/store/
#
# Runs `go test <arguments>` from the repo root and keeps its output. On a
# pass it exits 0. On a failure it runs `knownred filter` on that output:
#   KNOWN  every failing test is listed, unexpired, for its package, and its
#          failure matches the entry's signature: prints the entries and the
#          log tail, exits 0;
#   FAIL   anything else (a test not on the list, a listed test that failed
#          another way, a build failure, a panic outside a test, a timeout):
#          prints the log tail, exits with go test's status.
# The full log stays in a temp file named on the last line. A FAIL is a new
# red: check it once on the base (release-line red or merge-caused); a KNOWN
# needs no base run.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT" || exit 2
GO=${GO:-go}

if [ $# -eq 0 ]; then
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
fi

log=$(mktemp "${TMPDIR:-/tmp}/gate-go-test.XXXXXX")
"$GO" test "$@" > "$log" 2>&1
rc=$?
if [ "$rc" -eq 0 ]; then
    tail -n 5 "$log"
    echo "gate-go-test: PASS (go test $*)"
    rm -f "$log"
    exit 0
fi
if "$GO" run ./scripts/ci/knownred filter "$log" > "$log.known" 2>&1; then
    sed 's/^/  | /' "$log.known"
    echo "  | log tail:"
    tail -n 30 "$log" | sed 's/^/  | /'
    echo "gate-go-test: KNOWN, only known reds (go test $*; full log: $log)"
    rm -f "$log.known"
    exit 0
fi
sed 's/^/  | /' "$log.known"
echo "  | log tail:"
tail -n 30 "$log" | sed 's/^/  | /'
echo "gate-go-test: FAIL, exit $rc (go test $*; full log: $log)"
rm -f "$log.known"
exit "$rc"
