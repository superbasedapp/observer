#!/usr/bin/env bash
# test-release-branch.sh: hermetic rehearsal of scripts/release.sh's
# release-branch mode and hotfix lane (plan 07 M11.5): branch-cut,
# cherry-pick and branch-verify. It copies release.sh into a throwaway git
# repository under a mktemp dir (so REPO_ROOT is that repository), uses a
# local ref as "main" (RELEASE_NO_FETCH=1, --main-ref main) and fixed clocks
# (--now, epoch --promoted-at), and never touches the network, a remote, a
# tag, or the real repository. `tag` itself is not run (it needs gh and a
# remote); everything it checks locally is branch-verify.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail=0
pass=0

repo="$work/repo"
mkdir -p "$repo/scripts"
cp "$here/release.sh" "$repo/scripts/release.sh"
git -C "$repo" init -q -b main
git -C "$repo" config user.name "Release Test"
git -C "$repo" config user.email "release-test@example.invalid"
git -C "$repo" config commit.gpgsign false
export RELEASE_NO_FETCH=1
rel() { (cd "$repo" && bash scripts/release.sh "$@"); }
commit() { # commit FILE TEXT -> sha
    echo "$2" >>"$repo/$1"
    git -C "$repo" add -A
    git -C "$repo" commit -q -m "$2"
    git -C "$repo" rev-parse HEAD
}

DAY=86400
NOW=1800000000 # a fixed "now"
old=$((NOW - 15 * DAY))
young=$((NOW - 13 * DAY))
day_old=$((NOW - 25 * 3600))
hours_old=$((NOW - 12 * 3600))

ok() { echo "ok   $1"; pass=$((pass + 1)); }
no() { echo "FAIL $1"; fail=$((fail + 1)); }
# expect_ok DESC CMD...: the command must exit 0.
expect_ok() {
    local d=$1
    shift
    if out=$("$@" 2>&1); then ok "$d"; else no "$d: $out"; fi
}
# expect_refused DESC PATTERN CMD...: exit non-zero and the output matches.
expect_refused() {
    local d=$1 pat=$2
    shift 2
    if out=$("$@" 2>&1); then
        no "$d: succeeded, output: $out"
    elif grep -q -- "$pat" <<<"$out"; then
        ok "$d"
    else
        no "$d: refused for another reason: $out"
    fi
}

git -C "$repo" add -A
git -C "$repo" commit -q -m "release.sh" # the script is tracked: a clean tree
c1=$(commit a.txt one)
c2=$(commit a.txt two)

# ---- branch-cut ----------------------------------------------------------
expect_refused "cut: no soak evidence" "no soak evidence" rel branch-cut 1.2 "$c1" --main-ref main --now "$NOW"
expect_refused "cut: 13 days is too young" "needs 336 hours" rel branch-cut 1.2 "$c1" --main-ref main --now "$NOW" --promoted-at "$young"
expect_refused "cut: bad version name" "must be X.Y" rel branch-cut one "$c1" --main-ref main --now "$NOW" --promoted-at "$old"
git -C "$repo" checkout -q -b side
side=$(commit b.txt side)
git -C "$repo" checkout -q main
expect_refused "cut: a SHA that is not on main" "is not on main" rel branch-cut 1.2 "$side" --main-ref main --now "$NOW" --promoted-at "$old"
printf '# train record\n%s %s\n' "${c1:0:12}" "$old" >"$work/record"
expect_ok "cut: 15 days, evidence from a train record" rel branch-cut 1.2 "$c1" --main-ref main --now "$NOW" --record "$work/record"
expect_refused "cut: the branch exists now" "already exists" rel branch-cut 1.2 "$c1" --main-ref main --now "$NOW" --promoted-at "$old"
[ "$(git -C "$repo" rev-parse release/v1.2)" = "$c1" ] && ok "cut: release/v1.2 points at the cut SHA" || no "cut: release/v1.2 is elsewhere"
expect_refused "cut: a record that does not name the SHA" "no soak evidence" rel branch-cut 1.3 "$c2" --main-ref main --now "$NOW" --record "$work/record"

# ---- branch-verify on the cut and the guards -----------------------------
expect_refused "verify: not on a release branch" "not on a release branch" rel branch-verify v1.2.0 --main-ref main --now "$NOW" --promoted-at "$old"
git -C "$repo" checkout -q release/v1.2
expect_ok "verify: v1.2.0 is the soaked cut" rel branch-verify v1.2.0 --main-ref main --now "$NOW" --promoted-at "$old"
expect_refused "verify: wrong minor for the branch" "does not belong on release/v1.2" rel branch-verify v1.3.0 --main-ref main --now "$NOW" --promoted-at "$old"
expect_refused "verify: a pre-release name" "exactly v<major>" rel branch-verify v1.2.0-rc.1 --main-ref main --now "$NOW" --promoted-at "$old"
expect_refused "verify: a patch with no fix" "no cherry-picked commit" rel branch-verify v1.2.1 --main-ref main --now "$NOW" --promoted-at "$old"

# ---- cherry-pick (the hotfix lane) ---------------------------------------
git -C "$repo" checkout -q main
fix=$(commit fix.txt "fix: adapter broken by a vendor change")
expect_refused "pick: only on a release branch" "runs on a release branch" rel cherry-pick "$fix" --main-ref main --now "$NOW" --promoted-at "$day_old"
git -C "$repo" checkout -q release/v1.2
expect_refused "pick: 12 hours is too young" "needs 24 hours" rel cherry-pick "$fix" --main-ref main --now "$NOW" --promoted-at "$hours_old"
expect_refused "pick: no evidence" "no soak evidence" rel cherry-pick "$fix" --main-ref main --now "$NOW"
expect_refused "pick: a commit that is not on main" "is not on main" rel cherry-pick "$side" --main-ref main --now "$NOW" --promoted-at "$day_old"
expect_ok "pick: 25 hours, hotfix lane" rel cherry-pick --hotfix "adapter broken" "$fix" --main-ref main --now "$NOW" --promoted-at "$day_old"
git -C "$repo" log -1 --format=%B | grep -q "cherry picked from commit $fix" && ok "pick: the -x trailer names the source" || no "pick: no -x trailer"
expect_refused "pick: the same fix twice" "is already on" rel cherry-pick "$fix" --main-ref main --now "$NOW" --promoted-at "$day_old"
expect_ok "verify: v1.2.1 after one cherry-pick" rel branch-verify v1.2.1 --main-ref main --now "$NOW" --promoted-at "$old"
expect_refused "verify: the cut name with a fix on the branch" "carries commits after the cut" rel branch-verify v1.2.0 --main-ref main --now "$NOW" --promoted-at "$old"

# ---- a commit written on the branch is refused ---------------------------
own=$(commit own.txt "written on the branch")
expect_refused "verify: a commit that is not a cherry-pick" "is not a cherry-pick" rel branch-verify v1.2.2 --main-ref main --now "$NOW" --promoted-at "$old"
git -C "$repo" reset -q --hard HEAD~1
[ "$(git -C "$repo" rev-parse HEAD)" != "$own" ] && ok "cleanup: the stray commit is gone" || no "cleanup failed"

# ---- nothing was pushed or tagged ----------------------------------------
[ -z "$(git -C "$repo" tag -l)" ] && ok "no tag was made" || no "a tag exists"
[ -z "$(git -C "$repo" remote)" ] && ok "no remote exists" || no "a remote exists"

echo
echo "release-branch rehearsal: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
