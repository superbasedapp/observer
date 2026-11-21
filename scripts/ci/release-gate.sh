# shellcheck shell=bash
# release-gate.sh: the ci.yml half of scripts/release.sh's green-before-tag
# check (D-602, D-609, P-222 of 2026-11-01). Sourced by release.sh, and by
# tests/invariant/release_gate_test.go with a fake gh; it defines functions
# only and runs nothing.
#
# A commit passes when one of its ci.yml runs that count (workflow_dispatch
# on main) is green and either
#   FULL      its title is not a narrowed title (every package, the whole
#             omit-tag list), or
#   NARROWED  its title is "ci narrowed since <base>" (ci.yml's run-name for
#             a dispatch with the `since` input) and the base passes
#             gate_narrowed_base_ok: the base has a green FULL dispatch on
#             main, is an ancestor of the commit, and comes after the newest
#             release tag below the commit. So only a REPEAT release commit
#             of a cycle can pass narrowed; the first one needs a full run.
# The narrowed run tested what the diff since the base can affect
# (cipkgs narrow / affected; anything it cannot see through ran full).
#
# Inputs (set by the caller):
#   GATE_REPO     owner/name of the private repository (gh --repo)
#   GATE_GIT      the clone whose history and tags are read
#   GATE_GO_ROOT  the tree holding scripts/ci/cipkgs (the gate's run parser)

# gate_runs <sha>: the ci.yml run records of one commit, as gh prints them.
gate_runs() {
    gh run list --repo "$GATE_REPO" --workflow ci.yml --commit "$1" --limit 50 \
        --json status,conclusion,event,headBranch,displayTitle
}

# gate_parse head|base: cipkgs gate over the records on stdin.
gate_parse() {
    go -C "$GATE_GO_ROOT" run ./scripts/ci/cipkgs gate "$1"
}

# gate_prev_release <sha>: the newest vX.Y.Z tag that is an ancestor of sha.
gate_prev_release() {
    local t
    for t in $(git -C "$GATE_GIT" tag -l 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -rV); do
        if git -C "$GATE_GIT" merge-base --is-ancestor "$t" "$1" 2>/dev/null; then
            echo "$t"
            return 0
        fi
    done
    return 1
}

# gate_narrowed_base_ok <sha> <base>: 0 when a narrowed run of sha against
# base may pass the gate; otherwise prints why and returns 1.
gate_narrowed_base_ok() {
    local sha=$1 base=$2 json v prev pc
    if ! json=$(gate_runs "$base"); then
        echo "could not read the ci runs of base ${base:0:9}"
        return 1
    fi
    if ! v=$(printf '%s' "$json" | gate_parse base) || [ "$v" != full ]; then
        echo "base ${base:0:9} has no green FULL dispatch on main"
        return 1
    fi
    if ! git -C "$GATE_GIT" merge-base --is-ancestor "$base" "$sha" 2>/dev/null; then
        echo "base ${base:0:9} is not an ancestor of ${sha:0:9}"
        return 1
    fi
    if ! prev=$(gate_prev_release "$sha"); then
        echo "no earlier release tag below ${sha:0:9}: the first release needs a full run"
        return 1
    fi
    pc=$(git -C "$GATE_GIT" rev-parse "${prev}^{commit}")
    if [ "$pc" = "$base" ] || ! git -C "$GATE_GIT" merge-base --is-ancestor "$pc" "$base" 2>/dev/null; then
        echo "base ${base:0:9} is not after the previous release $prev: the first release commit of a cycle needs a full run"
        return 1
    fi
    return 0
}

# gate_ci_verdict <sha>: prints one of
#   success                   a green full run
#   success-narrowed <base>   a green narrowed run whose base passes
#   running | none | failed:<conclusions>
#   narrowed-refused: <why>   only narrowed runs are green, no base passes
# Returns 1 when the runs could not be read or parsed.
gate_ci_verdict() {
    local sha=$1 json lines first base why="" r
    json=$(gate_runs "$sha") || return 1
    lines=$(printf '%s' "$json" | gate_parse head) || return 1
    first=${lines%%$'\n'*}
    case "$first" in
        full) echo success; return 0 ;;
        "narrowed "*) ;;
        *) echo "$first"; return 0 ;;
    esac
    while read -r _ base; do
        if r=$(gate_narrowed_base_ok "$sha" "$base"); then
            echo "success-narrowed $base"
            return 0
        fi
        why+="${why:+; }$r"
    done <<< "$lines"
    echo "narrowed-refused: $why"
}
