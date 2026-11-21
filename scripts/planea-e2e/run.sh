#!/usr/bin/env bash
# AI Apps live end-to-end playbook runner. See docs/planea-e2e-playbook.md.
#
#   scripts/planea-e2e/run.sh --dry-run                       # set up + canary, no provider contacted
#   scripts/planea-e2e/run.sh --frameworks openai,langgraph   # live, cheap models only
#   scripts/planea-e2e/run.sh --destination all --providers openai
#   scripts/planea-e2e/run.sh --help
#
# Keys come only from OPENAI_API_KEY / ANTHROPIC_API_KEY in the environment.
# Everything runs against a throwaway machine (and org); a real ~/.observer,
# :8820, :8081 or :4318 is never touched. The runner refuses to start on a
# machine that looks like a developer's own (a real ~/.observer/observer.db,
# a superbased answering on :8081 or :8820) unless --allow-live-host, and
# always on Windows or with a symlinked node_modules.
#
# A full run takes 25-35 minutes: run it in the background or with a long
# timeout (an agent's foreground shell call is capped at 10 minutes).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
command -v python3 >/dev/null 2>&1 || { echo "planea-e2e: python3 is not on PATH" >&2; exit 2; }

# Only the tools the selection needs: go (unless --bin) and the selected
# languages' tools, from the LANGS table in e2e.py (one owner).
case " $* " in
  *" -h "* | *" --help "*) ;;
  *)
    tools="$(python3 "$here/e2e.py" --print-tools "$@")" || exit 2
    for tool in $tools; do
      command -v "$tool" >/dev/null 2>&1 || { echo "planea-e2e: $tool is not on PATH" >&2; exit 2; }
    done
    ;;
esac
exec python3 "$here/e2e.py" "$@"
