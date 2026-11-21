#!/usr/bin/env bash
# Check the last chatbot run (run.json) arrived on this machine, or with --target org on the organization.
# Two LLM spans when the machine's admission policy refuses turn 3 (README); pass --llm-spans 3 otherwise.
set -euo pipefail
cd "$(dirname "$0")"
args=("$@")
[[ " $* " == *" --llm-spans "* ]] || args+=(--llm-spans 2)
exec python3 ../../verify.py run.json "${args[@]}"
