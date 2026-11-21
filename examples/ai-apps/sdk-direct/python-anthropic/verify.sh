#!/usr/bin/env bash
# Check the last chatbot run (run.json) arrived on this machine, or with --target org on the organization.
# Three LLM spans when no admission policy refuses turn 3; pass --llm-spans 2 when one does (README).
# --price checks the stored cost against Anthropic's usage at claude-haiku-5-5's list rates.
set -euo pipefail
cd "$(dirname "$0")"
args=("$@")
[[ " $* " == *" --llm-spans "* ]] || args+=(--llm-spans 3)
exec python3 ../../verify.py run.json --model claude-haiku --price 0.1,0.5,0.01,0.125 "${args[@]}"
