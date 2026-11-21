#!/usr/bin/env bash
# Check the last run (run.json) arrived on this machine, or with --target org on the organization.
# --price checks the stored cost against Anthropic's usage at claude-haiku-5-5's list rates
# ($/MTok: input 0.10, output 0.50, cache read 0.01, cache write 0.125).
set -euo pipefail
cd "$(dirname "$0")"
exec python3 ../../verify.py run.json --llm-spans 4 --model claude-haiku --price 0.1,0.5,0.01,0.125 --ignore-span '^Anthropic._prepare_chat_with_tools$' "$@"
