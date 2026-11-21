#!/usr/bin/env bash
# Check the last run (run.json) arrived on this machine, or with --target org on the organization.
# Usage: ./verify.sh [--target machine|org] (extra flags go to ../../verify.py)
set -euo pipefail
cd "$(dirname "$0")"
exec python3 ../../verify.py run.json --llm-spans 6 "$@"
