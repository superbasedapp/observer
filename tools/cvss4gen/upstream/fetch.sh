#!/usr/bin/env bash
# fetch.sh: download FIRST's CVSS 4.0 calculator files at the commit named in
# UPSTREAM into a temporary directory and print the `file` lines for UPSTREAM.
# It never overwrites this directory; copy the files over after reading the
# diff. Needs curl and sha256sum. The only host contacted is
# raw.githubusercontent.com.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
commit="$(awk '$1 == "commit" { print $2 }' "$here/UPSTREAM")"
repo="$(awk '$1 == "repo" { print $2 }' "$here/UPSTREAM" | sed 's|https://github.com/||')"
dest="$(mktemp -d)"
files="LICENSE cvss_lookup.js max_composed.js max_severity.js cvss_config.js cvss_score.js"

for f in $files; do
  curl -fsSL "https://raw.githubusercontent.com/$repo/$commit/$f" -o "$dest/$f"
done
echo "downloaded to $dest (commit $commit)"
for f in $files; do
  printf 'file %s %s\n' "$f" "$(sha256sum "$dest/$f" | cut -d' ' -f1)"
done
echo "compare with: diff -r $dest $here (UPSTREAM and fetch.sh are expected to differ)"
