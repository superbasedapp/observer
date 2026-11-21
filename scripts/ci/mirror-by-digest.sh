#!/usr/bin/env bash
# mirror-by-digest.sh <source-repository> <digest> <destination-repository> <tag>:
# copy an upstream image index BY DIGEST into our registry with cosign, so the
# upstream signature and attestations travel with it. Used by the agentgateway
# mirror jobs of agent-access-images.yml and demo-org-images.yml.
#
# Rules, in order:
#   1. The destination already holds <digest>: keep it. Never `cosign copy -f`
#      over an existing mirror; that would replace the .sig tag and drop the
#      counter-signatures earlier releases added.
#   2. The registry says the digest is not there (manifest unknown / not
#      found): copy. Our counter-signature is added only after a complete copy,
#      so an absent index has none to lose, and `-f` only replaces what an
#      earlier, interrupted copy left behind (the same digests). Without `-f`
#      such leftovers fail every later run ("already exists. Use -f to
#      overwrite", v1.41.0).
#   3. Any other answer (auth, network, rate limit): fail. We cannot tell
#      whether rule 1 applies, so we must not overwrite.
# GHCR can refuse one of cosign's parallel manifest pushes (DENIED on a
# manifest that was pushed a moment earlier, v1.40.0), so the copy is retried.
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $0 <source-repository> <digest> <destination-repository> <tag>" >&2
  exit 2
fi
src=$1 digest=$2 dst=$3 tag=$4
case "$digest" in
  sha256:*) ;;
  *) echo "mirror-by-digest: digest must be sha256:<hex>, got $digest" >&2; exit 2 ;;
esac
attempts=${MIRROR_ATTEMPTS:-3}
pause=${MIRROR_RETRY_SECONDS:-20}

if out=$(docker buildx imagetools inspect "${dst}@${digest}" 2>&1); then
  echo "${dst}@${digest} already mirrored; keeping its signatures"
  exit 0
fi
lower=$(printf '%s' "$out" | tr '[:upper:]' '[:lower:]')
case "$lower" in
  *"manifest unknown"* | *"not found"* | *"name unknown"*) ;;
  *)
    echo "mirror-by-digest: cannot tell whether ${dst}@${digest} is mirrored, refusing to copy:" >&2
    printf '%s\n' "$out" >&2
    exit 1
    ;;
esac

echo "${dst}@${digest} is not mirrored yet; copying from ${src}"
n=1
while :; do
  if cosign copy -f "${src}@${digest}" "${dst}:${tag}"; then
    break
  fi
  if [ "$n" -ge "$attempts" ]; then
    echo "mirror-by-digest: cosign copy failed ${attempts} times" >&2
    exit 1
  fi
  echo "mirror-by-digest: copy attempt ${n} failed; retrying in $((pause * n))s" >&2
  sleep $((pause * n))
  n=$((n + 1))
done

# The copy is only good if the destination now serves the digest itself.
docker buildx imagetools inspect "${dst}@${digest}" >/dev/null
echo "${dst}@${digest} mirrored"
