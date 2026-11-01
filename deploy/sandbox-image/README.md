# Observer's default sandbox image

The recipe for the image a container sandbox (`oci-runc`, `oci-runsc`) uses
when `[terminal.sandbox.oci].image` is empty. Plan of record: sandbox plan v2
section 12.3; ledger row SBX-IMG-1. **Not published yet**: until the
operator's release signing step publishes a signed `sandbox.image` manifest,
an empty `image` leaves the container sandbox unavailable, exactly as before.

## What is in it

A Debian userland (`packages.txt`) for the host-toolchain bind: the host's own
agent CLI and its runtime are bound in read-only at launch (plan section 5.4),
so the image holds the glibc loader, the shared libraries a host binary links
against and the tools an agent runs. It never carries an agent CLI; the recipe
test (`internal/sandboximage/recipe_test.go`), `build.sh --check`, the SBOM
generator and the node's SBOM check each refuse one. It sets no `ENTRYPOINT`,
`CMD`, `USER` or `ENV`: the driver sets the entrypoint and runs the container
as your uid and gid.

## Build (reproducible)

```bash
deploy/sandbox-image/build.sh --version 1.0.0 --repository <registry>/observer-sandbox \
    --snapshot 20261020T000000Z
```

Every input is pinned: the base by digest (`ARG BASE` in the Dockerfile), the
packages by a snapshot.debian.org timestamp, and every timestamp by
`SOURCE_DATE_EPOCH` (the recipe's last commit), with BuildKit's
`rewrite-timestamp=true`. Two builds from the same commit and snapshot give the
same digest. The output in `dist/sandbox-image/` is the OCI layout tarball,
the per-platform package lists, and in `sandbox.image/` the descriptor
(`sandbox-image.json`) and the SPDX 2.3 SBOM (`sandbox-image.spdx.json`),
written by `go run ./scripts/vendorsign sandboximage`.

## Release step (operator only)

`publish.sh` takes `build.sh`'s output and does everything short of the
release key (`docs/release-runbook.md` "Sandbox artifacts"):

```bash
# every check, no push, no signature
deploy/sandbox-image/publish.sh --registry <registry> --dry-run
# push by digest, then sign with the vendor key
deploy/sandbox-image/publish.sh --registry <registry> --key <vendor key file> --manifest-version <next>
```

1. It checks that the OCI layout still carries the descriptor's digest and
   image ids (`vendorsign sandboximage -from-build`, no key): a rebuilt or
   changed layout is refused with `sandbox_image_digest_mismatch` (exit 4),
   and the descriptor's repository must be under `--registry`. The registry
   is a required argument; none is baked in.
2. It pushes with the pinned `skopeo 1.16.1` (`copy --all
   --preserve-digests`; the version is checked before anything runs and
   written to `publish-record.txt`), then reads the manifest back by digest
   and checks its sha256.
3. It runs the signing seam `vendorsign sandboximage -from-build -key <file>
   -manifest-version <next>`, which writes `sandbox.image/manifest.json`, the
   signed content manifest covering the descriptor and the SBOM bytes
   `build.sh` wrote (never rewritten), valid at most 180 days. `--revoke
   <sha256>` withdraws an earlier image or artifact. With no `--key` the
   script pushes and stops at the named seam
   `sandbox_image_signing_key_missing` (exit 3): the manifest stays unsigned
   and no node accepts it.
4. Publish the three files the way the security feeds are published. A node
   enrolled with an organization takes them only from its organization's
   mirror, never from the public channel; the organization's administrator
   fills that mirror. The image bytes themselves are pulled by digest from
   the registry, never through the content mirror.

`SKOPEO` and `VENDORSIGN` override the two tools (the tests in
`scripts/vendorsign/publish_test.go` use a fake push tool).

## What a node checks

`internal/sandboximage` (pure) over `internal/contentchan`: the manifest
signature against the vendor key compiled into the agent (none, or another
key: `artifact_unverified`), the monotonic manifest version and epoch (a
replayed older manifest is refused), the expiry (an expired manifest keeps an
image already present usable as last-known-good, reported; a run that would
need the image fetched is refused), the descriptor and SBOM digests on every
read, the minimum version (the manifest's and the agent's own floor,
`sandboximage.MinVersion`), revocation, and before each run the engine's view
of the image (the repository at the signed digest, and the signed image id).
