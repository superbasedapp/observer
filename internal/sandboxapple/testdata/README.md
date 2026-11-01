# Recorded `container` outputs

Two sets:

- Reconstructed from the documentation (lane SBX-P5, no Mac available):
  the pre-1.6 shapes the parsers keep reading.
  - `ls.json`: four containers: two of install `a1b2c3d4e5f60718` (one live
    run, one orphan), one of another install, one that is not Observer's.
  - `inspect.json`: one run's container as planned (no network, the planned
    mounts and limits).
  - `inspect_weaker.json`: the same container attached to the default
    network with an extra writable mount (the read-back must refuse it).
  - `images.json`: two local images, one of them the configured digest.
- Captured live from Apple container 1.6.0 on a bare-metal Mac (macOS
  26.7.1, 2026-10-23 and 2026-10-24), anonymized (user paths, temp dirs,
  labels, container names, the local image name, MAC and IPv6 addresses
  replaced; digests kept):
  - `images_live.json`: `container image list --format json` (the name and
    digest under `configuration`).
  - `inspect_live.json`, `inspect_live_net.json`: `container inspect` of a
    `--network none` container in the pre-fix mount shape and of a
    default-network one (the status is an object).
  - `ls_live.json`: the two `container ls --all --format json` answers,
    one entry each, joined into one list.
  - `mountinfo_live.txt`: the guest's `/proc/self/mountinfo` with the
    workspace, the `.git` pin and three `--read-only-path` entries (the
    fixed shape).
  - `mountinfo_live_da3.txt`: the same with the `.git` pin plus a
    `.git/config` file mount (`-v`): the `.git` mount is missing (D-A3).
  - `run_help_live.txt`: `container run --help`.
