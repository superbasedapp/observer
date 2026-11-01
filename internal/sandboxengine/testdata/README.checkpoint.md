# Checkpoint and restart-fact fixtures (lane GATES-SBX)

`checkpoint_*.json` are RECONSTRUCTED answers, not live captures: their field
names follow Docker Engine API's `/info` (`LiveRestoreEnabled`) and Podman's
libpod REST reference (`/libpod/info` `host.conmon.path`, container inspect
`OCIRuntime`, `POST /libpod/containers/{name}/restore?import=true` answering
`{"Id", "Err", "RawInput"}`). The live check on the Scaleway Elastic Metal
box (rootful Docker with live-restore, rootful Podman with CRIU) replaces
them with captured answers; until then the tests prove the client reads these
fields and nothing else.
