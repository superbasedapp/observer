Recorded responses reconstructed from Daytona's public API specs, read
2026-11-11: the main API https://www.daytona.io/docs/openapi.json
(components/schemas Sandbox, ListSandboxesResponse, SshAccessDto; the spec's
own servers entry is localhost, the cloud origin https://app.daytona.io/api
is the docs' curl base) and the toolbox API
https://www.daytona.io/docs/toolbox-openapi.json (definitions ErrorResponse).

- sandbox_200.json: a Sandbox with the spec's field names; the values are
  illustrative, in the state a create of this client asks for (container
  class, started, ephemeral, auto-stop off, a TTL deadline).
- list_200.json: a ListSandboxesResponse ({items, nextCursor}) with the
  fields the client reads.
- ssh_access_200.json: an SshAccessDto. The token field is left out here
  (the fake fills a fake one per call) and the host is the one the SSH
  access page names (ssh.app.daytona.io); the port shape follows the spec's
  example ("ssh -p 2222 token@localhost").
- error_404.json: a toolbox ErrorResponse. The code value is illustrative
  (the spec's DaemonErrorCode enum is not checked here). The main API
  documents no error body; the client reads the same fields there where
  present.

No live call was made and no key was used.
