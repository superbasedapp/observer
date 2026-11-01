// Package sandboxengine is the hand-written Engine API client of the
// `oci-runc` sandbox driver (sandbox plan v2 sections 4.6 and 4.8): plain
// HTTP over the engine's local unix socket, shared by Docker Engine and
// Podman's Docker-compatible socket, plus the libpod calls only Podman
// answers (its info and inspect, which carry the rootless flag, the uid map
// and the real OCI runtime).
//
// It is a boundary package: it dials only the unix socket path it is given
// (never TCP, never off the machine; egress lane "sandbox.engine" in
// tests/invariant/egress_lanes_test.go), negotiates the API version
// (internal/sandboxoci.NegotiateAPI), and returns plain values and typed
// errors. Which socket to trust, what to create and how to judge the answer
// are decided by the pure planner internal/sandboxoci; the cmd layer
// (cmd/observer/terminal_sandbox_oci*.go) validates the socket before it
// ever builds a Client. go.mod gains no Docker or Podman module.
//
// Endpoints (about fifteen): _ping, version, info, libpod/info,
// containers/{id}/archive (HEAD, a path stat),
// images/{ref}/json, images/create, containers/create, containers/{id}/json,
// libpod/containers/{id}/json, containers/{id}/wait, containers/{id}/attach
// (hijacked), containers/{id}/start, containers/{id}/resize,
// containers/{id}/kill, containers/{id}/stop, DELETE containers/{id},
// containers/json (label filtered), events (label filtered stream),
// volumes/create.
package sandboxengine
