// Package sandboxoci is the pure planner of the `oci-runc` sandbox driver
// (sandbox plan v2 sections 4.4, 4.6, 4.7 and 13 P3; spike JSP-4): Docker
// Engine and Podman driven through the Engine API on their unix sockets, on
// Linux and WSL2, same kernel.
//
// It decides everything and does nothing: which engine and mode a socket
// answers for (engine.go), the uid strategy per engine mode (uid.go), the
// container create body from the run's bind plan (spec.go), the strict
// per-engine read-back of what the engine built (readback.go), the PID 1
// contract of the in-container init (pid1.go), the run labels and the
// orphan rule (labels.go), the socket validation rules (socket.go), the API
// version negotiation (version.go), and the probe ladder over injected
// facts (probe.go). The Engine API client is internal/sandboxengine; every
// real socket, stat and exec call lives in cmd/observer
// (terminal_sandbox_oci*.go).
//
// The package is pure: no database/sql, net, net/http, os, os/exec or
// fsnotify, and no observer-internal import but the neutral vocabulary leaf
// (imports_test.go pins it).
package sandboxoci
