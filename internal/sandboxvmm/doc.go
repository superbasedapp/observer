// Package sandboxvmm is the Cloud Hypervisor REST client of the microVM
// sandbox driver (sandbox plan v2 sections 4.6 and 4.8, lane SBX-P4): the
// VMM's API over its --api-socket unix socket, reached through an injected
// dialer (the internal/sandboxengine precedent), and the host side of the
// hybrid vsock CONNECT exchange over the VMM's vsock socket.
//
// The calls are vmm.ping, vm.create, vm.boot, vm.info, vm.shutdown,
// vm.delete and vmm.shutdown. Every answer is bounded and checked: a status
// the call does not document, a body where none is due, a malformed or
// oversized JSON answer is refused, never guessed at. The pure decisions
// (the create body, the read-back judge, the CONNECT parser) are
// internal/sandboxvm's; this package moves bytes only. No exec, no
// database, no file watching, no TLS (imports_test.go).
package sandboxvmm
