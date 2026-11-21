// Package promptjudgeipc is the hook lane's ask channel to the organization's
// coding-agent prompt judge (P-228 phase 2, lane adm-2): the
// `promptjudge.ask` local egress lane. A prompt gate hook (any tool whose
// integration registry row wires the prompt-gate capability, proxy-routable
// or not) asks the daemon over the owner-only local IPC transport
// internal/localipc (a unix socket under a 0700 directory, or a named pipe
// with an owner-only DACL), never TCP loopback and with no token, and the
// daemon judges through the SAME node lane, verdict cache, negative cache,
// secret gate and audit seam the proxy lane uses.
//
// The secask precedent (internal/secask): one JSON line each way, strict
// decoding of the answer, a size cap, and one deadline that covers dial,
// write and read. A daemon that is down, slow or wrong is an error the hook
// maps onto the policy's strict flag, never a clean answer.
//
// The package carries the wire shape, the client and a server that calls an
// injected answer function; it does no judging itself.
package promptjudgeipc
