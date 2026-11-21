// Package cloudagentsnet is the ONLY egress of the node cloud-agent pull
// connectors (docs/plans/cloud-agents/cloud-agents-implementation-plan-2026-10-31.md
// section 5.1, decision CA-D5; operator reference docs/cloud-agents.md).
// tests/invariant/cloudagents_egress_test.go pins that it is the only
// package of the feature importing net, net/http or os/exec, that only
// cmd/observer and internal/cloudagentssvc import it, and that the always-on
// daemon paths (watcher, proxy, store, hook, adapters, the dashboard) never
// link it.
//
// Vendor CLI rules (the internal/deliverynet gh precedent):
//
//   - only the argv internal/cloudagents builds runs, and its argv[0] must be
//     the connector row's own command (codex or gh);
//   - the binary is resolved on PATH skipping Observer's shim directory and
//     any file carrying the shim marker, so a command-wrapping shim never
//     runs;
//   - the process gets empty stdin, an allow-listed environment plus a fixed
//     non-interactive one, a timeout, and capped stdout and stderr;
//   - stderr is classified into a closed cloudagents.ErrorClass and never
//     returned, logged or stored;
//   - Observer stores nothing for a CLI connector: the CLI's own login is
//     the credential.
//
// HTTPS rules for the API connectors of lane CA-B2 (the internal/planlimitsnet
// precedent): HTTPS only, port 443, no user info, the host must be in the
// connector table's exact-host list, redirects are never followed, bodies
// are capped, every call has a timeout, and header values are never logged
// or returned in an error. With the first-wave table no host is allowed, so
// every URL is refused.
package cloudagentsnet
