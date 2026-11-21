// Package sandboxsetupnet is sandbox setup's one egress lane (lane id
// sandbox.setup.net in tests/invariant/egress_lanes_test.go; ledger SHR-3
// and SBXSETUP-2 in docs/security.md): the pinned download of a sandbox
// host tool's vendor release asset (sandbox installation lifecycle plan
// sections 3.5 and 8, decision O2=B). Today that is the Cloud Hypervisor
// static binary named by internal/sandboxsetup's pin table.
//
// What it does, and nothing else:
//
//   - HTTPS only, port 443 only, to an exact host allow-list: github.com
//     and the two hosts its release downloads redirect to,
//     release-assets.githubusercontent.com and
//     objects.githubusercontent.com.
//   - A redirect is followed only to a host in the list, over HTTPS, and
//     at most five times.
//   - Every body is capped at the pin's size: a declared length over the
//     cap is refused before a byte is read, a streamed body is cut at the
//     cap plus one byte and refused.
//   - A context timeout bounds the whole transfer; a User-Agent names
//     Observer; no cookie jar, so no cookie is ever stored or sent; a
//     URL with user info is refused, and any user info (a proxy
//     credential) is redacted from the errors it returns, so it can never
//     reach a log line.
//
// Nothing about a project or the person is sent: the URL names the
// version and the platform's asset. The gate in front of it is the
// caller's (cmd/observer/sandbox_setup_download.go, reached from the setup
// runner on a person's click or `observer sandbox setup run`): the sandbox
// module, [terminal.launch].allow_install, the per-step consent echo, and
// never on a managed node (decision O3: downloads there come from the org
// mirror only). It is linked only into the cmd layer, never into the
// watcher, proxy, store or hook (tests/invariant/sandboxsetup_egress_test.go).
package sandboxsetupnet
