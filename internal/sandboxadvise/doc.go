// Package sandboxadvise is the advisor lite of the sandbox egress refusal
// audit (OpenShell build plan 05 section 3.5, lane N5): from one stored
// refusal it decides whether the dashboard may offer the owner "allow this
// host", and why not when it may not.
//
// It is pure: no database, no HTTP, no file reads. The dashboard loads the
// config the gateway reads and asks the gateway's own host check; it hands
// the results here as Facts, and Decide walks one ordered table. Only an
// allow-list miss is ever offerable. A provider host, a private range, a
// host-local or SSRF-floor refusal, or a host an organization pin refuses is
// never offered, and nothing here approves anything by itself (ruling R-8:
// no auto-approve, no batch approve). The owner applies one offer at a time.
package sandboxadvise
