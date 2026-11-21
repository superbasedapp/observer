// Package scalibrchild is the body of the dependency scan child process
// (`observer security scan-child`, security pillar plan section 8.4 as the
// JSP-9b spike adjusted it): the daemon never links a SCALIBR scan into its
// own process; it starts its own binary again through the shared runner
// internal/extrun, under the runner's memory and wall-time caps, hands it a
// depscan.ChildRequest on stdin and reads a depscan.ChildResponse from
// stdout.
//
// The child extracts the project's inventory through
// internal/secscan/scalibrfacade, applies depscan's drop table, and matches
// each ecosystem on its own against the local database the daemon already
// downloaded (osvlocal with Download false), with that ecosystem's canary
// as the self-test. It opens no network connection: the local matcher's
// only client refuses every request. In a build without SCALIBR
// (sbo_omit_security_scan_scalibr) it answers Compiled false and every
// ecosystem "not scanned"; the daemon does not start it in such a build.
//
// With ChildRequest.ReachGo (component security.reach.go, reach.go) it then
// runs the Go symbol check: govulncheck's binary mode, linked in through
// internal/secreachgovuln, over each Go binary the artifact extractors read,
// against the matched records written as a flat directory; a stripped
// binary is never run. The answers ride ChildResponse.Reach and change no
// finding.
//
// An image request (depscan.KindOSImage, osimage.go, component
// security.scan.os) instead extracts an image root's OS packages and
// matches them against one release's database with that release's canary.
//
// It belongs to security.scan.scalibr's wiring and is compiled out with
// sbo_omit_security_deps (its only importer is cmd/observer).
package scalibrchild
