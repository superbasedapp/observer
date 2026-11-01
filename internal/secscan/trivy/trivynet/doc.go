// Package trivynet is the security.scan.trivy driver's one egress lane
// (lane GATES-SEC, ledger SHR-3 and SECP-34): HTTPS only, to an exact host
// allow-list, a redirect followed only from one allow-listed host to
// another, every body capped. It reaches github.com and the two hosts its
// release downloads redirect to (release-assets.githubusercontent.com and
// objects.githubusercontent.com), for the pinned Trivy release archive of
// the guided install and its sigstore bundle. Nothing about a project is
// sent; the URL names the version and the platform's asset.
//
// The gate is the caller's (cmd/observer/security_iac_install.go): the
// component security.scan.trivy selected, an individual node (a managed
// node takes its engine from the org mirror only), and the developer's
// one-time size consent for the pin in force (dashboard or CLI, never an
// agent: R-165). It is linked only into the cmd layer.
package trivynet
