// Package trivydb is the security.scan.trivy.db egress lane (OS and CI
// vulnerability scanning plan section 6.7, lane OS-2 T; ledger SHR-3): the
// download of Trivy's vulnerability database for the Trivy image driver
// (security.scan.image.trivy). Trivy itself never downloads it (every run
// passes --skip-db-update); Observer pulls the public OCI artifact
// ghcr.io/aquasecurity/trivy-db:2 anonymously over the OCI distribution
// API and unpacks it into its own Trivy cache directory.
//
// The client (client.go) reaches exactly two hosts, over HTTPS only:
// ghcr.io for the anonymous pull token, the manifest by tag and the layer
// request, and pkg-containers.githubusercontent.com, the one host the
// registry redirects the layer download to (grounded live on 2026-11-04 by
// the token, manifest and a one-byte ranged blob request). A redirect is
// followed only on the layer request and only to that host; every body is
// capped; the manifest is checked against its digest, the one
// application/vnd.aquasec.trivy.db.layer.v1.tar+gzip layer against the
// manifest's digest and size. Nothing about a project or an image is sent:
// the requests name the repository, the tag and the layer digest, and the
// User-Agent is superbased-observer.
//
// The store (store.go) unpacks only trivy.db and metadata.json from the
// layer, into a new generation directory, and switches to it by rewriting
// its state file atomically, so a failed download or unpack leaves the
// last known good database in use. Refresh (Due) runs at most every 6
// hours and not before the database's own NextUpdate.
//
// The gate is the caller's (cmd/observer/security_scan_image_trivy.go):
// the component selected, an individual node (a managed node's
// organization mirror does not serve Trivy's database yet, so a managed
// node makes no request), and the developer's one-time accept
// (osvdb.TrivyConsent, never an agent: R-165). It is linked only into the
// cmd layer (tests/invariant/security_trivydb_egress_test.go).
package trivydb
