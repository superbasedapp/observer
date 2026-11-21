package otelident

// RepositoryKeys name the source repository a service was built from, in
// candidate order (Plane A build-out W4-3, lane C3: the cross-plane link
// from a running service to the coding sessions that built it). Resource-
// scoped ONLY, like ServiceKeys: a repository is a fact about the deployed
// service, not about one span. vcs.repository.url.full is the OTel semconv
// key (VCS registry); sbo.repository is the SDK spelling.
//
// The value is a git remote URL. Consumers reduce it with git.NormalizeRemote
// and hash it the way a machine hashes its own git remote
// (internal/crossplane.RepositoryHash), so it joins the Project Identity
// Resolver's remote hashes without a new identity scheme. Like the other
// identity values it is clamped to MaxValueLen.
var RepositoryKeys = []string{
	"sbo.repository",
	"vcs.repository.url.full",
}
