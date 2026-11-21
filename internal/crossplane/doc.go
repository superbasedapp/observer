// Package crossplane is the pure core of the cross-plane link (Plane A
// build-out W4-3 and W5-8, lane C3): it joins a running AI service (Plane A,
// an AI app's OTel service) to the coding-agent sessions (Plane B) that
// built it, on the project identity the Project Identity Resolver already
// owns. It never mints an identity of its own:
//
//   - a service's REPOSITORY (the OTel resource attribute
//     vcs.repository.url.full, otelident.RepositoryKeys) is reduced with
//     git.NormalizeRemote and hashed exactly like the node hashes its own git
//     remote (sha256 of the normalized string), so it equals
//     sessions.git_remote_hash / project_identity_signals.remote_hash for the
//     same repository; orgcontract.ProjectRemoteForms adds the
//     case-insensitive-host and Azure DevOps forms when the raw remote is
//     known;
//   - a service's PROJECT ROOT (sbo.project_root, the dev-loop attribute) is
//     hashed like the node hashes a project root, so it equals
//     sessions.project_root_hash for the same checkout.
//
// The link rules are an ordered table (linkRules, see RuleNames), walked top-down, the first
// match per project winning. The build-vs-run series merge, the regression
// window and its session classification are pure functions too. No SQL,
// HTTP, file watching or exec (imports_test.go): the org rollup
// (internal/orgserver/rollup/crossplane*.go) and the machine's Your apps
// route (internal/obs/httpapi) load the rows and call in.
package crossplane
