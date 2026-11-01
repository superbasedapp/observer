//go:build sbo_omit_security_trust

package secverify

import "context"

// repoTrustRun is nil in a build without the security.trust component:
// the repo_trust detector row reports "not in this build".
var repoTrustRun func(context.Context, Input) Result
