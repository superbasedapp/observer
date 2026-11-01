// Package deliverynet is the ONLY network code of the commit to PR to merge
// tracking arc (docs/plans/commit-pr-merge-tracking-plan-2026-10-15.md,
// sections 7.2 and 12.2). Every GitHub API call, every `gh api` process and
// every git clone, fetch and ls-remote the delivery feature runs goes through
// this package. tests/invariant/delivery_egress_test.go pins that only
// internal/deliverysvc and cmd/observer import it, and that the always-on
// daemon paths (watcher, proxy, store, hook, adapters, landingscan) never
// link it.
//
// GitHub REST rules, enforced before any credential is attached (copied from
// internal/planlimitsnet):
//
//   - HTTPS only, no user info, port 443, and the host must be api.github.com
//     or a GitHub Enterprise Server host the operator declared;
//   - redirects are never followed: a 301 from a renamed repository becomes
//     the typed KindRepoMoved result instead of carrying the token to a
//     different URL;
//   - bodies are capped and every call has a timeout;
//   - conditional requests (If-None-Match with a remembered ETag) keep a
//     repeat poll free, and the rate-limit headers are parsed so a client
//     that saw X-RateLimit-Remaining 0 sends nothing until X-RateLimit-Reset;
//   - the token header is never logged or returned in an error.
//
// The gh_cli auth mode runs the user's own gh with a fixed argv (`gh api -H
// Accept:application/vnd.github+json [--hostname H] <path>`), empty stdin,
// an allow-listed environment and a timeout, never resolved to an Observer
// PATH shim. Observer stores nothing for that mode.
//
// Mirror rules (plan 12.2, operator ruling "No active changes" to the user's
// repository): git runs ONLY against an Observer-owned bare blobless mirror
// under ~/.observer/delivery/mirrors (or a target directory there for a
// clone). This package never runs git against a user repository. Every git
// process gets GIT_TERMINAL_PROMPT=0, a failing askpass, ssh forced into
// batch mode (appended to the user's own ssh command, so a passphrase or a
// host key prompt fails at once as KindNeedsNonInteractive), LC_ALL=C, an
// allow-listed environment (so an inherited GIT_DIR or GIT_WORK_TREE can
// never point it at a user repository), GIT_CEILING_DIRECTORIES above the
// mirror root, an allow-listed transport set, no hooks and no templates. No
// credential.helper is ever written anywhere; the user's own helper from
// their global configuration is used as is. The remote URL a mirror stores
// in its config has its user info stripped.
package deliverynet
