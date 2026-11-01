//go:build !sbo_omit_security && !sbo_omit_security_deps && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"

	"github.com/marmutapp/superbased-observer/internal/secfeed/online"
)

// A node that is not enrolled fetches the sandbox kinds from the vendor's
// signed content feed through the security.online lane's client (plain GETs
// of public files at superbased.app, no redirects); a build without
// security.deps has no such client and fetches nothing (lane SBX-P3D).
func init() {
	sandboxContentFeed = func() sandboxFeedClient { return online.New(online.Options{}) }
	// A feed that does not publish the kind (404 or 410) is retried daily,
	// not hourly (sandboxContentRetryAfter).
	sandboxContentNotPublished = append(sandboxContentNotPublished, func(err error) bool { return errors.Is(err, online.ErrFeedNotPublished) })
}
