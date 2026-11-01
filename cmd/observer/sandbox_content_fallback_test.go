//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// tenancyOrg is the org seam with the enrolment's tenancy, as the real
// orgclient.Client answers it.
type tenancyOrg struct {
	*fakeSandboxOrg
	managed bool
	err     error
}

func (o tenancyOrg) EnrolmentManaged(context.Context) (bool, error) { return o.managed, o.err }

func rigWithTenancy(t *testing.T, managed bool, tenancyErr, orgErr error) *sandboxContentRig {
	t.Helper()
	r := newSandboxContentRig(t, true)
	r.org.err = orgErr
	org := tenancyOrg{fakeSandboxOrg: r.org, managed: managed, err: tenancyErr}
	r.env.org = func(context.Context) (sandboxMirrorInstaller, func(), error) { return org, func() {}, nil }
	return r
}

// TestSandboxContentFeedFallbackRule (SBX-P3D audit finding 2): a managed
// node falls back to the public signed feed on exactly the org server's two
// typed refusals (orgclient.SandboxContentFeedFallback, pinned against the
// real content route in secrelay's TestSandboxFeedFallbackAgainstTheRealContentRoute),
// never on a network error, a 5xx or a kind its org's mirror lacks; an
// individual enrolment uses the feed directly; an unreadable tenancy
// fetches nothing.
func TestSandboxContentFeedFallbackRule(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		orgErr error
		feed   bool
	}{
		{"relay mode off (404 not_supported)", fmt.Errorf("wrapped: %w", orgclient.ErrSecurityContentNotSupported), true},
		{"managed enrolments only (403)", orgclient.ErrSecurityContentManagedOnly, true},
		{"not in the org's mirror", orgclient.ErrSecurityContentNotMirrored, false},
		{"a 5xx", errors.New("orgclient: security content: server returned 503"), false},
		{"a network error", errors.New("orgclient: security content: dial tcp: connection refused"), false},
		{"an auth failure", orgclient.ErrAuthFailed, false},
	} {
		r := rigWithTenancy(t, true, nil, tc.orgErr)
		out, err := r.env.fetch(ctx, content.SandboxNative)
		if tc.feed {
			if err != nil || out.Source != sandboxSourceFeed || out.Fallback == "" || out.State.Accepted == nil {
				t.Fatalf("%s: %+v %v, want the feed", tc.name, out, err)
			}
			line := sandboxContentStatusLine(r.env.store, r.env.trust, content.SandboxNative)
			if !strings.Contains(line, "from vendor_feed (the org server refused the mirror route") {
				t.Fatalf("%s: status %s", tc.name, line)
			}
			continue
		}
		if err == nil || r.feed.calls.Load() != 0 {
			t.Fatalf("%s: err %v, feed calls %d: a managed node bypassed its org", tc.name, err, r.feed.calls.Load())
		}
	}

	// An individual enrolment: the feed, never the org mirror.
	r := rigWithTenancy(t, false, nil, nil)
	out, err := r.env.fetch(ctx, content.SandboxNative)
	if err != nil || out.Source != sandboxSourceFeed || r.org.calls.Load() != 0 || !strings.Contains(out.Fallback, "individual") {
		t.Fatalf("individual: %+v %v org calls %d", out, err, r.org.calls.Load())
	}

	// The tenancy unreadable: nothing fetched from either source.
	r = rigWithTenancy(t, true, errors.New("store locked"), nil)
	if _, err := r.env.fetch(ctx, content.SandboxNative); err == nil || r.feed.calls.Load()+r.org.calls.Load() != 0 {
		t.Fatalf("unreadable tenancy: %v", err)
	}
}
