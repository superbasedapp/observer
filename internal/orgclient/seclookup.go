package orgclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// seclookup.go is the managed node's security relay call (security pillar
// plan section 8.3, spike JSP-11): the install gate's online queries go to
// the enrolled org server only, over the existing org.client lane (its
// enrolment bearer, TLS and key pin), never to a public host. The security
// service receives this method as an injected function; on a managed
// enrolment it is never handed the public client at all.

// maxSecurityLookupResponseBytes caps the relay's answer.
const maxSecurityLookupResponseBytes = 1 << 20

// ErrSecurityRelayNotSupported is a relay that is not mounted (404): the
// org server predates security Phase E. The node reads every query as
// online_unknown and never falls back to a public host.
var ErrSecurityRelayNotSupported = errors.New("orgclient: the org server has no security relay")

// ErrSecurityRelayRateLimited is a relay answering 429: this node is over
// its per-node lookup rate. The error returned is a
// *SecurityRelayRateLimitedError carrying the server's Retry-After.
var ErrSecurityRelayRateLimited = errors.New("orgclient: the org security relay rate-limited this node")

// SecurityRelayRateLimitedError is a 429 from the relay with its
// Retry-After hint (0 when absent).
type SecurityRelayRateLimitedError struct {
	RetryAfter time.Duration
}

// Error implements error.
func (e *SecurityRelayRateLimitedError) Error() string {
	return ErrSecurityRelayRateLimited.Error()
}

// Is matches ErrSecurityRelayRateLimited.
func (e *SecurityRelayRateLimitedError) Is(target error) bool {
	return target == ErrSecurityRelayRateLimited
}

// SecurityRelayRetryAfter is the server's Retry-After hint, read by the
// dependency scan's pacer through an interface.
func (e *SecurityRelayRateLimitedError) SecurityRelayRetryAfter() time.Duration {
	return e.RetryAfter
}

// SecurityLookup sends one batch of public package queries to the org
// relay and returns its answers, each matched to a query or dropped.
func (c *Client) SecurityLookup(ctx context.Context, in orgcontract.SecurityLookupRequest) (orgcontract.SecurityLookupResponse, error) {
	if len(in.Queries) == 0 {
		return orgcontract.SecurityLookupResponse{}, nil
	}
	if len(in.Queries) > orgcontract.SecurityLookupMaxQueries {
		in.Queries = in.Queries[:orgcontract.SecurityLookupMaxQueries]
	}
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return orgcontract.SecurityLookupResponse{}, fmt.Errorf("orgclient.SecurityLookup: load enrolment: %w", err)
	}
	if enr == nil {
		return orgcontract.SecurityLookupResponse{}, ErrNotEnrolled
	}
	bearer, err := c.bearers.LoadBearer()
	if err != nil {
		return orgcontract.SecurityLookupResponse{}, fmt.Errorf("orgclient.SecurityLookup: load bearer: %w", err)
	}
	body, err := json.Marshal(in)
	if err != nil {
		return orgcontract.SecurityLookupResponse{}, err
	}
	url := strings.TrimRight(enr.OrgServerURL, "/") + orgcontract.AgentSecurityLookupPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return orgcontract.SecurityLookupResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return orgcontract.SecurityLookupResponse{}, fmt.Errorf("orgclient.SecurityLookup: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	noteSecurityRelayPerMinute(resp.Header.Get(orgcontract.SecurityLookupPerMinuteHeader))
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		return orgcontract.SecurityLookupResponse{}, ErrSecurityRelayNotSupported
	case http.StatusUnauthorized, http.StatusForbidden:
		return orgcontract.SecurityLookupResponse{}, ErrAuthFailed
	case http.StatusTooManyRequests:
		return orgcontract.SecurityLookupResponse{}, &SecurityRelayRateLimitedError{RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())}
	default:
		return orgcontract.SecurityLookupResponse{}, fmt.Errorf("orgclient.SecurityLookup: server returned %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxSecurityLookupResponseBytes+1))
	if err != nil {
		return orgcontract.SecurityLookupResponse{}, fmt.Errorf("orgclient.SecurityLookup: %w", err)
	}
	if len(b) > maxSecurityLookupResponseBytes {
		return orgcontract.SecurityLookupResponse{}, errors.New("orgclient.SecurityLookup: answer over its cap")
	}
	var out orgcontract.SecurityLookupResponse
	if err := json.Unmarshal(b, &out); err != nil {
		return orgcontract.SecurityLookupResponse{}, fmt.Errorf("orgclient.SecurityLookup: %w", err)
	}
	asked := map[string]bool{}
	for _, q := range in.Queries {
		asked[q.Ecosystem+"\x00"+q.Name+"\x00"+q.Version] = true
	}
	kept := out.Answers[:0]
	for _, a := range out.Answers {
		if asked[a.Ecosystem+"\x00"+a.Name+"\x00"+a.Version] {
			kept = append(kept, a)
		}
	}
	out.Answers = kept
	return out, nil
}

// securityRelayPerMinute is the per-node lookup budget the org relay last
// sent (orgcontract.SecurityLookupPerMinuteHeader, lane LEFT-SHARED); 0
// until a relay that sends it answers. Process-wide because the relay's
// budget is per node.
var securityRelayPerMinute atomic.Int64

// noteSecurityRelayPerMinute records a usable header value; an answer
// without one (an older server) leaves the last value.
func noteSecurityRelayPerMinute(v string) {
	if n := orgcontract.ParseSecurityLookupPerMinute(v); n > 0 {
		securityRelayPerMinute.Store(int64(n))
	}
}

// SecurityRelayPerMinute is the per-node lookup budget the org relay last
// sent, 0 when none has (the dependency scan then paces to the default).
func SecurityRelayPerMinute() int { return int(securityRelayPerMinute.Load()) }
