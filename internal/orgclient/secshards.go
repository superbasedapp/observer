package orgclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvshardkey"
)

// secshards.go is the managed node's fetch of one advisory shard object
// from its org mirror (OS and CI vulnerability scanning plan 13.5 and 13.10,
// lane RM-3): the Fetcher the package lookup's walk (internal/secscan/
// osvshard) uses on a managed node whose org's signed security policy turns
// the lookup on. It reaches only the enrolled org server, over the
// existing org.client lane (its bearer, TLS and key pin), at
// GET orgcontract.AgentSecurityShardsPath + <path>; a managed node never
// contacts SuperBased's shard host. The request names one content-addressed
// digest the walk chose from a hash prefix of a package name, never a name,
// a version or a path; the walk verifies every body against the digest its
// parent pins, exactly as it verifies the shard host's.

// ErrSecurityShardsNotEnabled: the org server refuses the shard route for
// this node because its org's security policy does not turn the package
// lookup on (403 lookup_not_enabled).
var ErrSecurityShardsNotEnabled = errors.New("orgclient: the org's security policy does not turn the package lookup on")

// FetchSecurityShard GETs one shard object (an osvshardkey object path) from
// the org mirror, refusing a body over max. It satisfies the walk's Fetcher.
// The typed refusals are ErrNotEnrolled, ErrSecurityContentNotSupported (no
// relay or mirror on the server), ErrSecurityContentManagedOnly,
// ErrSecurityShardsNotEnabled, ErrSecurityContentNotMirrored and
// ErrAuthFailed; nothing is retried here.
func (c *Client) FetchSecurityShard(ctx context.Context, path string, max int64) ([]byte, error) {
	op, ok := osvshardkey.ParseObjectPath(path)
	if !ok {
		return nil, fmt.Errorf("orgclient: bad shard object path %q", path)
	}
	if max <= 0 || max > op.MaxObjectBytes() {
		return nil, fmt.Errorf("orgclient: shard object %s: size %d out of range", path, max)
	}
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return nil, fmt.Errorf("orgclient: load enrolment: %w", err)
	}
	if enr == nil {
		return nil, ErrNotEnrolled
	}
	bearer, err := c.bearers.LoadBearer()
	if err != nil {
		return nil, fmt.Errorf("orgclient: load bearer: %w", err)
	}
	// The path is exactly the bucket's object path, checked above, so it
	// needs no escaping and carries no query.
	u := strings.TrimRight(enr.OrgServerURL, "/") + orgcontract.AgentSecurityShardsPath + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("orgclient: shard object: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, shardRefusal(resp)
	}
	if resp.ContentLength > max {
		return nil, fmt.Errorf("orgclient: shard object %s: %d bytes, over %d", path, resp.ContentLength, max)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("orgclient: shard object: %w", err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("orgclient: shard object %s: over %d bytes", path, max)
	}
	return b, nil
}

// shardRefusals maps the shard route's refusals to typed errors, walked top
// down: the status, then the error code the body names ("" matches any).
var shardRefusals = []struct {
	status int
	code   string
	err    error
}{
	{http.StatusNotFound, "not_mirrored", ErrSecurityContentNotMirrored},
	{http.StatusNotFound, "", ErrSecurityContentNotSupported},
	{http.StatusMethodNotAllowed, "", ErrSecurityContentNotSupported},
	{http.StatusForbidden, managedOnlyCode, ErrSecurityContentManagedOnly},
	{http.StatusForbidden, orgcontract.SecurityShardsNotEnabledCode, ErrSecurityShardsNotEnabled},
	{http.StatusForbidden, "", ErrAuthFailed},
	{http.StatusUnauthorized, "", ErrAuthFailed},
}

func shardRefusal(resp *http.Response) error {
	var e struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = json.Unmarshal(b, &e)
	for _, r := range shardRefusals {
		if r.status == resp.StatusCode && (r.code == "" || e.Error == r.code || e.Code == r.code) {
			return r.err
		}
	}
	return fmt.Errorf("orgclient: shard object: server returned %d", resp.StatusCode)
}

// SecurityShardFetcher is FetchSecurityShard in the walk's Fetcher shape
// (internal/secscan/osvshard.Fetcher), so the node's lookup takes it
// without this package importing the walk.
type SecurityShardFetcher struct{ Client *Client }

// Fetch is FetchSecurityShard.
func (f SecurityShardFetcher) Fetch(ctx context.Context, path string, max int64) ([]byte, error) {
	return f.Client.FetchSecurityShard(ctx, path, max)
}
