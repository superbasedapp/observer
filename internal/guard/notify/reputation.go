package notify

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Reputation lookups (guard spec §15.3): optional npm-registry
// metadata for MCP server packages. v1 is the on-demand surface
// (`observer guard mcp reputation <package>`) — lookups route through
// the Egress worker like every other cloud call, the registry host is
// allowlisted only when [guard.cloud].reputation.enabled, and results
// are presented to the operator rather than auto-firing rules (a
// young-package rule needs threshold calibration first; recorded as
// deferred in the spec §22 tick). GitHub metadata and curl|sh domain
// reputation join the same builder pattern later.

// NPMRegistryBase is the allowlist prefix and lookup base. The
// trailing slash makes it a prefix-form allow entry.
const NPMRegistryBase = "https://registry.npmjs.org/"

// BuildNPMLookup renders the metadata GET for one package name
// (scoped names are escaped per the registry's URL convention).
func BuildNPMLookup(pkg string) (Request, error) {
	if pkg == "" {
		return Request{}, fmt.Errorf("notify.BuildNPMLookup: package name required")
	}
	// The registry wants %2f for the scope separator; PathEscape
	// produces exactly that for "/".
	return Request{
		Feature:  "reputation",
		Endpoint: NPMRegistryBase + url.PathEscape(pkg),
		Method:   http.MethodGet,
	}, nil
}

// NPMPackageInfo is the operator-facing reputation summary.
type NPMPackageInfo struct {
	Name         string
	Description  string
	Latest       string
	VersionCount int
	// CreatedAt / ModifiedAt are the registry's package timestamps.
	CreatedAt  time.Time
	ModifiedAt time.Time
	// AgeDays is the whole-day age of the package at `now`.
	AgeDays int
	// Maintainers is the registry's maintainer count.
	Maintainers int
}

// ParseNPMMetadata extracts the reputation summary from a registry
// metadata document.
func ParseNPMMetadata(body []byte, now time.Time) (NPMPackageInfo, error) {
	var doc struct {
		Name        string            `json:"name"`
		Description string            `json:"description"`
		DistTags    map[string]string `json:"dist-tags"`
		Versions    map[string]any    `json:"versions"`
		Time        map[string]string `json:"time"`
		Maintainers []any             `json:"maintainers"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return NPMPackageInfo{}, fmt.Errorf("notify.ParseNPMMetadata: %w", err)
	}
	if doc.Name == "" {
		return NPMPackageInfo{}, fmt.Errorf("notify.ParseNPMMetadata: not a package document")
	}
	info := NPMPackageInfo{
		Name:         doc.Name,
		Description:  bound(doc.Description),
		Latest:       doc.DistTags["latest"],
		VersionCount: len(doc.Versions),
		Maintainers:  len(doc.Maintainers),
	}
	if created, err := time.Parse(time.RFC3339, doc.Time["created"]); err == nil {
		info.CreatedAt = created
		if now.After(created) {
			info.AgeDays = int(now.Sub(created).Hours() / 24)
		}
	}
	if modified, err := time.Parse(time.RFC3339, doc.Time["modified"]); err == nil {
		info.ModifiedAt = modified
	}
	return info, nil
}

// FormatNPMInfo renders the operator-facing summary lines.
func FormatNPMInfo(info NPMPackageInfo) []string {
	lines := []string{
		fmt.Sprintf("package:     %s", info.Name),
		fmt.Sprintf("latest:      %s (%d versions)", info.Latest, info.VersionCount),
		fmt.Sprintf("age:         %d days (created %s)", info.AgeDays, fmtDay(info.CreatedAt)),
		fmt.Sprintf("modified:    %s", fmtDay(info.ModifiedAt)),
		fmt.Sprintf("maintainers: %d", info.Maintainers),
	}
	if info.Description != "" {
		lines = append(lines, "description: "+info.Description)
	}
	return lines
}

// fmtDay renders a date or "unknown".
func fmtDay(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.UTC().Format("2006-01-02")
}

// YoungPackageDays is the age under which a lookup warns: a package this new
// deserves a review before an MCP server from it is trusted.
const YoungPackageDays = 14

// YoungPackageWarning is the operator-facing warning for a young package.
const YoungPackageWarning = "package is less than 14 days old - review before trusting an MCP server from it"

// Young reports whether the package is younger than YoungPackageDays.
func (i NPMPackageInfo) Young() bool { return i.AgeDays < YoungPackageDays }

// ErrReputationOff is the D1 double opt-in refusal: reputation lookups are a
// cloud feature, off until both [guard.cloud] and [guard.cloud.reputation]
// are enabled. The CLI and the dashboard both show it, so it names the
// dashboard's consent card first and the config keys second (plan
// docs/plans/dashboard-cli-parity-plan-2026-11-06.md decision P-2).
var ErrReputationOff = errors.New("reputation lookups are a cloud feature and are OFF by default (D1): opt in on the Observer dashboard (Security > MCP, Network features, Reputation lookups) or set [guard.cloud] enabled = true and [guard.cloud.reputation] enabled = true in config.toml - a lookup makes ONE outbound HTTPS request to registry.npmjs.org")

// ErrPackageNotFound is a 404 from the registry.
var ErrPackageNotFound = errors.New("package not found on the npm registry")

// ReputationLookupOptions configures LookupNPMReputation.
type ReputationLookupOptions struct {
	// CloudEnabled and ReputationEnabled are [guard.cloud].enabled and
	// [guard.cloud.reputation].enabled: both must be true (D1).
	CloudEnabled, ReputationEnabled bool
	// MaxBodyBytes is [guard.cloud].payload_max_bytes.
	MaxBodyBytes int
	// Doer overrides the HTTP client (tests); nil = the egress default.
	Doer Doer
	// Now stamps the package age; zero = time.Now().UTC().
	Now time.Time
}

// LookupNPMReputation is THE on-demand reputation lookup (guard spec
// section 15.3), shared by `observer guard mcp reputation` and the
// dashboard's Security > MCP control (T-496) so the two cannot drift: the
// D1 opt-in gate, ONE request through the Egress worker (allowlist,
// redaction, size cap), and the metadata parse. Nothing calls it on its
// own; every call is an explicit operator action.
func LookupNPMReputation(pkg string, opts ReputationLookupOptions) (NPMPackageInfo, error) {
	if !opts.CloudEnabled || !opts.ReputationEnabled {
		return NPMPackageInfo{}, ErrReputationOff
	}
	req, err := BuildNPMLookup(pkg)
	if err != nil {
		return NPMPackageInfo{}, err
	}
	done := make(chan Result, 1)
	e := NewEgress(EgressOptions{
		Allow:        []string{NPMRegistryBase},
		MaxBodyBytes: opts.MaxBodyBytes,
		OnResult:     func(r Result) { done <- r },
		Doer:         opts.Doer,
	})
	e.Submit(req)
	e.Close() // drains: the result lands before Close returns
	res := <-done
	switch {
	case res.Refused || res.Err != "":
		return NPMPackageInfo{}, fmt.Errorf("lookup failed: %s", res.Err)
	case res.Status == http.StatusNotFound:
		return NPMPackageInfo{}, fmt.Errorf("%w: %q", ErrPackageNotFound, pkg)
	case res.Status != http.StatusOK:
		return NPMPackageInfo{}, fmt.Errorf("registry returned HTTP %d", res.Status)
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return ParseNPMMetadata(res.Body, now)
}
