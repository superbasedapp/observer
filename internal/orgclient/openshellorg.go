package orgclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// openshellorg.go is the node's client of the org-hosted OpenShell gateway's
// agent routes (tracker F-019, g1-design.md sections 5.3, 5.4 and 9.3, lane
// G4): login, poll, logout, mint (purposes probe, create, attach, return,
// teardown and resume), ended, hold, discard, held, and the member's fetch
// of their own collect (lane G3's route). Every call carries the enrolment
// bearer and an Ed25519 proof of possession of the node's agent key over a
// domain-separated message. The message is built by the one helper of the
// org-hosted core (internal/openshellorg.NodeMessage), which the driver
// injects (SetOpenShellNodeMessage) so this always-linked package never links
// that core into a build without the row.
//
// Nothing here logs, stores or wraps a token, a grant handle or a device
// code into an error: an error names the route and the server's closed
// reason only.

// The agent routes (section 9.3).
const (
	openShellAgentPrefix = "/api/agent/sandbox/openshell"
	openShellFetchPrefix = openShellAgentPrefix + "/collects/"
)

// The proof headers (internal/openshellorg pop.go; a test pins equality).
const (
	openShellHeaderProof   = "X-SBO-OpenShell-Proof"
	openShellHeaderProofTS = "X-SBO-OpenShell-TS"
)

// The proof domains (internal/openshellorg pop.go; a test pins equality).
const (
	OpenShellDomainMint  = "sbo-openshell-mint-v1"
	OpenShellDomainFetch = "sbo-openshell-fetch-v1"
)

// OpenShellNodeMessageFunc builds the message a node signs: domain, org id,
// run id, purpose, the signing time and the body.
type OpenShellNodeMessageFunc func(domain, orgID, runID, purpose string, ts int64, body []byte) []byte

var openShellNodeMessage OpenShellNodeMessageFunc

// SetOpenShellNodeMessage installs the org-hosted core's message helper (the
// driver's init). Until it is set every call answers ErrOpenShellNotInBuild.
func SetOpenShellNodeMessage(f OpenShellNodeMessageFunc) { openShellNodeMessage = f }

// ErrOpenShellNotInBuild: the org-hosted row is not compiled into this
// build.
var ErrOpenShellNotInBuild = errors.New("orgclient: the org-hosted OpenShell row is not in this build")

// ErrOpenShellNotOffered: the org server answered 404 (an older server, or
// the feature off): the row is not offered.
var ErrOpenShellNotOffered = errors.New("orgclient: the organization does not offer org-hosted sandboxes")

// OpenShellRefusal is a closed refusal from the org server: the reason
// (internal/openshellorg reasons.go) and the rule that refused.
type OpenShellRefusal struct {
	Status int
	Reason string
	Rule   string
}

func (e *OpenShellRefusal) Error() string {
	if e.Rule != "" {
		return fmt.Sprintf("orgclient: the organization refused (%s, rule %s)", e.Reason, e.Rule)
	}
	return fmt.Sprintf("orgclient: the organization refused (%s)", e.Reason)
}

// OpenShellLogin is the device approval the node prints.
type OpenShellLogin struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// String names the login without the device code.
func (l OpenShellLogin) String() string {
	return "login(" + l.UserCode + " at " + l.VerificationURI + ")"
}

// OpenShellGrant is the grant handle, returned once by the poll.
type OpenShellGrant struct {
	GrantHandle string    `json:"grant_handle"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// String names the grant without its handle.
func (g OpenShellGrant) String() string {
	return "grant(expires " + g.ExpiresAt.UTC().Format(time.RFC3339) + ")"
}

// OpenShellMintRequest is the signed mint body (internal/openshellorg
// MintRequest; a test pins the JSON shape equal).
type OpenShellMintRequest struct {
	GrantHandle            string   `json:"grant_handle"`
	RunID                  string   `json:"run_id"`
	Purpose                string   `json:"purpose"`
	TS                     int64    `json:"ts"`
	Tier                   string   `json:"tier,omitempty"`
	Source                 string   `json:"source,omitempty"`
	CloneURL               string   `json:"clone_url,omitempty"`
	NodeEgressAllowHosts   []string `json:"node_egress_allow_hosts,omitempty"`
	NodeRemoteAllowedHosts []string `json:"node_remote_allowed_hosts,omitempty"`
	SpecPreviewDigest      string   `json:"spec_preview_digest,omitempty"`
	LaptopRelay            bool     `json:"laptop_relay"`
	BoxRunID               string   `json:"box_run_id,omitempty"`
}

// OpenShellMint is the mint's answer. The token lives in memory only.
type OpenShellMint struct {
	Token        string    `json:"token"`
	ExpiresAt    time.Time `json:"expires_at"`
	Purpose      string    `json:"purpose"`
	RunID        string    `json:"run_id"`
	BoxRunID     string    `json:"box_run_id"`
	BoxName      string    `json:"box_name,omitempty"`
	SpecDigest   string    `json:"spec_digest,omitempty"`
	SpecReplaced bool      `json:"spec_replaced,omitempty"`
	ReturnToNode bool      `json:"return_to_node"`
	HoldPolicy   string    `json:"hold_policy"`
	MaxRunMins   int       `json:"max_run_minutes"`
	GatewayID    string    `json:"gateway_id"`
	FrontURL     string    `json:"front_url"`
}

// String names the mint without its token.
func (m OpenShellMint) String() string {
	return "mint(" + m.Purpose + " " + m.RunID + " box " + m.BoxName + ")"
}

// GoString is String.
func (m OpenShellMint) GoString() string { return m.String() }

// OpenShellEnded is the node's end report.
type OpenShellEnded struct {
	TS         int64 `json:"ts"`
	Returned   bool  `json:"returned"`
	Hold       bool  `json:"hold"`
	BoxMinutes int   `json:"box_minutes"`
	// Disconnected: the agent stream was cut, not ended (FX3 item 9): a
	// hold asked with it is a disconnect (H2) at the org.
	Disconnected bool `json:"disconnected,omitempty"`
}

// OpenShellEndedAnswer is what the server recorded.
type OpenShellEndedAnswer struct {
	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitempty"`
	// EndReason is the run's own end reason when the report came after its
	// row ended (lane FX6, FX6-A5); the terminal's words use Reason.
	EndReason string `json:"end_reason,omitempty"`
}

// OpenShellHeldBox is one of the member's own held boxes.
type OpenShellHeldBox struct {
	RunID       string     `json:"run_id"`
	State       string     `json:"state"`
	HeldSince   *time.Time `json:"held_since,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Reason      string     `json:"reason,omitempty"`
	ResumeCount int        `json:"resume_count"`
	Tier        string     `json:"tier"`
	Source      string     `json:"source"`
}

// OpenShellCollect is the member's fetch of their own collect: the staged
// diff and the commits bundle, untrusted input the node checks and saves,
// never applies. Each part matched its digest in the manifest and in the
// part's own X-Observer-SHA256 header.
type OpenShellCollect struct {
	Manifest OpenShellCollectManifest
	Diff     []byte
	Bundle   []byte
}

// OpenShellCollectManifest is the fetch route's manifest: lane G3's
// openshellgw.Manifest, snake_case, whose shape G3's TestManifestShape owns
// (fix round 2, G4-R1). Parts lists the parts to fetch next: diff always,
// bundle only when the collect carries commits.
type OpenShellCollectManifest struct {
	RunID        string    `json:"run_id"`
	DiffBytes    int64     `json:"diff_bytes"`
	BundleBytes  int64     `json:"bundle_bytes"`
	DiffSHA256   string    `json:"diff_sha256"`
	BundleSHA256 string    `json:"bundle_sha256"`
	CollectedAt  time.Time `json:"collected_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Reason       string    `json:"reason"`
	Parts        []string  `json:"parts"`
	// AskedRunID echoes the id the node asked for when the org resolved it
	// to the box's key (a resumed run's own id, lane FX6, F-P8-3).
	AskedRunID string `json:"asked_run_id,omitempty"`
}

// The collect parts a manifest may list.
const (
	openShellPartDiff   = "diff"
	openShellPartBundle = "bundle"
)

// openShellPartDigestHeader carries a fetched part's SHA-256 (lane G3).
const openShellPartDigestHeader = "X-Observer-SHA256"

// ErrOpenShellDigest refuses a fetched part whose bytes do not match the
// manifest's digest or the part's own header.
var ErrOpenShellDigest = errors.New("orgclient: a fetched part does not match its digest; nothing was saved")

// ErrOpenShellManifest refuses a collect manifest this node cannot trust or
// use: another run's, one that does not list the diff, one that names an
// unknown or repeated part, one whose part lengths differ from its byte
// counts, or one whose parts carry nothing to save while the manifest says
// they carry bytes.
var ErrOpenShellManifest = errors.New("orgclient: the collect's manifest is not usable; nothing was saved")

// ErrOpenShellNothingCollected is a real empty collect (G4-R6): the manifest
// says both parts are empty and the parts are empty, so the run's box had
// no changes to return. It is its own outcome, not a refused manifest.
var ErrOpenShellNothingCollected = errors.New("orgclient: nothing was collected: the run's box had no changes to return")

// openShellRaw receives a 200 answer's raw body and headers (a part fetch).
type openShellRaw struct {
	body   []byte
	header http.Header
}

// openShellMaxAnswer caps a route's answer (the fetch carries a diff and a
// bundle; the node checks the sizes again with workspace.CheckReturnSize).
const (
	openShellMaxAnswer  = 1 << 20
	openShellMaxCollect = 160 << 20
)

// openShellDo signs and sends one agent-route call and decodes a 200 answer
// into out. runID is "-" for the routes not about a run.
func (c *Client) openShellDo(ctx context.Context, method, route, domain, runID, purpose string, body []byte, ts int64, maxAnswer int64, out any) error {
	if openShellNodeMessage == nil {
		return ErrOpenShellNotInBuild
	}
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return fmt.Errorf("orgclient.openshell: %w", err)
	}
	if enr == nil {
		return ErrNotEnrolled
	}
	bearer, err := c.bearers.LoadBearer()
	if errors.Is(err, ErrNoSecret) {
		return ErrNotEnrolled
	}
	if err != nil {
		return fmt.Errorf("orgclient.openshell: load bearer: %w", err)
	}
	key, err := c.bearers.LoadAgentKey()
	if errors.Is(err, ErrNoSecret) {
		return ErrNotEnrolled
	}
	if err != nil {
		return fmt.Errorf("orgclient.openshell: load signing key: %w", err)
	}
	sig := ed25519.Sign(key, openShellNodeMessage(domain, enr.OrgID, runID, purpose, ts, body))
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(enr.OrgServerURL, "/")+route, rd)
	if err != nil {
		return fmt.Errorf("orgclient.openshell: new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(openShellHeaderProofTS, strconv.FormatInt(ts, 10))
	req.Header.Set(openShellHeaderProof, base64.RawURLEncoding.EncodeToString(sig))
	resp, err := c.httpClient.Do(req)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		return fmt.Errorf("orgclient.openshell %s: %w", route, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if int64(len(raw)) > maxAnswer {
		return fmt.Errorf("orgclient.openshell %s: the answer is over %d bytes", route, maxAnswer)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		if out == nil {
			return nil
		}
		if r, ok := out.(*openShellRaw); ok {
			r.body, r.header = raw, resp.Header.Clone()
			return nil
		}
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("orgclient.openshell %s: decode the answer", route)
		}
		return nil
	case http.StatusNotFound:
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return &OpenShellRefusal{Status: resp.StatusCode, Reason: e.Error}
		}
		return ErrOpenShellNotOffered
	case http.StatusUnauthorized:
		return fmt.Errorf("orgclient.openshell %s: %w", route, ErrAuthFailed)
	}
	var e struct {
		Error string `json:"error"`
		Rule  string `json:"rule"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Error != "" {
		return &OpenShellRefusal{Status: resp.StatusCode, Reason: e.Error, Rule: e.Rule}
	}
	return fmt.Errorf("orgclient.openshell %s: status %d", route, resp.StatusCode)
}

func openShellBody(v any) ([]byte, error) { return json.Marshal(v) }

// OpenShellLoginStart starts a device approval (design 5.3 step 1).
func (c *Client) OpenShellLoginStart(ctx context.Context, machineID string) (OpenShellLogin, error) {
	ts := time.Now().Unix()
	body, _ := openShellBody(struct {
		TS        int64  `json:"ts"`
		MachineID string `json:"machine_id,omitempty"`
	}{ts, machineID})
	var out OpenShellLogin
	err := c.openShellDo(ctx, http.MethodPost, openShellAgentPrefix+"/login", OpenShellDomainMint, "-", "login", body, ts, openShellMaxAnswer, &out)
	return out, err
}

// OpenShellLoginPoll polls the approval; a pending approval is the refusal
// device_code_pending.
func (c *Client) OpenShellLoginPoll(ctx context.Context, deviceCode string) (OpenShellGrant, error) {
	ts := time.Now().Unix()
	body, _ := openShellBody(struct {
		TS         int64  `json:"ts"`
		DeviceCode string `json:"device_code"`
	}{ts, deviceCode})
	var out OpenShellGrant
	err := c.openShellDo(ctx, http.MethodPost, openShellAgentPrefix+"/login/poll", OpenShellDomainMint, "-", "poll", body, ts, openShellMaxAnswer, &out)
	return out, err
}

// OpenShellLogout revokes the grant (the developer's own logout).
func (c *Client) OpenShellLogout(ctx context.Context, grantHandle string) error {
	ts := time.Now().Unix()
	body, _ := openShellBody(struct {
		TS          int64  `json:"ts"`
		GrantHandle string `json:"grant_handle"`
	}{ts, grantHandle})
	return c.openShellDo(ctx, http.MethodDelete, openShellAgentPrefix+"/grant", OpenShellDomainMint, "-", "logout", body, ts, openShellMaxAnswer, nil)
}

// OpenShellMintToken mints a run token. req.TS is set here.
func (c *Client) OpenShellMintToken(ctx context.Context, req OpenShellMintRequest) (OpenShellMint, error) {
	req.TS = time.Now().Unix()
	body, err := openShellBody(req)
	if err != nil {
		return OpenShellMint{}, err
	}
	var out OpenShellMint
	err = c.openShellDo(ctx, http.MethodPost, openShellAgentPrefix+"/token", OpenShellDomainMint, req.RunID, req.Purpose, body, req.TS, openShellMaxAnswer, &out)
	return out, err
}

func openShellRunRoute(run, verb string) string {
	return openShellAgentPrefix + "/runs/" + url.PathEscape(run) + "/" + verb
}

// OpenShellEndedReport reports the run's end (design 3.2 step 10).
func (c *Client) OpenShellEndedReport(ctx context.Context, run string, rep OpenShellEnded) (OpenShellEndedAnswer, error) {
	rep.TS = time.Now().Unix()
	body, _ := openShellBody(rep)
	var out OpenShellEndedAnswer
	err := c.openShellDo(ctx, http.MethodPost, openShellRunRoute(run, "ended"), OpenShellDomainMint, run, "ended", body, rep.TS, openShellMaxAnswer, &out)
	return out, err
}

// openShellTSBody is the body of the routes that carry only the time.
func openShellTSBody(ts int64) []byte {
	b, _ := openShellBody(struct {
		TS int64 `json:"ts"`
	}{ts})
	return b
}

// OpenShellHold asks for an explicit hold (trigger H3).
func (c *Client) OpenShellHold(ctx context.Context, run string) error {
	_, err := c.OpenShellHoldBox(ctx, run)
	return err
}

// OpenShellHoldBox asks for an explicit hold (trigger H3) and answers the
// id the organization holds the box under (its ledger key, the id `org-shell
// held` lists and resume accepts; lane FX6, F-P7-3). run may be the held id
// or a resumed run's own id. A server that names no id answers run.
func (c *Client) OpenShellHoldBox(ctx context.Context, run string) (string, error) {
	ts := time.Now().Unix()
	var out struct {
		RunID string `json:"run_id"`
	}
	if err := c.openShellDo(ctx, http.MethodPost, openShellRunRoute(run, "hold"), OpenShellDomainMint, run, "hold", openShellTSBody(ts), ts, openShellMaxAnswer, &out); err != nil {
		return "", err
	}
	if out.RunID == "" {
		return run, nil
	}
	return out.RunID, nil
}

// OpenShellDiscard asks for a held box to be deleted now (collected first
// when its work never came back).
func (c *Client) OpenShellDiscard(ctx context.Context, run string) error {
	ts := time.Now().Unix()
	return c.openShellDo(ctx, http.MethodPost, openShellRunRoute(run, "discard"), OpenShellDomainMint, run, "discard", openShellTSBody(ts), ts, openShellMaxAnswer, nil)
}

// OpenShellHeld lists the member's own held boxes.
func (c *Client) OpenShellHeld(ctx context.Context) ([]OpenShellHeldBox, error) {
	ts := time.Now().Unix()
	var out struct {
		Held []OpenShellHeldBox `json:"held"`
	}
	// A GET carries no body; the proof is over the empty body.
	err := c.openShellDo(ctx, http.MethodGet, openShellAgentPrefix+"/held", OpenShellDomainMint, "-", "held", nil, ts, openShellMaxAnswer, &out)
	return out.Held, err
}

// OpenShellFetch fetches the member's own collect of a run (lane G3's route,
// design 4.6): the manifest, then each part it lists (diff always, bundle
// when the collect has commits) one after another, each checked against the manifest's digest and its own
// X-Observer-SHA256 header; a mismatch refuses the whole fetch. Every call
// is signed under the fetch domain over the empty body, and the part is a
// field the core's NodeMessage signs: the purpose is "fetch:manifest",
// "fetch:diff" or "fetch:bundle" (OB-084), so the org's verifier and replay
// key separate the three calls and nothing here relies on the signing
// times differing.
func (c *Client) OpenShellFetch(ctx context.Context, run string) (OpenShellCollect, error) {
	route := openShellFetchPrefix + url.PathEscape(run)
	var out OpenShellCollect
	if err := c.openShellDo(ctx, http.MethodGet, route, OpenShellDomainFetch, run, openShellFetchPurpose("manifest"), nil, time.Now().Unix(), openShellMaxAnswer, &out.Manifest); err != nil {
		return OpenShellCollect{}, err
	}
	m := out.Manifest
	switch {
	case !openShellManifestNames(m, run):
		return OpenShellCollect{}, fmt.Errorf("%w (it names run %q, not %q)", ErrOpenShellManifest, m.RunID, run)
	case !slices.Contains(m.Parts, openShellPartDiff):
		return OpenShellCollect{}, fmt.Errorf("%w (it lists no diff)", ErrOpenShellManifest)
	}
	seen := map[string]bool{}
	for _, name := range m.Parts {
		var want string
		var size int64
		var dst *[]byte
		switch name {
		case openShellPartDiff:
			want, size, dst = m.DiffSHA256, m.DiffBytes, &out.Diff
		case openShellPartBundle:
			want, size, dst = m.BundleSHA256, m.BundleBytes, &out.Bundle
		default:
			return OpenShellCollect{}, fmt.Errorf("%w (unknown part %q)", ErrOpenShellManifest, name)
		}
		if seen[name] {
			return OpenShellCollect{}, fmt.Errorf("%w (part %q listed twice)", ErrOpenShellManifest, name)
		}
		seen[name] = true
		var raw openShellRaw
		if err := c.openShellDo(ctx, http.MethodGet, route+"?part="+name, OpenShellDomainFetch, run, openShellFetchPurpose(name), nil, time.Now().Unix(), openShellMaxCollect, &raw); err != nil {
			return OpenShellCollect{}, err
		}
		got := sha256Hex(raw.body)
		if !strings.EqualFold(got, want) || !strings.EqualFold(got, raw.header.Get(openShellPartDigestHeader)) {
			return OpenShellCollect{}, fmt.Errorf("%w (%s)", ErrOpenShellDigest, name)
		}
		// The part's length is the manifest's byte count (RC1-A7): a
		// manifest whose sizes disagree with the parts it names is refused.
		if int64(len(raw.body)) != size {
			return OpenShellCollect{}, fmt.Errorf("%w (%s is %d bytes, the manifest says %d)", ErrOpenShellManifest, name, len(raw.body), size)
		}
		*dst = raw.body
	}
	// A fetch that ends with nothing to save is never a success. When the
	// manifest agrees that both parts are empty, the collect really holds
	// no changes (its own error and wording, G4-R6); otherwise the manifest
	// and the parts disagree and the manifest is refused.
	if len(out.Diff) == 0 && len(out.Bundle) == 0 {
		if m.DiffBytes == 0 && m.BundleBytes == 0 {
			return OpenShellCollect{}, ErrOpenShellNothingCollected
		}
		return OpenShellCollect{}, fmt.Errorf("%w (the collect's parts are empty)", ErrOpenShellManifest)
	}
	return out, nil
}

// openShellFetchPurpose is the signed purpose of one fetch call: "fetch:"
// and the part ("manifest", "diff" or "bundle").
func openShellFetchPurpose(part string) string { return "fetch:" + part }

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// AdvertiseManagedPullCapability adds an optional body field this build
// applies to a rail's capability header (a driver's init; the org-hosted
// row names orgcontract.SandboxCapabilityOrgOpenShell). Adding one twice is
// a no-op.
func AdvertiseManagedPullCapability(rail, capability string) {
	for _, c := range managedPullCapabilities[rail] {
		if c == capability {
			return
		}
	}
	managedPullCapabilities[rail] = append(managedPullCapabilities[rail], capability)
}

// openShellManifestNames reports whether a fetch manifest answers the run id
// the node asked for (lane FX6, F-P8-3): it names that run, or it names a
// box key and echoes the asked id, which is how the org says it resolved a
// resumed run's own id to the box's key from its own ledger. A manifest
// that names another run without that echo is for a different box and is
// refused.
func openShellManifestNames(m OpenShellCollectManifest, run string) bool {
	if m.RunID == run {
		return true
	}
	return m.RunID != "" && m.AskedRunID == run
}
