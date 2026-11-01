package orgclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/machineid"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// P0-6 effective-policy-state reverse channel, agent sender side
// (docs/plans/plane-a-p0-6-effective-policy-state-plan.md §2.2/§4.4). This file
// owns PostPolicyState (the dedicated POST /api/agent/policy-ack sender,
// mirroring PushOnce's Ed25519 signed-request proof) and ReportSeqCounter (the
// restart-safe monotonic ordering source, §2.2). It is a DEDICATED endpoint —
// nothing here touches SelectUnpushedSince or the orgpush.go privacy seam.

// ErrPolicyAckUnsupported is returned by PostPolicyState when the org server
// answers 404/405 — a pre-P0-6 server without the endpoint (S8 compat). It is
// NON-FATAL: the caller (the reporter) latches the channel off for the daemon
// lifetime, logs once, and never retries. A sentinel so the caller can
// distinguish it from a transient transport error.
var ErrPolicyAckUnsupported = errors.New("orgclient: policy-ack endpoint unsupported (pre-P0-6 server)")

// ErrPolicyAckRejected is returned by PostPolicyState when the org server
// answers 400 — the value guard refused the snapshot's SHAPE. Peer of
// ErrPolicyAckUnsupported: a sentinel exists so the caller can tell a
// deterministic shape rejection apart from a transient transport error and
// act on it, rather than retrying an identical body forever.
//
// The v2 reporter uses it as the feature-probe signal for a pre-v2 server
// (docs/plans/policy-state-v2-gateway-providers-spec-2026-08-15.md §3.2): a
// v1 server rejects the five-row snapshot with 400, and the reporter answers
// by re-posting the four CORE rows. It deliberately carries NO detail about
// WHY the server refused — the response message is prose, not contract, and
// matching on it would be brittle coupling.
var ErrPolicyAckRejected = errors.New("orgclient: policy-ack report rejected by the server value guard")

// ReportSeqCounter is the restart-safe monotonic source for
// PolicyStateReport.ReportSeq (§2.2/R4-B6). It persists the last-issued value
// in a 0600 sidecar file next to the org policy cache (or beside the observer
// DB when the cache path is unset), so a daemon restart continues strictly
// upward regardless of any wall-clock regression — time.Now() is NEVER used as
// the seq source (it is process-local and regresses with the clock). A
// missing/corrupt file starts at 1.
//
// Durability contract: Next() persists the new value ATOMICALLY (temp+rename)
// BEFORE returning it, and returns an error on a persistence failure so the
// caller can SKIP the POST — the node never sends a ReportSeq it has not
// durably persisted (else a crash-then-restart could re-issue a lower seq the
// server already stored).
type ReportSeqCounter struct {
	path string

	mu            sync.Mutex
	lastInProcess int64
}

// NewReportSeqCounter constructs a counter persisting to path (a 0600 sidecar
// file, created on first Next).
func NewReportSeqCounter(path string) *ReportSeqCounter {
	return &ReportSeqCounter{path: path}
}

// Next returns the next strictly-increasing report sequence:
// max(lastPersisted, lastInProcess) + 1, persisted atomically before it is
// returned (§2.2). It is safe for concurrent use.
func (c *ReportSeqCounter) Next() (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	base := c.readPersisted()
	if c.lastInProcess > base {
		base = c.lastInProcess
	}
	next := base + 1
	if err := writeFileAtomic(c.path, []byte(strconv.FormatInt(next, 10))); err != nil {
		return 0, fmt.Errorf("orgclient.ReportSeqCounter.Next: persist: %w", err)
	}
	c.lastInProcess = next
	return next, nil
}

// readPersisted returns the last persisted value, or 0 for a missing/corrupt
// file (first install / lost state — §2.2 starts the counter at 1 via Next).
func (c *ReportSeqCounter) readPersisted() int64 {
	raw, err := os.ReadFile(c.path)
	if err != nil {
		return 0
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || v < 0 {
		return 0
	}
	return v
}

// ManagedMachineIdentity returns this host's org-salted machine fingerprint
// (W-4, the same identity BindMachine presents) when — and only when — the
// node is currently managed: a managed enrolment, or an enrolment whose org
// switched it to enterprise and whose grant this node holds (NodeManagedFor,
// operator rulings P-204 and P-205; the org server serves such a node as a
// managed one, so it names its machine like one). It mirrors BindMachine's
// fail-open tolerance exactly: no enrolment, a load error, an individual/BYO
// enrolment, or a machine-id resolution error all return "" rather than
// propagating an error, because a report() caller has no error path to hand
// this to (report() is a fire-and-forget P1 posture) and an empty identity is
// simply the correct wire value for an unmanaged node — MachineIdentity is
// `omitempty` on PolicyStateReport.
func (c *Client) ManagedMachineIdentity(ctx context.Context) string {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return ""
	}
	managed, err := NodeManagedFor(ctx, c.store, enr)
	if err != nil {
		return ""
	}
	return managedMachineIdentityOf(enr, managed)
}

// managedMachineIdentityOf is ManagedMachineIdentity over an enrolment the
// caller already holds and the managed answer it resolved (the leave notice
// runs after the enrolment generation is fenced, so it resolves managed
// before the fence and must not re-read the row). "" for nil, an unmanaged
// node, or a machine-id resolution error.
func managedMachineIdentityOf(enr *store.Enrolment, managed bool) string {
	if enr == nil || !managed {
		return ""
	}
	mid, err := machineid.ForOrg(enr.OrgID)
	if err != nil {
		return ""
	}
	return mid
}

// PostPolicyState ships ONE effective-policy-state snapshot to the org server's
// dedicated POST /api/agent/policy-ack, authenticated with the same timestamped
// Ed25519 signed-request proof as PushOnce (§4.4). The report's ReportSeq MUST
// already be set (> 0) by the caller from a ReportSeqCounter — the durability
// rule (persist-before-send, skip-on-persist-failure, §2.2) lives at the
// caller so the reporter can skip the POST cleanly (the sender holds no
// per-daemon state).
//
// Attribution is empty-on-wire (R2-S2): any populated OrgID/UserEmail on a row
// is STRIPPED before marshalling so the wire never carries client-supplied
// attribution (the server stamps it from the verified bearer claims).
//
// Compat (S8): a 404/405 returns ErrPolicyAckUnsupported so the caller latches
// the channel off for the daemon lifetime; 400 returns ErrPolicyAckRejected
// (the value guard refused this snapshot's shape — the v2 reporter's pre-v2
// server probe); 401/403 returns ErrAuthFailed; any other non-200 returns a
// (retryable) error. ReportSeq rides INSIDE the signed
// wire body, so a replayed report carries its original seq and loses the
// server's strict-`>` comparison.
func (c *Client) PostPolicyState(ctx context.Context, report orgcontract.PolicyStateReport) error {
	if report.ReportSeq <= 0 {
		return fmt.Errorf("orgclient.PostPolicyState: report_seq must be > 0, got %d", report.ReportSeq)
	}
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return fmt.Errorf("orgclient.PostPolicyState: %w", err)
	}
	if enr == nil {
		return ErrNotEnrolled
	}
	bearer, err := c.bearers.LoadBearer()
	if errors.Is(err, ErrNoSecret) {
		return ErrNotEnrolled
	}
	if err != nil {
		return fmt.Errorf("orgclient.PostPolicyState: load bearer: %w", err)
	}
	signKey, err := c.bearers.LoadAgentKey()
	if errors.Is(err, ErrNoSecret) {
		return ErrNotEnrolled
	}
	if err != nil {
		return fmt.Errorf("orgclient.PostPolicyState: load signing key: %w", err)
	}

	// Attribution empty-on-wire (R2-S2): strip any populated attribution so a
	// mis-populated row can never carry a client-supplied org/user across the
	// wire. The server stamps identity from the verified bearer claims.
	for i := range report.Rows {
		report.Rows[i].OrgID = ""
		report.Rows[i].UserEmail = ""
	}

	raw, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("orgclient.PostPolicyState: marshal: %w", err)
	}
	wire, err := gzipBytes(raw)
	if err != nil {
		return fmt.Errorf("orgclient.PostPolicyState: encode: %w", err)
	}

	ts := time.Now().Unix()
	sig := ed25519.Sign(signKey, orgcontract.PushSigningMessage(ts, wire))

	url := strings.TrimRight(enr.OrgServerURL, "/") + "/api/agent/policy-ack"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return fmt.Errorf("orgclient.PostPolicyState: new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set(orgcontract.HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(orgcontract.HeaderAgentSignature, base64.RawURLEncoding.EncodeToString(sig))

	resp, err := c.httpClient.Do(req)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		return fmt.Errorf("orgclient.PostPolicyState: post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusOK:
		return nil
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed:
		return ErrPolicyAckUnsupported
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("orgclient.PostPolicyState: %w", ErrAuthFailed)
	case resp.StatusCode == http.StatusBadRequest:
		return fmt.Errorf("orgclient.PostPolicyState: %w", ErrPolicyAckRejected)
	default:
		return fmt.Errorf("orgclient.PostPolicyState: server returned %d", resp.StatusCode)
	}
}
