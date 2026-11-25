package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgclient/gen"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// EnrolmentState is a read-only snapshot of the agent's enrolment for the CLI
// and dashboard. LastPush is nil when the agent has never pushed.
type EnrolmentState struct {
	Enrolled     bool
	OrgID        string
	OrgName      string
	OrgServerURL string
	UserID       string
	UserEmail    string
	EnrolledAt   string
	Backend      string // bearer-store backend: "keychain" | "file"
	LastPush     *store.PushLogEntry
	// PushPaused is non-nil ONLY while the oversized-batch circuit is open:
	// the composed rollup exceeded the accepted push limit, so the loop is
	// parked (oversizedBatchBackoff) and no telemetry is reaching the org
	// server. Nil is the normal case — pushes are running or simply idle.
	PushPaused *store.PushBreakerState
}

// clearIdentityBoundDocs is Enroll's fail-closed clearing of the signed
// documents bound to one enrolment identity, run after the durable generation
// advanced and before the replacement enrolment row is written. It walks
// identityBoundCaches (identitycaches.go): the budget on every enrolment, every
// other identity-bound cache when the org or the member changes (T-393). A
// first enrolment, or a re-enrolment as the same org and member, keeps them.
func (c *Client) clearIdentityBoundDocs(ctx context.Context, oldEnr *store.Enrolment, newOrgKey, newUserID string) error {
	changed := oldEnr != nil && (OrgKey(oldEnr.OrgServerURL, oldEnr.OrgID) != newOrgKey || oldEnr.UserID != newUserID)
	for _, ic := range identityBoundCaches {
		if ic.scope == clearOnIdentityChange && !changed {
			continue
		}
		if err := ic.clear(ctx, c, oldEnr); err != nil {
			return fmt.Errorf("clear prior %s: %w", ic.name, err)
		}
	}
	return nil
}

// Enroll exchanges a one-time compound token for a long-lived bearer. It
// generates a fresh Ed25519 keypair, posts the public half, and on success
// persists the bearer + private key (keychain), seeds the push cursor from the
// current high-water ids (so only post-enrolment activity is ever shared), and
// writes the org_enrolment row. The keychain and cursor are written BEFORE the
// enrolment row so that a concurrently-running push loop, which keys off the
// enrolment row, never observes an enrolled state with an un-seeded cursor.
//
// Enroll applies the default switch rule (EnrollWithOptions with zero
// options): rows still waiting for a DIFFERENT organization are sent to it
// first, and the switch is refused when they cannot be.
func (c *Client) Enroll(ctx context.Context, orgURL, token string) (*store.Enrolment, *GrantOffer, error) {
	enr, offer, _, err := c.EnrollWithOptions(ctx, orgURL, token, EnrollOptions{})
	return enr, offer, err
}

// EnrollOptions steers one enrolment.
type EnrollOptions struct {
	// Drain bounds the drain to the previous organization (R3-78) and,
	// with Drain.DropUnsent, lets a switch proceed when it did not finish.
	Drain DrainOptions
	// Attach, when its Grant is set, enrols with a one-step attach grant
	// (Getting started v2; internal/attachgrant) instead of a one-time
	// token: the token argument must then be empty.
	Attach AttachCredential
}

// AttachCredential is an attach grant and the signer of its device proof.
// Prove is injected by the caller (cmd/observer's cloud seam), so this
// package never links the cloud's device key or network lane.
type AttachCredential struct {
	// Grant is the attach grant the cloud's approved poll carried. A secret
	// for its ten minutes: never logged or printed.
	Grant string
	// Prove signs the device proof over the grant and the node key this
	// enrolment generates (base64url, as sent in agent_public_key).
	Prove func(grant, agentPublicKey string) (orgcontract.AttachProof, error)
}

// ErrAttachGrantNotAccepted is an enrolment refused because the server does
// not take attach grants (an older server, or one with no pinned key). The
// caller falls back to the organization's own sign-in.
var ErrAttachGrantNotAccepted = errors.New("orgclient: this organization does not accept a Connect approval")

// ErrAttachGrantRefused is an attach grant the server checked and refused;
// the error's text carries the server's plain reason.
var ErrAttachGrantRefused = errors.New("orgclient: the Connect approval was refused")

// EnrollWithOptions is Enroll with options, returning the drain report too.
//
// SWITCHING ORGANIZATIONS (R3-78, operator ruling D-22). The push cursor is
// per node, so the reseed below would silently drop every row captured for the
// previous organization but not yet pushed. When this machine is enrolled
// elsewhere, the rows still waiting are sent there FIRST, through PushOnce
// (DrainPending), with the previous enrolment's own credentials:
//
//   - a different server URL is decided BEFORE the code is exchanged, so a
//     refusal (*UnsentRowsError) leaves the one-time code unspent and the
//     machine enrolled where it was;
//   - the same server URL is the same organization on every server that hosts
//     one (the server's org is known only once the code is exchanged, the
//     code carries no org id), so a same-org re-enrolment is unchanged: no
//     drain, the cursor is reseeded as before;
//   - the same server URL answering for a DIFFERENT organization (a server
//     that hosts several, or one that was reinstalled) is only known after
//     the code is spent: the drain is still tried with the old credentials,
//     but if it does not finish the switch goes ahead (refusing would strand
//     the person with a spent code) and the report says what was left
//     (Dropped).
func (c *Client) EnrollWithOptions(ctx context.Context, orgURL, token string, opts EnrollOptions) (*store.Enrolment, *GrantOffer, DrainReport, error) {
	var drain DrainReport
	orgURL = strings.TrimRight(strings.TrimSpace(orgURL), "/")
	if orgURL == "" {
		return nil, nil, drain, errors.New("orgclient.Enroll: org server URL is required")
	}
	attach := opts.Attach
	if err := checkEnrolCredential(token, attach); err != nil {
		return nil, nil, drain, err
	}

	// Snapshot the OLD enrolment (nil on a fresh install) before it is
	// overwritten below, so a re-enrolment can tombstone the old identity's
	// policy-resource generation (plan §6.9) after the new one activates.
	oldEnr, _ := c.store.LoadEnrolment(ctx) //nolint:errcheck // best-effort snapshot; a read failure just skips old-identity cleanup

	// R3-78: a different server is a different organization, decided before
	// the code is spent. Send the old organization its rows first.
	if oldEnr != nil && NormalizeOrgURL(oldEnr.OrgServerURL) != orgURL {
		rep, derr := c.DrainBeforeSwitch(ctx, orgURL, opts.Drain)
		if derr != nil {
			return nil, nil, rep, fmt.Errorf("orgclient.Enroll: %w", derr)
		}
		drain = rep
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, drain, fmt.Errorf("orgclient.Enroll: keygen: %w", err)
	}

	gc, err := c.genClient(orgURL)
	if err != nil {
		return nil, nil, drain, fmt.Errorf("orgclient.Enroll: %w", err)
	}
	enrolReq, err := newEnrolRequest(token, pub, attach)
	if err != nil {
		return nil, nil, drain, err
	}
	resp, err := gc.EnrollAgentWithResponse(ctx, enrolReq)
	if err != nil {
		return nil, nil, drain, fmt.Errorf("orgclient.Enroll: post: %w", err)
	}
	if err := enrolAnswerError(resp, attach.Grant != ""); err != nil {
		return nil, nil, drain, err
	}
	er := resp.JSON200
	if er == nil || er.Bearer == "" {
		return nil, nil, drain, errors.New("orgclient.Enroll: server returned no bearer")
	}

	// R3-78: the same server answering for a different organization is known
	// only now, with the code spent. The old credentials are still in place,
	// so try to send the old organization its rows; the switch goes ahead
	// either way (see EnrollWithOptions) and the report says what was left.
	if oldEnr != nil && NormalizeOrgURL(oldEnr.OrgServerURL) == orgURL && oldEnr.OrgID != er.OrgID {
		drain = c.drainSameServerSwitch(ctx, opts.Drain)
	}

	// Seed the cursor + persist secrets BEFORE the enrolment row (see doc).
	if err := c.seedEnrolState(ctx, priv, er.Bearer); err != nil {
		return nil, nil, drain, err
	}

	enr := store.Enrolment{
		OrgID:        er.OrgID,
		OrgName:      er.OrgName,
		OrgServerURL: orgURL,
		UserID:       er.UserID,
		UserEmail:    er.UserEmail,
		EnrolledAt:   time.Now().UTC().Format(time.RFC3339),
		BearerKeyID:  c.cfg.KeychainID,
		// Tenancy rides on the enrol response at the same authenticated-TLS
		// trust level as OrgID/OrgName; empty is normalised to individual by
		// WriteEnrolment. Managed makes the govern resolver honour the
		// managed authorities carried in the SIGNED grant (ConsentMode set in
		// evaluateGrantOffer).
		Tenancy: er.Tenancy,
		// In memory only (not stored): picks the share-default row.
		OwnerManaged: er.OwnerManaged,
		// In memory only (not stored): words the SDK key hint (SR-9).
		SDKKeys: er.SDKKeys,
	}

	// Plane-A P0-5 (plan §6.9 / R6-B2 / R3-B2 / Codex B1): activate the new
	// identity's policy-resource generation BEFORE WriteEnrolment so a
	// concurrent FetchAndAccept never observes enrolled-without-generation
	// (missing gen ≡ ErrNotEnrolled). Fail-closed on bump/clear errors —
	// never leave enrolment visible without an active generation row. On
	// any re-enrolment (same or different org key), clear prior
	// policy-resource state so CAS cannot wedge on a stale generation
	// column (Codex B3).
	newOrgKey := OrgKey(orgURL, er.OrgID)
	if oldEnr != nil {
		oldOrgKey := OrgKey(oldEnr.OrgServerURL, oldEnr.OrgID)
		if oldOrgKey != newOrgKey {
			if _, err := c.store.BumpEnrolmentGeneration(ctx, oldOrgKey, true); err != nil {
				return nil, nil, drain, fmt.Errorf("orgclient.Enroll: tombstone old enrolment generation: %w", err)
			}
		}
		if err := c.store.ClearPolicyResourceState(ctx, oldOrgKey); err != nil {
			return nil, nil, drain, fmt.Errorf("orgclient.Enroll: clear old policy-resource state: %w", err)
		}
		c.clearPolicyResourceCacheTree(oldOrgKey)
	}
	generation, err := c.store.BumpEnrolmentGeneration(ctx, newOrgKey, false)
	if err != nil {
		return nil, nil, drain, fmt.Errorf("orgclient.Enroll: activate enrolment generation: %w", err)
	}
	if err := c.clearIdentityBoundDocs(ctx, oldEnr, newOrgKey, er.UserID); err != nil {
		return nil, nil, drain, fmt.Errorf("orgclient.Enroll: %w", err)
	}
	if err := c.store.WriteEnrolment(ctx, enr); err != nil {
		return nil, nil, drain, fmt.Errorf("orgclient.Enroll: write enrolment: %w", err)
	}
	if c.orgIdentityChangedSink != nil {
		c.orgIdentityChangedSink()
	}

	// Pin the org POLICY signing key when the server delivered one
	// (guard spec §14.2 — the pin every fetched bundle's embedded key
	// is checked against; guard_policy_state is the pin home, append-
	// only so rotations stay auditable and a re-enrol records the new
	// key). A pre-G13 server omits the field: the first bundle fetch
	// then pins trust-on-first-fetch instead. A malformed key is a
	// server bug, WARN-only — enrolment's primary job (the push
	// channel) must not fail over it; the fetch path will TOFU-pin.
	pinnedKeyHash := ""
	if er.OrgPolicyPublicKey != "" {
		if keyHash, perr := pinBase64Key(er.OrgPolicyPublicKey); perr != nil {
			c.logger.Warn("org policy key not pinned", "err", perr)
		} else if _, perr := c.store.RecordGuardPolicyState(ctx, store.GuardPolicyStateRow{
			Layer: "org",
			Path:  PolicyKeyPinPath(orgURL),
			// PROVENANCE (C1). Enroll is the only writer that stamps this:
			// the policy-bundle and policy-resource rails write the same row
			// by trust-on-first-fetch with an empty version, and a pin this
			// node did not receive over the enrolment channel must never be
			// promoted to the trust root.
			Version:     enrolmentPinProvenance,
			ContentHash: keyHash,
			LoadedAt:    time.Now().UTC(),
		}); perr != nil {
			c.logger.Warn("org policy key not pinned", "err", perr)
		} else {
			pinnedKeyHash = keyHash
			c.logger.Info("org policy signing key pinned at enrolment", "key_sha256", keyHash)
		}
		// R1(b)/(d): the hash pin above cannot VERIFY anything, so the key
		// ITSELF is persisted beside it (orgpin.go, OrgKeyMaterialSuffix) —
		// this is the trust root every other rail is resolved and
		// cross-checked against. Written unconditionally whenever the
		// response carries a key, so a re-enrol against a rotated key wins
		// over whatever a fetch rail pinned in between; an EMPTY response
		// field still leaves the previous row alone (a server that stopped
		// delivering a key is not a server that revoked one).
		if keyStd, perr := c.recordEnrolmentKeyMaterial(ctx, orgURL, er.OrgPolicyPublicKey); perr != nil {
			c.logger.Warn("org policy key material not stored (budget/pricing rails will fall back to the fetch-rail pins)", "err", perr)
		} else {
			c.logger.Info("org distribution key stored at enrolment",
				"key_sha256_prefix", prefix12(pinnedKeyHash), "key_prefix", prefix8(keyStd))
		}
	}

	// Admin-controlled Plane B (spec §2.3, adversarial review A3/A4): the
	// grant is evaluated ONLY AFTER the org policy key was actually pinned,
	// and it is RETURNED, never written here. Two reasons this ordering is
	// load-bearing:
	//
	//   - The pin write above is best-effort by design (enrolment's primary
	//     job, the push channel, must not fail over it). A grant accepted
	//     without a pin would be authority bound to nothing: the NEXT policy
	//     fetch would TOFU-pin whatever key it saw, which need not be the key
	//     the grant was signed under. So a missing/failed pin REFUSES the
	//     grant, loudly, instead of storing it unverified.
	//   - orgclient has no TTY, and by this point the bearer is saved, the
	//     enrolment is written and the generation is bumped — there is no
	//     honest place here to ask a human anything. cmd/observer/org.go owns
	//     the confirmation and the store write.
	offer := c.evaluateGrantOffer(er, orgURL, newOrgKey, generation, pinnedKeyHash)

	c.logger.Info("enrolled in org", "org", enr.OrgName, "org_id", enr.OrgID,
		"user_email", enr.UserEmail, "server", orgURL, "store", c.bearers.Backend())
	return &enr, offer, drain, nil
}

// enrolResponseError maps the enrol exchange's HTTP answer to the error
// EnrollWithOptions returns: nil on 200, ErrMemberNotActive for a pending
// member (the token is NOT spent), ErrAuthFailed for a refused token, and the
// server's own text for anything else.
// checkEnrolCredential refuses an enrolment with no credential, with both a
// token and an attach grant, or with a grant and no device proof signer.
func checkEnrolCredential(token string, attach AttachCredential) error {
	switch {
	case attach.Grant != "" && strings.TrimSpace(token) != "":
		return errors.New("orgclient.Enroll: pass an enrolment token or an attach grant, not both")
	case attach.Grant != "" && attach.Prove == nil:
		return errors.New("orgclient.Enroll: an attach grant needs this machine's device proof")
	case attach.Grant == "" && strings.TrimSpace(token) == "":
		return errors.New("orgclient.Enroll: enrolment token is required")
	}
	return nil
}

// newEnrolRequest builds the enrol request for the node key pub: the
// one-time token, or the attach grant with its device proof. The proof binds
// the grant to THIS enrolment's node key, so it is signed only once the key
// exists.
func newEnrolRequest(token string, pub ed25519.PublicKey, attach AttachCredential) (gen.EnrollRequest, error) {
	req := gen.EnrollRequest{
		OneTimeToken:   token,
		AgentPublicKey: base64.RawURLEncoding.EncodeToString(pub),
		// This node verifies, stores (agent migration 159) and re-verifies a
		// grant carrying a signed initial component set, so the server may
		// shape one for it (orgcontract.GrantForNode, modular packaging P4).
		Capabilities: []string{orgcontract.EnrolCapabilityInitialComponents},
	}
	if attach.Grant == "" {
		return req, nil
	}
	proof, err := attach.Prove(attach.Grant, req.AgentPublicKey)
	if err != nil {
		return gen.EnrollRequest{}, fmt.Errorf("orgclient.Enroll: sign the device proof: %w", err)
	}
	req.OneTimeToken = ""
	req.AttachGrant = attach.Grant
	req.AttachProof = &proof
	return req, nil
}

// enrolAnswerError is the error for an enrol answer: a grant-bearing
// request's refusals first (attachRefusals), then the token rail's.
func enrolAnswerError(resp *gen.EnrollAgentResponse, viaGrant bool) error {
	if viaGrant {
		if err := attachResponseError(resp.StatusCode(), resp.Body); err != nil {
			return err
		}
	}
	return enrolResponseError(resp)
}

// attachRefusal is one row of attachRefusals: a status and error code the
// server answers a grant with, and the error it becomes.
type attachRefusal struct {
	status int
	code   string // "" matches any code
	err    error
}

// attachRefusals classify a non-200 answer to a grant-bearing enrolment,
// top-down. An older server, which ignores the grant fields, answers 400
// for the missing one-time token: that reads as "not accepted" so the
// caller falls back to the organization's own sign-in.
var attachRefusals = []attachRefusal{
	{status: http.StatusForbidden, code: "attach_grant_not_accepted", err: ErrAttachGrantNotAccepted},
	{status: http.StatusBadRequest, code: "bad_request", err: ErrAttachGrantNotAccepted},
	{status: http.StatusForbidden, code: "attach_grant_refused", err: ErrAttachGrantRefused},
}

// attachResponseError is the error for a grant-bearing enrolment's answer,
// nil for a 200 or an answer attachRefusals does not name (enrolResponseError
// then judges it).
func attachResponseError(status int, body []byte) error {
	if status == http.StatusOK {
		return nil
	}
	var eb struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &eb)
	for _, r := range attachRefusals {
		if r.status == status && (r.code == "" || r.code == eb.Error) {
			msg := strings.TrimSpace(eb.Message)
			if msg == "" {
				return fmt.Errorf("orgclient.Enroll: %w", r.err)
			}
			return fmt.Errorf("orgclient.Enroll: %w: %s", r.err, msg)
		}
	}
	return nil
}

func enrolResponseError(resp *gen.EnrollAgentResponse) error {
	switch resp.StatusCode() {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// The server's pending-member path (handlers.go EnrollAgent) answers
		// 403 with {"error":"member_not_active", ...} and deliberately does
		// NOT burn the token: the account behind it just is not active yet,
		// and the same compound token will exchange successfully once it is.
		// That is a materially different outcome from "invalid or expired" —
		// telling the developer to go ask their admin for a NEW token here
		// would send them back for a replacement that fails the exact same
		// way, when running the exact same command again (after signing in)
		// is what actually works.
		var eb struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(resp.Body, &eb)
		if resp.StatusCode() == http.StatusForbidden && eb.Error == "member_not_active" {
			msg := eb.Message
			if msg == "" {
				msg = "your organization account is not active yet"
			}
			// WINNODE2 16d: say what to do, in order; "after you have
			// signed in" left a new member guessing where.
			return fmt.Errorf("orgclient.Enroll: %w: %s"+
				" (your enrolment token is still valid: open the set-password link from your invitation first,"+
				" set your password and sign in to the organization dashboard once, then run the same command again)",
				ErrMemberNotActive, msg)
		}
		return fmt.Errorf("orgclient.Enroll: %w: invalid or expired enrolment token"+
			" (the link may have expired or already been used; ask your admin for a new one, or use --idp)", ErrAuthFailed)
	default:
		return fmt.Errorf("orgclient.Enroll: server returned %d: %s", resp.StatusCode(), strings.TrimSpace(string(resp.Body)))
	}
}

// drainSameServerSwitch sends the previous organization its rows when the
// same server answered the enrolment for a different organization (R3-78).
// The code is already spent, so the switch goes ahead either way; an
// unfinished drain is reported as Dropped.
func (c *Client) drainSameServerSwitch(ctx context.Context, opts DrainOptions) DrainReport {
	rep, derr := c.DrainPending(ctx, opts)
	if derr != nil {
		c.logger.Warn("org switch: could not count the rows left for the previous organization", "err", derr)
	}
	if !rep.Complete {
		rep.Dropped = true
		c.logger.Warn("org switch on the same server: rows for the previous organization were not sent",
			"old_org_id", rep.OrgID, "remaining", rep.Remaining, "reason", rep.Reason)
	}
	return rep
}

// seedEnrolState seeds the push cursor at the current high-water ids, clears
// the previous run's last-push state, and saves the agent key and bearer: the
// enrolment steps that must land before the enrolment row is written.
func (c *Client) seedEnrolState(ctx context.Context, priv ed25519.PrivateKey, bearer string) error {
	maxIDs, err := c.store.CurrentMaxIDs(ctx)
	if err != nil {
		return fmt.Errorf("orgclient.Enroll: seed cursor: %w", err)
	}
	if err := c.store.SavePushCursor(ctx, maxIDs); err != nil {
		return fmt.Errorf("orgclient.Enroll: save cursor: %w", err)
	}
	// Wipe any prior-run last-push state so `observer org status` after
	// a re-enroll reports "(none yet)" instead of a stale timestamp.
	// N5 in docs/audits/teams-test-regression-2026-06-03.md.
	if err := c.store.ClearLastPushState(ctx); err != nil {
		return fmt.Errorf("orgclient.Enroll: clear last-push state: %w", err)
	}
	if err := c.bearers.SaveAgentKey(priv); err != nil {
		return fmt.Errorf("orgclient.Enroll: %w", err)
	}
	if err := c.bearers.SaveBearer(bearer); err != nil {
		return fmt.Errorf("orgclient.Enroll: %w", err)
	}
	return nil
}

// GrantOffer is a VERIFIED enrolment grant plus the identity facts the node
// needs in order to store it. Enroll returns one only when every gate passed;
// a nil offer means "enrolled, ungoverned", which is exactly today's
// behaviour and what every pre-governance server produces.
type GrantOffer struct {
	Grant        orgcontract.EnrolmentGrant
	OrgKey       string
	Generation   int64
	KeyPinSHA256 string
	ReceiptHash  string
	// Tenancy is the enrolment class from the enrol response (individual vs
	// managed). The node-side grant writer maps managed → govern
	// ConsentMode=managed, which is the signal the govern resolver branches
	// on to honour the managed-only authorities carried in this grant.
	Tenancy string
	// ConsentMode / ConsentActor are the ACP-P6c consent evidence, resolved
	// ONCE here so cmd/observer records a single answer rather than choosing
	// between two sources of it.
	//
	// PREFERENCE ORDER, and why it matters: the copy bound into the SIGNED
	// grant wins, because by the time this struct exists that copy has been
	// verified under the key this very enrolment pinned. The enrol response's
	// envelope fields are the fallback — they ride at plain authenticated-TLS
	// trust, so anything able to rewrite them could equally have rewritten
	// the tenancy. Preferring the signed copy means the strongest statement
	// available is the one the node writes down and shows an auditor.
	//
	// Both empty is the token rail, where the node resolves its consent mode
	// from Tenancy exactly as it did before P6c.
	ConsentMode  string
	ConsentActor string
	// OwnerManaged is EnrollResponse.OwnerManaged: the organization asking
	// is the developer's own (a personal organization, managed by its
	// owner). It only changes the consent screen's words.
	OwnerManaged bool
}

// evaluateGrantOffer runs the accept gates for an offered grant. EVERY
// refusal is logged with a named reason (adversarial review A3: a silently
// skipped grant leaves the admin staring at a permanently ungoverned node
// with no diagnosis) and returns nil, which enrols the node ungoverned.
func (c *Client) evaluateGrantOffer(er *orgcontract.EnrollResponse, orgURL, orgKey string, generation int64, pinnedKeyHash string) *GrantOffer {
	if er.Grant == nil {
		return nil
	}
	g := *er.Grant
	switch {
	case er.OrgPolicyPublicKey == "":
		c.logger.Warn("enrolment grant REFUSED: the server offered governance but sent no org policy signing key, so the grant cannot be bound to any key - enrolling ungoverned")
		return nil
	case pinnedKeyHash == "":
		c.logger.Warn("enrolment grant REFUSED: the org policy signing key could not be pinned, so a grant would be authority bound to nothing - enrolling ungoverned")
		return nil
	case g.KeyPinSHA256 == "" || g.KeyPinSHA256 != pinnedKeyHash:
		c.logger.Warn("enrolment grant REFUSED: the grant names a different org policy signing key than the one this enrolment pinned - enrolling ungoverned",
			"grant_key_sha256", g.KeyPinSHA256, "pinned_key_sha256", pinnedKeyHash)
		return nil
	case g.OrgID != er.OrgID:
		c.logger.Warn("enrolment grant REFUSED: the grant names a different org than the enrolment - enrolling ungoverned",
			"grant_org_id", g.OrgID, "enrolment_org_id", er.OrgID)
		return nil
	case strings.TrimRight(strings.TrimSpace(g.OrgServerURL), "/") != orgURL:
		c.logger.Warn("enrolment grant REFUSED: the grant names a different org server than the one being enrolled with - enrolling ungoverned",
			"grant_server", g.OrgServerURL, "enrolment_server", orgURL)
		return nil
	}
	pubRaw, derr := base64.RawURLEncoding.DecodeString(er.OrgPolicyPublicKey)
	if derr != nil {
		c.logger.Warn("enrolment grant REFUSED: org policy public key did not decode - enrolling ungoverned", "err", derr)
		return nil
	}
	if verr := orgcontract.VerifyEnrolmentGrant(g, ed25519.PublicKey(pubRaw)); verr != nil {
		c.logger.Warn("enrolment grant REFUSED: signature did not verify under the pinned org policy key - enrolling ungoverned", "err", verr)
		return nil
	}
	if g.ExpiresAt != "" {
		exp, perr := time.Parse(time.RFC3339, g.ExpiresAt)
		if perr != nil {
			c.logger.Warn("enrolment grant REFUSED: expires_at is not RFC3339 - enrolling ungoverned", "expires_at", g.ExpiresAt)
			return nil
		}
		if !time.Now().UTC().Before(exp) {
			c.logger.Warn("enrolment grant REFUSED: it is already expired - enrolling ungoverned", "expires_at", g.ExpiresAt)
			return nil
		}
	}
	consentMode, consentActor := g.ConsentMode, g.ConsentActor
	if consentMode == "" {
		// No evidence inside the verified grant: fall back to the response
		// envelope. See GrantOffer.ConsentMode for why this order and not the
		// other one.
		consentMode, consentActor = er.ConsentMode, er.ConsentActor
	}
	return &GrantOffer{
		Grant:        g,
		OrgKey:       orgKey,
		Generation:   generation,
		KeyPinSHA256: pinnedKeyHash,
		ReceiptHash:  orgcontract.EnrolmentGrantReceiptHash(g),
		Tenancy:      er.Tenancy,
		ConsentMode:  consentMode,
		ConsentActor: consentActor,
		OwnerManaged: er.OwnerManaged,
	}
}

// clearAgentAccessKeys removes the per-device agent-access key on unenrol
// (ledger AA-5): the injected slot when set, and the slot beside the bearer
// store's own location (keychain record AND 0600 file) when the bearer store
// is one of the real backends - so an unenrolled node keeps no agent-access
// key whether or not the slot was wired. Both clears are idempotent.
func (c *Client) clearAgentAccessKeys() error {
	var errs []error
	if c.agentAccessKeys != nil {
		if err := c.agentAccessKeys.ClearAgentAccessKey(); err != nil {
			errs = append(errs, err)
		}
	}
	if cl, ok := c.bearers.(agentAccessKeyClearer); ok {
		if err := cl.agentAccessKeys().ClearAgentAccessKey(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Unenroll leaves the organization: it walks the structured unenrol table
// (unenrol.go, T-718) - fence the enrolment epoch, retire every enforcement
// artifact the enrolment conferred, tell the organization (best effort), then
// retire the identity and the credentials. Absent state is not an error
// (idempotent). UnenrollWithReport returns the per-step outcome.
func (c *Client) Unenroll(ctx context.Context) error {
	_, err := c.UnenrollWithReport(ctx)
	return err
}

// Status returns a snapshot of the agent's enrolment for the CLI / dashboard.
func (c *Client) Status(ctx context.Context) (EnrolmentState, error) {
	st := EnrolmentState{Backend: c.bearers.Backend()}
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return st, fmt.Errorf("orgclient.Status: %w", err)
	}
	if enr == nil {
		return st, nil
	}
	st.Enrolled = true
	st.OrgID, st.OrgName, st.OrgServerURL = enr.OrgID, enr.OrgName, enr.OrgServerURL
	st.UserID, st.UserEmail, st.EnrolledAt = enr.UserID, enr.UserEmail, enr.EnrolledAt
	last, err := c.store.LastPushLog(ctx)
	if err != nil {
		return st, fmt.Errorf("orgclient.Status: %w", err)
	}
	st.LastPush = last
	// Surface an OPEN oversized-batch circuit. A parked push loop is otherwise
	// invisible except as a 'failed' row in org_push_log, which reads like any
	// other transient failure rather than "telemetry has stopped for an hour".
	paused, err := c.store.LoadPushBreaker(ctx)
	if err != nil {
		return st, fmt.Errorf("orgclient.Status: %w", err)
	}
	st.PushPaused = paused
	return st, nil
}
