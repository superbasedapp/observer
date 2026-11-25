package store

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/connectflow"
	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// connect.go is the store seam of the Getting started v2 connect flow (cloud
// 0150, and 0159 for the SDK quickstart's sdk_key purpose;
// docs/plans/onboarding-v2-connect-flow.md; docs/security.md CONNECT-1,
// SDKQS-1): the only SQL over connect_requests, connect_poll_replay and
// connect_consents. The decisions (field rules, status machine, delivery,
// share level, disclosure) are internal/cloudserver/connectflow's; this file
// stores them under row locks.
//
// connect_requests and connect_poll_replay are system tables (a request is
// created pre-auth), so creating, reading and polling run in WithSystem. A
// request gains an account only when a signed-in browser resolves it; that
// and the sign-in delivery run in WithAccount, so the consent receipt
// (connect_consents, a tenant table), the device approval and the device
// credential are written under the account's row-level security.

// Connect flow errors.
var (
	// ErrConnectNotPending: the request is approved, declined or expired.
	ErrConnectNotPending = errors.New("cloudserver/store: connect request is not pending")
	// ErrConnectSignInDelivered: the sign-in was already handed over as often,
	// or as late, as allowed.
	ErrConnectSignInDelivered = errors.New("cloudserver/store: connect sign-in already delivered")
	// ErrConnectTargetUnavailable: the chosen dashboard is not one the
	// account can connect a machine to now.
	ErrConnectTargetUnavailable = errors.New("cloudserver/store: connect target unavailable")
	// ErrConnectDisclosureStale: the disclosure the browser showed is not the
	// one the server would show for that dashboard now.
	ErrConnectDisclosureStale = errors.New("cloudserver/store: connect disclosure changed")
	// ErrConnectAnswerNotAllowed: the request's purpose does not take that
	// browser answer (an SDK key has no "Not now").
	ErrConnectAnswerNotAllowed = errors.New("cloudserver/store: connect answer not allowed for this request")
	// ErrConnectKeyGrantDelivered: the key grant was already handed over as
	// often, or as late, as allowed.
	ErrConnectKeyGrantDelivered = errors.New("cloudserver/store: connect key grant already delivered")
	// ErrConnectKeyGrantWindowClosed: the delivery window closed before any
	// key grant was handed over.
	ErrConnectKeyGrantWindowClosed = errors.New("cloudserver/store: connect key grant window closed")
)

// connectCodeAttempts bounds how many fresh user codes a create tries when a
// minted code collides with a live one.
const connectCodeAttempts = 5

// connectSweepBatch bounds one opportunistic sweep.
const connectSweepBatch = 200

// ConnectTarget is the dashboard an approved request connects to.
type ConnectTarget struct {
	OrgID       string
	Slug        string
	Kind        OrgKind
	DisplayName string
	ShareLevel  connectflow.ShareLevel
}

// ConnectRequest is one connect_requests row. Status is the STORED status;
// callers read connectflow.EffectiveStatus for the wire.
type ConnectRequest struct {
	RequestID string
	UserCode  string
	// Purpose is what the request is for (0159; every older row is a
	// machine). It never changes after create.
	Purpose connectflow.Purpose
	// Auth is how its polls prove themselves (connectflow.AuthFor(Purpose)
	// at create, stored).
	Auth            connectflow.AuthKind
	PublicKey       []byte // a machine's device key; nil for an SDK request
	Thumbprint      string
	MachineName     string
	OS              string
	Arch            string
	ObserverVersion string // "" for an SDK request
	TargetHint      string
	OriginNetwork   string
	// DeviceCodeHash is the hex SHA-256 of an SDK request's device code.
	DeviceCodeHash string
	// RedeemHash, Client, ClientVersion and ProjectName are an SDK request's
	// create fields ("" for a machine).
	RedeemHash    string
	Client        string
	ClientVersion string
	ProjectName   string
	Status        connectflow.Status
	CreatedAt     time.Time
	ExpiresAt     time.Time
	ResolvedAt    time.Time
	AccountID     string
	Target        *ConnectTarget
	ConsentID     string
	// Deliveries counts the polls that received the request's answer (the
	// sign-in, or the key grant).
	Deliveries int
}

// connectColumns is the select list scanConnectRequest reads.
const connectColumns = `request_id::text, coalesce(user_code, ''), device_public_key, coalesce(device_thumbprint, ''),
	machine_name, os, arch, coalesce(observer_version, ''), target_hint, origin_network, status,
	created_at, expires_at, resolved_at, coalesce(account_id::text, ''),
	coalesce(target_org_id::text, ''), coalesce(target_slug, ''), coalesce(target_kind, ''),
	coalesce(target_name, ''), coalesce(share_level, ''), coalesce(consent_id::text, ''), deliveries,
	purpose, auth_kind, coalesce(device_code_hash, ''), coalesce(redeem_hash, ''),
	coalesce(client, ''), coalesce(client_version, ''), coalesce(project_name, '')`

func scanConnectRequest(row pgx.Row) (ConnectRequest, error) {
	var (
		c                                 ConnectRequest
		status, purpose, auth             string
		resolved                          *time.Time
		orgID, slug, kind, name, shareLvl string
	)
	err := row.Scan(&c.RequestID, &c.UserCode, &c.PublicKey, &c.Thumbprint,
		&c.MachineName, &c.OS, &c.Arch, &c.ObserverVersion, &c.TargetHint, &c.OriginNetwork, &status,
		&c.CreatedAt, &c.ExpiresAt, &resolved, &c.AccountID,
		&orgID, &slug, &kind, &name, &shareLvl, &c.ConsentID, &c.Deliveries,
		&purpose, &auth, &c.DeviceCodeHash, &c.RedeemHash,
		&c.Client, &c.ClientVersion, &c.ProjectName)
	if err != nil {
		return ConnectRequest{}, err
	}
	c.Status = connectflow.Status(status)
	c.Purpose, c.Auth = connectflow.Purpose(purpose), connectflow.AuthKind(auth)
	if resolved != nil {
		c.ResolvedAt = resolved.UTC()
	}
	c.CreatedAt, c.ExpiresAt = c.CreatedAt.UTC(), c.ExpiresAt.UTC()
	if orgID != "" {
		c.Target = &ConnectTarget{
			OrgID: orgID, Slug: slug, Kind: OrgKind(kind), DisplayName: name,
			ShareLevel: connectflow.ShareLevel(shareLvl),
		}
	}
	return c, nil
}

// CreateConnectInput is what POST /v1/connect/requests stores.
type CreateConnectInput struct {
	Request connectflow.Create
	// OriginNetwork is the requester's masked network (connectflow.NetworkPrefix).
	OriginNetwork string
	// DeviceCodeHash is the hash of the device code the create answers
	// (connectflow.NewDeviceCode); required exactly when the purpose polls
	// with a device code, and the raw code never reaches the store.
	DeviceCodeHash string
	Now            time.Time
	// Random is the user-code entropy source; nil means crypto/rand.
	Random io.Reader
}

// nullIfEmpty maps "" to SQL NULL (an optional column of the other purpose).
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// CreateConnectRequest stores a new pending request with a fresh user code,
// valid for connectflow.RequestTTL. A minted code that collides with a live
// one is replaced (the insert does nothing on conflict). It also runs one
// bounded sweep of ended requests first.
func (s *Store) CreateConnectRequest(ctx context.Context, in CreateConnectInput) (ConnectRequest, error) {
	now := nowOr(in.Now)
	rnd := in.Random
	if rnd == nil {
		rnd = rand.Reader
	}
	purpose := in.Request.Purpose
	if purpose == "" {
		purpose = connectflow.PurposeMachine
	}
	auth, ok := connectflow.AuthFor(purpose)
	if !ok {
		return ConnectRequest{}, fmt.Errorf("cloudserver/store.CreateConnectRequest: unknown purpose %q", purpose)
	}
	if (auth == connectflow.AuthDeviceCode) != (in.DeviceCodeHash != "") {
		return ConnectRequest{}, errors.New("cloudserver/store.CreateConnectRequest: a device code hash is required exactly for a device-code request")
	}
	// A machine carries its device key and thumbprint; an SDK request has
	// neither (both columns NULL, 0159's purpose CHECK).
	var pubKey, thumb any
	if len(in.Request.PublicKey) > 0 {
		pubKey, thumb = []byte(in.Request.PublicKey), Thumbprint(in.Request.PublicKey)
	}
	var out ConnectRequest
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := sweepConnectTx(ctx, tx, now); err != nil {
			return err
		}
		for attempt := 0; attempt < connectCodeAttempts; attempt++ {
			code, err := connectflow.NewUserCode(rnd)
			if err != nil {
				return err
			}
			c, err := scanConnectRequest(tx.QueryRow(ctx,
				`INSERT INTO connect_requests
				   (user_code, device_public_key, device_thumbprint, machine_name, os, arch,
				    observer_version, target_hint, origin_network, created_at, expires_at,
				    purpose, auth_kind, device_code_hash, redeem_hash, client, client_version, project_name)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
				 ON CONFLICT (user_code) DO NOTHING
				 RETURNING `+connectColumns,
				code, pubKey, thumb,
				in.Request.MachineName, in.Request.OS, in.Request.Arch, nullIfEmpty(in.Request.ObserverVersion),
				in.Request.TargetHint, in.OriginNetwork, now, now.Add(connectflow.RequestTTL),
				string(purpose), string(auth), nullIfEmpty(in.DeviceCodeHash), nullIfEmpty(in.Request.RedeemHash),
				nullIfEmpty(in.Request.Client), nullIfEmpty(in.Request.ClientVersion), nullIfEmpty(in.Request.ProjectName)))
			if errors.Is(err, pgx.ErrNoRows) {
				continue // the code is taken by another live request
			}
			if err != nil {
				return fmt.Errorf("insert: %w", err)
			}
			out = c
			return nil
		}
		return errors.New("no free user code")
	})
	if err != nil {
		return ConnectRequest{}, fmt.Errorf("cloudserver/store.CreateConnectRequest: %w", err)
	}
	return out, nil
}

// sweepConnectTx deletes one bounded batch of ended requests (a pending one a
// day past its expiry, a declined one a day after it was declined, an approved
// one connectflow.ApprovedRetention after approval), clears the network
// prefix and hint of approvals older than a day, and drops expired poll
// proofs.
func sweepConnectTx(ctx context.Context, tx pgx.Tx, now time.Time) error {
	ended := now.Add(-connectflow.EndedRetention)
	if _, err := tx.Exec(ctx,
		`DELETE FROM connect_requests WHERE request_id IN (
		    SELECT request_id FROM connect_requests
		     WHERE (status = 'pending'  AND expires_at  < $1)
		        OR (status = 'declined' AND resolved_at < $1)
		        OR (status = 'approved' AND resolved_at < $2)
		     LIMIT $3)`,
		ended, now.Add(-connectflow.ApprovedRetention), connectSweepBatch); err != nil {
		return fmt.Errorf("sweep requests: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE connect_requests SET origin_network = '', target_hint = ''
		  WHERE request_id IN (
		    SELECT request_id FROM connect_requests
		     WHERE status = 'approved' AND resolved_at < $1 AND (origin_network <> '' OR target_hint <> '')
		     LIMIT $2)`,
		ended, connectSweepBatch); err != nil {
		return fmt.Errorf("sweep networks: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM connect_poll_replay WHERE ctid IN (
		    SELECT ctid FROM connect_poll_replay WHERE expires_at < $1 LIMIT $2)`,
		now, connectSweepBatch); err != nil {
		return fmt.Errorf("sweep poll proofs: %w", err)
	}
	return nil
}

// ConnectRequestByID reads one request (any status), or ErrNotFound.
func (s *Store) ConnectRequestByID(ctx context.Context, requestID string) (ConnectRequest, error) {
	var out ConnectRequest
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		c, err := scanConnectRequest(tx.QueryRow(ctx,
			`SELECT `+connectColumns+` FROM connect_requests WHERE request_id = $1::uuid`, requestID))
		if errors.Is(err, pgx.ErrNoRows) || isInvalidUUIDErr(err) {
			return ErrNotFound
		}
		out = c
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return ConnectRequest{}, ErrNotFound
	}
	if err != nil {
		return ConnectRequest{}, fmt.Errorf("cloudserver/store.ConnectRequestByID: %w", err)
	}
	return out, nil
}

// RecordConnectPollJTI records one poll proof's jti for requestID and reports
// whether it was already used (a replay).
func (s *Store) RecordConnectPollJTI(ctx context.Context, requestID, jti string, expiresAt time.Time) (replay bool, err error) {
	err = s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`INSERT INTO connect_poll_replay (request_id, jti, expires_at)
			 VALUES ($1::uuid, $2, $3) ON CONFLICT (request_id, jti) DO NOTHING`,
			requestID, jti, expiresAt)
		if e != nil {
			return fmt.Errorf("record jti: %w", e)
		}
		replay = ct.RowsAffected() == 0
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("cloudserver/store.RecordConnectPollJTI: %w", err)
	}
	return replay, nil
}

// DeliverConnectSignIn hands an approved request's sign-in to its machine:
// under a row lock it applies connectflow.DeliveryDecision, revokes the token
// a previous delivery minted, and mints a fresh one through
// registerDeviceAndMintTokenTx (the same owner as Exchange). It returns the
// request as stored after the delivery, and the sign-in. A request that is
// not approved returns its row and a nil sign-in; one past its deliveries
// returns ErrConnectSignInDelivered.
func (s *Store) DeliverConnectSignIn(ctx context.Context, requestID, label string, ttl time.Duration, now time.Time) (ConnectRequest, *ExchangeResult, error) {
	now = nowOr(now)
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}
	cur, err := s.ConnectRequestByID(ctx, requestID)
	if err != nil {
		return ConnectRequest{}, nil, err
	}
	if answer, _ := connectflow.AnswerFor(cur.Purpose); answer != connectflow.AnswerSignIn {
		// Never a cloud sign-in for a request whose answer is something else
		// (an SDK key request: no cloud API token reaches an SDK).
		return cur, nil, nil
	}
	if cur.Status != connectflow.StatusApproved || cur.AccountID == "" {
		return cur, nil, nil
	}
	rawToken, err := randToken()
	if err != nil {
		return ConnectRequest{}, nil, fmt.Errorf("cloudserver/store.DeliverConnectSignIn: rand token: %w", err)
	}
	var (
		out ConnectRequest
		res *ExchangeResult
	)
	err = s.WithAccount(ctx, cur.AccountID, func(ctx context.Context, tx pgx.Tx) error {
		c, e := scanConnectRequest(tx.QueryRow(ctx,
			`SELECT `+connectColumns+` FROM connect_requests
			  WHERE request_id = $1::uuid AND account_id = $2::uuid FOR UPDATE`, requestID, cur.AccountID))
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return e
		}
		out = c
		switch connectflow.DeliveryDecision(connectflow.DeliveryFacts{
			Status: c.Status, Deliveries: c.Deliveries, ApprovedAt: c.ResolvedAt, Now: now,
		}) {
		case connectflow.DeliverNone:
			return nil
		case connectflow.DeliverExhausted:
			return ErrConnectSignInDelivered
		}
		var status string
		if e := tx.QueryRow(ctx, `SELECT status FROM accounts WHERE account_id = $1::uuid`, c.AccountID).Scan(&status); e != nil {
			return fmt.Errorf("read account status: %w", e)
		}
		if status != accountStatusActive {
			return ErrAccountSuspended
		}
		// One live token per request: a re-delivery revokes the last one.
		if _, e := tx.Exec(ctx,
			`UPDATE api_tokens SET revoked_at = $3
			  WHERE account_id = $1::uuid AND revoked_at IS NULL
			    AND id = (SELECT delivered_token FROM connect_requests WHERE request_id = $2::uuid)`,
			c.AccountID, requestID, now); e != nil {
			return fmt.Errorf("revoke previous delivery: %w", e)
		}
		r, e := registerDeviceAndMintTokenTx(ctx, tx, c.AccountID, c.PublicKey, label, ttl, now, rawToken)
		if e != nil {
			return e
		}
		if _, e := tx.Exec(ctx,
			`UPDATE connect_requests
			    SET deliveries = deliveries + 1,
			        delivered_token = (SELECT id FROM api_tokens WHERE token_hash = $2)
			  WHERE request_id = $1::uuid`,
			requestID, hashSecret(rawToken)); e != nil {
			return fmt.Errorf("record delivery: %w", e)
		}
		out.Deliveries++
		res = &r
		return nil
	})
	if errors.Is(err, ErrConnectSignInDelivered) || errors.Is(err, ErrNotFound) ||
		errors.Is(err, ErrDeviceRevoked) || errors.Is(err, ErrDeviceApprovalRequired) || errors.Is(err, ErrAccountSuspended) {
		return out, nil, err
	}
	if err != nil {
		return ConnectRequest{}, nil, fmt.Errorf("cloudserver/store.DeliverConnectSignIn: %w", err)
	}
	return out, res, nil
}

// LookupConnectCode resolves a normalized user code to its pending,
// unexpired request id, or ErrNotFound.
func (s *Store) LookupConnectCode(ctx context.Context, code string, now time.Time) (string, error) {
	now = nowOr(now)
	var id string
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT request_id::text FROM connect_requests
			  WHERE user_code = $1 AND status = 'pending' AND expires_at > $2`, code, now).Scan(&id)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return e
	})
	if errors.Is(err, ErrNotFound) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("cloudserver/store.LookupConnectCode: %w", err)
	}
	return id, nil
}

// ResolveConnectInput is a signed-in browser's answer to a request.
type ResolveConnectInput struct {
	AccountID string
	SessionID string
	RequestID string
	Event     connectflow.Event
	// TargetOrgID is the chosen dashboard (EventConnect only).
	TargetOrgID string
	// DisclosureVersion and DisclosureSHA256 are what the browser showed
	// (EventConnect only); they must equal what the server renders now.
	DisclosureVersion string
	DisclosureSHA256  string
	Now               time.Time
}

// connectTargetAllowed reports whether a machine may be connected to org now:
// an active team or personal dashboard, or a personal dashboard still being
// set up (the machine waits for it).
func connectTargetAllowed(o MyOrg) bool {
	switch {
	case o.Status == platformcontract.StateActive:
		return o.Kind == OrgPersonal || o.Kind == OrgTeam
	case o.Status == platformcontract.StateProvisioning:
		return o.Kind == OrgPersonal
	default:
		return false
	}
}

// ResolveConnectRequest applies a browser's Connect, Not now or decline to a
// pending request, under a row lock, through connectflow.Transition. Connect
// checks the account is a member of the dashboard, derives the share level
// from its kind, checks the browser showed the current disclosure, and writes
// the consent receipt. Connect and Not now also write the device approval when
// the account holds a passkey (the caller has applied the passkey rule to the
// session), so the delivery may register the new device. It returns the
// request as stored after the change.
func (s *Store) ResolveConnectRequest(ctx context.Context, in ResolveConnectInput) (ConnectRequest, error) {
	now := nowOr(in.Now)
	var out ConnectRequest
	err := s.WithAccount(ctx, in.AccountID, func(ctx context.Context, tx pgx.Tx) error {
		c, e := scanConnectRequest(tx.QueryRow(ctx,
			`SELECT `+connectColumns+` FROM connect_requests WHERE request_id = $1::uuid FOR UPDATE`, in.RequestID))
		if errors.Is(e, pgx.ErrNoRows) || isInvalidUUIDErr(e) {
			return ErrNotFound
		}
		if e != nil {
			return e
		}
		to, withTarget, ok := connectflow.Transition(connectflow.EffectiveStatus(c.Status, c.ExpiresAt, now), in.Event)
		if !ok {
			return ErrConnectNotPending
		}
		if !connectflow.Allows(c.Purpose, in.Event) {
			return ErrConnectAnswerNotAllowed
		}
		var (
			target    *ConnectTarget
			consentID string
		)
		if withTarget {
			o, e := getMyOrgTx(ctx, tx, in.TargetOrgID)
			if errors.Is(e, ErrNotFound) {
				return ErrConnectTargetUnavailable
			}
			if e != nil {
				return fmt.Errorf("read target: %w", e)
			}
			if !connectTargetAllowed(o) {
				return ErrConnectTargetUnavailable
			}
			// The disclosure is the purpose's (a machine's share level, or
			// the SDK key's), and its share level is the kind's.
			d, ok := connectflow.DisclosureFor(c.Purpose, connectflow.DashboardKind(o.Kind), o.DisplayName)
			if !ok {
				return ErrConnectTargetUnavailable
			}
			level := d.Level
			if d.Version != in.DisclosureVersion || d.SHA256 != in.DisclosureSHA256 {
				return ErrConnectDisclosureStale
			}
			if e := tx.QueryRow(ctx,
				`INSERT INTO connect_consents
				   (account_id, request_id, org_id, share_level, disclosure_version, disclosure_sha256, created_at)
				 VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7) RETURNING consent_id::text`,
				in.AccountID, c.RequestID, o.OrgID, string(level), d.Version, d.SHA256, now).Scan(&consentID); e != nil {
				return fmt.Errorf("insert consent: %w", e)
			}
			target = &ConnectTarget{OrgID: o.OrgID, Slug: o.Slug, Kind: o.Kind, DisplayName: o.DisplayName, ShareLevel: level}
		}
		// A machine's approval doubles as its device approval; an SDK key
		// request registers no device (its answer is a key grant).
		if answer, _ := connectflow.AnswerFor(c.Purpose); to == connectflow.StatusApproved && answer == connectflow.AnswerSignIn {
			passkey, e := accountHoldsPasskeyTx(ctx, tx, in.AccountID)
			if e != nil {
				return e
			}
			if passkey {
				if e := approveDeviceTx(ctx, tx, in.AccountID, in.SessionID, c.Thumbprint, now, now.Add(connectflow.DeliveryWindow)); e != nil {
					return fmt.Errorf("approve device: %w", e)
				}
			}
		}
		var orgID, slug, kind, name, level, consent any
		if target != nil {
			orgID, slug, kind, name, level, consent = target.OrgID, target.Slug, string(target.Kind), target.DisplayName, string(target.ShareLevel), consentID
		}
		r, e := scanConnectRequest(tx.QueryRow(ctx,
			`UPDATE connect_requests
			    SET status = $2, user_code = NULL, resolved_at = $3, account_id = $4::uuid,
			        approver_session = $5::uuid, target_org_id = $6::uuid, target_slug = $7,
			        target_kind = $8, target_name = $9, share_level = $10, consent_id = $11::uuid
			  WHERE request_id = $1::uuid
			  RETURNING `+connectColumns,
			c.RequestID, string(to), now, in.AccountID, in.SessionID, orgID, slug, kind, name, level, consent))
		if e != nil {
			return fmt.Errorf("resolve: %w", e)
		}
		out = r
		return nil
	})
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrConnectNotPending),
		errors.Is(err, ErrConnectTargetUnavailable), errors.Is(err, ErrConnectDisclosureStale),
		errors.Is(err, ErrConnectAnswerNotAllowed):
		return ConnectRequest{}, err
	case err != nil:
		return ConnectRequest{}, fmt.Errorf("cloudserver/store.ResolveConnectRequest: %w", err)
	}
	return out, nil
}

// ConnectHome is the account home's live state.
type ConnectHome struct {
	// Devices is the account's unrevoked device registrations (signed-in
	// machines).
	Devices int
	// Recent is the account's approvals since the cut-off, newest first.
	Recent []ConnectRequest
}

// ConnectHomeState reads the account's signed-in machine count and its
// machine approvals at or after since (at most connectflow.RecentLimit). An
// SDK key approval connects no machine, so it is not listed.
func (s *Store) ConnectHomeState(ctx context.Context, accountID string, since time.Time) (ConnectHome, error) {
	var out ConnectHome
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		if e := tx.QueryRow(ctx,
			`SELECT count(*) FROM device_registrations WHERE account_id = $1::uuid AND revoked_at IS NULL`,
			accountID).Scan(&out.Devices); e != nil {
			return fmt.Errorf("count devices: %w", e)
		}
		rows, e := tx.Query(ctx,
			`SELECT `+connectColumns+` FROM connect_requests
			  WHERE account_id = $1::uuid AND status = 'approved' AND resolved_at >= $2
			    AND purpose = 'machine'
			  ORDER BY resolved_at DESC LIMIT $3`,
			accountID, since, connectflow.RecentLimit)
		if e != nil {
			return fmt.Errorf("recent: %w", e)
		}
		defer rows.Close()
		for rows.Next() {
			c, e := scanConnectRequest(rows)
			if e != nil {
				return e
			}
			out.Recent = append(out.Recent, c)
		}
		return rows.Err()
	})
	if err != nil {
		return ConnectHome{}, fmt.Errorf("cloudserver/store.ConnectHomeState: %w", err)
	}
	return out, nil
}

// KeyGrantDelivery is the outcome of one SDK key poll's delivery step.
type KeyGrantDelivery struct {
	// Request is the request as stored after the step.
	Request ConnectRequest
	// Decision is connectflow.KeyGrantDecision's outcome for this poll:
	// KeyGrantDeliver means this poll was counted and must hand the grant
	// over.
	Decision connectflow.KeyGrantPoll
}

// DeliverConnectKeyGrant decides, under the request's row lock, whether this
// poll of an approved SDK key request hands the key grant over
// (connectflow.KeyGrantDecision), and counts the delivery when it does.
// targetReady is the caller's reading of the chosen dashboard's state; a
// dashboard that is not ready is waited for without using a delivery. A
// request past its deliveries returns ErrConnectKeyGrantDelivered. The grant
// itself is signed by the caller (the store never holds the key). A request
// whose window closed before any delivery returns
// ErrConnectKeyGrantWindowClosed.
func (s *Store) DeliverConnectKeyGrant(ctx context.Context, requestID string, targetReady bool, now time.Time) (KeyGrantDelivery, error) {
	now = nowOr(now)
	cur, err := s.ConnectRequestByID(ctx, requestID)
	if err != nil {
		return KeyGrantDelivery{}, err
	}
	if answer, _ := connectflow.AnswerFor(cur.Purpose); answer != connectflow.AnswerKeyGrant ||
		cur.Status != connectflow.StatusApproved || cur.AccountID == "" {
		return KeyGrantDelivery{Request: cur, Decision: connectflow.KeyGrantNone}, nil
	}
	var out KeyGrantDelivery
	err = s.WithAccount(ctx, cur.AccountID, func(ctx context.Context, tx pgx.Tx) error {
		c, e := scanConnectRequest(tx.QueryRow(ctx,
			`SELECT `+connectColumns+` FROM connect_requests
			  WHERE request_id = $1::uuid AND account_id = $2::uuid FOR UPDATE`, requestID, cur.AccountID))
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return e
		}
		out.Request = c
		out.Decision = connectflow.KeyGrantDecision(connectflow.KeyGrantFacts{
			Status: c.Status, Deliveries: c.Deliveries, ApprovedAt: c.ResolvedAt,
			TargetReady: targetReady && c.Target != nil, Now: now,
		})
		switch out.Decision {
		case connectflow.KeyGrantExhausted:
			return ErrConnectKeyGrantDelivered
		case connectflow.KeyGrantWindowClosed:
			return ErrConnectKeyGrantWindowClosed
		case connectflow.KeyGrantDeliver:
			if _, e := tx.Exec(ctx,
				`UPDATE connect_requests SET deliveries = deliveries + 1 WHERE request_id = $1::uuid`, requestID); e != nil {
				return fmt.Errorf("record delivery: %w", e)
			}
			out.Request.Deliveries++
		}
		return nil
	})
	if errors.Is(err, ErrConnectKeyGrantDelivered) || errors.Is(err, ErrConnectKeyGrantWindowClosed) || errors.Is(err, ErrNotFound) {
		return out, err
	}
	if err != nil {
		return KeyGrantDelivery{}, fmt.Errorf("cloudserver/store.DeliverConnectKeyGrant: %w", err)
	}
	return out, nil
}

// MyOrgEntitlementBody returns the version and body of the newest
// entitlements document the cloud issued for orgID, read in accountID's own
// context through the sbci_my_org_entitlements view (cloud 0159): only an
// org the account is a member of answers. ErrNotFound when none was issued
// yet, or the account is not a member. The SDK key approval page reads it to
// say whether a dashboard's plan includes AI Apps (the front door holds no
// grant on the documents themselves).
func (s *Store) MyOrgEntitlementBody(ctx context.Context, accountID, orgID string) (int64, []byte, error) {
	var (
		version int64
		body    []byte
	)
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT version, body FROM sbci_my_org_entitlements WHERE org_id = $1::uuid`, orgID).Scan(&version, &body)
		if errors.Is(e, pgx.ErrNoRows) || isInvalidUUIDErr(e) {
			return ErrNotFound
		}
		return e
	})
	if errors.Is(err, ErrNotFound) {
		return 0, nil, ErrNotFound
	}
	if err != nil {
		return 0, nil, fmt.Errorf("cloudserver/store.MyOrgEntitlementBody: %w", err)
	}
	return version, body, nil
}

// ConnectTargetActive reports whether orgID is active, read in accountID's
// own context (the approver's membership, getMyOrgTx): false when the org is
// still being set up, is suspended or gone, or the account is no longer a
// member. An SDK key poll hands its grant over only once this is true.
func (s *Store) ConnectTargetActive(ctx context.Context, accountID, orgID string) (bool, error) {
	var active bool
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		o, e := getMyOrgTx(ctx, tx, orgID)
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		active = o.Status == platformcontract.StateActive
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("cloudserver/store.ConnectTargetActive: %w", err)
	}
	return active, nil
}
