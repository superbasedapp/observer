package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// structural_test.go is the W2 server half's suite: the upload path's digest,
// canonicality, standing-grant, idempotency, currency and isolation rules, and
// the account-day materialization they feed.

const (
	testSourceWindowRule = "completed_utc_days_trailing_30"
	// A window range wide enough to cover every fixture period below.
	fixtureFrom = "2020-01-01"
	fixtureTo   = "2099-12-31"
)

// baseSnapshot builds a schema-valid snapshot for a window. The coverage
// numerators are set so the bands the server RE-DERIVES on merge are checkable.
func baseSnapshot(period string, revision, sessions, actions int) cloudcontract.StructuralSnapshot {
	s := cloudcontract.StructuralSnapshot{
		SchemaVersion:            cloudcontract.StructuralSnapshotSchemaVersion,
		Period:                   period,
		PeriodRuleVersion:        1,
		TimezoneRuleVersion:      1,
		DeclaredTimezone:         "UTC",
		Revision:                 revision,
		SourceWatermark:          period + "T23:59:00Z",
		Active:                   sessions > 0,
		SessionCount:             sessions,
		ActionCount:              actions,
		TokensIn:                 100 * sessions,
		TokensOut:                20 * sessions,
		CacheReadTokens:          5 * sessions,
		CostUSD:                  0.25 * float64(sessions),
		VerificationCoverageBand: cloudcontract.CoverageBandNone,
		OutcomeEvidenceBand:      cloudcontract.CoverageBandNone,
	}
	if sessions > 0 {
		s.ToolMix = []cloudcontract.StructuralMixEntry{{Key: "claude-code", Count: sessions}}
		s.ModelFamilyMix = []cloudcontract.StructuralMixEntry{{Key: "claude", Count: sessions}}
		s.CoverageDenominators = cloudcontract.StructuralCoverageDenominators{
			SessionsWithVerification: sessions,
		}
		s.VerificationCoverageBand = cloudcontract.CoverageBandHigh
	}
	return s
}

// seal computes the non-self-referential digest, embeds it, and returns the
// canonical upload bytes — exactly what the node's serializer produces.
func seal(t *testing.T, s cloudcontract.StructuralSnapshot) []byte {
	t.Helper()
	s.Digest = ""
	d, err := cloudcontract.StructuralDigest(s)
	if err != nil {
		t.Fatalf("StructuralDigest: %v", err)
	}
	s.Digest = d
	b, err := cloudcontract.StructuralUploadBytes(s)
	if err != nil {
		t.Fatalf("StructuralUploadBytes: %v", err)
	}
	return b
}

// uploadStructural POSTs a snapshot with the full standing-grant binding.
func (c *testClient) uploadStructural(body []byte, generation int64, dictionary, rule string) *http.Response {
	c.t.Helper()
	req := c.signedReq("POST", "/v1/structural-insights", body)
	req.Header.Set("SBO-Consent-Generation", strconv.FormatInt(generation, 10))
	req.Header.Set("SBO-Data-Dictionary-Digest", dictionary)
	req.Header.Set("SBO-Source-Window-Rule", rule)
	req.Header.Set("SBO-Feature", "structural_insights")
	return c.do(req)
}

// upload is the happy-path shorthand: generation 1, the service's own current
// data dictionary, the v1 source-window rule.
func (c *testClient) upload(body []byte) *http.Response {
	c.t.Helper()
	return c.uploadStructural(body, 1, cloudcontract.StructuralDataDictionaryDigest(), testSourceWindowRule)
}

type snapshotAck struct {
	SnapshotID string `json:"snapshot_id"`
	Status     string `json:"status"`
	Replay     bool   `json:"replay"`
}

func ackOf(t *testing.T, resp *http.Response, wantStatus int) snapshotAck {
	t.Helper()
	if resp.StatusCode != wantStatus {
		t.Fatalf("status=%d, want %d; body=%s", resp.StatusCode, wantStatus, readAll(resp))
	}
	var ack snapshotAck
	decode(t, resp, &ack)
	return ack
}

// errCodeOf reads the honest {code} the server refused with.
func errCodeOf(t *testing.T, resp *http.Response, wantStatus int) string {
	t.Helper()
	body := readAll(resp)
	if resp.StatusCode != wantStatus {
		t.Fatalf("status=%d, want %d; body=%s", resp.StatusCode, wantStatus, body)
	}
	var e struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatalf("decode error body %q: %v", body, err)
	}
	return e.Code
}

// timeNowUTCDay returns a period label offset by `days` from today in UTC. The
// portal's insights window is anchored on the server's own clock, so fixtures
// that must appear in it have to be dated relative to now rather than pinned.
func timeNowUTCDay(days int) string {
	return time.Now().UTC().AddDate(0, 0, days).Format(cloudcontract.StructuralPeriodLayout)
}

func daysOf(t *testing.T, h *harness, accountID string) []store.StructuralAccountDay {
	t.Helper()
	rows, err := h.store.ListStructuralAccountDays(context.Background(), accountID, fixtureFrom, fixtureTo)
	if err != nil {
		t.Fatalf("ListStructuralAccountDays: %v", err)
	}
	return rows
}

// --- happy path + materialization -------------------------------------------

func TestStructuralUploadStoresAndMaterializes(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "struct-alice")

	body := seal(t, baseSnapshot("2026-08-30", 1, 4, 40))
	ack := ackOf(t, c.upload(body), http.StatusAccepted)
	if ack.Replay || ack.Status != "stored" || ack.SnapshotID == "" {
		t.Fatalf("unexpected ack: %+v", ack)
	}

	rows := daysOf(t, h, c.accountID)
	if len(rows) != 1 {
		t.Fatalf("materialized %d days, want 1: %+v", len(rows), rows)
	}
	d := rows[0]
	if d.Period != "2026-08-30" || d.DeviceCount != 1 || d.SessionCount != 4 || d.ActionCount != 40 {
		t.Fatalf("unexpected materialized day: %+v", d)
	}
	if d.TokensIn != 400 || d.TokensOut != 80 || d.CacheReadTokens != 20 {
		t.Fatalf("token sums wrong: %+v", d)
	}
	if len(d.ToolMix) != 1 || d.ToolMix[0].Key != "claude-code" || d.ToolMix[0].Count != 4 {
		t.Fatalf("tool mix wrong: %+v", d.ToolMix)
	}
	// The band is RE-DERIVED from the merged numerators (4 of 4 ⇒ high).
	if d.VerificationCoverageBand != string(cloudcontract.CoverageBandHigh) {
		t.Fatalf("verification band = %q, want high", d.VerificationCoverageBand)
	}
	if d.OutcomeEvidenceBand != string(cloudcontract.CoverageBandNone) {
		t.Fatalf("outcome band = %q, want none", d.OutcomeEvidenceBand)
	}

	// The grant registered itself on this first upload.
	grants, err := h.store.ListStructuralGrants(context.Background(), c.accountID)
	if err != nil {
		t.Fatalf("ListStructuralGrants: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("registered %d grants, want 1", len(grants))
	}
	g := grants[0]
	if g.Purpose != string(cloudcontract.PurposeStructuralInsights) ||
		g.DataDictionaryDigest != cloudcontract.StructuralDataDictionaryDigest() ||
		g.ConsentGeneration != 1 || g.DeclaredTimezone != "UTC" || g.SourceWindowRule != testSourceWindowRule {
		t.Fatalf("registration did not record the R1 binding: %+v", g)
	}
	if g.RevokedAt != nil {
		t.Fatalf("a fresh registration must not be revoked: %+v", g)
	}
}

// --- digest / canonicality --------------------------------------------------

func TestStructuralRejectsTamperedBytes(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "struct-tamper")

	t.Run("wrong declared digest", func(t *testing.T) {
		s := baseSnapshot("2026-08-01", 1, 1, 1)
		s.Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		body, err := cloudcontract.StructuralUploadBytes(s)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if code := errCodeOf(t, c.upload(body), http.StatusUnprocessableEntity); code != "digest_mismatch" {
			t.Fatalf("code = %q, want digest_mismatch", code)
		}
	})

	t.Run("value edited after digesting", func(t *testing.T) {
		body := seal(t, baseSnapshot("2026-08-02", 1, 4, 40))
		// Rewrite a count in the already-digested bytes: the embedded digest now
		// describes a window that is not the one being sent.
		tampered := []byte(strings.Replace(string(body), `"action_count": 40`, `"action_count": 41`, 1))
		if string(tampered) == string(body) {
			t.Fatalf("test fixture did not actually tamper the bytes:\n%s", body)
		}
		if code := errCodeOf(t, c.upload(tampered), http.StatusUnprocessableEntity); code != "digest_mismatch" {
			t.Fatalf("code = %q, want digest_mismatch", code)
		}
	})

	t.Run("re-framed but value-identical bytes", func(t *testing.T) {
		// Same values, different framing (compact instead of the canonical
		// two-space indent). The digest still matches — it covers values, not
		// framing — so only the canonicality check catches this, and it must,
		// or we would store bytes the node never digested.
		s := baseSnapshot("2026-08-03", 1, 2, 5)
		s.Digest = ""
		d, err := cloudcontract.StructuralDigest(s)
		if err != nil {
			t.Fatalf("StructuralDigest: %v", err)
		}
		s.Digest = d
		compact, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if code := errCodeOf(t, c.upload(compact), http.StatusUnprocessableEntity); code != "noncanonical_bytes" {
			t.Fatalf("code = %q, want noncanonical_bytes", code)
		}
	})

	// None of the three refusals stored anything.
	if rows := daysOf(t, h, c.accountID); len(rows) != 0 {
		t.Fatalf("a rejected upload was materialized: %+v", rows)
	}
}

// --- idempotency + currency -------------------------------------------------

func TestStructuralReplayAckAndRevisionConflict(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "struct-replay")

	body := seal(t, baseSnapshot("2026-08-10", 1, 2, 9))
	first := ackOf(t, c.upload(body), http.StatusAccepted)

	// Byte-identical resend ⇒ replay-ack of the SAME row, nothing stored twice.
	second := ackOf(t, c.upload(body), http.StatusOK)
	if !second.Replay || second.Status != "replay" || second.SnapshotID != first.SnapshotID {
		t.Fatalf("resend was not a replay-ack of the same row: first=%+v second=%+v", first, second)
	}

	// Same window key + revision, DIFFERENT content ⇒ refused. A changed window
	// is a new revision, never an overwrite.
	other := seal(t, baseSnapshot("2026-08-10", 1, 3, 11))
	if code := errCodeOf(t, c.upload(other), http.StatusConflict); code != "revision_conflict" {
		t.Fatalf("code = %q, want revision_conflict", code)
	}

	rows := daysOf(t, h, c.accountID)
	if len(rows) != 1 || rows[0].SessionCount != 2 {
		t.Fatalf("the conflicting upload changed the materialization: %+v", rows)
	}
}

func TestStructuralConcurrentSameRevision(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "struct-concurrent")
	body := seal(t, baseSnapshot("2026-08-11", 1, 1, 1))

	const n = 6
	var (
		mu      sync.Mutex
		codes   []int
		acks    []snapshotAck
		wg      sync.WaitGroup
		startCh = make(chan struct{})
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startCh
			// Each attempt mints its own PoP (fresh jti), exactly like a retry.
			req := c.signedReq("POST", "/v1/structural-insights", body)
			req.Header.Set("SBO-Consent-Generation", "1")
			req.Header.Set("SBO-Data-Dictionary-Digest", cloudcontract.StructuralDataDictionaryDigest())
			req.Header.Set("SBO-Source-Window-Rule", testSourceWindowRule)
			resp, err := c.http.Do(req)
			if err != nil {
				mu.Lock()
				codes = append(codes, -1)
				mu.Unlock()
				return
			}
			var ack snapshotAck
			_ = json.NewDecoder(resp.Body).Decode(&ack)
			resp.Body.Close()
			mu.Lock()
			codes = append(codes, resp.StatusCode)
			acks = append(acks, ack)
			mu.Unlock()
		}()
	}
	close(startCh)
	wg.Wait()

	stored, replayed := 0, 0
	for i, code := range codes {
		switch code {
		case http.StatusAccepted:
			stored++
		case http.StatusOK:
			if !acks[i].Replay {
				t.Errorf("a 200 that is not a replay-ack: %+v", acks[i])
			}
			replayed++
		default:
			t.Errorf("unexpected status %d (%+v)", code, acks[i])
		}
	}
	if stored != 1 || replayed != n-1 {
		t.Fatalf("concurrent identical uploads: stored=%d replayed=%d, want 1 and %d", stored, replayed, n-1)
	}
	if rows := daysOf(t, h, c.accountID); len(rows) != 1 || rows[0].SessionCount != 1 {
		t.Fatalf("concurrency corrupted the materialization: %+v", rows)
	}
}

// TestStructuralConcurrentDifferentRevisions is the supersession-atomicity
// case: two revisions of the SAME window racing. Both must be stored (neither
// is a duplicate), and whichever order they land in, exactly one row is left
// current and it is the HIGHER revision. Without the per-window lock this is
// the race that would either leave two current rows or fail one write on the
// partial unique index.
func TestStructuralConcurrentDifferentRevisions(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "struct-race")

	bodies := [][]byte{
		seal(t, baseSnapshot("2026-08-13", 1, 3, 30)),
		seal(t, baseSnapshot("2026-08-13", 2, 8, 80)),
	}
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		codes   []int
		startCh = make(chan struct{})
	)
	for _, body := range bodies {
		wg.Add(1)
		go func(b []byte) {
			defer wg.Done()
			<-startCh
			resp := c.upload(b)
			resp.Body.Close()
			mu.Lock()
			codes = append(codes, resp.StatusCode)
			mu.Unlock()
		}(body)
	}
	close(startCh)
	wg.Wait()

	for _, code := range codes {
		if code != http.StatusAccepted {
			t.Fatalf("a racing revision was refused: statuses=%v", codes)
		}
	}
	rows := daysOf(t, h, c.accountID)
	if len(rows) != 1 || rows[0].SessionCount != 8 || rows[0].DeviceCount != 1 {
		t.Fatalf("the higher revision is not current after the race: %+v", rows)
	}
	// Exactly one un-superseded row survives, whichever order they landed in.
	ctx := context.Background()
	var current int
	if err := h.store.Pool().QueryRow(ctx,
		`SELECT count(*) FROM structural_snapshots
		  WHERE account_id = $1::uuid AND period = '2026-08-13' AND superseded_at IS NULL`,
		c.accountID).Scan(&current); err != nil {
		t.Fatalf("count current: %v", err)
	}
	if current != 1 {
		t.Fatalf("%d current rows for one window, want exactly 1", current)
	}
	var total int
	if err := h.store.Pool().QueryRow(ctx,
		`SELECT count(*) FROM structural_snapshots WHERE account_id = $1::uuid AND period = '2026-08-13'`,
		c.accountID).Scan(&total); err != nil {
		t.Fatalf("count total: %v", err)
	}
	if total != 2 {
		t.Fatalf("%d stored revisions, want 2 — a racing revision was dropped", total)
	}
}

// TestStructuralRevisionCurrencyR2BeforeR1 is the ordering rule: currency is
// decided by revision NUMBER, so a revision that arrives late is kept but never
// becomes the current view.
func TestStructuralRevisionCurrencyR2BeforeR1(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "struct-currency")

	r2 := seal(t, baseSnapshot("2026-08-12", 2, 7, 70))
	if ack := ackOf(t, c.upload(r2), http.StatusAccepted); ack.Status != "stored" {
		t.Fatalf("r2 status = %q, want stored", ack.Status)
	}

	r1 := seal(t, baseSnapshot("2026-08-12", 1, 3, 30))
	ack := ackOf(t, c.upload(r1), http.StatusAccepted)
	if ack.Status != "stored_superseded" {
		t.Fatalf("a late lower revision must be stored already-superseded, got %q", ack.Status)
	}

	rows := daysOf(t, h, c.accountID)
	if len(rows) != 1 || rows[0].SessionCount != 7 {
		t.Fatalf("the late r1 became current: %+v", rows)
	}

	// And a LATER revision does supersede: r3 replaces r2 as current.
	r3 := seal(t, baseSnapshot("2026-08-12", 3, 11, 110))
	if ack := ackOf(t, c.upload(r3), http.StatusAccepted); ack.Status != "stored" {
		t.Fatalf("r3 status = %q, want stored", ack.Status)
	}
	rows = daysOf(t, h, c.accountID)
	if len(rows) != 1 || rows[0].SessionCount != 11 || rows[0].DeviceCount != 1 {
		t.Fatalf("r3 did not become current: %+v", rows)
	}
}

// --- standing-grant validation ----------------------------------------------

func TestStructuralGrantValidation(t *testing.T) {
	dict := cloudcontract.StructuralDataDictionaryDigest()

	t.Run("first upload registers, same generation is unchanged", func(t *testing.T) {
		h := newHarness(t)
		c := h.login(t, "grant-first")
		ackOf(t, c.upload(seal(t, baseSnapshot("2026-07-01", 1, 1, 1))), http.StatusAccepted)
		ackOf(t, c.upload(seal(t, baseSnapshot("2026-07-02", 1, 1, 1))), http.StatusAccepted)
		grants, _ := h.store.ListStructuralGrants(context.Background(), c.accountID)
		if len(grants) != 1 || grants[0].ConsentGeneration != 1 {
			t.Fatalf("unexpected registration: %+v", grants)
		}
	})

	t.Run("newer generation updates the registration", func(t *testing.T) {
		h := newHarness(t)
		c := h.login(t, "grant-newer")
		ackOf(t, c.upload(seal(t, baseSnapshot("2026-07-03", 1, 1, 1))), http.StatusAccepted)
		resp := c.uploadStructural(seal(t, baseSnapshot("2026-07-04", 1, 1, 1)), 5, dict, "some_newer_rule")
		ackOf(t, resp, http.StatusAccepted)
		grants, _ := h.store.ListStructuralGrants(context.Background(), c.accountID)
		if len(grants) != 1 || grants[0].ConsentGeneration != 5 || grants[0].SourceWindowRule != "some_newer_rule" {
			t.Fatalf("a newer generation did not update the registration: %+v", grants)
		}
	})

	t.Run("older generation is refused", func(t *testing.T) {
		h := newHarness(t)
		c := h.login(t, "grant-older")
		ackOf(t, c.uploadStructural(seal(t, baseSnapshot("2026-07-05", 1, 1, 1)), 9, dict, testSourceWindowRule), http.StatusAccepted)
		resp := c.uploadStructural(seal(t, baseSnapshot("2026-07-06", 1, 1, 1)), 8, dict, testSourceWindowRule)
		if code := errCodeOf(t, resp, http.StatusConflict); code != "consent_generation_stale" {
			t.Fatalf("code = %q, want consent_generation_stale", code)
		}
		if rows := daysOf(t, h, c.accountID); len(rows) != 1 {
			t.Fatalf("a stale-generation upload was stored: %+v", rows)
		}
	})

	t.Run("wrong data dictionary is refused", func(t *testing.T) {
		h := newHarness(t)
		c := h.login(t, "grant-dict")
		resp := c.uploadStructural(seal(t, baseSnapshot("2026-07-07", 1, 1, 1)), 1,
			"sha256:1111111111111111111111111111111111111111111111111111111111111111", testSourceWindowRule)
		if code := errCodeOf(t, resp, http.StatusForbidden); code != "data_dictionary_mismatch" {
			t.Fatalf("code = %q, want data_dictionary_mismatch", code)
		}
		grants, _ := h.store.ListStructuralGrants(context.Background(), c.accountID)
		if len(grants) != 0 {
			t.Fatalf("a refused dictionary still registered a grant: %+v", grants)
		}
	})

	t.Run("revoked registration refuses every upload", func(t *testing.T) {
		h := newHarness(t)
		c := h.login(t, "grant-revoked")
		ackOf(t, c.upload(seal(t, baseSnapshot("2026-07-08", 1, 1, 1))), http.StatusAccepted)
		if _, err := h.store.Pool().Exec(context.Background(),
			`UPDATE structural_grants SET revoked_at = now() WHERE account_id = $1::uuid`,
			c.accountID); err != nil {
			t.Fatalf("revoke registration: %v", err)
		}
		resp := c.upload(seal(t, baseSnapshot("2026-07-09", 1, 1, 1)))
		if code := errCodeOf(t, resp, http.StatusForbidden); code != "grant_revoked" {
			t.Fatalf("code = %q, want grant_revoked", code)
		}
		if rows := daysOf(t, h, c.accountID); len(rows) != 1 {
			t.Fatalf("an upload under a revoked grant was stored: %+v", rows)
		}
	})

	t.Run("missing binding headers are refused", func(t *testing.T) {
		h := newHarness(t)
		c := h.login(t, "grant-headers")
		body := seal(t, baseSnapshot("2026-07-10", 1, 1, 1))
		for name, tc := range map[string]struct {
			gen, dict string
			wantCode  string
		}{
			"no generation":      {"", dict, "missing_consent_generation"},
			"zero generation":    {"0", dict, "invalid_consent_generation"},
			"garbage generation": {"abc", dict, "invalid_consent_generation"},
			"no dictionary":      {"1", "", "missing_data_dictionary_digest"},
		} {
			req := c.signedReq("POST", "/v1/structural-insights", body)
			if tc.gen != "" {
				req.Header.Set("SBO-Consent-Generation", tc.gen)
			}
			if tc.dict != "" {
				req.Header.Set("SBO-Data-Dictionary-Digest", tc.dict)
			}
			if code := errCodeOf(t, c.do(req), http.StatusBadRequest); code != tc.wantCode {
				t.Errorf("%s: code = %q, want %q", name, code, tc.wantCode)
			}
		}
	})
}

// --- multi-device merge + tenant isolation ----------------------------------

// TestStructuralMaterializationMergesDevices proves the merge is per-device and
// that a revision REPLACES that device's contribution rather than adding to it.
func TestStructuralMaterializationMergesDevices(t *testing.T) {
	h := newHarness(t)
	// Two devices, ONE account: the same dev subject exchanges twice, which the
	// identity-link bootstrap resolves to one account with two device rows.
	laptop := h.login(t, "struct-two-devices")
	desktop := h.login(t, "struct-two-devices")
	if laptop.accountID != desktop.accountID {
		t.Fatalf("fixture broke: two devices resolved to different accounts")
	}
	if laptop.thumbprint == desktop.thumbprint {
		t.Fatalf("fixture broke: both logins minted the same device")
	}

	ackOf(t, laptop.upload(seal(t, baseSnapshot("2026-06-01", 1, 2, 20))), http.StatusAccepted)
	ackOf(t, desktop.upload(seal(t, baseSnapshot("2026-06-01", 1, 3, 30))), http.StatusAccepted)

	rows := daysOf(t, h, laptop.accountID)
	if len(rows) != 1 {
		t.Fatalf("materialized %d days, want 1: %+v", len(rows), rows)
	}
	if rows[0].DeviceCount != 2 || rows[0].SessionCount != 5 || rows[0].ActionCount != 50 {
		t.Fatalf("two devices did not merge: %+v", rows[0])
	}
	if len(rows[0].ToolMix) != 1 || rows[0].ToolMix[0].Count != 5 {
		t.Fatalf("mixes did not merge by key: %+v", rows[0].ToolMix)
	}

	// A NEW revision from the laptop replaces the laptop's contribution only.
	ackOf(t, laptop.upload(seal(t, baseSnapshot("2026-06-01", 2, 10, 100))), http.StatusAccepted)
	rows = daysOf(t, h, laptop.accountID)
	if rows[0].DeviceCount != 2 || rows[0].SessionCount != 13 || rows[0].ActionCount != 130 {
		t.Fatalf("a revision did not REPLACE the device's contribution: %+v", rows[0])
	}
}

// TestStructuralTenantIsolation is the RLS wall: two accounts, two corpora,
// neither visible from the other's tenant transaction.
func TestStructuralTenantIsolation(t *testing.T) {
	h := newHarness(t)
	alice := h.login(t, "iso-alice")
	bob := h.login(t, "iso-bob")
	if alice.accountID == bob.accountID {
		t.Fatalf("fixture broke: two subjects share an account")
	}

	ackOf(t, alice.upload(seal(t, baseSnapshot("2026-05-01", 1, 4, 40))), http.StatusAccepted)
	ackOf(t, bob.upload(seal(t, baseSnapshot("2026-05-02", 1, 9, 90))), http.StatusAccepted)

	aliceRows := daysOf(t, h, alice.accountID)
	if len(aliceRows) != 1 || aliceRows[0].Period != "2026-05-01" || aliceRows[0].SessionCount != 4 {
		t.Fatalf("alice sees the wrong corpus: %+v", aliceRows)
	}
	bobRows := daysOf(t, h, bob.accountID)
	if len(bobRows) != 1 || bobRows[0].Period != "2026-05-02" || bobRows[0].SessionCount != 9 {
		t.Fatalf("bob sees the wrong corpus: %+v", bobRows)
	}

	aliceGrants, _ := h.store.ListStructuralGrants(context.Background(), alice.accountID)
	bobGrants, _ := h.store.ListStructuralGrants(context.Background(), bob.accountID)
	if len(aliceGrants) != 1 || len(bobGrants) != 1 {
		t.Fatalf("grant registrations leaked across accounts: alice=%+v bob=%+v", aliceGrants, bobGrants)
	}

	aliceCov, err := h.store.StructuralCoverageFor(context.Background(), alice.accountID)
	if err != nil {
		t.Fatalf("StructuralCoverageFor: %v", err)
	}
	if aliceCov.Snapshots != 1 || aliceCov.Devices != 1 || aliceCov.TotalDays != 1 {
		t.Fatalf("alice's coverage counted another tenant's rows: %+v", aliceCov)
	}

	// The checks above all run through store methods whose SQL also carries an
	// account_id predicate, so they would pass even with RLS switched off. This
	// probe removes that escape: an UNFILTERED count, under the sbci_app role
	// with alice's tenant GUC, must still see only alice's rows — which is RLS
	// doing the work and nothing else.
	for _, tc := range []struct {
		table string
		want  int
	}{
		{"structural_snapshots", 1},
		{"structural_account_days", 1},
		{"structural_grants", 1},
	} {
		ctx := context.Background()
		tx, err := h.store.Pool().Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE sbci_app`); err != nil {
			t.Fatalf("set role: %v", err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('sbci.account_id', $1, true)`, alice.accountID); err != nil {
			t.Fatalf("set tenant: %v", err)
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM `+tc.table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", tc.table, err)
		}
		_ = tx.Rollback(ctx)
		if n != tc.want {
			t.Fatalf("unfiltered count of %s under alice's tenant = %d, want %d — RLS is not isolating this table",
				tc.table, n, tc.want)
		}
	}
}

// --- bounds -----------------------------------------------------------------

func TestStructuralBounds(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "struct-bounds")

	t.Run("oversized body", func(t *testing.T) {
		big := make([]byte, (64<<10)+1)
		for i := range big {
			big[i] = 'x'
		}
		if code := errCodeOf(t, c.upload(big), http.StatusRequestEntityTooLarge); code != "body_too_large" {
			t.Fatalf("code = %q, want body_too_large", code)
		}
	})

	t.Run("empty body", func(t *testing.T) {
		if code := errCodeOf(t, c.upload([]byte{}), http.StatusBadRequest); code != "bad_request" {
			t.Fatalf("code = %q, want bad_request", code)
		}
	})

	t.Run("not JSON", func(t *testing.T) {
		if code := errCodeOf(t, c.upload([]byte("not json at all")), http.StatusBadRequest); code != "bad_request" {
			t.Fatalf("code = %q, want bad_request", code)
		}
	})

	t.Run("schema-invalid snapshot", func(t *testing.T) {
		// Active=false while carrying aggregates: an inactive window that claims
		// activity. Validate refuses it, so it never reaches storage.
		s := baseSnapshot("2026-04-01", 1, 3, 3)
		s.Active = false
		body := seal(t, s)
		if code := errCodeOf(t, c.upload(body), http.StatusUnprocessableEntity); code != "invalid_snapshot" {
			t.Fatalf("code = %q, want invalid_snapshot", code)
		}
	})

	if rows := daysOf(t, h, c.accountID); len(rows) != 0 {
		t.Fatalf("a bounds refusal stored something: %+v", rows)
	}
}

// TestStructuralRateLimitHasItsOwnBucket drives the rail's dedicated limiter
// with every other dimension disabled, so a 429 can only have come from it.
func TestStructuralRateLimitHasItsOwnBucket(t *testing.T) {
	h := newHarnessRL(t, api.RateLimitConfig{StructuralPerWindow: 2})
	c := h.login(t, "struct-rl")

	for i := 1; i <= 2; i++ {
		body := seal(t, baseSnapshot("2026-03-0"+strconv.Itoa(i), 1, 1, 1))
		ackOf(t, c.upload(body), http.StatusAccepted)
	}
	resp := c.upload(seal(t, baseSnapshot("2026-03-09", 1, 1, 1)))
	if code := errCodeOf(t, resp, http.StatusTooManyRequests); code != "rate_limited" {
		t.Fatalf("code = %q, want rate_limited", code)
	}

	// The interactive surface is NOT starved by the structural bucket.
	if resp := c.do(c.signedReq("GET", "/v1/usage", nil)); resp.StatusCode != http.StatusOK {
		t.Fatalf("the structural cap leaked onto /v1/usage: status=%d", resp.StatusCode)
	}
}

// --- deletion ---------------------------------------------------------------

// TestDeletionPurgesStructuralData extends the deletion coverage: the three W2
// tables are enumerated by the deletion skeleton (they are NOT reached by an FK
// cascade), snapshots and the rollup are purged outright, and the grant
// registration survives as a REVOKED consent audit fact.
func TestDeletionPurgesStructuralData(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "struct-delete")
	ackOf(t, c.upload(seal(t, baseSnapshot("2026-02-01", 1, 2, 20))), http.StatusAccepted)
	ackOf(t, c.upload(seal(t, baseSnapshot("2026-02-02", 1, 3, 30))), http.StatusAccepted)
	if rows := daysOf(t, h, c.accountID); len(rows) != 2 {
		t.Fatalf("fixture did not materialize: %+v", rows)
	}

	ctx := context.Background()
	req, err := h.store.CreateDeletionRequest(ctx, c.accountID, time.Now().UTC())
	if err != nil {
		t.Fatalf("CreateDeletionRequest: %v", err)
	}
	if req.State != "done" {
		t.Fatalf("deletion state=%q, want done: %+v", req.State, req)
	}
	if req.PurgedRows < 2 {
		t.Fatalf("deletion purged too little (expected >=2 structural rows): %+v", req)
	}

	if rows := daysOf(t, h, c.accountID); len(rows) != 0 {
		t.Fatalf("account-day rollup survived deletion: %+v", rows)
	}
	cov, err := h.store.StructuralCoverageFor(ctx, c.accountID)
	if err != nil {
		t.Fatalf("StructuralCoverageFor: %v", err)
	}
	if cov.Snapshots != 0 || cov.TotalDays != 0 {
		t.Fatalf("snapshots survived deletion: %+v", cov)
	}
	grants, err := h.store.ListStructuralGrants(ctx, c.accountID)
	if err != nil {
		t.Fatalf("ListStructuralGrants: %v", err)
	}
	if len(grants) != 1 || grants[0].RevokedAt == nil {
		t.Fatalf("the grant registration must survive as a REVOKED audit fact: %+v", grants)
	}
}

// --- F5: the FULL R1 binding is compared at equal generation -----------------

// snapshotIn builds the store-level input for a window, so a test can drive
// PutStructuralSnapshot directly and exercise the admission re-check the HTTP
// handler cannot be interrupted in the middle of (F7).
func snapshotIn(t *testing.T, deviceID string, snap cloudcontract.StructuralSnapshot, generation int64) store.StructuralSnapshotInput {
	t.Helper()
	body := seal(t, snap)
	var sealed cloudcontract.StructuralSnapshot
	if err := json.Unmarshal(body, &sealed); err != nil {
		t.Fatalf("decode sealed snapshot: %v", err)
	}
	return store.StructuralSnapshotInput{
		DeviceID:          deviceID,
		Purpose:           string(cloudcontract.PurposeStructuralInsights),
		Period:            sealed.Period,
		PeriodRuleVersion: sealed.PeriodRuleVersion,
		SchemaVersion:     sealed.SchemaVersion,
		Revision:          sealed.Revision,
		Digest:            sealed.Digest,
		CanonicalBytes:    body,
		DeclaredTimezone:  sealed.DeclaredTimezone,
		SourceWatermark:   sealed.SourceWatermark,
		ConsentGeneration: generation,
	}
}

// deviceIDOf reads the device row the client's thumbprint minted, so a
// store-level test can name the same device the HTTP path would have used.
func deviceIDOf(t *testing.T, h *harness, c *testClient) string {
	t.Helper()
	devices, err := h.store.ListDevices(context.Background(), c.accountID)
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	for _, d := range devices {
		if d.Thumbprint == c.thumbprint {
			return d.ID
		}
	}
	t.Fatalf("no device row for thumbprint %s", c.thumbprint)
	return ""
}

// TestStructuralGrantBindingEqualityAtEqualGeneration is the F5 regression. At
// an unchanged consent generation only the dictionary digest used to be
// compared, so two devices could register incompatible declared timezones (or
// source-window rules) under one registration — and their day windows, which
// mean different spans of real time, would then be merged into one account-day
// row as though they lined up.
func TestStructuralGrantBindingEqualityAtEqualGeneration(t *testing.T) {
	dict := cloudcontract.StructuralDataDictionaryDigest()

	// tzSnapshot is a schema-valid snapshot in a NON-UTC declared zone.
	tzSnapshot := func(period string, zone string) cloudcontract.StructuralSnapshot {
		s := baseSnapshot(period, 1, 1, 1)
		s.DeclaredTimezone = zone
		return s
	}

	t.Run("equal generation, different declared timezone is refused", func(t *testing.T) {
		h := newHarness(t)
		c := h.login(t, "bind-tz")
		ackOf(t, c.upload(seal(t, tzSnapshot("2026-04-01", "UTC"))), http.StatusAccepted)

		resp := c.uploadStructural(seal(t, tzSnapshot("2026-04-02", "Pacific/Auckland")), 1, dict, testSourceWindowRule)
		if code := errCodeOf(t, resp, http.StatusForbidden); code != "grant_terms_mismatch" {
			t.Fatalf("code = %q, want grant_terms_mismatch", code)
		}
		// Nothing stored, and the registration still holds the ORIGINAL terms.
		if rows := daysOf(t, h, c.accountID); len(rows) != 1 {
			t.Fatalf("a mismatched-timezone upload was stored: %+v", rows)
		}
		grants, _ := h.store.ListStructuralGrants(context.Background(), c.accountID)
		if len(grants) != 1 || grants[0].DeclaredTimezone != "UTC" {
			t.Fatalf("the refused upload moved the registration: %+v", grants)
		}
	})

	t.Run("equal generation, different source window rule is refused", func(t *testing.T) {
		h := newHarness(t)
		c := h.login(t, "bind-rule")
		ackOf(t, c.upload(seal(t, baseSnapshot("2026-04-03", 1, 1, 1))), http.StatusAccepted)

		resp := c.uploadStructural(seal(t, baseSnapshot("2026-04-04", 1, 1, 1)), 1, dict, "completed_local_days_trailing_7")
		if code := errCodeOf(t, resp, http.StatusForbidden); code != "grant_terms_mismatch" {
			t.Fatalf("code = %q, want grant_terms_mismatch", code)
		}
		grants, _ := h.store.ListStructuralGrants(context.Background(), c.accountID)
		if len(grants) != 1 || grants[0].SourceWindowRule != testSourceWindowRule {
			t.Fatalf("the refused upload moved the registration: %+v", grants)
		}
	})

	t.Run("a HIGHER generation updates the whole binding", func(t *testing.T) {
		h := newHarness(t)
		c := h.login(t, "bind-higher")
		ackOf(t, c.upload(seal(t, tzSnapshot("2026-04-05", "UTC"))), http.StatusAccepted)

		// Re-confirming the grant is what changes terms, and confirming raises
		// the generation — so the same timezone change that was refused above is
		// accepted here, and the registration moves with it.
		resp := c.uploadStructural(seal(t, tzSnapshot("2026-04-06", "Pacific/Auckland")), 2, dict, "completed_local_days_trailing_7")
		ackOf(t, resp, http.StatusAccepted)

		grants, _ := h.store.ListStructuralGrants(context.Background(), c.accountID)
		if len(grants) != 1 {
			t.Fatalf("registered %d grants, want 1", len(grants))
		}
		g := grants[0]
		if g.ConsentGeneration != 2 || g.DeclaredTimezone != "Pacific/Auckland" ||
			g.SourceWindowRule != "completed_local_days_trailing_7" {
			t.Fatalf("a higher generation did not update the WHOLE binding: %+v", g)
		}
		if rows := daysOf(t, h, c.accountID); len(rows) != 2 {
			t.Fatalf("the re-confirmed upload was not stored: %+v", rows)
		}
	})

	t.Run("an empty source window rule is refused", func(t *testing.T) {
		h := newHarness(t)
		c := h.login(t, "bind-empty")
		body := seal(t, baseSnapshot("2026-04-07", 1, 1, 1))
		// The header omitted entirely, and present-but-blank: both are a
		// registration with a hole in it, and both are refused before anything
		// is registered.
		for name, rule := range map[string]string{"omitted": "", "blank": "   "} {
			req := c.signedReq("POST", "/v1/structural-insights", body)
			req.Header.Set("SBO-Consent-Generation", "1")
			req.Header.Set("SBO-Data-Dictionary-Digest", dict)
			if rule != "" {
				req.Header.Set("SBO-Source-Window-Rule", rule)
			}
			if code := errCodeOf(t, c.do(req), http.StatusBadRequest); code != "missing_source_window_rule" {
				t.Errorf("%s: code = %q, want missing_source_window_rule", name, code)
			}
		}
		grants, _ := h.store.ListStructuralGrants(context.Background(), c.accountID)
		if len(grants) != 0 {
			t.Fatalf("an incomplete binding still registered a grant: %+v", grants)
		}
	})

	t.Run("the store refuses an incomplete binding directly", func(t *testing.T) {
		h := newHarness(t)
		c := h.login(t, "bind-store")
		base := store.StructuralGrantInput{
			Purpose:              string(cloudcontract.PurposeStructuralInsights),
			DataDictionaryDigest: dict,
			SchemaVersion:        cloudcontract.StructuralSnapshotSchemaVersion,
			ConsentGeneration:    1,
			DeclaredTimezone:     "UTC",
			SourceWindowRule:     testSourceWindowRule,
		}
		for name, mutate := range map[string]func(*store.StructuralGrantInput){
			"no timezone":   func(in *store.StructuralGrantInput) { in.DeclaredTimezone = "" },
			"no rule":       func(in *store.StructuralGrantInput) { in.SourceWindowRule = "" },
			"no dictionary": func(in *store.StructuralGrantInput) { in.DataDictionaryDigest = "" },
			"no schema":     func(in *store.StructuralGrantInput) { in.SchemaVersion = "" },
		} {
			in := base
			mutate(&in)
			_, _, err := h.store.RegisterStructuralGrant(context.Background(), c.accountID, in)
			if !errors.Is(err, store.ErrStructuralBindingIncomplete) {
				t.Errorf("%s: err = %v, want ErrStructuralBindingIncomplete", name, err)
			}
		}
	})
}

// --- F6: the first-registration race ----------------------------------------

// TestStructuralGrantFirstRegistrationRace is the F6 regression. `FOR UPDATE`
// locks no row that does not exist, so two concurrent FIRST registrations both
// saw absence, both took the insert path, and the loser's unconditional ON
// CONFLICT update overwrote the winner's row — including with a LOWER
// generation, silently re-opening terms the developer had already replaced.
//
// The fix is an advisory lock taken BEFORE the read plus a conditional conflict
// arm. What is asserted here is the invariant, not a scheduling outcome: the
// registration NEVER ends below the highest generation any caller declared, and
// the low-generation caller is refused whenever the high one won the race. Which
// of the two the scheduler runs first is genuinely not determined, so asserting
// a fixed winner would be asserting the scheduler, not the code.
func TestStructuralGrantFirstRegistrationRace(t *testing.T) {
	dict := cloudcontract.StructuralDataDictionaryDigest()
	ctx := context.Background()

	// The deterministic half: a registration at 5 refuses a later 1, and does
	// not move.
	t.Run("a lower generation never lands after a higher one", func(t *testing.T) {
		h := newHarness(t)
		c := h.login(t, "race-seq")
		ackOf(t, c.uploadStructural(seal(t, baseSnapshot("2026-03-01", 1, 1, 1)), 5, dict, testSourceWindowRule), http.StatusAccepted)
		resp := c.uploadStructural(seal(t, baseSnapshot("2026-03-02", 1, 1, 1)), 1, dict, testSourceWindowRule)
		if code := errCodeOf(t, resp, http.StatusConflict); code != "consent_generation_stale" {
			t.Fatalf("code = %q, want consent_generation_stale", code)
		}
		grants, _ := h.store.ListStructuralGrants(ctx, c.accountID)
		if len(grants) != 1 || grants[0].ConsentGeneration != 5 {
			t.Fatalf("the stale caller regressed the registration: %+v", grants)
		}
	})

	// The racing half, repeated so a scheduling order that happens to be benign
	// once cannot pass for the invariant. It is a SMOKE TEST, not the gate:
	// measured by mutation, it still passes with the lock removed, because two
	// HTTP registrations land milliseconds apart and the loser reads the
	// winner's committed row. TestStructuralGrantRegistrationTakesTheLock below
	// is the deterministic guard.
	t.Run("concurrent first registrations cannot regress the row", func(t *testing.T) {
		const rounds = 12
		staleSeen := 0
		for i := 0; i < rounds; i++ {
			h := newHarness(t)
			// Two DEVICES on one account, so both calls are a first
			// registration for the same (account, purpose).
			laptop := h.login(t, "race-par")
			desktop := h.login(t, "race-par")
			if laptop.accountID != desktop.accountID {
				t.Fatalf("fixture broke: two devices resolved to different accounts")
			}

			var (
				wg      sync.WaitGroup
				mu      sync.Mutex
				results = map[int64]int{}
				start   = make(chan struct{})
			)
			for _, tc := range []struct {
				client *testClient
				gen    int64
				period string
			}{
				{laptop, 5, "2026-03-03"},
				{desktop, 1, "2026-03-04"},
			} {
				wg.Add(1)
				go func(c *testClient, gen int64, period string) {
					defer wg.Done()
					<-start
					resp := c.uploadStructural(seal(t, baseSnapshot(period, 1, 1, 1)), gen, dict, testSourceWindowRule)
					code := resp.StatusCode
					resp.Body.Close()
					mu.Lock()
					results[gen] = code
					mu.Unlock()
				}(tc.client, tc.gen, tc.period)
			}
			close(start)
			wg.Wait()

			grants, err := h.store.ListStructuralGrants(ctx, laptop.accountID)
			if err != nil {
				t.Fatalf("ListStructuralGrants: %v", err)
			}
			if len(grants) != 1 {
				t.Fatalf("round %d: registered %d grants, want 1", i, len(grants))
			}
			if grants[0].ConsentGeneration != 5 {
				t.Fatalf("round %d: registration ended at generation %d, want 5 — a lower generation overwrote a higher one (statuses: %v)",
					i, grants[0].ConsentGeneration, results)
			}
			if results[5] != http.StatusAccepted {
				t.Fatalf("round %d: the generation-5 upload was refused (%d); it is never the stale one", i, results[5])
			}
			switch results[1] {
			case http.StatusConflict:
				// The 5 landed first: the 1 is stale, exactly as intended.
				staleSeen++
			case http.StatusAccepted:
				// The 1 landed first and the 5 then updated the row. Legal, and
				// the generation assertion above already proved the row is at 5.
			default:
				t.Fatalf("round %d: unexpected status %d for the generation-1 upload", i, results[1])
			}
		}
		if staleSeen == 0 {
			t.Logf("note: over %d rounds the generation-1 upload always won the race, so the stale refusal "+
				"was not exercised here; the deterministic subtest above covers it", rounds)
		}
	})
}

// --- F7: the insert re-validates grant + account -----------------------------

// TestStructuralInsertRevalidatesAdmission is the F7 regression. Registration
// and insert ran in two separate transactions, so an account deletion committing
// between them (it fences the account 'closed', revokes the registration, and
// purges the tables) left the insert free to RE-CREATE activity data for an
// account whose data had just been purged.
func TestStructuralInsertRevalidatesAdmission(t *testing.T) {
	ctx := context.Background()

	t.Run("a closed account is refused at the insert", func(t *testing.T) {
		h := newHarness(t)
		c := h.login(t, "adm-closed")
		// One good upload registers the grant.
		ackOf(t, c.upload(seal(t, baseSnapshot("2026-02-01", 1, 1, 1))), http.StatusAccepted)
		device := deviceIDOf(t, h, c)

		// Fence the account exactly as the deletion skeleton does, leaving the
		// grant intact so this isolates the ACCOUNT check.
		if _, err := h.store.Pool().Exec(ctx,
			`UPDATE accounts SET status = 'closed' WHERE account_id = $1::uuid`, c.accountID); err != nil {
			t.Fatalf("fence account: %v", err)
		}

		// Over HTTP there is an EARLIER wall: token introspection refuses a
		// non-active account, so a request that starts after the fence never
		// reaches the handler. Pinned here so the layering is explicit rather
		// than assumed.
		resp := c.upload(seal(t, baseSnapshot("2026-02-02", 1, 1, 1)))
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("a request begun after the fence = %d, want 401 from token introspection; body=%s",
				resp.StatusCode, readAll(resp))
		}
		resp.Body.Close()

		// The window the introspection wall cannot cover is a request already
		// PAST it when the fence commits. That is the store's own guard, and it
		// is what F7 adds.
		_, err := h.store.PutStructuralSnapshot(ctx, c.accountID,
			snapshotIn(t, device, baseSnapshot("2026-02-02", 1, 1, 1), 1))
		if !errors.Is(err, store.ErrAccountClosed) {
			t.Fatalf("err = %v, want ErrAccountClosed", err)
		}
		if rows := daysOf(t, h, c.accountID); len(rows) != 1 {
			t.Fatalf("an upload to a closed account was stored: %+v", rows)
		}
	})

	t.Run("a grant revoked after registration refuses the insert", func(t *testing.T) {
		h := newHarness(t)
		c := h.login(t, "adm-revoked")
		ackOf(t, c.upload(seal(t, baseSnapshot("2026-02-03", 1, 1, 1))), http.StatusAccepted)
		device := deviceIDOf(t, h, c)

		// Revoke AFTER the registration the in-flight upload would have used.
		// Driving the store directly is what puts the revocation exactly in the
		// window the HTTP path cannot be interrupted in.
		if _, err := h.store.Pool().Exec(ctx,
			`UPDATE structural_grants SET revoked_at = now() WHERE account_id = $1::uuid`, c.accountID); err != nil {
			t.Fatalf("revoke grant: %v", err)
		}
		_, err := h.store.PutStructuralSnapshot(ctx, c.accountID,
			snapshotIn(t, device, baseSnapshot("2026-02-04", 1, 1, 1), 1))
		if !errors.Is(err, store.ErrStructuralGrantRevoked) {
			t.Fatalf("err = %v, want ErrStructuralGrantRevoked", err)
		}
		if rows := daysOf(t, h, c.accountID); len(rows) != 1 {
			t.Fatalf("an upload under a revoked grant was stored: %+v", rows)
		}
	})

	t.Run("a registration that moved generation refuses the insert", func(t *testing.T) {
		h := newHarness(t)
		c := h.login(t, "adm-gen")
		ackOf(t, c.upload(seal(t, baseSnapshot("2026-02-05", 1, 1, 1))), http.StatusAccepted)
		device := deviceIDOf(t, h, c)

		if _, err := h.store.Pool().Exec(ctx,
			`UPDATE structural_grants SET consent_generation = 9 WHERE account_id = $1::uuid`, c.accountID); err != nil {
			t.Fatalf("move generation: %v", err)
		}
		_, err := h.store.PutStructuralSnapshot(ctx, c.accountID,
			snapshotIn(t, device, baseSnapshot("2026-02-06", 1, 1, 1), 1))
		if !errors.Is(err, store.ErrStructuralGenerationStale) {
			t.Fatalf("err = %v, want ErrStructuralGenerationStale", err)
		}
	})

	t.Run("a full deletion cannot be undone by an in-flight insert", func(t *testing.T) {
		h := newHarness(t)
		c := h.login(t, "adm-deleted")
		ackOf(t, c.upload(seal(t, baseSnapshot("2026-02-07", 1, 3, 30))), http.StatusAccepted)
		device := deviceIDOf(t, h, c)

		if _, err := h.store.CreateDeletionRequest(ctx, c.accountID, time.Now()); err != nil {
			t.Fatalf("CreateDeletionRequest: %v", err)
		}
		// The window the account's own device was about to send, arriving after
		// the purge. This is the exact shape that used to re-create data.
		_, err := h.store.PutStructuralSnapshot(ctx, c.accountID,
			snapshotIn(t, device, baseSnapshot("2026-02-08", 1, 5, 50), 1))
		if err == nil {
			t.Fatal("a post-deletion insert succeeded — it re-created purged data")
		}
		if !errors.Is(err, store.ErrAccountClosed) {
			t.Fatalf("err = %v, want ErrAccountClosed", err)
		}
		var snapshots, days int
		if e := h.store.Pool().QueryRow(ctx,
			`SELECT (SELECT count(*) FROM structural_snapshots WHERE account_id = $1::uuid),
			        (SELECT count(*) FROM structural_account_days WHERE account_id = $1::uuid)`,
			c.accountID).Scan(&snapshots, &days); e != nil {
			t.Fatalf("count purged tables: %v", e)
		}
		if snapshots != 0 || days != 0 {
			t.Fatalf("after deletion + refused insert: %d snapshots, %d days, want 0/0", snapshots, days)
		}
	})
}

// --- F8: the account-day materialization must not lose an update -------------

// TestStructuralConcurrentDevicesSamePeriod is the F8 regression. The advisory
// lock covers (account, DEVICE, window) but the materialization merges EVERY
// device's current snapshot for the day, so two devices uploading the same
// period concurrently held disjoint locks, each recomputed from a table state
// that did not contain the other's row, and the later commit overwrote the
// earlier with a one-device answer. The fix is a SECOND advisory lock on
// (account, period), taken after the window lock.
//
// Two things about the setup are load-bearing, and were both arrived at by
// watching the test FAIL to reproduce a defect that is genuinely there:
//
//   - The writers are driven at the STORE seam, not over HTTP. The HTTP path
//     spends milliseconds on proof-of-possession, JSON parsing and digest
//     recomputation before reaching the transaction, and that jitter is more
//     than the race window.
//   - The pool is WARMED and the inputs are PRE-BUILT before the barrier. The
//     losing interleaving needs both transactions inside the window between the
//     leader's recompute SELECT and its COMMIT — a few milliseconds. A goroutine
//     that has to open a fresh Postgres connection after the barrier starts
//     ~7ms late and lands just outside it, which makes the test pass for a
//     reason that has nothing to do with the lock.
//
// Repeated, because a lost update is a race: one benign interleaving proves
// nothing. Even so, it is a SMOKE TEST rather than the gate: measured by
// mutation it still passes with the lock removed, and only fails when an
// artificial delay widens the SELECT-to-COMMIT window.
// TestStructuralRecomputeTakesThePeriodLock is the deterministic guard.
func TestStructuralConcurrentDevicesSamePeriod(t *testing.T) {
	const rounds = 15
	ctx := context.Background()
	const period = "2026-01-15"

	for i := 0; i < rounds; i++ {
		h := newHarness(t)
		laptop := h.login(t, "day-race")
		desktop := h.login(t, "day-race")
		if laptop.accountID != desktop.accountID {
			t.Fatalf("fixture broke: two devices resolved to different accounts")
		}
		if laptop.thumbprint == desktop.thumbprint {
			t.Fatalf("fixture broke: both logins minted the same device")
		}
		// Register the standing grant once, over the real HTTP path, on a day
		// that is NOT the contested one. After this both devices are admissible
		// and the race below is purely the materialization's.
		ackOf(t, laptop.upload(seal(t, baseSnapshot("2026-01-01", 1, 1, 1))), http.StatusAccepted)

		inputs := []store.StructuralSnapshotInput{
			snapshotIn(t, deviceIDOf(t, h, laptop), baseSnapshot(period, 1, 2, 20), 1),
			snapshotIn(t, deviceIDOf(t, h, desktop), baseSnapshot(period, 1, 3, 30), 1),
		}

		// Warm the pool so neither goroutine pays for a connection handshake
		// after the barrier (see the note above).
		var warm sync.WaitGroup
		for range inputs {
			warm.Add(1)
			go func() {
				defer warm.Done()
				if _, err := h.store.StructuralCoverageFor(ctx, laptop.accountID); err != nil {
					t.Errorf("warm pool: %v", err)
				}
			}()
		}
		warm.Wait()

		var (
			ready sync.WaitGroup
			wg    sync.WaitGroup
			mu    sync.Mutex
			errs  []error
			start = make(chan struct{})
		)
		for _, in := range inputs {
			ready.Add(1)
			wg.Add(1)
			go func(in store.StructuralSnapshotInput) {
				defer wg.Done()
				ready.Done()
				<-start
				_, err := h.store.PutStructuralSnapshot(ctx, laptop.accountID, in)
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}(in)
		}
		ready.Wait() // both goroutines are parked ON the barrier, not merely spawned
		close(start)
		wg.Wait()

		for _, err := range errs {
			if err != nil {
				t.Fatalf("round %d: a concurrent device upload failed: %v", i, err)
			}
		}
		rows, err := h.store.ListStructuralAccountDays(ctx, laptop.accountID, period, period)
		if err != nil {
			t.Fatalf("round %d: ListStructuralAccountDays: %v", i, err)
		}
		if len(rows) != 1 {
			t.Fatalf("round %d: materialized %d rows for one period, want 1", i, len(rows))
		}
		d := rows[0]
		if d.DeviceCount != 2 || d.SessionCount != 5 || d.ActionCount != 50 {
			t.Fatalf("round %d: the account-day lost a device's contribution: device_count=%d sessions=%d actions=%d "+
				"(want 2/5/50) — the (account, period) lock did not serialize the recompute",
				i, d.DeviceCount, d.SessionCount, d.ActionCount)
		}
		if len(d.ToolMix) != 1 || d.ToolMix[0].Count != 5 {
			t.Fatalf("round %d: mixes did not merge across both devices: %+v", i, d.ToolMix)
		}
	}
}

// TestStructuralRecomputeTakesThePeriodLock is the DETERMINISTIC half of the F8
// guard, and it exists because the probabilistic half above is not a reliable
// gate on its own.
//
// Measured on this repo's Postgres, the losing interleaving needs both writers
// inside the few milliseconds between the leader's recompute SELECT and its
// COMMIT. Two uploads fired from a warmed pool at a shared barrier still land
// ~5ms apart, which is just outside it — so the race test passes with the lock
// REMOVED (verified by mutation), and only fails when an artificial delay widens
// the window. A test that cannot fail on the bug is not a gate.
//
// So this asserts the mechanism instead of the symptom: hold the (account,
// period) advisory lock from an outside connection, and an upload for that
// period must BLOCK until it is released. That is true exactly when the lock is
// taken, on the right key, before the recompute — which is the whole fix.
func TestStructuralRecomputeTakesThePeriodLock(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	c := h.login(t, "day-lock")
	const period = "2026-01-20"

	// Register the grant on an unrelated day.
	ackOf(t, c.upload(seal(t, baseSnapshot("2026-01-19", 1, 1, 1))), http.StatusAccepted)
	device := deviceIDOf(t, h, c)
	in := snapshotIn(t, device, baseSnapshot(period, 1, 4, 40), 1)

	// Hold the period lock from a connection of our own.
	holder, err := h.store.Pool().Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire holder conn: %v", err)
	}
	defer holder.Release()
	tx, err := holder.Begin(ctx)
	if err != nil {
		t.Fatalf("begin holder tx: %v", err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`,
		store.StructuralPeriodLockKey(c.accountID, period)); err != nil {
		t.Fatalf("take the period lock: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, e := h.store.PutStructuralSnapshot(ctx, c.accountID, in)
		done <- e
	}()

	select {
	case e := <-done:
		t.Fatalf("the upload completed (%v) while the (account, period) lock was HELD — "+
			"the recompute does not serialize on it, so two devices can lose each other's contribution", e)
	case <-time.After(750 * time.Millisecond):
		// Correct: blocked on the lock.
	}

	// A DIFFERENT period must not be blocked by this lock — the lock is
	// per-period, not a global writer lock.
	otherDone := make(chan error, 1)
	go func() {
		_, e := h.store.PutStructuralSnapshot(ctx, c.accountID,
			snapshotIn(t, device, baseSnapshot("2026-01-21", 1, 1, 1), 1))
		otherDone <- e
	}()
	select {
	case e := <-otherDone:
		if e != nil {
			t.Fatalf("an upload for a DIFFERENT period failed: %v", e)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("an upload for a DIFFERENT period blocked on this period's lock — the lock is too coarse")
	}

	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("release the period lock: %v", err)
	}
	select {
	case e := <-done:
		if e != nil {
			t.Fatalf("the upload failed once the lock was released: %v", e)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the upload never completed after the lock was released")
	}

	rows, err := h.store.ListStructuralAccountDays(ctx, c.accountID, period, period)
	if err != nil {
		t.Fatalf("ListStructuralAccountDays: %v", err)
	}
	if len(rows) != 1 || rows[0].SessionCount != 4 {
		t.Fatalf("the unblocked upload did not materialize correctly: %+v", rows)
	}
}

// TestStructuralGrantRegistrationTakesTheLock is the DETERMINISTIC half of the
// F6 guard. As with F8, the racing test above cannot be relied on: two
// first-registrations fired together land milliseconds apart and the loser
// almost always reads the winner's committed row, so the test passes with the
// lock removed (verified by mutation). What is asserted here is the mechanism —
// the (account, purpose) advisory lock is taken BEFORE the read, which is
// exactly what `FOR UPDATE` could not do for a row that does not exist yet.
func TestStructuralGrantRegistrationTakesTheLock(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	c := h.login(t, "grant-lock")
	purpose := string(cloudcontract.PurposeStructuralInsights)

	holder, err := h.store.Pool().Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire holder conn: %v", err)
	}
	defer holder.Release()
	tx, err := holder.Begin(ctx)
	if err != nil {
		t.Fatalf("begin holder tx: %v", err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`,
		store.StructuralGrantLockKey(c.accountID, purpose)); err != nil {
		t.Fatalf("take the grant lock: %v", err)
	}

	in := store.StructuralGrantInput{
		Purpose:              purpose,
		DataDictionaryDigest: cloudcontract.StructuralDataDictionaryDigest(),
		SchemaVersion:        cloudcontract.StructuralSnapshotSchemaVersion,
		ConsentGeneration:    1,
		DeclaredTimezone:     "UTC",
		SourceWindowRule:     testSourceWindowRule,
	}
	done := make(chan error, 1)
	go func() {
		_, _, e := h.store.RegisterStructuralGrant(ctx, c.accountID, in)
		done <- e
	}()

	select {
	case e := <-done:
		t.Fatalf("a FIRST registration completed (%v) while the (account, purpose) lock was HELD — "+
			"the read-then-write is not serialized, so two concurrent first registrations can both see absence",
			e)
	case <-time.After(750 * time.Millisecond):
		// Correct: blocked before the read.
	}

	// While it is blocked, land a HIGHER generation directly. When the lock is
	// released the blocked caller must re-read under the lock, see generation 5,
	// and refuse — never overwrite it with its own 1.
	if _, err := h.store.Pool().Exec(ctx,
		`INSERT INTO structural_grants
		   (account_id, purpose, data_dictionary_digest, schema_version, consent_generation,
		    declared_timezone, source_window_rule)
		 VALUES ($1::uuid, $2, $3, $4, 5, 'UTC', $5)`,
		c.accountID, purpose, in.DataDictionaryDigest, in.SchemaVersion, testSourceWindowRule); err != nil {
		t.Fatalf("land the higher generation: %v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("release the grant lock: %v", err)
	}

	select {
	case e := <-done:
		if !errors.Is(e, store.ErrStructuralGenerationStale) {
			t.Fatalf("the unblocked generation-1 registration returned %v, want ErrStructuralGenerationStale", e)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the registration never completed after the lock was released")
	}

	grants, err := h.store.ListStructuralGrants(ctx, c.accountID)
	if err != nil {
		t.Fatalf("ListStructuralGrants: %v", err)
	}
	if len(grants) != 1 || grants[0].ConsentGeneration != 5 {
		t.Fatalf("the blocked generation-1 caller regressed the registration: %+v", grants)
	}
}
