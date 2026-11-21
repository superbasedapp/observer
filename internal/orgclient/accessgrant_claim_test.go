package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// claimFixture is an enrolled node whose grant cache holds one verified
// document, plus a raw handle on the same database file for tampering (a
// second connection, which is what another process on the machine is).
type claimFixture struct {
	c    *Client
	s    *store.Store
	raw  *sql.DB
	path string
	priv ed25519.PrivateKey
	now  time.Time
}

func newClaimFixture(t *testing.T, grants ...orgcontract.AccessGrantWire) claimFixture {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "agent.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	s := store.New(database)
	gs := newGrantRailServer(t)
	if err := s.WriteEnrolment(ctx, store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: gs.srv.URL,
		UserID: "scim-42", UserEmail: "dev@acme.example",
		EnrolledAt: time.Now().UTC().Format(time.RFC3339), BearerKeyID: "test",
	}); err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s, &memBearerStore{bearer: "bearer-xyz"})
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	gs.set(200, signGrants(t, priv, "org-1", testGrantSubject, 1, now, grants...))
	if out, err := c.FetchAccessGrants(ctx); err != nil || out.State != GrantFetchApplied {
		t.Fatalf("fetch: %+v %v", out, err)
	}
	raw, err := dbtemplate.Open(ctx, db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	return claimFixture{c: c, s: s, raw: raw, path: path, priv: priv, now: now}
}

func denyQuery() accessgrant.Query {
	return accessgrant.Query{RuleID: "R-171", Lane: accessgrant.LaneTool, OperandHash: "op-1", Decision: accessgrant.DecisionDeny}
}

// TestClaimAccessGrantConsumesOncePerCall: every allowed call counts exactly
// one use; past max_uses nothing is granted and nothing more is counted.
func TestClaimAccessGrantConsumesOncePerCall(t *testing.T) {
	ctx := context.Background()
	g := exemptGrant(7, time.Now(), 2*time.Hour)
	g.MaxUses = 2
	f := newClaimFixture(t, g)
	for i, wantLeft := range []int64{1, 0} {
		cl := ClaimAccessGrant(ctx, f.s, denyQuery(), time.Now())
		if !cl.OK || cl.Hit.GrantID != 7 || cl.Hit.UsesLeft != wantLeft {
			t.Fatalf("claim %d: %+v", i, cl)
		}
	}
	if cl := ClaimAccessGrant(ctx, f.s, denyQuery(), time.Now()); cl.OK {
		t.Fatalf("a third claim was granted past max_uses: %+v", cl)
	}
	var used int64
	if err := f.raw.QueryRow(`SELECT uses_used FROM org_access_grants WHERE grant_id = 7`).Scan(&used); err != nil || used != 2 {
		t.Fatalf("uses_used = %d (%v), want 2", used, err)
	}
	// A query the grant does not cover consumes nothing.
	g2 := exemptGrant(8, time.Now(), time.Hour)
	f2 := newClaimFixture(t, g2)
	if cl := ClaimAccessGrant(ctx, f2.s, accessgrant.Query{RuleID: "R-999", Decision: accessgrant.DecisionDeny}, time.Now()); cl.OK {
		t.Fatalf("another rule claimed: %+v", cl)
	}
	if err := f2.raw.QueryRow(`SELECT uses_used FROM org_access_grants WHERE grant_id = 8`).Scan(&used); err != nil || used != 0 {
		t.Fatalf("a miss counted a use: %d %v", used, err)
	}
}

// TestClaimAccessGrantReadsTheSignedBodyNotTheRows: the decoded rows are a
// same-user-writable copy. A row widened or forged after the verified fetch
// changes nothing; only the signed body decides what a grant covers.
func TestClaimAccessGrantReadsTheSignedBodyNotTheRows(t *testing.T) {
	ctx := context.Background()
	g := exemptGrant(7, time.Now(), 2*time.Hour)
	g.OperandHash = "op-1"
	f := newClaimFixture(t, g)
	other := denyQuery()
	other.OperandHash = "op-2"
	if cl := ClaimAccessGrant(ctx, f.s, other, time.Now()); cl.OK {
		t.Fatal("exact grant matched another operand")
	}
	// Widen the stored row to rule-wide and forge a second, perpetual grant.
	if _, err := f.raw.Exec(`UPDATE org_access_grants SET operand_hash = '' WHERE grant_id = 7`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec(`INSERT INTO org_access_grants (grant_id, type, effect, rule_id, starts_at_ns, doc_version)
		VALUES (99, 'guard_exemption', 'exempt', 'R-171', 0, 1)`); err != nil {
		t.Fatal(err)
	}
	if cl := ClaimAccessGrant(ctx, f.s, other, time.Now()); cl.OK {
		t.Fatalf("a tampered row widened the grant: %+v", cl)
	}
	if cl := ClaimAccessGrant(ctx, f.s, denyQuery(), time.Now()); !cl.OK || cl.Hit.GrantID != 7 {
		t.Fatalf("the signed grant should still cover its own operand: %+v", cl)
	}
}

// TestClaimAccessGrantFailsClosedWhenUnverified: a cache whose body, signature
// or key no longer verifies grants nothing and says so.
func TestClaimAccessGrantFailsClosedWhenUnverified(t *testing.T) {
	ctx := context.Background()
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	cases := []struct {
		name   string
		tamper func(t *testing.T, f claimFixture)
	}{
		{"body edited", func(t *testing.T, f claimFixture) {
			mustExec(t, f.raw, `UPDATE org_access_grant_state SET body = replace(body, 'R-171', 'R-172')`)
		}},
		{"signature dropped", func(t *testing.T, f claimFixture) {
			mustExec(t, f.raw, `UPDATE org_access_grant_state SET signature = ''`)
		}},
		{"re-signed under another key while the enrolment key is pinned", func(t *testing.T, f claimFixture) {
			// The enrolment trust root: the key the org delivered at enrolment.
			pub := f.priv.Public().(ed25519.PublicKey)
			if _, err := f.c.recordEnrolmentKeyMaterial(ctx, mustEnrolURL(t, f.s), base64.RawURLEncoding.EncodeToString(pub)); err != nil {
				t.Fatal(err)
			}
			forged := signGrants(t, otherPriv, "org-1", testGrantSubject, 9, time.Now(), exemptGrant(7, time.Now(), 30*24*time.Hour))
			otherPub := base64.StdEncoding.EncodeToString(otherPriv.Public().(ed25519.PublicKey))
			mustExec(t, f.raw, `UPDATE org_access_grant_state SET body = ?, body_hash = ?, signature = ?, server_pubkey = ?, version = 9`,
				forged.Body, forged.BodyHash, forged.Signature, otherPub)
		}},
		// C156-27 / M3-02: a document signed for ANOTHER machine of the same
		// member (a cache copied between machines) passed the old user-prefix
		// check; the subject is now compared exactly.
		{"subject of another machine of the same member", func(t *testing.T, f claimFixture) {
			forged := signGrants(t, f.priv, "org-1", "scim-42|machine-a", 1, time.Now(), exemptGrant(7, time.Now(), time.Hour))
			mustExec(t, f.raw, `UPDATE org_access_grant_state SET subject = 'scim-42|machine-a', body = ?, body_hash = ?, signature = ?`,
				forged.Body, forged.BodyHash, forged.Signature)
		}},
		{"subject of another member", func(t *testing.T, f claimFixture) {
			forged := signGrants(t, f.priv, "org-1", "mallory|", 1, time.Now(), exemptGrant(7, time.Now(), time.Hour))
			mustExec(t, f.raw, `UPDATE org_access_grant_state SET subject = 'mallory|', body = ?, body_hash = ?, signature = ?`,
				forged.Body, forged.BodyHash, forged.Signature)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newClaimFixture(t, exemptGrant(7, time.Now(), 2*time.Hour))
			if cl := ClaimAccessGrant(ctx, f.s, denyQuery(), time.Now()); !cl.OK {
				t.Fatalf("baseline claim failed: %+v", cl)
			}
			c.tamper(t, f)
			cl := ClaimAccessGrant(ctx, f.s, denyQuery(), time.Now())
			if cl.OK || !cl.Unverified {
				t.Fatalf("tampered cache: %+v, want no hit and Unverified", cl)
			}
			view, _, err := f.c.AccessGrantsView(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// M4-09: the surface must be able to tell an unverified cache
			// from a confirmed one.
			if !view.Unverified {
				t.Fatalf("an unverified cache is not flagged: %+v", view)
			}
			for _, g := range view.Grants {
				if g.Honoured {
					t.Fatalf("the dashboard view honours an unverified grant: %+v", g)
				}
			}
		})
	}
}

// TestClaimAccessGrantOfflineWindowIsTheSignedOne pins C156-37: the offline
// window and the server clock are read from the SIGNED body. Widening the
// unsigned max_offline_s column no longer keeps a grant honoured past the
// org's window.
func TestClaimAccessGrantOfflineWindowIsTheSignedOne(t *testing.T) {
	ctx := context.Background()
	f := newClaimFixture(t, exemptGrant(7, time.Now(), 30*24*time.Hour))
	// The signed window is 86400 s. Pretend the last verified sync was two
	// days ago and widen the column to seven days.
	old := time.Now().Add(-48 * time.Hour).UnixNano()
	mustExec(t, f.raw, `UPDATE org_access_grant_state SET max_offline_s = ?, last_verified_ns = ?`, 7*86400, old)
	if cl := ClaimAccessGrant(ctx, f.s, denyQuery(), time.Now()); cl.OK {
		t.Fatalf("an edited offline window kept the grant honoured: %+v", cl)
	}
}

// TestClaimAccessGrantLockedRule: a rule the node's org bundle locks is only
// reachable by a grant issued under the locked-rule approval rule.
func TestClaimAccessGrantLockedRule(t *testing.T) {
	ctx := context.Background()
	plain := exemptGrant(7, time.Now(), time.Hour)
	f := newClaimFixture(t, plain)
	q := denyQuery()
	q.RuleLocked = true
	if cl := ClaimAccessGrant(ctx, f.s, q, time.Now()); cl.OK || !cl.LockRefused {
		t.Fatalf("a grant without lock override reached a locked rule: %+v", cl)
	}
	over := exemptGrant(8, time.Now(), time.Hour)
	over.LockOverride = true
	f2 := newClaimFixture(t, over)
	if cl := ClaimAccessGrant(ctx, f2.s, q, time.Now()); !cl.OK || cl.Hit.GrantID != 8 {
		t.Fatalf("a lock-override grant should reach the locked rule: %+v", cl)
	}
}

// TestClaimAccessGrantRaceAcrossProcesses: two (and more) hook PROCESSES
// claim the same grant at once over one database file. Exactly as many calls
// are allowed as there were uses left; the counter ends at the cap.
func TestClaimAccessGrantRaceAcrossProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns child processes")
	}
	for _, c := range []struct {
		procs   int
		maxUses int64
	}{{2, 1}, {6, 2}} {
		t.Run(fmt.Sprintf("%d procs %d uses", c.procs, c.maxUses), func(t *testing.T) {
			g := exemptGrant(7, time.Now(), 2*time.Hour)
			g.MaxUses = c.maxUses
			f := newClaimFixture(t, g)
			start := filepath.Join(t.TempDir(), "go")
			cmds := make([]*exec.Cmd, c.procs)
			outs := make([]*strings.Builder, c.procs)
			for i := range cmds {
				cmd := exec.Command(os.Args[0], "-test.run=^TestClaimAccessGrantChildProcess$", "-test.count=1")
				cmd.Env = append(os.Environ(), "G3_CLAIM_DB="+f.path, "G3_CLAIM_START="+start)
				outs[i] = &strings.Builder{}
				cmd.Stdout, cmd.Stderr = outs[i], outs[i]
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				cmds[i] = cmd
			}
			if err := os.WriteFile(start, []byte("go"), 0o600); err != nil {
				t.Fatal(err)
			}
			granted := 0
			for i, cmd := range cmds {
				if err := cmd.Wait(); err != nil {
					t.Fatalf("child %d: %v\n%s", i, err, outs[i])
				}
				switch {
				case strings.Contains(outs[i].String(), "CLAIM=granted"):
					granted++
				case strings.Contains(outs[i].String(), "CLAIM=refused"):
				default:
					t.Fatalf("child %d said nothing useful:\n%s", i, outs[i])
				}
			}
			if int64(granted) != c.maxUses {
				t.Fatalf("%d calls were allowed with %d uses", granted, c.maxUses)
			}
			var used int64
			if err := f.raw.QueryRow(`SELECT uses_used FROM org_access_grants WHERE grant_id = 7`).Scan(&used); err != nil || used != c.maxUses {
				t.Fatalf("uses_used = %d (%v), want %d", used, err, c.maxUses)
			}
		})
	}
}

// TestClaimAccessGrantChildProcess is the hook-process half of the race test;
// it does nothing unless the parent set G3_CLAIM_DB.
func TestClaimAccessGrantChildProcess(t *testing.T) {
	path := os.Getenv("G3_CLAIM_DB")
	if path == "" {
		t.Skip("child half of TestClaimAccessGrantRaceAcrossProcesses")
	}
	start := os.Getenv("G3_CLAIM_START")
	for deadline := time.Now().Add(20 * time.Second); ; {
		if _, err := os.Stat(start); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("start signal never came")
		}
		time.Sleep(2 * time.Millisecond)
	}
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	cl := ClaimAccessGrant(ctx, store.New(database), denyQuery(), time.Now())
	if cl.OK {
		fmt.Println("CLAIM=granted uses_left=" + strconv.FormatInt(cl.Hit.UsesLeft, 10))
	} else {
		fmt.Printf("CLAIM=refused %+v\n", cl)
	}
}

func mustExec(t *testing.T, raw *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := raw.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func mustEnrolURL(t *testing.T, s *store.Store) string {
	t.Helper()
	enr, err := s.LoadEnrolment(context.Background())
	if err != nil || enr == nil {
		t.Fatalf("enrolment: %v", err)
	}
	return enr.OrgServerURL
}

// TestClaimAccessGrantWhileTheDatabaseIsBusy pins the 2026-11-13 operator
// report: a hook's grant question asked while the daemon held the write lock
// read as "no grant" with nothing recorded, so a rule the developer held a
// perpetual grant for still stopped them now and then, and they asked for
// the same grant again. The decision is made from reads; only a use-limited
// grant needs its write, and a question that cannot be answered says so.
func TestClaimAccessGrantWhileTheDatabaseIsBusy(t *testing.T) {
	cases := []struct {
		name     string
		maxUses  int64
		consume  bool
		wantOK   bool
		wantErr  bool
		wantUsed int64
	}{
		{"unlimited grant, claim: applies, the local counter is skipped", 0, true, true, false, 0},
		{"unlimited grant, peek: applies, writes nothing", 0, false, true, false, 0},
		{"use-limited grant, peek: applies, writes nothing", 3, false, true, false, 0},
		{"use-limited grant, claim: no grant, and the failure is reported", 3, true, false, true, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			g := exemptGrant(7, time.Now(), 2*time.Hour)
			g.MaxUses = c.maxUses
			f := newClaimFixture(t, g)
			// The hook's own handle: a short busy wait, as cmd/observer opens it.
			hook, err := sql.Open("sqlite", "file:"+f.path+"?_pragma=busy_timeout(50)")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = hook.Close() }()
			hook.SetMaxOpenConns(1)
			// Another process (the daemon) holds the write lock throughout.
			writer, err := f.raw.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = writer.Close() }()
			if _, err := writer.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
				t.Fatal(err)
			}
			defer func() { _, _ = writer.ExecContext(ctx, `ROLLBACK`) }()

			qctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			var cl GrantClaim
			if c.consume {
				cl = ClaimAccessGrant(qctx, store.New(hook), denyQuery(), time.Now())
			} else {
				cl = PeekAccessGrant(qctx, store.New(hook), denyQuery(), time.Now())
			}
			if cl.OK != c.wantOK || (cl.Err != nil) != c.wantErr {
				t.Fatalf("claim = %+v, want ok=%v err=%v", cl, c.wantOK, c.wantErr)
			}
			if c.wantOK && cl.Hit.GrantID != 7 {
				t.Fatalf("hit = %+v, want G-7", cl.Hit)
			}
			var used int64
			if err := hook.QueryRow(`SELECT uses_used FROM org_access_grants WHERE grant_id = 7`).Scan(&used); err != nil || used != c.wantUsed {
				t.Fatalf("uses_used = %d (%v), want %d", used, err, c.wantUsed)
			}
		})
	}
}

// TestClaimAccessGrantNamesAScopeMiss: a grant for the rule that is pinned to
// another project is reported, not silently skipped.
func TestClaimAccessGrantNamesAScopeMiss(t *testing.T) {
	ctx := context.Background()
	g := exemptGrant(7, time.Now(), 2*time.Hour)
	g.ProjectRootHash = "project-a"
	f := newClaimFixture(t, g)
	q := denyQuery()
	for _, c := range []struct {
		name, project string
		ok            bool
		miss          int64
	}{
		{"the granted project", "project-a", true, 0},
		{"another project", "project-b", false, 7},
		{"no project on the event", "", false, 7},
	} {
		q.ProjectRootHash = c.project
		for _, cl := range []GrantClaim{PeekAccessGrant(ctx, f.s, q, time.Now()), ClaimAccessGrant(ctx, f.s, q, time.Now())} {
			if cl.OK != c.ok || cl.ScopeMissID != c.miss || cl.Err != nil {
				t.Errorf("%s: %+v, want ok=%v scope miss G-%d", c.name, cl, c.ok, c.miss)
			}
		}
	}
}
