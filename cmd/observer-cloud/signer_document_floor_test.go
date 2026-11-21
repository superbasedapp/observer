package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/entitlements"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// floorDocKey signs the test documents.
var floorDocKey = func() ed25519.PrivateKey {
	s := sha256.Sum256([]byte("raise-floor test key"))
	return ed25519.NewKeyFromSeed(s[:])
}()

// signedEntDoc is a signed, issuable team entitlements document for org at v.
func signedEntDoc(t *testing.T, org string, v int64) pc.EntitlementDocument {
	t.Helper()
	b, err := entitlements.Compose("team", 1, org, time.Now().Unix(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	sig, kid, err := pc.SignDocument(floorDocKey, pc.KindEntitlements, org, v, raw)
	if err != nil {
		t.Fatal(err)
	}
	return pc.EntitlementDocument{Version: v, Body: raw, Signature: sig, KeyID: kid}
}

// recordFiles serves record files by name from memory.
func recordFiles(files map[string]string) func(string) ([]byte, error) {
	return func(name string) ([]byte, error) {
		raw, ok := files[name]
		if !ok {
			return nil, os.ErrNotExist
		}
		return []byte(raw), nil
	}
}

// TestRaiseFloorVerb drives `signer document raise-floor` (W16-D6) through
// its run function against a real PostgreSQL with the operator role: the
// refusals, a dry run that writes nothing, an apply that raises exactly the
// streams the record is ahead on, a repeated run that changes nothing, a
// later record that never lowers a floor, the store refusing a version at
// or below the floor, and the history naming the operator and the record's
// sha256.
func TestRaiseFloorVerb(t *testing.T) {
	t.Parallel()
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()
	app, err := store.NewForRole(pool, store.RoleApp)
	if err != nil {
		t.Fatal(err)
	}
	api, err := store.NewForRole(pool, store.RoleAPI)
	if err != nil {
		t.Fatal(err)
	}
	var owner string
	if err := pool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING account_id::text`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	var orgs [2]string
	for i, slug := range []string{"floor-a", "floor-b"} {
		o, err := api.ProvisionOrg(ctx, owner, store.ProvisionOrgInput{
			Kind: store.OrgTeam, Slug: slug, DisplayName: slug, Tenancy: store.TenancyManaged,
		})
		if err != nil {
			t.Fatal(err)
		}
		orgs[i] = o.OrgID
	}
	orgA, orgB := orgs[0], orgs[1]
	now := time.Now().UTC().Truncate(time.Second)
	// The restored database: org A at v100, org B at v60; no availability.
	for org, v := range map[string]int64{orgA: 100, orgB: 60} {
		if err := app.InsertEntitlementDocument(ctx, org, signedEntDoc(t, org, v), store.IssuedBySystem, now); err != nil {
			t.Fatal(err)
		}
	}
	// The signer's record: ahead on A and on availability, behind on B.
	record := fmt.Sprintf(`{"v":1,"versions":{"entitlements":{%q:200,%q:50},"availability":{"platform":5}}}`, orgA, orgB)
	sum := sha256.Sum256([]byte(record))
	digest := hex.EncodeToString(sum[:])
	files := recordFiles(map[string]string{
		"versions.json":  record,
		"later.json":     fmt.Sprintf(`{"v":1,"versions":{"entitlements":{%q:150}}}`, orgA),
		"empty.json":     `{"v":1,"versions":{}}`,
		"not-a-record":   `{"hello":"world"}`,
		"bad-entry.json": `{"v":1,"versions":{"availability":{"other":1}}}`,
	})

	t.Run("refusals write nothing", func(t *testing.T) {
		for name, req := range map[string]raiseFloorRequest{
			"no record":        {Operator: "ops"},
			"no operator":      {RecordPath: "versions.json"},
			"missing file":     {RecordPath: "nope.json", Operator: "ops", Apply: true},
			"not a record":     {RecordPath: "not-a-record", Operator: "ops", Apply: true},
			"bad entry":        {RecordPath: "bad-entry.json", Operator: "ops", Apply: true},
			"bad operator":     {RecordPath: "versions.json", Operator: "two words", Apply: true},
			"operator too big": {RecordPath: "versions.json", Operator: strings.Repeat("x", 65), Apply: true},
		} {
			var out bytes.Buffer
			if err := runRaiseFloor(ctx, &out, app, req, files, now); err == nil {
				t.Errorf("%s: accepted (%s)", name, out.String())
			}
		}
		if h, err := app.DocumentFloorHistory(ctx); err != nil || len(h) != 0 {
			t.Fatalf("history after refusals = %v, %v; want empty", h, err)
		}
	})

	var out bytes.Buffer
	if err := runRaiseFloor(ctx, &out, app, raiseFloorRequest{RecordPath: "empty.json", Operator: "ops"}, files, now); err != nil ||
		!strings.Contains(out.String(), "no change") {
		t.Fatalf("empty record = %q, %v; want no change", out.String(), err)
	}

	// Dry run: says what it would do, writes nothing.
	out.Reset()
	if err := runRaiseFloor(ctx, &out, app, raiseFloorRequest{RecordPath: "versions.json", Operator: "ops"}, files, now); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"dry run", digest, "2 floors would be raised", "would raise", "database is at or past the record"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("dry run output lacks %q:\n%s", want, out.String())
		}
	}
	if h, _ := app.DocumentFloorHistory(ctx); len(h) != 0 {
		t.Fatalf("dry run wrote %d floor rows", len(h))
	}

	// Apply: A and availability raised, B untouched.
	out.Reset()
	if err := runRaiseFloor(ctx, &out, app, raiseFloorRequest{RecordPath: "versions.json", Operator: "santosh", Apply: true}, files, now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "2 floors raised") {
		t.Fatalf("apply output:\n%s", out.String())
	}
	for _, c := range []struct {
		kind  pc.DocumentKind
		scope string
		want  int64
	}{{pc.KindEntitlements, orgA, 200}, {pc.KindEntitlements, orgB, 0}, {pc.KindAvailability, pc.AvailabilityScope, 5}} {
		if got, err := app.DocumentVersionFloor(ctx, c.kind, c.scope); err != nil || got != c.want {
			t.Errorf("floor %s/%s = %d, %v; want %d", c.kind, c.scope, got, err, c.want)
		}
	}
	h, err := app.DocumentFloorHistory(ctx)
	if err != nil || len(h) != 2 {
		t.Fatalf("history = %v, %v; want 2 rows", h, err)
	}
	for _, r := range h {
		if r.Operator != "santosh" || r.RecordSHA256 != digest {
			t.Errorf("floor row %+v does not name the operator and the record digest", r)
		}
	}

	// Idempotent: the same record again, dry run and apply, changes nothing.
	for _, apply := range []bool{false, true} {
		out.Reset()
		if err := runRaiseFloor(ctx, &out, app, raiseFloorRequest{RecordPath: "versions.json", Operator: "santosh", Apply: apply}, files, now); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "no change: the database is at or past the record for every entry") {
			t.Errorf("repeat (apply=%v) output:\n%s", apply, out.String())
		}
	}
	// A record behind the floor never lowers it.
	out.Reset()
	if err := runRaiseFloor(ctx, &out, app, raiseFloorRequest{RecordPath: "later.json", Operator: "santosh", Apply: true}, files, now); err != nil {
		t.Fatal(err)
	}
	if got, _ := app.DocumentFloorHistory(ctx); len(got) != 2 || !strings.Contains(out.String(), "a floor at or past the record is in force") {
		t.Fatalf("a lower record changed the floors (%d rows):\n%s", len(got), out.String())
	}

	// The store refuses a version at or below the floor and takes the next.
	err = app.InsertEntitlementDocument(ctx, orgA, signedEntDoc(t, orgA, 200), store.IssuedBySystem, now)
	if !errors.Is(err, pc.ErrVersionNotNewer) {
		t.Fatalf("insert at the floor = %v, want ErrVersionNotNewer", err)
	}
	if err := app.InsertEntitlementDocument(ctx, orgA, signedEntDoc(t, orgA, 201), store.IssuedBySystem, now); err != nil {
		t.Fatalf("insert at floor + 1: %v", err)
	}

	// The history verb prints both rows.
	out.Reset()
	if err := runFloorHistory(ctx, &out, app); err != nil || strings.Count(out.String(), "by santosh") != 2 {
		t.Fatalf("history = %q, %v", out.String(), err)
	}
}
