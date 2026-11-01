//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	"github.com/marmutapp/superbased-observer/internal/policyfam/terminalsisolation"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestReadoptCLIAndRouteReadTheSameFloors (R-035): the daemon route reads
// the floors it installed and a CLI readopt or restore reads the verified
// cache through the same sandboxOrgFloorsFor, and both see the same floors.
// Before the fix a CLI process saw none. Not parallel: process-wide floors.
func TestReadoptCLIAndRouteReadTheSameFloors(t *testing.T) {
	spec := terminalsisolation.PolicySpec{MinIsolation: vocab.ClassHWVM, MinEgress: vocab.TierNone, RequireFullCapture: true, Keys: []string{"min_isolation", "min_egress", "require_full_capture"}}
	if !spec.InForce() {
		t.Fatal("the test spec is not in force")
	}
	prevCached, prevHere := sandboxCachedIsolationSpec, policyResourceInstalledHere.Load()
	t.Cleanup(func() {
		sandboxCachedIsolationSpec = prevCached
		policyResourceInstalledHere.Store(prevHere)
		isolationFloorsClear()
	})
	sandboxCachedIsolationSpec = func(context.Context, config.Config) (terminalsisolation.PolicySpec, bool, error) {
		return spec, true, nil
	}

	// A CLI process: nothing installed in memory, the cache read decides.
	policyResourceInstalledHere.Store(false)
	isolationFloorsClear()
	cli, err := sandboxOrgFloorsFor(context.Background(), config.Default())
	if err != nil || !cli.InForce() || cli.OrgMinClass != vocab.ClassHWVM || !cli.RequireFullCapture {
		t.Fatalf("a CLI process did not see the cached floors: %+v", cli)
	}

	// The daemon: the floors it installed, whatever the cache says.
	policyResourceInstalledHere.Store(true)
	isolationFloorsPublish(orgclient.PolicyResourceResult{Spec: spec, EnforceAllowed: true, Version: 1})
	daemon, err := sandboxOrgFloorsFor(context.Background(), config.Default())
	if err != nil || !reflect.DeepEqual(cli, daemon) {
		t.Fatalf("the CLI and the daemon route read different floors:\nCLI    %+v\ndaemon %+v", cli, daemon)
	}

	// And the daemon never falls back to the cache: a withdrawal it applied
	// stays applied.
	isolationFloorsClear()
	if f, err := sandboxOrgFloorsFor(context.Background(), config.Default()); err != nil || f.InForce() {
		t.Fatalf("the daemon read the cache after it cleared its floors: %+v", f)
	}
}

// TestLoadPolicyResourceFromCache (R-035): the CLI's read-only half of the
// LKG matrix applies a verified cache only when it matches the durable
// state exactly, and never otherwise.
func TestLoadPolicyResourceFromCache(t *testing.T) {
	ctx := context.Background()
	t.Run("not enrolled", func(t *testing.T) {
		cfg, st, _ := lkgTestSetup(t, nil)
		if _, _, ok := loadPolicyResourceFromCache(ctx, cfg, st, policyfam.FamilyAdmissionInput); ok {
			t.Fatal("applied a policy on a node that is not enrolled")
		}
	})
	setup := func(t *testing.T, floor int64) (config.Config, *store.Store) {
		cfg, st, cacheDir := lkgTestSetup(t, []string{policyfam.FamilyAdmissionInput})
		orgKey := seedLKGEnrolment(t, st, "https://org.example")
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		resource := lkgSignedResource(t, priv, pub, 1, `{"mode":"enforce"}`)
		pinLKGKey(t, st, "https://org.example", pub)
		digest, err := orgcontract.PolicyResourceMessageDigest(resource)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.WithPolicyResourceFence(ctx, orgKey, policyfam.FamilyAdmissionInput,
			func(context.Context, store.PolicyResourceFence) (*store.PolicyResourceCommit, error) {
				return &store.PolicyResourceCommit{Generation: 1, FloorVersion: floor, LastVersion: floor, BodyHash: resource.BodyHash, MsgDigest: digest}, nil
			}); err != nil {
			t.Fatal(err)
		}
		writeLKGCache(t, cacheDir, orgKey, 1, resource)
		return cfg, st
	}
	t.Run("a cache matching the durable floor applies", func(t *testing.T) {
		cfg, st := setup(t, 1)
		spec, inert, ok := loadPolicyResourceFromCache(ctx, cfg, st, policyfam.FamilyAdmissionInput)
		if !ok || spec == nil || inert != "" {
			t.Fatalf("spec %v, inert %q, ok %v; want the cached spec applied", spec, inert, ok)
		}
	})
	t.Run("a cache behind the durable floor never applies", func(t *testing.T) {
		cfg, st := setup(t, 2)
		if _, _, ok := loadPolicyResourceFromCache(ctx, cfg, st, policyfam.FamilyAdmissionInput); ok {
			t.Fatal("applied a cache behind the durable floor")
		}
	})
	t.Run("a family not accepted never applies", func(t *testing.T) {
		cfg, st := setup(t, 1)
		cfg.OrgClient.Policy.AcceptFamilies = nil
		if _, _, ok := loadPolicyResourceFromCache(ctx, cfg, st, policyfam.FamilyAdmissionInput); ok {
			t.Fatal("applied a family the node does not accept")
		}
	})
}

// isolationLKGResource signs a terminals.isolation envelope (version, body)
// with priv, the shape the org serves and the node caches.
func isolationLKGResource(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, version int64, body string) orgcontract.SignedPolicyResource {
	t.Helper()
	sum := sha256.Sum256([]byte(body))
	r := orgcontract.SignedPolicyResource{
		ID: "default", Version: version, Family: policyfam.FamilyTerminalsIsolation,
		CompilerVersion: "v1", Body: body, BodyHash: hex.EncodeToString(sum[:]),
		SelectorsJSON: "{}", PublicKey: base64.RawURLEncoding.EncodeToString(pub),
		SignedAt: "2026-10-27T00:00:00Z",
	}
	return signLKGResource(t, priv, r)
}

// signLKGResource signs r in place of any signature it carries.
func signLKGResource(t *testing.T, priv ed25519.PrivateKey, r orgcontract.SignedPolicyResource) orgcontract.SignedPolicyResource {
	t.Helper()
	r.Signature = ""
	sig, err := orgcontract.SignPolicyResource(priv, r)
	if err != nil {
		t.Fatalf("SignPolicyResource: %v", err)
	}
	r.Signature = sig
	return r
}

// recordIsolationFloor records r as the durable terminals.isolation floor
// of generation 1, the state the node's accept path commits.
func recordIsolationFloor(t *testing.T, st *store.Store, orgKey string, r orgcontract.SignedPolicyResource) {
	t.Helper()
	digest, err := orgcontract.PolicyResourceMessageDigest(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WithPolicyResourceFence(context.Background(), orgKey, policyfam.FamilyTerminalsIsolation,
		func(context.Context, store.PolicyResourceFence) (*store.PolicyResourceCommit, error) {
			return &store.PolicyResourceCommit{Generation: 1, FloorVersion: r.Version, LastVersion: r.Version, BodyHash: r.BodyHash, MsgDigest: digest}, nil
		}); err != nil {
		t.Fatal(err)
	}
}

// writeIsolationCache writes r where the node caches the family.
func writeIsolationCache(t *testing.T, cacheDir, orgKey string, r orgcontract.SignedPolicyResource) {
	t.Helper()
	dir := filepath.Join(cacheDir, orgKey, "1")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, policyfam.FamilyTerminalsIsolation+".json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestCLIFloorsFailClosedWhenUnreadable (R-166, LEFT2-SBX audit finding 8):
// a CLI readopt or restore that cannot tell which organization floors are
// in force refuses with org_floors_unreadable, as the daemon route fails
// closed; it never judges against no floor. Where nothing is recorded, or
// the record is a verified withdrawal, there is no floor and no error.
// Not parallel: process-wide floors state.
func TestCLIFloorsFailClosedWhenUnreadable(t *testing.T) {
	prevHere := policyResourceInstalledHere.Load()
	t.Cleanup(func() { policyResourceInstalledHere.Store(prevHere) })
	policyResourceInstalledHere.Store(false) // a CLI process
	ctx := context.Background()
	const body = `{"min_isolation":"container"}`
	type world struct {
		cfg config.Config
		st  *store.Store
		dir string
		key string
	}
	enrolled := func(t *testing.T) world {
		cfg, st, cacheDir := lkgTestSetup(t, []string{policyfam.FamilyTerminalsIsolation})
		cfg.OrgClient.Policy.AcceptFamilies = []string{policyfam.FamilyTerminalsIsolation}
		return world{cfg: cfg, st: st, dir: cacheDir, key: seedLKGEnrolment(t, st, "https://org.example")}
	}
	keys := func(t *testing.T, w world) (ed25519.PublicKey, ed25519.PrivateKey) {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		pinLKGKey(t, w.st, "https://org.example", pub)
		return pub, priv
	}
	cases := []struct {
		name       string
		build      func(t *testing.T) config.Config
		wantErr    bool
		wantFloors bool
	}{
		{"no database file: never enrolled, no floor", func(t *testing.T) config.Config {
			cfg := config.Default()
			cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
			return cfg
		}, false, false},
		{"the database cannot be opened: unreadable", func(t *testing.T) config.Config {
			cfg := config.Default()
			cfg.Observer.DBPath = t.TempDir() // a directory, not a database
			return cfg
		}, true, false},
		{"enrolled, nothing recorded: no floor", func(t *testing.T) config.Config {
			return enrolled(t).cfg
		}, false, false},
		{"a floor recorded and its cache missing: unreadable", func(t *testing.T) config.Config {
			w := enrolled(t)
			pub, priv := keys(t, w)
			recordIsolationFloor(t, w.st, w.key, isolationLKGResource(t, priv, pub, 1, body))
			return w.cfg
		}, true, false},
		{"a floor recorded and its cache tampered: unreadable", func(t *testing.T) config.Config {
			w := enrolled(t)
			pub, priv := keys(t, w)
			r := isolationLKGResource(t, priv, pub, 1, body)
			recordIsolationFloor(t, w.st, w.key, r)
			r.Body = `{"min_isolation":"process"}`
			writeIsolationCache(t, w.dir, w.key, r)
			return w.cfg
		}, true, false},
		{"a floor recorded and its cache behind it: unreadable", func(t *testing.T) config.Config {
			w := enrolled(t)
			pub, priv := keys(t, w)
			recordIsolationFloor(t, w.st, w.key, isolationLKGResource(t, priv, pub, 2, body))
			writeIsolationCache(t, w.dir, w.key, isolationLKGResource(t, priv, pub, 1, body))
			return w.cfg
		}, true, false},
		{"a cached floor not yet recorded: unreadable", func(t *testing.T) config.Config {
			w := enrolled(t)
			pub, priv := keys(t, w)
			writeIsolationCache(t, w.dir, w.key, isolationLKGResource(t, priv, pub, 1, body))
			return w.cfg
		}, true, false},
		{"a floor recorded and its cache matching: the floor applies", func(t *testing.T) config.Config {
			w := enrolled(t)
			pub, priv := keys(t, w)
			r := isolationLKGResource(t, priv, pub, 1, body)
			recordIsolationFloor(t, w.st, w.key, r)
			writeIsolationCache(t, w.dir, w.key, r)
			return w.cfg
		}, false, true},
		{"the recorded withdrawal: no floor", func(t *testing.T) config.Config {
			w := enrolled(t)
			pub, priv := keys(t, w)
			tomb := orgcontract.NewPolicyResourceTombstone("default", policyfam.FamilyTerminalsIsolation, "u1", 2)
			tomb.PublicKey = base64.RawURLEncoding.EncodeToString(pub)
			tomb = signLKGResource(t, priv, tomb)
			recordIsolationFloor(t, w.st, w.key, tomb)
			writeIsolationCache(t, w.dir, w.key, tomb)
			return w.cfg
		}, false, false},
		{"the floor cache cannot be checked: unreadable", func(t *testing.T) config.Config {
			w := enrolled(t)
			prev := sandboxFloorCacheStat
			t.Cleanup(func() { sandboxFloorCacheStat = prev })
			sandboxFloorCacheStat = func(name string) (os.FileInfo, error) {
				return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrPermission}
			}
			return w.cfg
		}, true, false},
		{"the family not accepted: no floor", func(t *testing.T) config.Config {
			w := enrolled(t)
			pub, priv := keys(t, w)
			recordIsolationFloor(t, w.st, w.key, isolationLKGResource(t, priv, pub, 1, body))
			w.cfg.OrgClient.Policy.AcceptFamilies = nil
			return w.cfg
		}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			floors, err := sandboxOrgFloorsFor(ctx, tc.build(t))
			if tc.wantErr {
				if !errors.Is(err, errOrgFloorsUnreadable) || !strings.Contains(err.Error(), "org_floors_unreadable") {
					t.Fatalf("err %v, want the named org_floors_unreadable refusal", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if floors.InForce() != tc.wantFloors {
				t.Fatalf("floors in force %v, want %v: %+v", floors.InForce(), tc.wantFloors, floors)
			}
		})
	}
}

// TestIsolationSpecFromCache (audit F3 of the RBFIX lane): a body the
// cache applied that does not decode to the family's spec is a broken
// cache and refuses with org_floors_unreadable; an inert body or one with
// no floor in force is "no floor".
func TestIsolationSpecFromCache(t *testing.T) {
	inForce := terminalsisolation.PolicySpec{Keys: []string{"min_isolation"}}
	if !inForce.InForce() {
		t.Fatalf("fixture spec not in force: %+v", inForce)
	}
	for _, tc := range []struct {
		name      string
		raw       any
		inert     string
		wantErr   bool
		wantFloor bool
	}{
		{"the wrong type: unreadable", struct{}{}, "", true, false},
		{"nil: unreadable", nil, "", true, false},
		{"a spec in force: the floor applies", inForce, "", false, true},
		{"an inert body: no floor", inForce, "capability_missing", false, false},
		{"no floor in the spec: no floor", terminalsisolation.PolicySpec{}, "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ok, err := isolationSpecFromCache(tc.raw, tc.inert)
			if tc.wantErr {
				if !errors.Is(err, errOrgFloorsUnreadable) {
					t.Fatalf("err %v, want org_floors_unreadable", err)
				}
				return
			}
			if err != nil || ok != tc.wantFloor {
				t.Fatalf("ok %v err %v, want ok %v and no error", ok, err, tc.wantFloor)
			}
		})
	}
}
