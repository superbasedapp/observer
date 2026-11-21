package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// postureOrgNode is a throwaway node directory: config, DB, org bundle
// cache and user policy all under one temp dir.
type postureOrgNode struct {
	dir, cp, dbPath, bundle, user string
}

func newPostureOrgNode(t *testing.T, guardBlock string) postureOrgNode {
	t.Helper()
	dir := t.TempDir()
	n := postureOrgNode{
		dir: dir, cp: filepath.Join(dir, "config.toml"), dbPath: filepath.Join(dir, "observer.db"),
		bundle: filepath.Join(dir, "org-policy-bundle.json"), user: filepath.Join(dir, "guard-policy.toml"),
	}
	writeFileT(t, n.cp, fmt.Sprintf("[observer]\ndb_path = %q\n%s\n[guard.rules]\norg_bundle = %q\nuser_policy = %q\n[guard.prompt]\nenabled = false\n",
		n.dbPath, guardBlock, n.bundle, n.user))
	return n
}

// forgeOpenPosture writes a signed-looking "not enforced" posture whose MAC
// was not made with the daemon's key (so the hook ignores it).
func forgeOpenPosture(t *testing.T, cp string) {
	t.Helper()
	writePosture(t, cp, enforcedPosture)
	data, err := json.Marshal(guardposture.Posture{Schema: guardposture.Schema, Source: "local", MAC: strings.Repeat("ab", 32)})
	if err != nil {
		t.Fatal(err)
	}
	writeFileT(t, guardposture.PosturePath(cp), string(data))
}

func writeOrgBundle(t *testing.T, path, bundleTOML string) (pub ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeFileT(t, path, signedGuardBundleJSON(t, priv, pub, 1, bundleTOML))
	return pub
}

// seedPin records an enrolment key pin in the node DB the way the org
// client does (guard_policy_state, path suffix "#policy-key").
func seedPin(t *testing.T, dbPath, pin string) {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := store.New(database).RecordGuardPolicyState(context.Background(), store.GuardPolicyStateRow{
		Layer: "org", Path: "https://org.test/x" + orgclient.PolicyKeyPinSuffix, Version: "1", ContentHash: pin, LoadedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
}

// TestPostureFallbackSeesOrgAndPerRuleEnforcement pins the Sol A2-02
// follow-up: when the posture is ignored, the hook computes enforcement
// from the SAME inputs as the daemon (org bundle under the enrolment pin,
// per-rule enforce, tenancy), so a forged open posture cannot open a gate
// that only the org or a per-rule enforce closes, and a guard-off
// individual node stays open.
func TestPostureFallbackSeesOrgAndPerRuleEnforcement(t *testing.T) {
	const observe = "[guard]\nenabled = true\nmode = \"observe\""
	cases := []struct {
		name  string
		guard string
		setup func(t *testing.T, n postureOrgNode)
		want  bool
	}{
		{"forged open posture + org bundle that enforces: closed", observe, func(t *testing.T, n postureOrgNode) {
			writeOrgBundle(t, n.bundle, "[[override]]\nrule = \"R-101\"\nenforce = true\n")
		}, true},
		{"forged open posture + per-rule enforce = true: closed", observe, func(t *testing.T, n postureOrgNode) {
			writeFileT(t, n.user, "[[override]]\nrule = \"R-101\"\nenforce = true\n")
		}, true},
		{"individual node, no bundle, guard off: open", "[guard]\nenabled = false", func(*testing.T, postureOrgNode) {}, false},
		{"org bundle signed under the enrolment pin, not enforcing: open", observe, func(t *testing.T, n postureOrgNode) {
			pub := writeOrgBundle(t, n.bundle, "[[override]]\nrule = \"R-172\"\noverridable = true\n")
			seedPin(t, n.dbPath, pinOf(pub))
		}, false},
		{"bundle signed by another key than the pin, individual node: counts as absent", observe, func(t *testing.T, n postureOrgNode) {
			writeOrgBundle(t, n.bundle, "[[override]]\nrule = \"R-101\"\nenforce = true\n")
			seedPin(t, n.dbPath, strings.Repeat("0", 64))
		}, false},
		{"unverifiable bundle, tenancy unreadable (no DB): counts as enforcing", observe, func(t *testing.T, n postureOrgNode) {
			writeFileT(t, n.bundle, "{not a bundle")
			if err := os.Mkdir(n.dbPath, 0o700); err != nil { // a directory: the DB cannot open
				t.Fatal(err)
			}
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := newPostureOrgNode(t, tc.guard)
			tc.setup(t, n)
			forgeOpenPosture(t, n.cp)
			if got := resolveHookFailurePlan("claude-code", "pre-tool", n.cp).FailClosed; got != tc.want {
				t.Errorf("tool gate FailClosed = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPostureFallbackLatency measures the fallback against the hook budget
// (run with -v). The first call opens a fresh DB (migrations); production
// hooks open the daemon's existing DB, which the later calls model.
func TestPostureFallbackLatency(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, n postureOrgNode)
	}{
		{"valid bundle under the pin", func(t *testing.T, n postureOrgNode) {
			pub := writeOrgBundle(t, n.bundle, "[[override]]\nrule = \"R-101\"\nenforce = true\n")
			seedPin(t, n.dbPath, pinOf(pub))
		}},
		{"unverifiable bundle (tenancy read)", func(t *testing.T, n postureOrgNode) {
			writeOrgBundle(t, n.bundle, "[[override]]\nrule = \"R-101\"\nenforce = true\n")
			seedPin(t, n.dbPath, strings.Repeat("0", 64))
		}},
	} {
		n := newPostureOrgNode(t, "[guard]\nenabled = true\nmode = \"observe\"")
		tc.setup(t, n) // seedPin creates and migrates the DB first
		forgeOpenPosture(t, n.cp)
		const iters = 5
		var worst, total time.Duration
		for i := 0; i < iters; i++ {
			start := time.Now()
			resolveHookFailurePlan("claude-code", "pre-tool", n.cp)
			d := time.Since(start)
			total += d
			if d > worst {
				worst = d
			}
		}
		t.Logf("posture fallback, %s: mean %v, worst %v over %d calls (existing DB)", tc.name, total/iters, worst, iters)
		if worst > defaultHookMaxRuntime/4 {
			t.Errorf("%s: worst %v exceeds a quarter of the hook budget %v", tc.name, worst, defaultHookMaxRuntime)
		}
	}
	// A node whose daemon never ran: there is no DB, so the fallback reads
	// no pin or tenancy and creates nothing (migrating a fresh DB inside
	// hookFallbackDBTimeout could overrun and roll back).
	n := newPostureOrgNode(t, "[guard]\nenabled = true\nmode = \"observe\"")
	writeOrgBundle(t, n.bundle, "[[override]]\nrule = \"R-101\"\nenforce = true\n")
	forgeOpenPosture(t, n.cp)
	start := time.Now()
	resolveHookFailurePlan("claude-code", "pre-tool", n.cp)
	t.Logf("posture fallback, no DB yet: %v", time.Since(start))
	if _, err := os.Stat(n.dbPath); !os.IsNotExist(err) {
		t.Errorf("the fallback created the node DB (stat err %v); it must only read an existing one", err)
	}
}

func pinOf(pub ed25519.PublicKey) string { return orgcontract.PublicKeyPinHash(pub) }
