package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Sentinel bodies stuffed into an action's four never-shipped body columns.
// They avoid the `key: value` shape the tool write-filter redacts, so the
// committed bytes are exactly what this test asserts on.
const (
	raiseSentinelInput     = "RAISECHAIN_RAWINPUT_9Q"
	raiseSentinelOutput    = "RAISECHAIN_RAWOUTPUT_9Q"
	raiseSentinelReasoning = "RAISECHAIN_REASONING_9Q"
	raiseSentinelErr       = "RAISECHAIN_ERRMSG_9Q"
	raiseSentinelTarget    = "RAISECHAIN_TARGET_PATH_9Q"
	raiseSentinelSource    = "RAISECHAIN_SOURCE_FILE_9Q"
)

// raiseChainGrant builds a grant carrying capture.pin (populates
// Effective.Share from the org body's share block) plus the managed
// extraction authority. tenancy selects the plane: govern.ConsentManaged for
// the enterprise raise, govern.ConsentInteractive for the individual floor.
func raiseChainGrant(now time.Time, tenancy string) *govern.Grant {
	return &govern.Grant{
		OrgKey: "ok", Generation: 2, OrgName: "Acme", KeyPinSHA256: "pin",
		ConsentMode: tenancy,
		Authority: []string{
			govern.AuthorityCapturePin,
			govern.AuthorityExtractManaged,
		},
		GrantedAt: now.Add(-time.Hour), ExpiresAt: now.Add(30 * 24 * time.Hour),
	}
}

// raiseChainStore seeds a single-action agent DB and stuffs the four body
// columns (plus target/source_file) with sentinels, so a SelectUnpushedSince
// batch can be searched for whether the bodies actually shipped.
func raiseChainStore(ctx context.Context, t *testing.T) *store.Store {
	t.Helper()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)

	ev := models.ToolEvent{
		SourceFile: "cc.jsonl", SourceEventID: "cc-1", SessionID: "sess-cc-1",
		ProjectRoot: "/inv/project-alpha", Timestamp: time.Now().UTC().Add(-time.Hour),
		Tool: models.ToolClaudeCode, Model: "claude-opus-4-7",
		ActionType: models.ActionEditFile, Target: "main.go", Success: true,
	}
	if _, err := st.Ingest(ctx, []models.ToolEvent{ev}, nil, store.IngestOptions{}); err != nil {
		t.Fatalf("seed Ingest: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`UPDATE actions SET raw_tool_input = ?, raw_tool_output = ?, preceding_reasoning = ?, error_message = ?, target = ?, source_file = ?`,
		raiseSentinelInput, raiseSentinelOutput, raiseSentinelReasoning, raiseSentinelErr, raiseSentinelTarget, raiseSentinelSource); err != nil {
		t.Fatalf("stuff actions: %v", err)
	}
	return st
}

// resolveRaiseBody runs a real node.governance body through the exact daemon
// chain — nodegov.CompileBody → govern.Resolve → lowerShareOptions — for the
// given grant, and returns the ShareOptions the push seam would run under.
func resolveRaiseBody(t *testing.T, grant *govern.Grant, body string) store.ShareOptions {
	t.Helper()
	spec, _, err := nodegov.CompileBody([]byte(body), 1<<20)
	if err != nil {
		t.Fatalf("CompileBody(%s): %v", body, err)
	}
	now := time.Now().UTC()
	eff := govern.Resolve(
		govern.Delivered{Present: true, Version: 14, BodyHash: "bh", Spec: spec},
		grant,
		govern.LiveIdentity{Enrolled: true, OrgKey: "ok", Generation: 2, KeyPinSHA256: "pin"},
		now,
	)
	// The node's own config is the metadata-only floor (bodies opted OUT).
	return lowerShareOptions(store.ShareOptions{}, eff)
}

// TestManagedRaiseChainShipsToolBodies is the end-to-end proof the P2 handoff
// flagged as a gap and the regression guard every new P5 extraction tier
// extends: a real managed grant + a node.governance body that turns a tier on
// (share.full_tool_bodies=true), run through govern.Resolve →
// lowerShareOptions → SelectUnpushedSince, actually ships the four body
// columns — and the SAME body on an INDIVIDUAL grant ships nothing. The
// govern unit tests drive RaiseBool with a synthetic Effective and the
// privacy sentinel drives the seam with ShareOptions directly; only this test
// welds the whole resolve→raise→wire chain together.
func TestManagedRaiseChainShipsToolBodies(t *testing.T) {
	ctx := context.Background()
	const body = `{"schema":2,"share":{"full_tool_bodies":true}}`
	now := time.Now().UTC()

	// --- Managed plane: the admin raises the tier remotely. ---
	managed := resolveRaiseBody(t, raiseChainGrant(now, govern.ConsentManaged), body)
	if !managed.FullToolBodies {
		t.Fatalf("managed raise chain did not flip FullToolBodies on; ShareOptions=%+v", managed)
	}
	// Bodies grant, not paths — full_content stays where the node left it.
	if managed.FullContent {
		t.Errorf("full_tool_bodies raise also raised full_content — the tiers must stay orthogonal")
	}

	batch := raiseBatchUnder(ctx, t, managed)
	for _, s := range []string{raiseSentinelInput, raiseSentinelOutput, raiseSentinelReasoning, raiseSentinelErr} {
		if !bytes.Contains(batch, []byte(s)) {
			t.Errorf("body column %q did NOT ship after a managed raise — the resolve→raise→wire chain is broken", s)
		}
	}
	// full_tool_bodies is orthogonal to the path tier: it must not ship paths.
	for _, s := range []string{raiseSentinelTarget, raiseSentinelSource} {
		if bytes.Contains(batch, []byte(s)) {
			t.Errorf("path/target %q leaked under a full_tool_bodies raise — the tier must not ship paths", s)
		}
	}

	// --- Individual plane: the identical body must be inert. ---
	individual := resolveRaiseBody(t, raiseChainGrant(now, govern.ConsentInteractive), body)
	if individual.FullToolBodies {
		t.Fatalf("individual grant was server-RAISED by the same body — the Never-server-forced guarantee is broken; ShareOptions=%+v", individual)
	}
	indBatch := raiseBatchUnder(ctx, t, individual)
	for _, s := range []string{raiseSentinelInput, raiseSentinelOutput, raiseSentinelReasoning, raiseSentinelErr} {
		if bytes.Contains(indBatch, []byte(s)) {
			t.Errorf("body column %q shipped on the INDIVIDUAL plane under a raise body — individual nodes must never ship bodies without a local opt-in", s)
		}
	}
}

// TestManagedRaiseChainFullTraces is the P5b extension: the full-traces / obs
// family (obs.traces + obs.content, the T2 structure + T3 body tiers) raises on
// a managed grant and is inert on an individual one, through the same
// resolve->raise chain. The privacy sentinel separately proves ShareOptions
// with those tiers set actually ships the obs rows; this proves the raise flips
// them.
func TestManagedRaiseChainFullTraces(t *testing.T) {
	now := time.Now().UTC()
	const body = `{"schema":2,"share":{"obs.traces":true,"obs.content":true}}`

	managed := resolveRaiseBody(t, raiseChainGrant(now, govern.ConsentManaged), body)
	if !managed.ObsTraces || !managed.ObsContent {
		t.Fatalf("managed raise did not flip the obs trace/content tiers; ShareOptions=%+v", managed)
	}

	individual := resolveRaiseBody(t, raiseChainGrant(now, govern.ConsentInteractive), body)
	if individual.ObsTraces || individual.ObsContent {
		t.Fatalf("individual grant was server-RAISED into obs trace sharing; ShareOptions=%+v", individual)
	}
}

// raiseChainGrantAuth is raiseChainGrant with an explicit authority list, so
// a test can drive a SINGLE per-tier extraction authority (Arc 4 P4a) through
// the resolve->raise chain. capture.pin is always included so the org body's
// share block populates Effective.Share.
func raiseChainGrantAuth(now time.Time, tenancy string, auth ...string) *govern.Grant {
	return &govern.Grant{
		OrgKey: "ok", Generation: 2, OrgName: "Acme", KeyPinSHA256: "pin",
		ConsentMode: tenancy,
		Authority:   append([]string{govern.AuthorityCapturePin}, auth...),
		GrantedAt:   now.Add(-time.Hour), ExpiresAt: now.Add(30 * 24 * time.Hour),
	}
}

// TestManagedRaiseChainPerTierIsolation is the P4a end-to-end proof: a managed
// grant carrying ONLY a single per-tier extraction authority raises exactly
// that tier and no sibling, through the real CompileBody -> Resolve ->
// lowerShareOptions chain. It welds the govern-unit independence property to
// the daemon wiring: granting extract.cache must not also ship tool bodies.
func TestManagedRaiseChainPerTierIsolation(t *testing.T) {
	now := time.Now().UTC()
	// The body turns TWO tiers on; the grant authorizes only cache. Only cache
	// may end up true.
	const body = `{"schema":2,"share":{"cache_detail":true,"full_tool_bodies":true}}`

	managed := resolveRaiseBody(t, raiseChainGrantAuth(now, govern.ConsentManaged, govern.AuthorityExtractCache), body)
	if !managed.CacheDetail {
		t.Fatalf("extract.cache grant did not raise CacheDetail; ShareOptions=%+v", managed)
	}
	if managed.FullToolBodies {
		t.Fatalf("extract.cache grant ALSO raised FullToolBodies — the per-tier split leaked; ShareOptions=%+v", managed)
	}

	// The umbrella extract.managed still raises both tiers (back-compat).
	umbrella := resolveRaiseBody(t, raiseChainGrantAuth(now, govern.ConsentManaged, govern.AuthorityExtractManaged), body)
	if !umbrella.CacheDetail || !umbrella.FullToolBodies {
		t.Fatalf("umbrella extract.managed did not raise both tiers; ShareOptions=%+v", umbrella)
	}

	// The same single-tier grant is inert on the individual plane.
	individual := resolveRaiseBody(t, raiseChainGrantAuth(now, govern.ConsentInteractive, govern.AuthorityExtractCache), body)
	if individual.CacheDetail || individual.FullToolBodies {
		t.Fatalf("individual grant was server-RAISED; ShareOptions=%+v", individual)
	}
}

// raiseBatchUnder runs SelectUnpushedSince under the given ShareOptions and
// returns the marshalled wire batch for sentinel searching.
func raiseBatchUnder(ctx context.Context, t *testing.T, share store.ShareOptions) []byte {
	t.Helper()
	st := raiseChainStore(ctx, t)
	batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example", share, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	return raw
}
