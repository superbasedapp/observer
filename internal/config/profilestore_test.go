package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProfileStore_CRUDAndResolve covers the user-profile lifecycle:
// create from a built-in, edit a key, resolve with partial-merge +
// enablement split, stamp changes on edit, delete.
func TestProfileStore_CRUDAndResolve(t *testing.T) {
	ps := ProfileStore{Dir: filepath.Join(t.TempDir(), "profiles")}

	if err := ps.Create("my-tuning", "codex-safe"); err != nil {
		t.Fatal(err)
	}
	names := ps.Names()
	found := false
	for _, n := range names {
		if n == "my-tuning" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Names() missing my-tuning: %v", names)
	}
	if err := ps.Validate("my-tuning"); err != nil {
		t.Fatal(err)
	}

	master := Default().Compression
	master.Conversation.Enabled = true
	resolved, stamp1, err := ps.ResolveCompression(master, "my-tuning")
	if err != nil {
		t.Fatal(err)
	}
	// Seeded from codex-safe: its tuned values came along.
	if resolved.Conversation.PreserveLastN != 15 {
		t.Errorf("seeded preserve_last_n: got %d want 15", resolved.Conversation.PreserveLastN)
	}
	if stamp1 == "" {
		t.Error("user profile must carry a content stamp")
	}

	// Edit a key; resolution + stamp follow.
	if err := ps.SetKey("my-tuning", "compression.conversation.preserve_last_n", "30"); err != nil {
		t.Fatal(err)
	}
	resolved, stamp2, err := ps.ResolveCompression(master, "my-tuning")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Conversation.PreserveLastN != 30 {
		t.Errorf("edited preserve_last_n: got %d want 30", resolved.Conversation.PreserveLastN)
	}
	if stamp2 == stamp1 {
		t.Error("stamp must change on edit (hot-reload key input)")
	}
	// Enablement split holds for user profiles too.
	masterOff := master
	masterOff.Conversation.Enabled = false
	offResolved, _, err := ps.ResolveCompression(masterOff, "my-tuning")
	if err != nil {
		t.Fatal(err)
	}
	if offResolved.Conversation.Enabled {
		t.Error("user profile must not flip the master conversation switch")
	}

	if err := ps.Delete("my-tuning"); err != nil {
		t.Fatal(err)
	}
	if err := ps.Validate("my-tuning"); err == nil {
		t.Error("deleted profile must no longer validate")
	}
}

// TestProfileStore_SetKeyPreservesPresence pins the D16 fix: SetKey
// touches ONLY the dotted key. The pre-fix re-marshal materialized
// every key the file never mentioned as an explicit zero
// (summary_model = "", stash dir = "", …), which then PINNED over
// master fallthrough per the explicit-zeros rule — silently breaking
// partial-overlay semantics and single-variable A/B discipline.
func TestProfileStore_SetKeyPreservesPresence(t *testing.T) {
	ps := ProfileStore{Dir: filepath.Join(t.TempDir(), "profiles")}
	if err := ps.Create("cand", "codex-safe"); err != nil {
		t.Fatal(err)
	}
	if err := ps.SetKey("cand", "compression.conversation.target_ratio", "0.9"); err != nil {
		t.Fatal(err)
	}
	body, err := ps.Read("cand")
	if err != nil {
		t.Fatal(err)
	}
	for _, sentinel := range []string{"summary_model", "auth_cache_size", "threshold_tokens"} {
		if strings.Contains(string(body), sentinel) {
			t.Errorf("SetKey materialized %q — keys the file never set must stay absent:\n%s", sentinel, body)
		}
	}

	// Resolution proof: a master-only param (rolling summary model)
	// still falls through after the edit, and the edit applied.
	master := Default().Compression
	master.Conversation.Enabled = true
	master.Conversation.Rolling.SummaryModel = "claude-haiku-4-5"
	resolved, _, err := ps.ResolveCompression(master, "cand")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Conversation.TargetRatio != 0.9 {
		t.Errorf("edit lost: target_ratio %v", resolved.Conversation.TargetRatio)
	}
	if resolved.Conversation.Rolling.SummaryModel != "claude-haiku-4-5" {
		t.Errorf("master fallthrough broken: summary_model %q", resolved.Conversation.Rolling.SummaryModel)
	}

	// Editing a file with no [compression] table yet (a default-seeded
	// profile) creates exactly the path asked for.
	if err := ps.Create("fresh", ""); err != nil {
		t.Fatal(err)
	}
	if err := ps.SetKey("fresh", "compression.conversation.mode", "token"); err != nil {
		t.Fatal(err)
	}
	body, err = ps.Read("fresh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "mode") || strings.Contains(string(body), "target_ratio") {
		t.Errorf("fresh profile edit wrong shape:\n%s", body)
	}
}

// TestProfileStore_Guards pins the refusal set: reserved names,
// invalid names, immutable built-ins, non-compression keys,
// duplicate create, zero-value store.
func TestProfileStore_Guards(t *testing.T) {
	ps := ProfileStore{Dir: filepath.Join(t.TempDir(), "profiles")}

	if err := ps.Create("claude-code", ""); err == nil {
		t.Error("built-in name must be reserved")
	}
	if err := ps.Create("Bad Name", ""); err == nil {
		t.Error("invalid name must be refused")
	}
	if err := ps.Create("../escape", ""); err == nil {
		t.Error("path-escaping name must be refused")
	}
	if err := ps.SetKey("codex-safe", "compression.conversation.target_ratio", "0.5"); err == nil ||
		!strings.Contains(err.Error(), "immutable") {
		t.Errorf("built-ins must be immutable: %v", err)
	}

	if err := ps.Create("mine", ""); err != nil {
		t.Fatal(err)
	}
	if err := ps.Create("mine", ""); err == nil {
		t.Error("duplicate create must be refused")
	}
	if err := ps.SetKey("mine", "profiles.default", "codex-safe"); err == nil {
		t.Error("profile files accept only compression.* keys")
	}
	if err := ps.Delete("codex-safe"); err == nil {
		t.Error("built-ins must not be deletable")
	}

	// Zero-value store: built-ins only, degrades cleanly.
	var zero ProfileStore
	if err := zero.Validate("claude-code"); err != nil {
		t.Error("zero store must validate built-ins")
	}
	if err := zero.Validate("mine"); err == nil {
		t.Error("zero store must not see user profiles")
	}
	if _, _, err := zero.ResolveCompression(Default().Compression, "claude-code"); err != nil {
		t.Errorf("zero store must resolve built-ins: %v", err)
	}
}

// TestProfileStore_CorruptFileLoud: a user profile that no longer
// parses errors at resolution (the router warn-once + fallback path
// handles it) rather than silently passing master params.
func TestProfileStore_CorruptFileLoud(t *testing.T) {
	ps := ProfileStore{Dir: filepath.Join(t.TempDir(), "profiles")}
	if err := ps.Create("broken", "codex-safe"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ps.Dir, "broken.toml"), []byte("not [valid"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ps.ResolveCompression(Default().Compression, "broken"); err == nil {
		t.Error("corrupt profile must error at resolution")
	}
	if err := ps.SetKey("broken", "compression.conversation.target_ratio", "0.5"); err == nil {
		t.Error("SetKey must refuse to clobber a corrupt file")
	}
}
