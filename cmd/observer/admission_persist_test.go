package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// editorPolicyJSON marshals a minimal editor policy body (the wire shape the
// httpapi persist seam hands us).
func editorPolicyJSON(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(admissionEditorPolicy{
		Mode:              "enforce",
		Strict:            true,
		Scope:             "last_user",
		SecretRemoteJudge: "deny",
		Prefilter: admissionEditorPrefilter{
			Deny:            []string{"(?i)ignore previous"},
			MaxMessageBytes: 4096,
		},
		Criteria: []admissionEditorCriterion{
			{ID: "AD-scope", Type: "custom", Name: "on scope", Definition: "Must be about supported coding tasks.", Decision: "deny", Severity: "high"},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// TestApplyAdmissionEditorPolicy asserts the pure overlay writes the editable
// fields and PRESERVES the non-editor config (judge, budget, chunk sizing).
func TestApplyAdmissionEditorPolicy(t *testing.T) {
	base := config.Default()
	base.Observability.Enabled = true
	base.Observability.Admission.Judge.Model = "llama3.1:8b"
	base.Observability.Admission.Judge.BaseURL = "http://127.0.0.1:11434/v1"
	base.Observability.Admission.JudgeChunkBytes = 4200
	base.Observability.Admission.Budget.Enabled = true
	base.Observability.Admission.Budget.PerUser5hUSD = 5

	var p admissionEditorPolicy
	if err := json.Unmarshal(editorPolicyJSON(t), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got := applyAdmissionEditorPolicy(base, p)
	ac := got.Observability.Admission

	if !ac.Enabled || ac.Mode != "enforce" || !ac.Strict || ac.Scope != "last_user" || ac.SecretRemoteJudge != "deny" {
		t.Errorf("posture not applied: %+v", ac)
	}
	if len(ac.Criterion) != 1 || ac.Criterion[0].ID != "AD-scope" {
		t.Errorf("criteria = %+v, want AD-scope", ac.Criterion)
	}
	if ac.Prefilter.MaxMessageBytes != 4096 || len(ac.Prefilter.Deny) != 1 {
		t.Errorf("prefilter = %+v, want it applied", ac.Prefilter)
	}
	// Non-editor fields must survive untouched.
	if ac.Judge.Model != "llama3.1:8b" || ac.Judge.BaseURL != "http://127.0.0.1:11434/v1" {
		t.Errorf("judge clobbered: %+v", ac.Judge)
	}
	if ac.JudgeChunkBytes != 4200 {
		t.Errorf("judge_chunk_bytes clobbered: %d, want 4200", ac.JudgeChunkBytes)
	}
	if !ac.Budget.Enabled || ac.Budget.PerUser5hUSD != 5 {
		t.Errorf("budget clobbered: %+v", ac.Budget)
	}
}

// TestAdmissionPolicyPersisterRoundTrip drives the full seam on a fresh node:
// persist writes config.toml, and a subsequent config.Load yields the policy.
func TestAdmissionPolicyPersisterRoundTrip(t *testing.T) {
	home := t.TempDir()
	pinToolHomesAt(t, home) // the persister writes <home>/.observer/config.toml (FU-20)
	path := filepath.Join(home, ".observer", "config.toml")

	if err := admissionPolicyPersister("")(context.Background(), editorPolicyJSON(t)); err != nil {
		t.Fatalf("persist: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("config.toml not written: %v", err)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	ac := cfg.Observability.Admission
	if !ac.Enabled || ac.Mode != "enforce" || !ac.Strict {
		t.Errorf("reloaded posture = %+v, want enabled enforce strict", ac)
	}
	if len(ac.Criterion) != 1 || ac.Criterion[0].ID != "AD-scope" {
		t.Errorf("reloaded criteria = %+v, want AD-scope", ac.Criterion)
	}
	if ac.Prefilter.MaxMessageBytes != 4096 {
		t.Errorf("reloaded prefilter max = %d, want 4096", ac.Prefilter.MaxMessageBytes)
	}
}

// TestAdmissionPolicyPersisterPreservesUnrelated confirms an existing on-disk
// config's unrelated settings survive a policy persist (struct round-trip:
// values preserved; hand-written comments are not — Option A, see WriteToml).
func TestAdmissionPolicyPersisterPreservesUnrelated(t *testing.T) {
	home := t.TempDir()
	pinToolHomesAt(t, home) // the persister writes <home>/.observer/config.toml (FU-20)
	path := filepath.Join(home, ".observer", "config.toml")

	// Seed an existing config carrying an unrelated setting + a judge.
	seed := config.Default()
	seed.Observability.Enabled = true
	seed.Observability.Admission.Judge.Model = "qwen2.5:7b"
	seed.Proxy.Port = 9911
	if err := config.WriteToml(path, seed); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	if err := admissionPolicyPersister("")(context.Background(), editorPolicyJSON(t)); err != nil {
		t.Fatalf("persist: %v", err)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if cfg.Proxy.Port != 9911 {
		t.Errorf("unrelated proxy.port not preserved: %d, want 9911", cfg.Proxy.Port)
	}
	if cfg.Observability.Admission.Judge.Model != "qwen2.5:7b" {
		t.Errorf("judge not preserved: %q", cfg.Observability.Admission.Judge.Model)
	}
	if cfg.Observability.Admission.Mode != "enforce" {
		t.Errorf("policy not applied over seed: mode=%q", cfg.Observability.Admission.Mode)
	}
}
