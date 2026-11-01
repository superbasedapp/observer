package secchangeexport

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secchange"
)

var update = flag.Bool("update", false, "rewrite the goldens")

var (
	t0     = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	sha    = "6dcb09b5b57875f334f61aebed695e2e4193db5e"
	tree   = "7734793b756b3921c88db5375a8c156e9532447b"
	pathA  = "src/main.go"
	pathB  = "README.md"
	hashOf = sha256Hex
)

// fixture is one signed record over two AI files and one human-only file,
// with its trust set and the commit's changed paths.
func fixture(t *testing.T, agents, models []string, mutate func(*secchange.BuildInput)) Input {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	pub, _ := priv.Public().(ed25519.PublicKey)
	in := secchange.BuildInput{
		Binding:      secchange.Binding{CommitSHA: sha, TreeSHA: tree, PatchFPState: "binary_only", ProjectHash: strings.Repeat("c", 64)},
		Key:          secchange.KeyRef{ID: secchange.KeyID(pub), Attestation: secchange.AttestationSelf, Storage: secchange.StorageFileKey},
		CommittedAt:  t0.Add(-time.Hour),
		RecordedAt:   t0,
		HumanCapture: "vscode",
		Files: []secchange.FileInput{
			{PathHash: hashOf(pathA), Added: 10, AI: 10},
			{PathHash: hashOf(pathB), Added: 6, AI: 2, Human: 4},
			{PathHash: hashOf("docs/human.md"), Added: 3, Human: 3},
			{PathHash: hashOf("gone/elsewhere.go"), Added: 2, AI: 2},
		},
		Sessions: []string{"sess-1", "sess-2"}, Agents: agents, Models: models,
		PromptIDs: []string{"101", "102"},
	}
	if mutate != nil {
		mutate(&in)
	}
	env, err := secchange.Sign(secchange.Build(in), priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	trust, err := secchange.NewTrustSet(secchange.TrustFile{Version: secchange.TrustVersion, Keys: []secchange.TrustKey{secchange.SelfKeyEntry(pub, "", "")}})
	if err != nil {
		t.Fatal(err)
	}
	return Input{
		Envelope: raw, Trust: trust, Commit: secchange.CommitFacts{SHA: sha, Tree: tree},
		Paths:       map[string]string{hashOf(pathA): pathA, hashOf(pathB): pathB, hashOf("docs/human.md"): "docs/human.md"},
		ToolVersion: "v1.40.0",
	}
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(p, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s drifted (go test ./internal/secchangeexport -update):\n%s", name, got)
	}
}

// TestGoldens: each format's output from the fixture record.
func TestGoldens(t *testing.T) {
	in := fixture(t, []string{"claude-code"}, []string{"claude-opus-4-8"}, nil)
	for _, f := range []struct{ format, file string }{{FormatAgentTrace, "agent-trace.json"}, {FormatGitAI, "git-ai.note"}} {
		out, err := Export(f.format, in)
		if err != nil {
			t.Fatalf("%s: %v", f.format, err)
		}
		golden(t, f.file, out)
	}
}

// TestAgentTraceFields: absent stays absent (no ranges, no model_id with
// two models, no file the commit does not carry, no human-only file), the
// label present while the spec is a draft, prompt ids only.
func TestAgentTraceFields(t *testing.T) {
	out, err := Export(FormatAgentTrace, fixture(t, []string{"claude-code", "codex"}, []string{"a", "b"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal(out, &rec); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"version", "id", "timestamp", "files"} {
		if _, ok := rec[k]; !ok {
			t.Errorf("required %s missing", k)
		}
	}
	s := string(out)
	for _, never := range []string{"ranges", "model_id", "docs/human.md", "elsewhere", "start_line", "prompt_text"} {
		if strings.Contains(s, never) {
			t.Errorf("%q in the output", never)
		}
	}
	if !strings.Contains(s, `"label": "experimental"`) || !strings.Contains(s, `"unresolved_files": 1`) {
		t.Errorf("label or unresolved count missing:\n%s", s)
	}
	if !strings.Contains(s, `"type": "mixed"`) || !strings.Contains(s, `"type": "ai"`) {
		t.Error("contributor types missing")
	}
}

// TestGitAIRules: the session id formula, the empty attestation section,
// the label, and the refusals for a record that would need a guess.
func TestGitAIRules(t *testing.T) {
	out, err := Export(FormatGitAI, fixture(t, []string{"claude-code"}, []string{"m1", "m2"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.HasPrefix(s, "---\n{") {
		t.Fatalf("the attestation section must be empty:\n%s", s)
	}
	var meta map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(s, "---\n")), &meta); err != nil {
		t.Fatal(err)
	}
	sessions, _ := meta["sessions"].(map[string]any)
	if len(sessions) != 2 || sessions[GitAISessionID("claude-code", "sess-1")] == nil || len(GitAISessionID("x", "y")) != 16 {
		t.Fatalf("sessions %v", sessions)
	}
	if meta["schema_version"] != "authorship/3.0.0" || meta["base_commit_sha"] != sha || strings.Contains(s, `"model"`) {
		t.Errorf("meta %v", meta)
	}
	if !strings.Contains(s, `"export_status": "experimental"`) || !strings.Contains(s, `"prompt_ids": "101,102"`) {
		t.Error("label or prompt ids missing")
	}
	if _, err := Export(FormatGitAI, fixture(t, []string{"claude-code", "codex"}, nil, nil)); !errors.Is(err, ErrNotExportable) {
		t.Errorf("two agents: %v", err)
	}
	if _, err := Export(FormatGitAI, fixture(t, []string{"claude-code"}, nil, func(b *secchange.BuildInput) { b.Sessions = nil })); !errors.Is(err, ErrNotExportable) {
		t.Errorf("no sessions: %v", err)
	}
}

// TestUnverifiedRefused: a tampered envelope, an unknown key and a record
// bound to another commit are never exported, in either format.
func TestUnverifiedRefused(t *testing.T) {
	good := fixture(t, []string{"claude-code"}, nil, nil)
	tampered := good
	tampered.Envelope = bytes.Replace(append([]byte{}, good.Envelope...), []byte(`"sig":"`), []byte(`"sig":"A`), 1)
	noKey := good
	noKey.Trust, _ = secchange.NewTrustSet(secchange.TrustFile{Version: secchange.TrustVersion})
	other := good
	other.Commit.SHA = strings.Repeat("f", 40)
	moved := good
	moved.Commit.Tree = strings.Repeat("e", 40)
	for _, f := range []string{FormatAgentTrace, FormatGitAI} {
		for name, in := range map[string]Input{"tampered": tampered, "unknown key": noKey, "another commit": other, "another tree": moved, "garbage": {Envelope: []byte("{")}} {
			if _, err := Export(f, in); !errors.Is(err, ErrUnverified) {
				t.Errorf("%s %s: %v", f, name, err)
			}
		}
	}
	if _, err := Export("cyclonedx", good); !errors.Is(err, ErrFormat) {
		t.Errorf("unknown format: %v", err)
	}
}

// TestPinsDeclared: every format carries its pin, and a draft is labelled.
func TestPinsDeclared(t *testing.T) {
	for f, s := range Specs {
		if s.Version == "" || !strings.HasPrefix(s.URL, "https://") || s.Read == "" || s.Status == "" || s.Format != f {
			t.Errorf("%s pin incomplete: %+v", f, s)
		}
	}
}

// TestAgentTraceShapeAgainstTheSchemaSummary (lane LEFT2-SEC item R-020):
// the spec text and its JSON schema (agent-trace.dev/schemas/v1/
// trace-record.json, JSON Schema 2020-12) were not reachable from the build
// sandbox on 2026-10-25, so the export is checked against what a secondary
// summary of that schema states and stays labelled experimental: version
// "0.1.0", a UUID id (RFC 9562), an RFC 3339 timestamp, files present, and
// every contributor type one of human, ai, mixed or unknown. A record with
// a human-only or unresolved file still yields only these shapes.
func TestAgentTraceShapeAgainstTheSchemaSummary(t *testing.T) {
	for _, models := range [][]string{{"claude-opus-4-8"}, {"a", "b"}} {
		out, err := Export(FormatAgentTrace, fixture(t, []string{"claude-code"}, models, nil))
		if err != nil {
			t.Fatal(err)
		}
		var rec struct {
			Version   string `json:"version"`
			ID        string `json:"id"`
			Timestamp string `json:"timestamp"`
			Files     []struct {
				Path          string `json:"path"`
				Conversations []struct {
					Contributor struct {
						Type string `json:"type"`
					} `json:"contributor"`
				} `json:"conversations"`
			} `json:"files"`
		}
		if err := json.Unmarshal(out, &rec); err != nil {
			t.Fatal(err)
		}
		if rec.Version != "0.1.0" || rec.Version != Specs[FormatAgentTrace].Version {
			t.Errorf("version %q", rec.Version)
		}
		if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(rec.ID) {
			t.Errorf("id %q is not an RFC 9562 UUID", rec.ID)
		}
		if _, err := time.Parse(time.RFC3339, rec.Timestamp); err != nil {
			t.Errorf("timestamp %q: %v", rec.Timestamp, err)
		}
		if rec.Files == nil {
			t.Error("files missing")
		}
		for _, f := range rec.Files {
			if f.Path == "" || len(f.Conversations) == 0 {
				t.Errorf("file %+v", f)
			}
			for _, c := range f.Conversations {
				switch c.Contributor.Type {
				case "human", "ai", "mixed", "unknown":
				default:
					t.Errorf("contributor type %q outside the schema's enum", c.Contributor.Type)
				}
			}
		}
	}
	if !Specs[FormatAgentTrace].Draft {
		t.Error("the Agent Trace export lost its experimental label before the spec text was checked")
	}
}
