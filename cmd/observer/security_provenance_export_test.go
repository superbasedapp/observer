//go:build !sbo_omit_security

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/commitscan"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/secchangeexport"
)

// recordedNode is a provenanceNode whose agent commit has its signed record.
func recordedNode(t *testing.T) *provenanceNode {
	t.Helper()
	n := newProvenanceNode(t)
	ctx := context.Background()
	if _, _, err := n.svc.signingKey(ctx); err != nil {
		t.Fatal(err)
	}
	if out, err := n.svc.recordCommit(ctx, commitscan.Root{ProjectID: n.project, RootPath: n.root}, n.commit); err != nil || out != provRecorded {
		t.Fatalf("record: %s %v", out, err)
	}
	return n
}

// TestProvenanceExportFormats: both formats export the verified record of
// the real commit (the path recovered from the commit itself), labelled
// experimental; a commit filter that names another commit exports nothing.
func TestProvenanceExportFormats(t *testing.T) {
	n := recordedNode(t)
	ctx := context.Background()
	var out, errb bytes.Buffer
	if err := provenanceExport(ctx, n.st, n.root, provExportOpts{format: secchangeexport.FormatAgentTrace, commit: n.commit.SHA}, &out, &errb); err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal(out.Bytes(), &rec); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), `"path": "a.go"`) || !strings.Contains(out.String(), `"label": "experimental"`) || !strings.Contains(errb.String(), "EXPERIMENTAL") {
		t.Fatalf("agent trace:\n%s\n%s", out.String(), errb.String())
	}
	if strings.Contains(out.String(), "add a") {
		t.Fatal("prompt text in the export")
	}
	out.Reset()
	file := filepath.Join(t.TempDir(), "ai.notes")
	if err := provenanceExport(ctx, n.st, n.root, provExportOpts{format: secchangeexport.FormatGitAI, out: file}, &out, &errb); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(file)
	if !strings.Contains(string(b), "commit "+n.commit.SHA+"\n---\n") || !strings.Contains(string(b), `"export_status": "experimental"`) || out.Len() != 0 {
		t.Fatalf("git-ai:\n%s", b)
	}
	out.Reset()
	errb.Reset()
	gitRun(t, n.root, "commit", "--allow-empty", "-q", "-m", "chore: later")
	later := gitRun(t, n.root, "rev-parse", "HEAD")
	if err := provenanceExport(ctx, n.st, n.root, provExportOpts{format: secchangeexport.FormatGitAI, commit: later}, &out, &errb); err != nil || out.Len() != 0 || !strings.Contains(errb.String(), "0 exported") {
		t.Fatalf("filter: %v %q %q", err, out.String(), errb.String())
	}
}

// TestProvenanceExportRefusesUnverified: a record whose key was rotated by
// hand (revoked, so every record it signed fails) is refused, never
// exported.
func TestProvenanceExportRefusesUnverified(t *testing.T) {
	n := recordedNode(t)
	ctx := context.Background()
	if _, err := n.svc.rotateKey(ctx); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if err := provenanceExport(ctx, n.st, n.root, provExportOpts{format: secchangeexport.FormatAgentTrace}, &out, &errb); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 || !strings.Contains(errb.String(), "refused") || !strings.Contains(errb.String(), "0 exported, 1 refused") {
		t.Fatalf("out %q err %q", out.String(), errb.String())
	}
}

// TestProvenanceExportNotes: --notes is refused without the notes consent;
// with it, the log lands under refs/notes/ai only (refs/notes/observer and
// HEAD untouched), and a second run leaves the existing note as it is.
func TestProvenanceExportNotes(t *testing.T) {
	n := recordedNode(t)
	ctx := context.Background()
	o := provExportOpts{format: secchangeexport.FormatGitAI, notes: true}
	if err := provenanceExport(ctx, n.st, n.root, o, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "consent") {
		t.Fatalf("without consent: %v", err)
	}
	if err := provenanceExport(ctx, n.st, n.root, provExportOpts{format: secchangeexport.FormatAgentTrace, notes: true}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("--notes accepted for agent-trace")
	}
	if _, err := provenanceSetConsent(ctx, n.st, t.TempDir(), gitview.RunReadOnlyTimeout, n.root, true, false, "cli", true, "/x/observer"); err != nil {
		t.Fatal(err)
	}
	head := gitRun(t, n.root, "rev-parse", "HEAD")
	if err := provenanceExport(ctx, n.st, n.root, provExportOpts{format: secchangeexport.FormatGitAI, rng: "zz"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("a malformed range was accepted")
	}
	var errb bytes.Buffer
	if err := provenanceExport(ctx, n.st, n.root, o, &bytes.Buffer{}, &errb); err != nil || !strings.Contains(errb.String(), "1 git notes written under refs/notes/ai") {
		t.Fatalf("with consent: %v %s", err, errb.String())
	}
	note := gitRun(t, n.root, "notes", "--ref=refs/notes/ai", "show", n.commit.SHA)
	if !strings.HasPrefix(note, "---\n{") || !strings.Contains(note, "authorship/3.0.0") {
		t.Fatalf("note:\n%s", note)
	}
	refs := gitRun(t, n.root, "for-each-ref", "--format=%(refname)", "refs/notes/")
	if strings.TrimSpace(refs) != "refs/notes/ai" {
		t.Fatalf("refs written: %q", refs)
	}
	errb.Reset()
	if err := provenanceExport(ctx, n.st, n.root, o, &bytes.Buffer{}, &errb); err != nil || !strings.Contains(errb.String(), "already has a git-ai note") {
		t.Fatalf("second run: %v %s", err, errb.String())
	}
	if got := gitRun(t, n.root, "rev-parse", "HEAD"); got != head {
		t.Fatalf("HEAD moved: %s -> %s", head, got)
	}
}

// TestProvenanceExportPagesAndSaysCut (audit finding F8): the export reads
// the repository's records page by page, past one page, and says when the
// overall bound cut it.
func TestProvenanceExportPagesAndSaysCut(t *testing.T) {
	n := recordedNode(t)
	ctx := context.Background()
	recs, err := n.st.ListChangeRecords(ctx, "", 10)
	if err != nil || len(recs) != 1 {
		t.Fatalf("records %d %v", len(recs), err)
	}
	extra := recs[0]
	extra.ID, extra.CommitSHA, extra.RecordDigest = 0, strings.Repeat("e", 40), strings.Repeat("f", 64)
	extra.RecordedAt = "2000-01-01T00:00:00Z"
	if _, err := n.st.InsertChangeRecord(ctx, extra); err != nil {
		t.Fatal(err)
	}
	prevPage, prevMax := provExportPageSize, provExportMaxRecords
	t.Cleanup(func() { provExportPageSize, provExportMaxRecords = prevPage, prevMax })
	provExportPageSize = 1
	var out, errb bytes.Buffer
	if err := provenanceExport(ctx, n.st, n.root, provExportOpts{format: secchangeexport.FormatAgentTrace}, &out, &errb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errb.String(), "1 exported, 1 refused") || strings.Contains(errb.String(), "CUT") {
		t.Fatalf("two records over one-record pages: %s", errb.String())
	}
	provExportMaxRecords = 1
	errb.Reset()
	out.Reset()
	if err := provenanceExport(ctx, n.st, n.root, provExportOpts{format: secchangeexport.FormatAgentTrace}, &out, &errb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errb.String(), "1 exported, 0 refused") || !strings.Contains(errb.String(), "CUT: only the newest 1 change records") {
		t.Fatalf("the bound did not say it cut: %s", errb.String())
	}
}
