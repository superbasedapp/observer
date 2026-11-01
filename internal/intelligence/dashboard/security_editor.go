//go:build !sbo_omit_security

package dashboard

import (
	"net/http"
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_editor.go serves GET /api/security/editor?root=<abs path>, the
// VS Code extension's diagnostics feed (security pillar plan section 6.1,
// "VS Code extension", lane sec-c3): the open findings of the project that
// contains a workspace folder, with project-relative paths and lines, the
// templated message and fix hint, never evidence. Owner-local: it resolves
// a directory the caller names to its git root.

type securityEditorFindingJS struct {
	ID         string `json:"id"`
	RuleID     string `json:"rule_id"`
	Category   string `json:"category"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Baseline   string `json:"baseline"`
	RelPath    string `json:"rel_path"`
	StartLine  int    `json:"start_line"`
	Message    string `json:"message"`
	FixHint    string `json:"fix_hint"`
}

// handleSecurityEditor serves GET /api/security/editor.
func (s *Server) handleSecurityEditor(w http.ResponseWriter, r *http.Request) {
	dir := r.URL.Query().Get("root")
	if dir == "" || !filepath.IsAbs(dir) {
		http.Error(w, "root must be an absolute directory", http.StatusBadRequest)
		return
	}
	root, ok := git.FindRoot(dir)
	if !ok {
		root = filepath.Clean(dir)
	}
	hash := secposture.ProjectRootHash(root)
	st := store.New(s.db())
	got, err := st.ListSecFindings(r.Context(), store.SecFindingFilter{ProjectRootHash: hash, Status: policy.FindingStatusOpen, Limit: 1000})
	if err != nil {
		writeErr(w, err)
		return
	}
	// In a linked worktree the project root is the main checkout (F0-14):
	// the hook, post-write and commit findings are kept under it, and a
	// scan run in the worktree itself (a custom scanner) under the
	// worktree's checkout. The worktree's editor reads both.
	if checkout, cok := git.FindCheckoutRoot(dir); cok && ok && checkout != root {
		more, err := st.ListSecFindings(r.Context(), store.SecFindingFilter{ProjectRootHash: secposture.ProjectRootHash(checkout), Status: policy.FindingStatusOpen, Limit: 1000})
		if err != nil {
			writeErr(w, err)
			return
		}
		got = append(got, more...)
	}
	out := make([]securityEditorFindingJS, 0, len(got))
	for _, f := range got {
		if f.Location.RelPath == "" {
			continue
		}
		out = append(out, securityEditorFindingJS{
			ID: f.ID, RuleID: f.Rule.ID, Category: string(f.Category), Severity: string(f.Severity),
			Confidence: string(f.Confidence), Baseline: string(f.Baseline), RelPath: f.Location.RelPath,
			StartLine: f.Location.StartLine, Message: f.Message, FixHint: f.FixHint,
		})
	}
	writeJSON(w, map[string]any{"project_root": root, "project_root_hash": hash, "findings": out})
}
