//go:build !sbo_omit_security && !sbo_omit_security_deps

package dashboard

import (
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_sbom.go serves GET /api/security/sbom?project=<root hash>, the
// Projects tab's "Export SBOM" (security coverage gaps plan
// docs/plans/security-coverage-gaps-plan-2026-11-13.md section 3): the
// project's CycloneDX document rendered from the inventory its last
// dependency scan stored, through the injected seam
// (Options.SecurityProjectSBOM), as a download. Owner-local: it names the
// project's packages. 404 unless security.deps is selected, for a project
// the dashboard does not know, and (no_inventory) before the project's
// first dependency scan.

func (s *Server) handleSecuritySBOM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	render := s.opts.SecurityProjectSBOM
	if render == nil {
		writeCompiledOut(w, "security.deps")
		return
	}
	snap, ok := s.comps.live(r.Context())
	if sel := s.opts.SecuritySelected; !ok || sel == nil || !sel(snap, "security.deps") {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{
			"error":  "not_selected",
			"detail": "the security.deps component is not selected: add it under [components]",
		})
		return
	}
	hash := r.URL.Query().Get("project")
	if hash == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "no_project", "detail": "name a project: ?project=<root hash>"})
		return
	}
	index, err := securityProjectIndex(r.Context(), store.New(s.db()))
	if err != nil {
		writeErr(w, err)
		return
	}
	ref, found := index[hash]
	if !found || ref.Root == "" {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "unknown_project"})
		return
	}
	doc, have, err := render(r.Context(), ref.Root)
	if err != nil {
		writeErr(w, err)
		return
	}
	if !have {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{
			"error":  "no_inventory",
			"detail": "no dependency scan has stored this project's packages yet: run a dependency scan (Scan now, or observer security scan) first",
		})
		return
	}
	w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="`+securitySBOMFileName(securityProjectName(ref))+`"`)
	_, _ = w.Write(doc)
}

// securitySBOMFileName is the download's file name: the project's name
// with anything but letters, digits, dot, dash and underscore replaced,
// then ".cdx.json".
func securitySBOMFileName(name string) string {
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		}
		return '_'
	}, name)
	clean = strings.Trim(clean, "._")
	if clean == "" {
		clean = "project"
	}
	if len(clean) > 64 {
		clean = clean[:64]
	}
	return clean + ".sbom.cdx.json"
}
