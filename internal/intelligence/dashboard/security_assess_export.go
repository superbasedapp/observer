//go:build !sbo_omit_security

package dashboard

import (
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
)

// security_assess_export.go is the export route of the Security assessments
// module (depth plan W6b):
//
//	GET /api/security/assessments/export?run=&format=json|md
//
// Both formats are built by Observer from the stored, checked copy of the run's
// model, never from the agent's own report: the JSON is the checked model with
// the validation report in one envelope, and the Markdown is rendered by Go from
// the same copy (secassess.RenderMarkdown), with every agent string escaped. Both
// pass the display redactor (setting display_redaction) like the model route's
// answer, and are served as text/plain or application/json with nosniff and a
// fixed attachment name built from the run id. Owner-local: the copy holds the
// agent's words about the code.

// codeBadFormat is the refusal of a format other than json or md.
const codeBadFormat = "bad_format"

// The export formats, one row each: the query word, the content type and the
// extension of the attachment's name.
var securityAssessExportFormats = []struct {
	word, contentType, ext string
}{
	{"json", "application/json", "json"},
	{"md", "text/plain; charset=utf-8", "md"},
}

// securityAssessExportFileName is the attachment's name: fixed words and the
// run's id (which is Observer's own 16 hex digits; anything else reads "run").
func securityAssessExportFileName(runID, ext string) string {
	if !secassess.ValidRunID(runID) {
		runID = "run"
	}
	return "observer-assessment-" + runID + "." + ext
}

// handleSecurityAssessExport serves GET /api/security/assessments/export.
func (s *Server) handleSecurityAssessExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	format := -1
	for i, f := range securityAssessExportFormats {
		if f.word == q.Get("format") {
			format = i
		}
	}
	if format < 0 {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "the format is json or md", "code": codeBadFormat})
		return
	}
	run, _, found, err := s.securityAssessRunRoot(r.Context(), q.Get("run"))
	if err != nil {
		s.writeSecurityAssessRunErr(w, err)
		return
	}
	if !found {
		http.Error(w, "unknown run", http.StatusNotFound)
		return
	}
	if securityAssessRefuseExport(w, run) {
		return
	}
	rec, ok := secassesssvc.ReadModel(secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath)).Side(), run.ID)
	if !ok {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "no stored model for this run", "code": "no_stored_model"})
		return
	}
	cfg := s.securityAssessConfig()
	redact, identity := securityAssessRedactorOf(cfg)
	res, hidden := s.displayResult(rec, redact, identity)
	a := cfg.Security.Assessments
	meta := secassess.ExportMeta{
		RunID: run.ID, Kind: secassess.ID(run.Kind), Project: run.ProjectName, ValidatedAt: rec.ValidatedAt, Anyway: rec.Anyway,
		SourceSHA: rec.SourceSHA, RedactionOn: redact != nil, Hidden: hidden,
		DiagramMaxNodes: a.DiagramMaxNodes, DiagramLabelChars: a.DiagramLabelChars,
	}
	var body []byte
	if securityAssessExportFormats[format].word == "json" {
		body, err = secassess.RenderExportJSON(meta, res)
		if err != nil {
			writeErrStatus(w, err, http.StatusInternalServerError)
			return
		}
	} else {
		body = []byte(secassess.RenderMarkdown(meta, res))
	}
	f := securityAssessExportFormats[format]
	w.Header().Set("Content-Type", f.contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	// Belt and braces beside nosniff and the attachment name: were a browser ever to
	// render the file, it would load and run nothing.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Content-Disposition", `attachment; filename="`+securityAssessExportFileName(run.ID, f.ext)+`"`)
	_, _ = w.Write(body) //nolint:gosec // G705: Observer's own rendering of the checked model, served as text/plain or application/json with nosniff, an attachment name and no-store, never as HTML
}
