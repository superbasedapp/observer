//go:build !sbo_omit_security

package dashboard

import (
	"encoding/json"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_provenance.go serves /api/security/provenance, the Code
// security page's AI change records card (component security.provenance,
// lane sec-f2a): GET the signing key, the record counts, a repository's
// records and its writer consent (and mint the confirm token); POST
// {action: "consent", project, notes, trailer} to give or withdraw a
// person's per-repository consent, or {action: "rotate_key"}. The seam
// (Options.Provenance) runs the same functions as `observer security
// provenance`. Owner-local with the confirm token on every write; guard
// rule R-165 denies an agent posting to it. Turning the trailer on writes
// a block into the repository's prepare-commit-msg hook: GET carries the
// exact block (trailer_preview), and the consent names its digest
// (trailer_block_digest), so the write is shown before it is made (PR11).

type securityProvenanceRequest struct {
	Action  string `json:"action"`
	Project string `json:"project"`
	Notes   bool   `json:"notes"`
	Trailer bool   `json:"trailer"`
	// TrailerBlockDigest is the digest of the previewed hook block, needed
	// when the consent turns the trailer on.
	TrailerBlockDigest string `json:"trailer_block_digest"`
}

func (s *Server) handleSecurityProvenance(w http.ResponseWriter, r *http.Request) {
	p := s.opts.Provenance
	if p == nil || p.Status == nil {
		writeCompiledOut(w, "security.provenance")
		return
	}
	resolve := secsvc.RootsResolver(store.New(s.db()).ProjectRoots)
	switch r.Method {
	case http.MethodGet:
		root := ""
		if project := r.URL.Query().Get("project"); project != "" {
			var ok bool
			if root, ok = resolve(r.Context(), project); !ok {
				http.Error(w, "unknown project", http.StatusNotFound)
				return
			}
		}
		s.writeProvenanceState(w, r, root, true)
	case http.MethodPost:
		if !requireConfirmToken(w, r) {
			return
		}
		var req securityProvenanceRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
			http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
			return
		}
		root := ""
		switch req.Action {
		case "consent":
			var ok bool
			if root, ok = resolve(r.Context(), req.Project); !ok {
				http.Error(w, "unknown project", http.StatusNotFound)
				return
			}
			if msg := provenanceTrailerUnshown(r, p, root, req); msg != "" {
				http.Error(w, msg, http.StatusConflict)
				return
			}
			if _, err := p.Consent(r.Context(), root, req.Notes, req.Trailer); err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
		case "rotate_key":
			if _, err := p.RotateKey(r.Context()); err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
		default:
			http.Error(w, `action must be "consent" or "rotate_key"`, http.StatusBadRequest)
			return
		}
		s.writeProvenanceState(w, r, root, false)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// provenanceTrailerUnshown says why a consent turning the trailer on is
// refused ("" when it may go ahead): the hook block it writes was not the
// one shown (its digest does not match the current preview).
func provenanceTrailerUnshown(r *http.Request, p *dashapi.Provenance, root string, req securityProvenanceRequest) string {
	if !req.Trailer || p.TrailerPreview == nil {
		return ""
	}
	if p.ConsentFor != nil {
		if _, on, err := p.ConsentFor(r.Context(), root); err == nil && on {
			return ""
		}
	}
	pv, err := p.TrailerPreview(r.Context(), root)
	if err != nil {
		return "the hook block cannot be previewed: " + err.Error()
	}
	if pv.Installed || req.TrailerBlockDigest == pv.Digest {
		return ""
	}
	return "show the prepare-commit-msg block first: the consent must name the block it installs (trailer_block_digest)"
}

func (s *Server) writeProvenanceState(w http.ResponseWriter, r *http.Request, root string, mint bool) {
	p := s.opts.Provenance
	st, err := p.Status(r.Context())
	if err != nil {
		http.Error(w, "change record state unavailable", http.StatusInternalServerError)
		return
	}
	out := map[string]any{"status": st}
	if p.Records != nil {
		recs, err := p.Records(r.Context(), root, 50)
		if err != nil {
			http.Error(w, "change records unavailable", http.StatusInternalServerError)
			return
		}
		out["records"] = recs
	}
	if root != "" && p.ConsentFor != nil {
		notes, trailer, err := p.ConsentFor(r.Context(), root)
		if err != nil {
			http.Error(w, "consent unavailable", http.StatusInternalServerError)
			return
		}
		out["consent"] = map[string]bool{"notes": notes, "trailer": trailer}
	}
	if root != "" && p.TrailerPreview != nil {
		if pv, err := p.TrailerPreview(r.Context(), root); err == nil {
			out["trailer_preview"] = pv
		}
	}
	if mint {
		out["confirm_token"] = setConfirmCookie(w, r)
	}
	writeJSON(w, out)
}
