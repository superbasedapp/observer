package dashboard

// tagdefinitions.go — the tag_definitions API surface (migration 101), a
// sibling of sessiontags.go:
//
//	GET  /api/tags/definitions   → the definitions vocabulary (View)
//	POST /api/tags/definitions   → set (or, on an empty definition, clear) one
//	                                tag's definition/category (Execute)
//
// Execute for the write is the same call sessiontags.go makes for
// /api/sessions/tags/manage: user-authored review metadata a paired remote
// owner legitimately drives, not machine-reaching config.
//
// All storage goes through the single internal/store/tagdefinitions.go seam.

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// tagDefinitionPayload is one entry of the GET /api/tags/definitions
// response map, keyed by tag.
type tagDefinitionPayload struct {
	Definition string `json:"definition"`
	Category   string `json:"category"`
}

// tagDefinitionRequest is the POST /api/tags/definitions body. An empty (or
// whitespace-only) Definition clears the tag's stored definition.
type tagDefinitionRequest struct {
	Tag        string `json:"tag"`
	Definition string `json:"definition"`
	Category   string `json:"category"`
}

// handleTagDefinitions serves GET /api/tags/definitions — every tag's
// definition/category, keyed by tag — and POST /api/tags/definitions, which
// upserts (or clears) one.
func (s *Server) handleTagDefinitions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleTagDefinitionsGet(w, r)
	case http.MethodPost:
		s.handleTagDefinitionsPost(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleTagDefinitionsGet(w http.ResponseWriter, r *http.Request) {
	st := store.New(s.db())
	defs, err := st.TagDefinitions(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	out := make(map[string]tagDefinitionPayload, len(defs))
	for tag, d := range defs {
		out[tag] = tagDefinitionPayload{Definition: d.Definition, Category: d.Category}
	}
	writeJSON(w, map[string]any{"definitions": out})
}

func (s *Server) handleTagDefinitionsPost(w http.ResponseWriter, r *http.Request) {
	var body tagDefinitionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.Tag == "" {
		http.Error(w, "missing tag", http.StatusBadRequest)
		return
	}
	st := store.New(s.db())
	if err := st.UpsertTagDefinition(r.Context(), body.Tag, body.Definition, body.Category); err != nil {
		if errors.Is(err, store.ErrInvalidTag) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}
