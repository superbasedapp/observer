package dashboard

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Lines-of-code dashboard surfaces
// (docs/plans/lines-of-code-tracking-plan-2026-09-07.md §3.2/§3.5).
//
// HONESTY RULES BAKED INTO THE PAYLOADS, not left to the UI:
//
//   - human_capture is always present, and is "none" until an editor is
//     reporting saves. The UI must not render an AI SHARE while it is
//     "none": with nothing measuring the developer's own typing, the
//     share is 100% by construction, which is a lie about the developer,
//     not a fact about the agent.
//   - overwrite_files and low_confidence_files travel WITH the counts, so
//     a caveat can sit next to the number instead of in a footnote.
//   - unknown is a first-class bucket, never folded into anything.

// LOCStatsPayload is the wire shape of one bucket set. It mirrors
// loc.Stats field for field and adds the derived totals the UI would
// otherwise recompute in three places.
type LOCStatsPayload struct {
	AddedCode      int `json:"added_code"`
	ModifiedCode   int `json:"modified_code"`
	DeletedCode    int `json:"deleted_code"`
	AddedComment   int `json:"added_comment"`
	DeletedComment int `json:"deleted_comment"`
	Whitespace     int `json:"whitespace"`
	Blank          int `json:"blank"`
	Unknown        int `json:"unknown"`
	// CodeTouched is added + modified code — the headline "lines of code
	// written" number. Deleted lines are deliberately NOT in it: deleting
	// code is valuable work, but it is not lines written, and summing the
	// two would let a delete-heavy refactor outscore a feature.
	CodeTouched int `json:"code_touched"`
	Total       int `json:"total"`
}

// locStatsPayload converts a loc.Stats.
func locStatsPayload(st loc.Stats) LOCStatsPayload {
	return LOCStatsPayload{
		AddedCode:      st.AddedCode,
		ModifiedCode:   st.ModifiedCode,
		DeletedCode:    st.DeletedCode,
		AddedComment:   st.AddedComment,
		DeletedComment: st.DeletedComment,
		Whitespace:     st.Whitespace,
		Blank:          st.Blank,
		Unknown:        st.Unknown,
		CodeTouched:    st.AddedCode + st.ModifiedCode,
		Total:          st.Total(),
	}
}

// LOCBucketPayload is one (actor, scope, category) cell.
type LOCBucketPayload struct {
	Actor     string `json:"actor"`
	Sidechain bool   `json:"sidechain"`
	Category  string `json:"category"`
	Files     int    `json:"files"`
	// LowConfidenceFiles and OverwriteFiles carry the caveats.
	LowConfidenceFiles int             `json:"low_confidence_files"`
	OverwriteFiles     int             `json:"overwrite_files"`
	DeletedFiles       int             `json:"deleted_files"`
	Stats              LOCStatsPayload `json:"stats"`
}

// locBucketPayloads converts a store bucket slice.
func locBucketPayloads(in []store.LOCBucket) []LOCBucketPayload {
	out := make([]LOCBucketPayload, 0, len(in))
	for _, b := range in {
		out = append(out, LOCBucketPayload{
			Actor:              b.Actor,
			Sidechain:          b.Sidechain,
			Category:           b.Category,
			Files:              b.Files,
			LowConfidenceFiles: b.LowConfidence,
			OverwriteFiles:     b.Overwrites,
			DeletedFiles:       b.Deleted,
			Stats:              locStatsPayload(b.Stats),
		})
	}
	return out
}

// LOCLanguagePayload is one language's share.
type LOCLanguagePayload struct {
	Language string          `json:"language"`
	Category string          `json:"category"`
	Files    int             `json:"files"`
	Stats    LOCStatsPayload `json:"stats"`
}

// SessionLOCResponse is the payload for GET /api/session/<id>/loc.
type SessionLOCResponse struct {
	SessionID string               `json:"session_id"`
	Buckets   []LOCBucketPayload   `json:"buckets"`
	Languages []LOCLanguagePayload `json:"languages"`
	Files     int                  `json:"files"`
	// HumanCapture is "none" | "vscode". See the honesty rules above.
	HumanCapture string `json:"human_capture"`
	// CaptureNote is the exact sentence the UI shows when human capture
	// is absent, so the wording is owned in ONE place rather than
	// re-invented per surface.
	CaptureNote       string `json:"capture_note"`
	ClassifierVersion int    `json:"classifier_version"`
	// AIMain / AISidechain / Human / System are the four headline
	// CODE-only roll-ups the session card renders, pre-summed so the card
	// never has to know the bucket algebra.
	AIMain      LOCStatsPayload `json:"ai_main"`
	AISidechain LOCStatsPayload `json:"ai_sidechain"`
	Human       LOCStatsPayload `json:"human"`
	System      LOCStatsPayload `json:"system"`
	// Docs and Config are the non-code buckets, kept separate so a
	// documentation-heavy session reads as documentation-heavy instead of
	// inflating the code number (19% of edits on the reference node are
	// Markdown).
	Docs   LOCStatsPayload `json:"docs"`
	Config LOCStatsPayload `json:"config"`
}

// captureNoteNone is the one wording for "we are not measuring the human
// side". It says what is missing and why no share is shown.
const captureNoteNone = "No editor is reporting saves, so human lines are not measured " +
	"and no AI share is shown. Install the SuperBased VS Code extension to capture them."

// captureNoteVSCode labels a measured human number for what it is.
const captureNoteVSCode = "Human lines are editor-reported (VS Code saves), not a filesystem measurement."

// handleSessionLOC serves GET /api/session/<id>/loc.
func (s *Server) handleSessionLOC(w http.ResponseWriter, r *http.Request, id string) {
	id = strings.TrimSpace(id)
	if id == "" {
		http.Error(w, "session id required", http.StatusBadRequest)
		return
	}
	res, err := store.New(s.db()).LoadSessionLOC(r.Context(), id)
	if err != nil {
		http.Error(w, fmt.Sprintf("load session loc: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, buildSessionLOCResponse(res))
}

// buildSessionLOCResponse folds the store's buckets into the card's
// headline roll-ups. It is a separate function so the fold is unit
// testable without an HTTP round trip.
func buildSessionLOCResponse(res store.SessionLOC) SessionLOCResponse {
	out := SessionLOCResponse{
		SessionID:         res.SessionID,
		Buckets:           locBucketPayloads(res.Buckets),
		Files:             res.Files,
		HumanCapture:      res.HumanCapture,
		CaptureNote:       captureNoteNone,
		ClassifierVersion: res.ClassifierVersion,
	}
	if res.HumanCapture != "none" {
		out.CaptureNote = captureNoteVSCode
	}
	for _, l := range res.Languages {
		out.Languages = append(out.Languages, LOCLanguagePayload{
			Language: l.Language,
			Category: l.Category,
			Files:    l.Files,
			Stats:    locStatsPayload(l.Stats),
		})
	}

	var aiMain, aiSide, human, system, docs, config loc.Stats
	for _, b := range res.Buckets {
		switch b.Category {
		case string(loc.CategoryDocs):
			docs.Add(b.Stats)
			continue
		case string(loc.CategoryConfig):
			config.Add(b.Stats)
			continue
		case string(loc.CategoryCode):
		default:
			// Generated / vendored / unknown categories carry no counts
			// by construction; they are represented in Buckets so the UI
			// can say how many files were skipped.
			continue
		}
		switch b.Actor {
		case store.LOCActorAI:
			if b.Sidechain {
				aiSide.Add(b.Stats)
			} else {
				aiMain.Add(b.Stats)
			}
		case store.LOCActorHuman:
			human.Add(b.Stats)
		case store.LOCActorSystem:
			system.Add(b.Stats)
		}
	}
	out.AIMain = locStatsPayload(aiMain)
	out.AISidechain = locStatsPayload(aiSide)
	out.Human = locStatsPayload(human)
	out.System = locStatsPayload(system)
	out.Docs = locStatsPayload(docs)
	out.Config = locStatsPayload(config)
	return out
}

// LOCDayPayload is one day of the trend series.
type LOCDayPayload struct {
	Day       string          `json:"day"`
	ProjectID int64           `json:"project_id"`
	Actor     string          `json:"actor"`
	Files     int             `json:"files"`
	Stats     LOCStatsPayload `json:"stats"`
}

// LOCSummaryResponse is the payload for GET /api/loc/summary.
type LOCSummaryResponse struct {
	Days         int                `json:"days"`
	Buckets      []LOCBucketPayload `json:"buckets"`
	ByDay        []LOCDayPayload    `json:"by_day"`
	HumanCapture string             `json:"human_capture"`
	CaptureNote  string             `json:"capture_note"`
	// AICodeTouched is the window's headline: AI-authored code lines
	// (added + modified), main and sidechain together.
	AICodeTouched int `json:"ai_code_touched"`
	// HumanCodeTouched is the editor-reported human equivalent. Zero and
	// meaningless while HumanCapture is "none" — which is exactly why
	// AIShare is omitted in that case rather than sent as 1.0.
	HumanCodeTouched int `json:"human_code_touched"`
	// AIShare is present ONLY when human capture exists.
	AIShare *float64 `json:"ai_share,omitempty"`
	// ClassifierVersion is the version this node counts at.
	ClassifierVersion int `json:"classifier_version"`
}

// handleLOCSummary serves GET /api/loc/summary?days=N[&project=<id>].
func (s *Server) handleLOCSummary(w http.ResponseWriter, r *http.Request) {
	days := 7
	if v := strings.TrimSpace(r.URL.Query().Get("days")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 3650 {
			days = n
		}
	}
	var projectID int64
	if v := strings.TrimSpace(r.URL.Query().Get("project")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			projectID = n
		}
	}
	res, err := store.New(s.db()).LoadLOCSummary(r.Context(), days, projectID)
	if err != nil {
		http.Error(w, fmt.Sprintf("load loc summary: %v", err), http.StatusInternalServerError)
		return
	}

	out := LOCSummaryResponse{
		Days:              res.Days,
		Buckets:           locBucketPayloads(res.Buckets),
		HumanCapture:      res.HumanCapture,
		CaptureNote:       captureNoteNone,
		ClassifierVersion: loc.Version,
	}
	if res.HumanCapture != "none" {
		out.CaptureNote = captureNoteVSCode
	}
	for _, d := range res.ByDay {
		out.ByDay = append(out.ByDay, LOCDayPayload{
			Day:       d.Day,
			ProjectID: d.ProjectID,
			Actor:     d.Actor,
			Files:     d.Files,
			Stats:     locStatsPayload(d.Stats),
		})
	}
	for _, b := range res.Buckets {
		if b.Category != string(loc.CategoryCode) {
			continue
		}
		touched := b.Stats.AddedCode + b.Stats.ModifiedCode
		switch b.Actor {
		case store.LOCActorAI:
			out.AICodeTouched += touched
		case store.LOCActorHuman:
			out.HumanCodeTouched += touched
		}
	}
	// The share is COMPUTED ONLY where a denominator exists. Sending 1.0
	// with no human capture would be the single most misleading number
	// this feature could produce.
	if res.HumanCapture != "none" {
		total := out.AICodeTouched + out.HumanCodeTouched
		if total > 0 {
			share := float64(out.AICodeTouched) / float64(total)
			out.AIShare = &share
		}
	}
	writeJSON(w, out)
}
