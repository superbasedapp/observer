package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

type codexSupportSnapshot struct {
	HasActivity          bool   `json:"has_activity"`
	AuthMode             string `json:"auth_mode,omitempty"`
	SessionCount         int    `json:"session_count"`
	TokenRowCount        int    `json:"token_row_count"`
	LinkedAPITurnCount   int    `json:"linked_api_turn_count"`
	UnlinkedAPITurnCount int    `json:"unlinked_api_turn_count"`
	Mode                 string `json:"mode"`
	CompressionMode      string `json:"compression_mode"`
	Headline             string `json:"headline"`
	Summary              string `json:"summary"`
	RecommendedAction    string `json:"recommended_action,omitempty"`
}

func buildCodexSupportSnapshot(ctx context.Context, database *sql.DB, days int, project string) (codexSupportSnapshot, error) {
	snap := codexSupportSnapshot{
		AuthMode:        detectCodexAuthMode(),
		Mode:            "idle",
		CompressionMode: "unknown",
		Headline:        "No Codex activity in this window",
		Summary:         "Observer has not seen Codex sessions in the selected window yet.",
	}
	since := time.Time{}
	if days > 0 {
		since = time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
	}

	sessArgs := []any{models.ToolCodex}
	sessWhere := []string{"s.tool = ?"}
	if !since.IsZero() {
		sessWhere = append(sessWhere, "s.started_at >= ?")
		sessArgs = append(sessArgs, since.Format(time.RFC3339Nano))
	}
	if project != "" {
		sessWhere = append(sessWhere, "s.project_id = (SELECT id FROM projects WHERE root_path = ?)")
		sessArgs = append(sessArgs, project)
	}
	if err := database.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM sessions s WHERE `+strings.Join(sessWhere, " AND "),
		sessArgs...,
	).Scan(&snap.SessionCount); err != nil {
		return snap, err
	}

	tokenArgs := []any{models.ToolCodex}
	tokenWhere := []string{"tu.tool = ?"}
	if !since.IsZero() {
		tokenWhere = append(tokenWhere, "tu.timestamp >= ?")
		tokenArgs = append(tokenArgs, since.Format(time.RFC3339Nano))
	}
	if project != "" {
		tokenWhere = append(tokenWhere, "s.project_id = (SELECT id FROM projects WHERE root_path = ?)")
		tokenArgs = append(tokenArgs, project)
	}
	if err := database.QueryRowContext(
		ctx,
		`SELECT COUNT(*)
		   FROM token_usage tu
		   LEFT JOIN sessions s ON s.id = tu.session_id
		  WHERE `+strings.Join(tokenWhere, " AND "),
		tokenArgs...,
	).Scan(&snap.TokenRowCount); err != nil {
		return snap, err
	}

	apiArgs := []any{models.ToolCodex}
	apiWhere := []string{"s.tool = ?"}
	if !since.IsZero() {
		apiWhere = append(apiWhere, "at.timestamp >= ?")
		apiArgs = append(apiArgs, since.Format(time.RFC3339Nano))
	}
	if project != "" {
		apiWhere = append(apiWhere, "s.project_id = (SELECT id FROM projects WHERE root_path = ?)")
		apiArgs = append(apiArgs, project)
	}
	if err := database.QueryRowContext(
		ctx,
		`SELECT COUNT(*)
		   FROM api_turns at
		   LEFT JOIN sessions s ON s.id = at.session_id
		  WHERE `+strings.Join(apiWhere, " AND "),
		apiArgs...,
	).Scan(&snap.LinkedAPITurnCount); err != nil {
		return snap, err
	}

	unlinkedArgs := []any{models.ProviderOpenAI}
	unlinkedWhere := []string{
		"at.provider = ?",
		"(at.session_id IS NULL OR at.session_id = '')",
		`(
			at.compression_original_bytes IS NOT NULL OR
			at.compression_compressed_bytes IS NOT NULL OR
			at.compression_count IS NOT NULL OR
			at.compression_dropped_count IS NOT NULL OR
			at.compression_marker_count IS NOT NULL
		)`,
	}
	if !since.IsZero() {
		unlinkedWhere = append(unlinkedWhere, "at.timestamp >= ?")
		unlinkedArgs = append(unlinkedArgs, since.Format(time.RFC3339Nano))
	}
	if err := database.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM api_turns at WHERE `+strings.Join(unlinkedWhere, " AND "),
		unlinkedArgs...,
	).Scan(&snap.UnlinkedAPITurnCount); err != nil {
		return snap, err
	}

	snap.HasActivity = snap.SessionCount > 0 || snap.TokenRowCount > 0 || snap.LinkedAPITurnCount > 0 || snap.UnlinkedAPITurnCount > 0
	if !snap.HasActivity {
		if snap.AuthMode == "chatgpt" {
			snap.Summary = "Codex on this machine is logged in with ChatGPT, but there is no Codex activity in the selected window yet."
		}
		return snap, nil
	}

	switch {
	case snap.LinkedAPITurnCount > 0:
		snap.Mode = "proxy+jsonl"
		snap.CompressionMode = "live"
		snap.Headline = "Codex is running with proxy-linked capture"
		snap.Summary = "Observer has linked Codex session activity to proxy-captured API turns in this window, so live compression data is available."
		snap.RecommendedAction = "Compression metrics in this tab are live proxy data for the linked turns."
	case snap.AuthMode == "chatgpt" && snap.UnlinkedAPITurnCount > 0:
		snap.Mode = "proxy_unlinked+jsonl"
		snap.CompressionMode = "live_unlinked"
		snap.Headline = "Codex ChatGPT auth is active with live proxy capture"
		snap.Summary = "Observer is seeing live proxy compression for ChatGPT-auth Codex turns in this window. On this path, token and cost details still come from the Codex JSONL logs, and some proxy turns may remain unlinked to a session."
		snap.RecommendedAction = "If the newest short rollout is missing token rows, use Run All to force a rescan of recent Codex session files."
	case snap.AuthMode == "chatgpt":
		snap.Mode = "jsonl_only"
		snap.CompressionMode = "unavailable"
		snap.Headline = "Codex is active in JSONL-only mode"
		snap.Summary = "Observer is seeing Codex session logs and token rows, but has not seen live proxy-compressed ChatGPT-auth turns in this window."
		snap.RecommendedAction = "Sessions, Actions, and token metrics still work. Once proxy traffic lands, this card will switch to live ChatGPT-auth capture."
	default:
		snap.Mode = "jsonl_only"
		snap.CompressionMode = "unavailable"
		snap.Headline = "Codex is active, but only JSONL capture is linked"
		snap.Summary = "Observer is seeing Codex session logs without linked proxy turns in this window, so compression data is not available yet."
		snap.RecommendedAction = "Point Codex at the observer proxy with OPENAI_BASE_URL=http://127.0.0.1:8820/v1 if you want live compression data."
	}
	return snap, nil
}

func detectCodexAuthMode() string {
	root := os.Getenv("CODEX_HOME")
	if strings.TrimSpace(root) == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		root = filepath.Join(home, ".codex")
	}
	body, err := os.ReadFile(filepath.Join(root, "auth.json")) //nolint:gosec // G703: reads the operator's own CODEX_HOME auth file for its mode only
	if err != nil {
		return ""
	}
	var raw struct {
		AuthMode string `json:"auth_mode"`
		APIKey   string `json:"OPENAI_API_KEY"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return ""
	}
	mode := strings.ToLower(strings.TrimSpace(raw.AuthMode))
	if mode != "" {
		return mode
	}
	if strings.TrimSpace(raw.APIKey) != "" {
		return "api_key"
	}
	return ""
}

func (s *Server) handleCodexSupport(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 0, 0, 36500)
	project := r.URL.Query().Get("project")
	snap, err := buildCodexSupportSnapshot(r.Context(), s.db(), days, project)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, snap)
}
