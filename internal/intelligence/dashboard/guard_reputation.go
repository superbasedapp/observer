package dashboard

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/guard/notify"
	"github.com/marmutapp/superbased-observer/internal/settingslink"
)

// The dashboard control for `observer guard mcp reputation <package>`
// (T-496, D-333): npm-registry metadata for an MCP server package, on the
// Security page's MCP tab beside the pins.
//
//	GET  /api/guard/mcp/reputation   L  opt-in status + the confirm token
//	POST /api/guard/mcp/reputation   L  {"package": "..."} -> one lookup
//
// Both call notify.LookupNPMReputation, the function the CLI verb calls, so
// the D1 double opt-in, the egress allowlist and the parse are one owner.
// The route is whole-route Local: a lookup makes ONE outbound HTTPS request
// to registry.npmjs.org, which a remote viewer must never be able to cause,
// and the POST carries the owner-local confirm token like every other
// owner-local action. The verb has no mutation; the opt-in itself is the
// consent card's write (PUT /api/guard/cloud, guard_cloud.go), human-only.

// guardReputationDoer is the dashboard lookup transport; a var so tests can
// stub the registry (nil = the egress worker's production client).
var guardReputationDoer notify.Doer

// guardReputationMaxPackage bounds the package name a lookup accepts (npm
// names are at most 214 characters).
const guardReputationMaxPackage = 214

// guardReputationResponse is a lookup's answer.
type guardReputationResponse struct {
	Package      string `json:"package"`
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"`
	Latest       string `json:"latest"`
	VersionCount int    `json:"version_count"`
	CreatedAt    string `json:"created_at,omitempty"`
	ModifiedAt   string `json:"modified_at,omitempty"`
	AgeDays      int    `json:"age_days"`
	Maintainers  int    `json:"maintainers"`
	// Lines is the CLI's own rendering (notify.FormatNPMInfo).
	Lines []string `json:"lines"`
	Young bool     `json:"young"`
	// Warning is the CLI's young-package warning, "" when not young.
	Warning string `json:"warning,omitempty"`
}

func (s *Server) handleGuardMCPReputation(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.guardReputationStatus(w, r)
	case http.MethodPost:
		s.guardReputationLookup(w, r)
	default:
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
	}
}

// guardReputationStatus reports whether lookups are opted in and mints the
// confirm token the lookup POST echoes.
func (s *Server) guardReputationStatus(w http.ResponseWriter, r *http.Request) {
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, err)
		return
	}
	cloud := cfg.Guard.Cloud
	writeJSON(w, map[string]any{
		"cloud_enabled":      cloud.Enabled,
		"reputation_enabled": cloud.Reputation.Enabled,
		"available":          cloud.Enabled && cloud.Reputation.Enabled,
		"registry":           notify.NPMRegistryBase,
		"young_days":         notify.YoungPackageDays,
		"off_reason":         offReason(cloud.Enabled && cloud.Reputation.Enabled),
		"confirm_token":      setConfirmCookie(w, r),
	})
}

func offReason(available bool) string {
	if available {
		return ""
	}
	return notify.ErrReputationOff.Error()
}

// guardReputationLookup runs one lookup.
func (s *Server) guardReputationLookup(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	var req struct {
		Package string `json:"package"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	pkg := strings.TrimSpace(req.Package)
	if pkg == "" || len(pkg) > guardReputationMaxPackage || strings.ContainsAny(pkg, " \t\r\n") {
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{
			"error":   "invalid_package",
			"message": "enter one npm package name, for example @modelcontextprotocol/server-filesystem",
		})
		return
	}
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, err)
		return
	}
	info, err := notify.LookupNPMReputation(pkg, notify.ReputationLookupOptions{
		CloudEnabled:      cfg.Guard.Cloud.Enabled,
		ReputationEnabled: cfg.Guard.Cloud.Reputation.Enabled,
		MaxBodyBytes:      cfg.Guard.Cloud.PayloadMaxBytes,
		Doer:              guardReputationDoer,
		Now:               s.now(),
	})
	switch {
	case errors.Is(err, notify.ErrReputationOff):
		writeNeedsSetting(w, http.StatusConflict, "reputation_off", msgReputationOff, settingslink.GuardNetwork)
		return
	case errors.Is(err, notify.ErrPackageNotFound):
		s.recordManageAudit(r, "guard_mcp_reputation", "package="+pkg+" result=not_found")
		writeJSONStatus(w, http.StatusNotFound, map[string]any{"error": "not_found", "message": err.Error()})
		return
	case err != nil:
		s.recordManageAudit(r, "guard_mcp_reputation", "package="+pkg+" result=failed")
		writeJSONStatus(w, http.StatusBadGateway, map[string]any{"error": "lookup_failed", "message": err.Error()})
		return
	}
	s.recordManageAudit(r, "guard_mcp_reputation", "package="+pkg+" result=ok")
	resp := guardReputationResponse{
		Package:      pkg,
		Name:         info.Name,
		Description:  info.Description,
		Latest:       info.Latest,
		VersionCount: info.VersionCount,
		AgeDays:      info.AgeDays,
		Maintainers:  info.Maintainers,
		Lines:        notify.FormatNPMInfo(info),
		Young:        info.Young(),
	}
	if !info.CreatedAt.IsZero() {
		resp.CreatedAt = info.CreatedAt.UTC().Format("2006-01-02")
	}
	if !info.ModifiedAt.IsZero() {
		resp.ModifiedAt = info.ModifiedAt.UTC().Format("2006-01-02")
	}
	if resp.Young {
		resp.Warning = notify.YoungPackageWarning
	}
	writeJSON(w, resp)
}
