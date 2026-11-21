package dashboard

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// browserSiteRow is one entry of the closed browser-capture site table: the
// key [browser.sites] uses (the *-web tool name) and how the card labels it.
type browserSiteRow struct {
	Site  string
	Label string
}

// browserSiteTable is the closed list of sites the capture rail knows, in
// display order. [browser.sites] is a free map in config.toml, but the
// dashboard only offers (and accepts) these keys, so a typo cannot create a
// toggle that matches nothing.
var browserSiteTable = []browserSiteRow{
	{"chatgpt-web", "ChatGPT"},
	{"claude-web", "Claude.ai"},
	{"perplexity-web", "Perplexity"},
	{"gemini-web", "Gemini"},
	{"copilot-web", "Microsoft Copilot"},
}

// browserSiteView is one row of GET /api/browser/sites.
type browserSiteView struct {
	Site  string `json:"site"`
	Label string `json:"label"`
	// Enabled is the effective state: a missing key means enabled.
	Enabled bool `json:"enabled"`
	// Explicit is true when config.toml sets the key itself.
	Explicit bool `json:"explicit"`
}

// browserSiteViews builds the card's rows from the loaded config, in table
// order. Pure.
func browserSiteViews(b config.BrowserConfig) []browserSiteView {
	out := make([]browserSiteView, 0, len(browserSiteTable))
	for _, row := range browserSiteTable {
		v, ok := b.Sites[row.Site]
		out = append(out, browserSiteView{Site: row.Site, Label: row.Label, Enabled: !ok || v, Explicit: ok})
	}
	return out
}

// applyBrowserSites validates a requested change against the closed site
// table and writes it onto cfg. Every requested site is stored explicitly
// (true or false): a missing key and an explicit true mean the same to the
// daemon, and writing the value keeps the file's meaning visible. Pure over
// cfg; returns the sorted site keys it set.
func applyBrowserSites(cfg *config.Config, want map[string]bool) ([]string, error) {
	if len(want) == 0 {
		return nil, fmt.Errorf("no sites in the request")
	}
	known := map[string]bool{}
	for _, row := range browserSiteTable {
		known[row.Site] = true
	}
	keys := make([]string, 0, len(want))
	for site := range want {
		if !known[site] {
			return nil, fmt.Errorf("unknown site %q (one of: %s)", site, strings.Join(browserSiteNames(), ", "))
		}
		keys = append(keys, site)
	}
	sort.Strings(keys)
	if cfg.Browser.Sites == nil {
		cfg.Browser.Sites = map[string]bool{}
	}
	for _, site := range keys {
		cfg.Browser.Sites[site] = want[site]
	}
	return keys, nil
}

// browserSiteNames lists the closed table's keys.
func browserSiteNames() []string {
	out := make([]string, 0, len(browserSiteTable))
	for _, row := range browserSiteTable {
		out = append(out, row.Site)
	}
	return out
}

// browserSitesBody is the POST /api/browser/sites body.
type browserSitesBody struct {
	Sites map[string]bool `json:"sites"`
}

// handleBrowserSites serves GET /api/browser/sites (the per-site toggles and
// a confirm token) and POST /api/browser/sites (set some toggles). The POST
// goes through the one config.toml save pipeline: `?dry_run=1` answers the
// diff, `?base_etag=` refuses a stale page, the write is read back and
// audited. Each captured turn reads [browser.sites] in its own hook process,
// so a change applies to the next turn with no daemon restart.
func (s *Server) handleBrowserSites(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
		if err != nil {
			writeErr(w, fmt.Errorf("load config: %w", err))
			return
		}
		etag, _ := configEtag(s.opts.ConfigPath)
		writeJSON(w, map[string]any{
			"confirm_token": setConfirmCookie(w, r),
			"config_etag":   etag,
			"sites":         browserSiteViews(cfg.Browser),
		})
	case http.MethodPost:
		if !requireConfirmToken(w, r) {
			return
		}
		if s.opts.ConfigPath == "" {
			http.Error(w, "config path not configured - server has no file to save to", http.StatusConflict)
			return
		}
		var body browserSitesBody
		if err := decodeJSONBody(r, &body); err != nil {
			http.Error(w, "decode browser sites: "+err.Error(), http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("dry_run") != "1" && s.setupExtrasGovernanceRefused(w, r, "browser") {
			return
		}
		s.commitConfigEdit(w, r, configEdit{
			section: "browser",
			edit: func(cfg *config.Config) (any, error) {
				_, err := applyBrowserSites(cfg, body.Sites)
				return nil, err
			},
			auditAction: "browser_sites",
			auditDetailFor: func(cfg config.Config) string {
				return "sites=" + strings.Join(sortedKeys(body.Sites), ",")
			},
			extra: func(cfg config.Config) map[string]any {
				return map[string]any{"sites": browserSiteViews(cfg.Browser)}
			},
		})
	default:
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
	}
}

// sortedKeys returns m's keys in order.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
