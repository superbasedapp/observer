package dashboard

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/ownagent"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// ownAgentsResponse is GET /api/own-agents: every own agent (P-228,
// docs/own-agents.md) grouped by name with its source label (proxy, OTLP
// spans or both, PT-55), plus what the empty state needs to print the setup
// snippet (the proxy base URL, the two header names and the span
// attribute).
type ownAgentsResponse struct {
	Agents        []store.OwnAgentSummary `json:"agents"`
	ProxyBaseURL  string                  `json:"proxy_base_url"`
	AgentHeader   string                  `json:"agent_header"`
	SessionHeader string                  `json:"session_header"`
	Tool          string                  `json:"tool"`
	// ClientAuth reports that the node wants the proxy client token
	// (OSH-R-009), so the snippet must use the /t/<token> base URL. The
	// token itself is never returned: this is a View route.
	ClientAuth bool `json:"client_auth"`
	// ClientTokenFile is where that token lives ([proxy].client_token_file,
	// as configured), set only with ClientAuth, for the view's "Copy path"
	// button. Only the PATH crosses the wire (GET /api/config already shows
	// it): the dashboard serves no existing long-lived credential, only
	// freshly minted shown-once ones, so the token stays off HTTP (lane L5
	// B-R3, plan decision P-4).
	ClientTokenFile string `json:"client_token_file,omitempty"`
	// AgentAttr is the OpenTelemetry resource attribute that names an agent
	// on the span path (PT-55), so the setup note never hard-codes it.
	AgentAttr string `json:"agent_attr"`
}

// handleOwnAgents serves GET /api/own-agents for the Sessions page's Own
// agents view. A pure read of sessions + api_turns through the store seam.
func (s *Server) handleOwnAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	agents, err := store.New(s.db()).ListOwnAgents(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	if agents == nil {
		agents = []store.OwnAgentSummary{}
	}
	resp := ownAgentsResponse{
		Agents:        agents,
		ProxyBaseURL:  fmt.Sprintf("http://127.0.0.1:%d", s.opts.ProxyPort),
		AgentHeader:   ownagent.AgentHeader,
		SessionHeader: ownagent.SessionHeader,
		Tool:          models.ToolCustomAgent,
		ClientAuth:    s.opts.ProxyClientToken != "",
		AgentAttr:     ownagent.ResourceAttr,
	}
	if resp.ClientAuth {
		resp.ClientTokenFile = ownAgentTokenFile(s.opts.ConfigPath)
	}
	writeJSON(w, resp)
}

// ownAgentTokenFile is the configured proxy client token PATH, falling back
// to the documented default when the config cannot be read or leaves it
// empty. It never opens the file.
func ownAgentTokenFile(configPath string) string {
	cfg, err := loadConfigForDashboard(configPath)
	if err != nil || strings.TrimSpace(cfg.Proxy.ClientTokenFile) == "" {
		return config.DefaultProxyClientTokenFile
	}
	return cfg.Proxy.ClientTokenFile
}
