package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"unicode"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard/notify"
)

// The [guard.cloud] consent card (plan docs/plans/dashboard-cli-parity-plan-
// 2026-11-06.md, B-G5, decision P-2): the guard's network opt-ins (MCP
// package reputation lookups, the LLM judge, the webhooks the master switch
// arms) turned on and off from the Security page's MCP tab instead of by a
// hand-written config.toml edit.
//
//	GET /api/guard/cloud  L  the switches, what each feature sends where, the confirm token
//	PUT /api/guard/cloud  L  write the [guard.cloud] switches and the judge's endpoint fields;
//	                         ?dry_run=1 previews the diff and writes nothing,
//	                         ?base_etag= refuses a config file that moved since the preview
//
// Consent is a person's, never an agent's: the route is whole-route Local
// (a remote viewer cannot cause it), the write carries the owner-local
// confirm token the GET mints, and guard rule R-165 denies an agent's write
// to it (internal/policy/rules_selfapproval.go, the cli-parity L4 row). The
// write goes through the one config save pipeline (commitConfigEdit) and
// names only the keys below: the webhook list and payload_max_bytes are
// never written here (a webhook URL and a PagerDuty routing key are
// credentials, which stay in config.toml under decision P-4), and the
// request decoder refuses any other field.

// guardCloudMaxEndpoint bounds the judge endpoint a save accepts.
const guardCloudMaxEndpoint = 2048

// guardCloudMaxModel bounds the judge model name a save accepts.
const guardCloudMaxModel = 200

// guardCloudEnvName is the shape of an environment variable name: the judge
// key is read from the variable it names, never written into config.toml.
var guardCloudEnvName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// guardCloudView is GET /api/guard/cloud (and the saved state a PUT returns).
type guardCloudView struct {
	// CloudEnabled is the master switch, [guard.cloud] enabled.
	CloudEnabled bool `json:"cloud_enabled"`
	// GuardActive is [guard] enabled with a mode other than off: the judge
	// and the webhooks ride the daemon's guard event sweep, which runs only
	// then. Reputation lookups do not depend on it.
	GuardActive bool `json:"guard_active"`
	// PayloadMaxBytes is [guard.cloud] payload_max_bytes: a body larger than
	// this is refused, never truncated.
	PayloadMaxBytes int `json:"payload_max_bytes"`
	// FieldLimit is the character bound free-text fields are cut to.
	FieldLimit int                    `json:"field_limit"`
	Reputation guardCloudReputation   `json:"reputation"`
	LLMJudge   guardCloudJudge        `json:"llm_judge"`
	Webhooks   guardCloudWebhookGroup `json:"webhooks"`
	// ConfirmToken is the owner-local token a PUT echoes (GET only).
	ConfirmToken string `json:"confirm_token,omitempty"`
	// ConfigEtag is config.toml's etag at read time (the PUT's base_etag).
	ConfigEtag string `json:"config_etag,omitempty"`
}

// guardCloudReputation is the reputation lookup feature.
type guardCloudReputation struct {
	Enabled bool `json:"enabled"`
	// Active is the double opt-in: the master switch and this one.
	Active bool `json:"active"`
	// Destination is the registry prefix a lookup requests.
	Destination string `json:"destination"`
}

// guardCloudJudge is the LLM judge feature.
type guardCloudJudge struct {
	Enabled bool `json:"enabled"`
	// Active is the master switch, this switch and an endpoint (the daemon
	// also needs the guard active and a restart).
	Active bool `json:"active"`
	// Endpoint is the configured endpoint without its user info, query or
	// fragment (display only).
	Endpoint     string `json:"endpoint"`
	EndpointHost string `json:"endpoint_host"`
	Model        string `json:"model"`
	APIKeyEnv    string `json:"api_key_env"`
	// APIKeySet reports whether the variable APIKeyEnv names is set in the
	// daemon's environment (never its value).
	APIKeySet bool `json:"api_key_set"`
	// Fields are the event fields one review sends (notify.JudgeFields).
	Fields []string `json:"fields"`
	// ConfidenceFloor is the confidence at which a judge allow is acted on.
	ConfidenceFloor float64 `json:"confidence_floor"`
	// ApprovalTTLMinutes is how long a judge-written session approval lasts.
	ApprovalTTLMinutes int `json:"approval_ttl_minutes"`
}

// guardCloudWebhookGroup is the configured webhooks, which the master switch
// arms or disarms as a group.
type guardCloudWebhookGroup struct {
	// Active is the master switch with at least one webhook URL set.
	Active bool                `json:"active"`
	Hooks  []guardCloudWebhook `json:"hooks"`
	// Fields are the alert fields a generic webhook carries
	// (notify.WebhookFields).
	Fields []string `json:"fields"`
}

// guardCloudWebhook is one [[guard.cloud.webhooks]] entry, without its
// credential parts: the host only, never the URL path (a Slack or Discord
// webhook path is the secret) and never the routing key.
type guardCloudWebhook struct {
	Kind          string `json:"kind"`
	Host          string `json:"host"`
	MinSeverity   string `json:"min_severity"`
	HasRoutingKey bool   `json:"has_routing_key"`
}

// guardCloudRequest is a PUT body. Every field is optional; an absent field
// keeps its value.
type guardCloudRequest struct {
	CloudEnabled      *bool                   `json:"cloud_enabled"`
	ReputationEnabled *bool                   `json:"reputation_enabled"`
	LLMJudge          *guardCloudJudgeRequest `json:"llm_judge"`
}

// guardCloudJudgeRequest is the judge part of a PUT body.
type guardCloudJudgeRequest struct {
	Enabled   *bool   `json:"enabled"`
	Endpoint  *string `json:"endpoint"`
	Model     *string `json:"model"`
	APIKeyEnv *string `json:"api_key_env"`
}

// guardCloudChecks are the save's refusals, walked top-down: each returns
// its message when the edited block fails it, "" when it passes. The first
// message answers 400 and nothing is written (CLAUDE.md rule 5: a table, not
// a ladder).
var guardCloudChecks = []func(c config.GuardCloudConfig) string{
	func(c config.GuardCloudConfig) string {
		if len(c.LLMJudge.Endpoint) > guardCloudMaxEndpoint {
			return fmt.Sprintf("the judge endpoint is longer than %d characters", guardCloudMaxEndpoint)
		}
		return ""
	},
	func(c config.GuardCloudConfig) string {
		if c.LLMJudge.Endpoint == "" {
			return ""
		}
		return guardCloudEndpointProblem(c.LLMJudge.Endpoint)
	},
	func(c config.GuardCloudConfig) string {
		if len(c.LLMJudge.Model) > guardCloudMaxModel || strings.IndexFunc(c.LLMJudge.Model, unicode.IsControl) >= 0 {
			return fmt.Sprintf("the judge model must be at most %d characters of plain text", guardCloudMaxModel)
		}
		return ""
	},
	func(c config.GuardCloudConfig) string {
		if c.LLMJudge.APIKeyEnv != "" && !guardCloudEnvName.MatchString(c.LLMJudge.APIKeyEnv) {
			return "the key setting takes the NAME of an environment variable (letters, digits and _), never the key itself"
		}
		return ""
	},
	func(c config.GuardCloudConfig) string {
		if c.LLMJudge.Enabled && c.LLMJudge.Endpoint == "" {
			return "the LLM judge needs an endpoint before it can be turned on"
		}
		return ""
	},
}

// guardCloudRefusal returns the first failing check's message, or "".
func guardCloudRefusal(c config.GuardCloudConfig) string {
	for _, check := range guardCloudChecks {
		if msg := check(c); msg != "" {
			return msg
		}
	}
	return ""
}

// guardCloudEndpointProblem explains why an endpoint is refused, or "". An
// endpoint must be an absolute http(s) URL with a host and no user info
// (credentials belong in the key variable); plain http only reaches a
// loopback host, so a judge on another machine is never sent event context
// in clear text.
func guardCloudEndpointProblem(raw string) string {
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http"):
		return "the judge endpoint must be a full http(s) URL, for example https://llm.example.com/v1/chat/completions"
	case u.User != nil:
		return "the judge endpoint must not carry a user name or password; name the key's environment variable instead"
	case u.Scheme == "http" && !guardCloudLoopback(u.Hostname()):
		return "a judge endpoint on another machine must use https; plain http is accepted only for this machine (localhost)"
	}
	return ""
}

// guardCloudLoopback reports whether host names this machine.
func guardCloudLoopback(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// guardCloudDisplayEndpoint renders an endpoint without user info, query or
// fragment, and its host. An unparsable value is shown as-is with no host.
func guardCloudDisplayEndpoint(raw string) (endpoint, host string) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return raw, ""
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	return u.String(), u.Hostname()
}

// guardCloudState builds the view from a loaded config.
func guardCloudState(cfg config.Config) guardCloudView {
	c := cfg.Guard.Cloud
	endpoint, host := guardCloudDisplayEndpoint(c.LLMJudge.Endpoint)
	payload := c.PayloadMaxBytes
	if payload <= 0 {
		payload = 4096 // notify.NewEgress's default for a non-positive cap
	}
	v := guardCloudView{
		CloudEnabled:    c.Enabled,
		GuardActive:     cfg.Guard.Enabled && cfg.Guard.Mode != "off",
		PayloadMaxBytes: payload,
		FieldLimit:      notify.FieldLimit,
		Reputation: guardCloudReputation{
			Enabled:     c.Reputation.Enabled,
			Active:      c.Enabled && c.Reputation.Enabled,
			Destination: notify.NPMRegistryBase,
		},
		LLMJudge: guardCloudJudge{
			Enabled:            c.LLMJudge.Enabled,
			Active:             c.Enabled && c.LLMJudge.Enabled && c.LLMJudge.Endpoint != "",
			Endpoint:           endpoint,
			EndpointHost:       host,
			Model:              c.LLMJudge.Model,
			APIKeyEnv:          c.LLMJudge.APIKeyEnv,
			APIKeySet:          c.LLMJudge.APIKeyEnv != "" && os.Getenv(c.LLMJudge.APIKeyEnv) != "",
			Fields:             notify.JudgeFields(),
			ConfidenceFloor:    notify.JudgeConfidenceFloor,
			ApprovalTTLMinutes: int(notify.JudgeApprovalTTL.Minutes()),
		},
		Webhooks: guardCloudWebhookGroup{Hooks: []guardCloudWebhook{}, Fields: notify.WebhookFields()},
	}
	for _, wh := range c.Webhooks {
		if strings.TrimSpace(wh.URL) == "" {
			continue
		}
		_, h := guardCloudDisplayEndpoint(wh.URL)
		kind := wh.Kind
		if kind == "" {
			kind = notify.WebhookGeneric
		}
		sev := wh.MinSeverity
		if sev == "" {
			sev = "high" // the dispatcher's default (cmd/observer/guardcloud.go defaultSeverity)
		}
		v.Webhooks.Hooks = append(v.Webhooks.Hooks, guardCloudWebhook{
			Kind: kind, Host: h, MinSeverity: sev, HasRoutingKey: wh.RoutingKey != "",
		})
	}
	v.Webhooks.Active = c.Enabled && len(v.Webhooks.Hooks) > 0
	return v
}

// handleGuardCloud serves /api/guard/cloud.
func (s *Server) handleGuardCloud(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
		if err != nil {
			writeErr(w, err)
			return
		}
		v := guardCloudState(cfg)
		v.ConfirmToken = setConfirmCookie(w, r)
		if s.opts.ConfigPath != "" {
			v.ConfigEtag, _ = configEtag(s.opts.ConfigPath)
		}
		writeJSON(w, v)
	case http.MethodPut:
		s.guardCloudSave(w, r)
	default:
		http.Error(w, "GET or PUT only", http.StatusMethodNotAllowed)
	}
}

// guardCloudSave writes the switches through the one save pipeline.
func (s *Server) guardCloudSave(w http.ResponseWriter, r *http.Request) {
	if s.opts.ConfigPath == "" {
		http.Error(w, "config path not configured - server has no file to save to", http.StatusConflict)
		return
	}
	q := r.URL.Query()
	dryRun := q.Get("dry_run") == "1" || q.Get("dry_run") == "true"
	// A dry run writes nothing; the real save is a consent and carries the
	// owner-local confirm token.
	if !dryRun && !requireJSONConfirm(w, r) {
		return
	}
	var req guardCloudRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.commitConfigEdit(w, r, configEdit{
		section: "guard.cloud",
		edit: func(cfg *config.Config) (any, error) {
			req.applyTo(&cfg.Guard.Cloud)
			if msg := guardCloudRefusal(cfg.Guard.Cloud); msg != "" {
				return nil, errors.New(msg)
			}
			return nil, nil
		},
		auditAction: "guard_cloud",
		auditDetailFor: func(cfg config.Config) string {
			c := cfg.Guard.Cloud
			_, host := guardCloudDisplayEndpoint(c.LLMJudge.Endpoint)
			return fmt.Sprintf("cloud=%v reputation=%v llm_judge=%v judge_host=%s webhooks=%d",
				c.Enabled, c.Reputation.Enabled, c.LLMJudge.Enabled, host, len(c.Webhooks))
		},
		extra: func(cfg config.Config) map[string]any {
			return map[string]any{"state": guardCloudState(cfg)}
		},
	})
}

// applyTo writes the request's present fields onto the [guard.cloud] block.
func (req guardCloudRequest) applyTo(c *config.GuardCloudConfig) {
	if req.CloudEnabled != nil {
		c.Enabled = *req.CloudEnabled
	}
	if req.ReputationEnabled != nil {
		c.Reputation.Enabled = *req.ReputationEnabled
	}
	if j := req.LLMJudge; j != nil {
		if j.Enabled != nil {
			c.LLMJudge.Enabled = *j.Enabled
		}
		if j.Endpoint != nil {
			c.LLMJudge.Endpoint = strings.TrimSpace(*j.Endpoint)
		}
		if j.Model != nil {
			c.LLMJudge.Model = strings.TrimSpace(*j.Model)
		}
		if j.APIKeyEnv != nil {
			c.LLMJudge.APIKeyEnv = strings.TrimSpace(*j.APIKeyEnv)
		}
	}
}
