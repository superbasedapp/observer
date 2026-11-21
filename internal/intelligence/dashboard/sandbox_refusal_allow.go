package dashboard

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxadvise"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// sandbox_refusal_allow.go is the advisor lite of the sandbox egress refusal
// audit (OpenShell build plan 05 section 3.5, lane N5): from a refusal row
// of rule allow-list-miss the Terminals page offers the owner "allow this
// host", and the owner applies it here. The decision is internal/
// sandboxadvise's table; this file only gathers its facts from the config
// the gateway reads and the gateway's own host check
// (Options.SandboxEgressHostCheck), and saves through the ONE config save
// pipeline (commitConfigEdit, section terminal.sandbox), the writer the
// sandbox config editor uses, so there is no second writer of the list.
// One refusal per request: there is no batch form and nothing approves on
// its own (ruling R-8).

// sandboxRefusalOffer is one refusal's offer on the GET answer.
type sandboxRefusalOffer struct {
	RefusalID int64  `json:"refusal_id"`
	Host      string `json:"host"`
	sandboxadvise.Offer
}

// sandboxRefusalAllowBody is the PUT body: the one refusal to allow.
type sandboxRefusalAllowBody struct {
	RefusalID int64 `json:"refusal_id"`
}

// handleSandboxRefusalAllow serves /api/sandbox/refusals/allow. GET answers
// the offers for the same page GET /api/sandbox/refusals answers (the same
// run_id, project, before and limit filters), keyed by refusal id, with the
// scope an applied offer covers and the confirm token a save carries. PUT
// applies one offer: it re-reads the refusal from the store, decides it
// again from the config as it is now, and adds the host to
// [terminal.sandbox].egress_allow_hosts through commitConfigEdit
// (`?dry_run=1` previews, `?base_etag=` refuses a file changed since the
// preview). LOCAL-ONLY and confirm-token-gated; guard rule R-167 denies an
// agent calling the PUT.
func (s *Server) handleSandboxRefusalAllow(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleSandboxRefusalAllowGet(w, r)
	case http.MethodPut:
		s.handleSandboxRefusalAllowPut(w, r)
	default:
		http.Error(w, "GET or PUT only", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSandboxRefusalAllowGet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := intArg(r, "limit", store.SandboxEgressRefusalDefaultPage, 1, store.SandboxEgressRefusalMaxPage)
	var before int64
	if raw := q.Get("before"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 {
			http.Error(w, "before must be a non-negative integer", http.StatusBadRequest)
			return
		}
		before = n
	}
	rows, err := store.New(s.db()).ListSandboxEgressRefusals(r.Context(), store.SandboxEgressRefusalQuery{
		RunID: q.Get("run_id"), ProjectRoot: q.Get("project"), Before: before, Limit: limit,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	confirmTok := setConfirmCookie(w, r)
	etag, _ := configEtag(s.opts.ConfigPath)
	env, err := s.loadRefusalAllowEnv()
	if err != nil {
		writeErr(w, fmt.Errorf("load sandbox config: %w", err))
		return
	}
	offers := make([]sandboxRefusalOffer, 0, len(rows))
	for _, row := range rows {
		host := sandboxadvise.NormalizeHost(row.Host)
		offers = append(offers, sandboxRefusalOffer{RefusalID: row.ID, Host: host, Offer: sandboxadvise.Decide(env.facts(row.Rule, row.Key, host))})
	}
	writeJSON(w, map[string]any{
		"confirm_token":   confirmTok,
		"config_etag":     etag,
		"config_writable": s.opts.ConfigPath != "",
		"scope":           sandboxadvise.ScopeNode,
		"scope_label":     sandboxadvise.ScopeLabel(sandboxadvise.ScopeNode),
		"key":             sandboxadvise.HostListKey,
		"offers":          offers,
	})
}

func (s *Server) handleSandboxRefusalAllowPut(w http.ResponseWriter, r *http.Request) {
	if !requireJSONConfirm(w, r) {
		return
	}
	if s.opts.SandboxEgressHostCheck == nil {
		http.Error(w, "this build has no sandbox egress gateway", http.StatusNotImplemented)
		return
	}
	if s.opts.ConfigPath == "" {
		http.Error(w, "config path not configured - server has no file to save to", http.StatusConflict)
		return
	}
	var body sandboxRefusalAllowBody
	if err := decodeJSONBody(r, &body); err != nil {
		http.Error(w, "decode refusal allow: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.RefusalID <= 0 {
		http.Error(w, "refusal_id must be a positive refusal id", http.StatusBadRequest)
		return
	}
	// The one row with that id: the newest row below id+1.
	rows, err := store.New(s.db()).ListSandboxEgressRefusals(r.Context(), store.SandboxEgressRefusalQuery{Before: body.RefusalID + 1, Limit: 1})
	if err != nil {
		writeErr(w, err)
		return
	}
	if len(rows) == 0 || rows[0].ID != body.RefusalID {
		http.Error(w, "no refusal with that id", http.StatusNotFound)
		return
	}
	row := rows[0]
	host := sandboxadvise.NormalizeHost(row.Host)
	var listLen int
	s.commitConfigEdit(w, r, configEdit{
		section: "terminal.sandbox",
		// Decided again under the write locks, from the config as it is
		// now: a pin or a list that changed since the page was read decides.
		edit: func(cfg *config.Config) (any, error) {
			env, err := s.loadRefusalAllowEnv()
			if err != nil {
				return nil, fmt.Errorf("load sandbox config: %w", err)
			}
			offer := sandboxadvise.Decide(env.facts(row.Rule, row.Key, host))
			if !offer.Offerable {
				return nil, configEditRefusal{status: http.StatusConflict, msg: string(offer.Reason) + ": " + offer.Message}
			}
			// The owner's own list, never the pinned intersection: a save
			// must not write the organization's narrowing into the file.
			cfg.Terminal.Sandbox.EgressAllowHosts = sandboxadvise.WithHost(env.own.Terminal.Sandbox.EgressAllowHosts, host)
			listLen = len(cfg.Terminal.Sandbox.EgressAllowHosts)
			return nil, nil
		},
		auditAction: "sandbox_refusal_allow",
		auditDetailFor: func(config.Config) string {
			return fmt.Sprintf("refusal_id=%d egress_allow_hosts=%d scope=%s", row.ID, listLen, sandboxadvise.ScopeNode)
		},
		extra: func(config.Config) map[string]any {
			return map[string]any{
				"refusal_id":  row.ID,
				"host":        host,
				"scope":       sandboxadvise.ScopeNode,
				"scope_label": sandboxadvise.ScopeLabel(sandboxadvise.ScopeNode),
				// The gateway reads the list when a run starts: runs
				// already open keep theirs, and no daemon restart is needed.
				// The key's restart class says so (next_spawn), so the
				// computed restart fields are not overridden here (F-049:
				// an override said false beside a listed restart key).
			}
		},
	})
}

// refusalAllowEnv is what one offer decision reads: the config the gateway
// reads (config.Load, governance pins applied), the owner's own config
// (no governance), the pins in force, and the gateway's host check.
type refusalAllowEnv struct {
	governed config.Config
	own      config.Config
	pins     map[string]any
	check    func(config.TerminalSandboxConfig, string) string
	provider func(config.Config, string) bool
	writable bool
}

// loadRefusalAllowEnv loads both configs. A missing file reads as the
// defaults with no pins, as loadConfigForDashboard does.
func (s *Server) loadRefusalAllowEnv() (refusalAllowEnv, error) {
	env := refusalAllowEnv{check: s.opts.SandboxEgressHostCheck, provider: s.opts.SandboxProviderHost, writable: s.opts.ConfigPath != ""}
	path := s.opts.ConfigPath
	if path == "" {
		env.governed, env.own = config.Default(), config.Default()
		return env, nil
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		env.governed, env.own = config.Default(), config.Default()
		return env, nil
	}
	governed, out, err := config.LoadGovernance(config.LoadOptions{GlobalPath: path})
	if err != nil {
		return env, err
	}
	own, err := config.Load(config.LoadOptions{GlobalPath: path, GovernanceSidecar: config.NoGovernanceSidecar})
	if err != nil {
		return env, err
	}
	env.governed, env.own, env.pins = governed, own, out.PinsInForce
	return env, nil
}

// facts gathers sandboxadvise.Facts for one refused host. AllowedAfter
// applies the pins in force to the owner's config with the host added
// through config.ApplyGovernancePinsTo, the one overlay the gateway's
// config load uses, and asks the gateway's own host check.
func (e refusalAllowEnv) facts(rule, key, host string) sandboxadvise.Facts {
	f := sandboxadvise.Facts{Rule: rule, Key: key, InBuild: e.check != nil, ConfigWritable: e.writable}
	if e.check == nil {
		return f
	}
	_, f.PinInForce = e.pins[sandboxadvise.HostListKey]
	// The gateway's provider block over the config it reads (N5-A1).
	f.ProviderHost = e.provider != nil && e.provider(e.governed, host)
	f.AlreadyAllowed = e.check(e.governed.Terminal.Sandbox, host) == ""
	after := e.own
	after.Terminal.Sandbox.EgressAllowHosts = sandboxadvise.WithHost(e.own.Terminal.Sandbox.EgressAllowHosts, host)
	if err := config.Validate(after); err != nil {
		return f
	}
	f.HostListable = true
	if len(e.pins) > 0 {
		after, _ = config.ApplyGovernancePinsTo(after, e.pins)
	}
	f.AllowedAfter = e.check(after.Terminal.Sandbox, host) == ""
	return f
}
