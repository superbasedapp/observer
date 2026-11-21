//go:build !sbo_omit_terminals_sandbox_openshell_org && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
)

// sandbox_orgshell_login_routes.go holds the owner-local dashboard routes
// the Settings card's "Org-hosted OpenShell" section and the New Terminal
// picker's held sessions call (lane G4; every CLI action of the row exists
// in the dashboard). Every route is CapabilityLocal: a paired remote viewer
// never reaches them. Every write needs the hosted panel's double-submit
// confirm token. No route returns a grant handle, a device code or a token.

func init() {
	hostedExtraDashboardRoutes = append(hostedExtraDashboardRoutes, orgShellDashboardRoutes)
}

// orgShellStatusView is GET /api/terminal/sandbox/orgshell.
type orgShellStatusView struct {
	ConfirmToken string                                   `json:"confirm_token"`
	Offered      bool                                     `json:"offered"`
	Published    *config.TerminalSandboxOrgShellPublished `json:"published,omitempty"`
	SignedIn     bool                                     `json:"signed_in"`
	SignInExpiry *time.Time                               `json:"sign_in_expires_at,omitempty"`
	LaptopRelay  bool                                     `json:"laptop_relay"`
	HoldOnEnd    bool                                     `json:"hold_on_end"`
	Disclosure   string                                   `json:"disclosure"`
	LastCheck    *orgShellCheck                           `json:"last_check,omitempty"`
	// Login is the pending device approval this daemon started, if any (the
	// code to type and where; never the device code).
	Login *orgShellLoginView `json:"login,omitempty"`
}

// orgShellLoginView is a pending approval as the card shows it.
type orgShellLoginView struct {
	UserCode        string    `json:"user_code"`
	VerificationURI string    `json:"verification_uri"`
	ExpiresAt       time.Time `json:"expires_at"`
	Error           string    `json:"error,omitempty"`
}

// orgShellPendingLogin is the one pending dashboard login (one owner).
var orgShellPendingLogin struct {
	mu   sync.Mutex
	view *orgShellLoginView
}

// orgShellLoginGet returns a copy of the pending login (nil when none).
func orgShellLoginGet() *orgShellLoginView {
	orgShellPendingLogin.mu.Lock()
	defer orgShellPendingLogin.mu.Unlock()
	if orgShellPendingLogin.view == nil {
		return nil
	}
	v := *orgShellPendingLogin.view
	return &v
}

// orgShellLoginSet replaces the pending login.
func orgShellLoginSet(change func(**orgShellLoginView)) {
	orgShellPendingLogin.mu.Lock()
	defer orgShellPendingLogin.mu.Unlock()
	change(&orgShellPendingLogin.view)
}

func orgShellDashboardRoutes(configPath string, gate func(http.HandlerFunc) http.HandlerFunc) []dashapi.ExtraRoute {
	load := func(ctx context.Context) (config.TerminalSandboxHostedOrgShellConfig, string, error) {
		cfg, _, done, err := loadConfigAndDBNoCreate(ctx, configPathOr(configPath))
		if err != nil {
			return config.TerminalSandboxHostedOrgShellConfig{}, "", err
		}
		defer done()
		return cliOrgShellEffective(ctx, cfg), filepath.Dir(cfg.Observer.DBPath), nil
	}
	return []dashapi.ExtraRoute{
		{Pattern: "GET /api/terminal/sandbox/orgshell", Capability: dashapi.CapabilityLocal, Handler: gate(orgShellStatusHandler(load))},
		{Pattern: "POST /api/terminal/sandbox/orgshell/laptop-relay", Capability: dashapi.CapabilityLocal, Handler: gate(orgShellToggle(configPath, func(o *config.TerminalSandboxHostedOrgShellConfig, on bool) { o.LaptopRelay = on }))},
		{Pattern: "POST /api/terminal/sandbox/orgshell/hold-on-end", Capability: dashapi.CapabilityLocal, Handler: gate(orgShellToggle(configPath, func(o *config.TerminalSandboxHostedOrgShellConfig, on bool) { o.HoldOnEnd = on }))},
		{Pattern: "POST /api/terminal/sandbox/orgshell/check", Capability: dashapi.CapabilityLocal, Handler: gate(func(w http.ResponseWriter, r *http.Request) {
			if !hostedConfirmed(w, r) {
				return
			}
			c, enr, cfg, done, err := orgShellOrgClient(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			defer done()
			orgShellJSON(w, orgShellRunCheck(r.Context(), c, enr, cliOrgShellEffective(r.Context(), cfg), filepath.Dir(cfg.Observer.DBPath), time.Now()))
		})},
		{Pattern: "POST /api/terminal/sandbox/orgshell/login", Capability: dashapi.CapabilityLocal, Handler: gate(orgShellLoginHandler)},
		{Pattern: "POST /api/terminal/sandbox/orgshell/logout", Capability: dashapi.CapabilityLocal, Handler: gate(func(w http.ResponseWriter, r *http.Request) {
			if !hostedConfirmed(w, r) {
				return
			}
			c, enr, cfg, done, err := orgShellOrgClient(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			defer done()
			dir := filepath.Dir(cfg.Observer.DBPath)
			if rec, gerr := orgShellLoadGrant(dir, enr, time.Now()); gerr == nil {
				_ = c.OpenShellLogout(r.Context(), rec.Handle)
			}
			if err := orgShellForgetGrant(dir); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			orgShellJSON(w, map[string]string{"status": "signed_out"})
		})},
		// A POST with the confirm token: the held list is a signed org call,
		// made only on the card's explicit "Show held sessions" click, never
		// by rendering the page (fix round 1, A6).
		{Pattern: "POST /api/terminal/sandbox/orgshell/held", Capability: dashapi.CapabilityLocal, Handler: gate(orgShellHeldHandler)},
		{Pattern: "POST /api/terminal/sandbox/orgshell/held/{run}/{verb}", Capability: dashapi.CapabilityLocal, Handler: gate(orgShellHeldVerbHandler)},
	}
}

// orgShellStatusHandler is GET /api/terminal/sandbox/orgshell: local facts
// only (the effective block, the sign-in marker, the cached check, a pending
// login). It never calls the org server (invariant I6, fix round 1, A6).
func orgShellStatusHandler(load func(context.Context) (config.TerminalSandboxHostedOrgShellConfig, string, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		o, dir, err := load(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		v := orgShellStatusView{ConfirmToken: hostedConfirmToken(w, r), Offered: o.Published.Offered, LaptopRelay: o.LaptopRelay, HoldOnEnd: o.HoldOnEnd, Disclosure: orgShellDisclosure, LastCheck: orgShellLoadCheck(dir), Login: orgShellLoginGet()}
		if o.Published.Offered {
			p := o.Published
			v.Published = &p
		}
		if s := orgShellLoadSignIn(dir); s != nil && s.ExpiresAt.After(time.Now()) {
			v.SignedIn, v.SignInExpiry = true, &s.ExpiresAt
		}
		orgShellJSON(w, v)
	}
}

// orgShellHeldHandler lists the member's own held boxes: a signed org call,
// behind the confirm token of an explicit click.
func orgShellHeldHandler(w http.ResponseWriter, r *http.Request) {
	if !hostedConfirmed(w, r) {
		return
	}
	c, _, _, done, err := orgShellOrgClient(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer done()
	held, err := c.OpenShellHeld(r.Context())
	if err != nil {
		orgShellRouteError(w, err)
		return
	}
	orgShellJSON(w, map[string]any{"held": held})
}

// configPathOr is the daemon's config path when none is given.
func configPathOr(p string) string {
	if p != "" {
		return p
	}
	return daemonConfigPath()
}

func orgShellJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// orgShellRouteError answers a refused call with its closed reason only.
func orgShellRouteError(w http.ResponseWriter, err error) {
	var ref *orgclient.OpenShellRefusal
	if errors.As(err, &ref) {
		w.WriteHeader(http.StatusConflict)
		orgShellJSON(w, map[string]string{"error": ref.Reason, "rule": ref.Rule})
		return
	}
	http.Error(w, err.Error(), http.StatusBadGateway)
}

// orgShellToggle is a confirm-token write of one node-local key: {"on":bool}.
// Turning the laptop relay on is the disclosure's agreement: the card shows
// orgShellDisclosure first.
func orgShellToggle(configPath string, set func(*config.TerminalSandboxHostedOrgShellConfig, bool)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !hostedConfirmed(w, r) {
			return
		}
		var body struct {
			On *bool `json:"on"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body) != nil || body.On == nil {
			http.Error(w, `want {"on": true|false}`, http.StatusBadRequest)
			return
		}
		on := *body.On
		if err := orgShellSetKey(configPath, func(o *config.TerminalSandboxHostedOrgShellConfig) { set(o, on) }); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		orgShellJSON(w, map[string]bool{"on": on})
	}
}

// orgShellLoginHandler starts a device approval and polls for it in the
// background; the card reads the code from the status route.
func orgShellLoginHandler(w http.ResponseWriter, r *http.Request) {
	if !hostedConfirmed(w, r) {
		return
	}
	ctx := context.WithoutCancel(r.Context())
	c, enr, cfg, done, err := orgShellOrgClient(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	l, err := c.OpenShellLoginStart(ctx, "")
	if err != nil {
		done()
		orgShellRouteError(w, err)
		return
	}
	view := &orgShellLoginView{UserCode: l.UserCode, VerificationURI: l.VerificationURI, ExpiresAt: time.Now().Add(time.Duration(l.ExpiresIn) * time.Second)}
	first := *view
	orgShellLoginSet(func(p **orgShellLoginView) { *p = view })
	go func() {
		defer done()
		if err := orgShellLogin(ctx, c, enr, filepath.Dir(cfg.Observer.DBPath), io.Discard, time.Sleep); err != nil {
			msg := err.Error()
			orgShellLoginSet(func(p **orgShellLoginView) {
				if *p == view {
					v := *view
					v.Error = msg
					*p = &v
				}
			})
			return
		}
		orgShellLoginSet(func(p **orgShellLoginView) {
			if *p == view {
				*p = nil
			}
		})
	}()
	orgShellJSON(w, first)
}

// orgShellHeldVerbHandler is hold, discard or fetch on one run.
func orgShellHeldVerbHandler(w http.ResponseWriter, r *http.Request) {
	if !hostedConfirmed(w, r) {
		return
	}
	run, err := orgShellRunArg([]string{r.PathValue("run")})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c, _, cfg, done, err := orgShellOrgClient(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer done()
	switch r.PathValue("verb") {
	case "hold":
		var held string
		held, err = c.OpenShellHoldBox(r.Context(), run)
		run = orgShellHeldAs(run, held)
	case "discard":
		err = c.OpenShellDiscard(r.Context(), run)
	case "fetch":
		var col orgclient.OpenShellCollect
		col, err = c.OpenShellFetch(r.Context(), run)
		if errors.Is(err, orgclient.ErrOpenShellNothingCollected) {
			orgShellJSON(w, map[string]any{"saved": []string{}, "nothing_collected": true})
			return
		}
		if err == nil {
			var paths []string
			if paths, err = orgShellSaveCollect(filepath.Dir(cfg.Observer.DBPath), run, col); err == nil {
				orgShellJSON(w, map[string]any{"saved": paths})
				return
			}
		}
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		orgShellRouteError(w, err)
		return
	}
	orgShellJSON(w, map[string]string{"status": "ok", "command": "observer sandbox org-shell resume " + run})
}
