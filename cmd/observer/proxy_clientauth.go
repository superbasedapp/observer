package main

import (
	"fmt"
	"log/slog"
	"os"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/proxyauth"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// proxy_clientauth.go wires the proxy client token (OSH-R-009,
// docs/plans/proxy-client-auth-2026-10-30.md) into the daemon, `observer
// init`, managed route maintenance and the launchers. The decisions live in
// internal/proxyauth; this file only gathers facts and does the file I/O.

// clientAuthLaunchers is the launcher coverage table: the `observer <tool>`
// launchers that put the client token form into the base URL they hand the
// tool through an environment variable (claude.go's child environment and
// its attach environment), never on a command line. A launcher-applied
// route of any other tool stays in the plain form in this release, so an
// installed one keeps enforcement off (proxyClientAuthFacts). Data, keyed by
// the registry tool id, like proxyroute's inspection table.
//
// codex is not in it: its launcher hands the base URL to codex on the
// command line (`-c openai_base_url=...`), which other local accounts can
// read, so it keeps the plain form; its persisted config route (`observer
// init`) carries the token instead.
var clientAuthLaunchers = map[string]bool{
	"claude-code": true,
}

// isolationModuleID is the sandboxed-terminal module whose proxy lanes do not
// carry the client token yet.
const isolationModuleID = "isolation"

// proxyClientToken returns the node's proxy client token when either client
// auth switch is on, and "" otherwise or when the file cannot be used. With
// create it makes the file on first use (resolveLocalTokenFile: owner-only,
// symlinks and foreign owners refused); without, it only reads it, so a
// launcher never creates a token the daemon does not hold.
func proxyClientToken(cfg config.Config, create bool) (string, error) {
	if !cfg.Proxy.ClientAuthWanted() || cfg.Proxy.ClientTokenFile == "" {
		return "", nil
	}
	read := readLocalTokenFile
	if create {
		read = resolveLocalTokenFile
	}
	tok, err := read(cfg.Proxy.ClientTokenFile)
	if err != nil || !proxyauth.ValidToken(tok) {
		return "", err
	}
	if err := proxyTokenFileOwnerOnly(cfg.Proxy.ClientTokenFile); err != nil {
		return "", err
	}
	return tok, nil
}

// proxyTokenFileOwnerOnly refuses a client token file another account can
// read (audit F6): on POSIX the owner is this user with no group or other
// bits (readLocalTokenFile already repairs the bits), on Windows the owner
// is the token user and the protected DACL allows only that user and
// SYSTEM, which is how resolveLocalTokenFile creates it
// (fsatomic.CreateOwnerOnly). A file made some other way (an inherited
// profile ACL) is refused with the remedy: delete it and restart.
func proxyTokenFileOwnerOnly(path string) error {
	ok, err := fsatomic.IsOwnerOnly(path)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("proxy client token file %s is readable by other accounts; delete it and restart the daemon to create an owner-only one", path)
	}
	return nil
}

// existingProxyClientToken reads the token file read-only whatever the
// switches say: "" when it is absent, unusable or not a token. It never
// creates the file.
func existingProxyClientToken(cfg config.Config) string {
	if cfg.Proxy.ClientTokenFile == "" {
		return ""
	}
	tok, err := readLocalTokenFile(cfg.Proxy.ClientTokenFile)
	if err != nil || !proxyauth.ValidToken(tok) || proxyTokenFileOwnerOnly(cfg.Proxy.ClientTokenFile) != nil {
		return ""
	}
	return tok
}

// registrationProxyClientToken is the token a route registration (`observer
// init`) writes with: the config at configPath, file created on first use.
// Fails soft to "" (the plain form, as before).
func registrationProxyClientToken(configPath string) string {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return ""
	}
	tok, _ := proxyClientToken(cfg, true)
	return tok
}

// daemonProxyClientToken is proxyClientToken for the daemon's own route
// writers (the dashboard Setup page), creating the file on first use; ""
// when client auth is off or the file is unusable.
func daemonProxyClientToken(cfg config.Config) string {
	tok, _ := proxyClientToken(cfg, true)
	return tok
}

// launchProxyURL is plain (a launcher's resolved proxy base URL) in the form
// the launcher hands tool: the client token form when client auth is wanted,
// the launcher is in clientAuthLaunchers and the tool's registry row carries
// the path token; plain otherwise. An explicit --proxy override is the
// operator's own URL and is never changed. The token is only read here.
func launchProxyURL(cfg config.Config, tool, plain string, override bool) string {
	if override || !clientAuthLaunchers[tool] {
		return plain
	}
	row, ok := integration.For(tool)
	if !ok || row.Proxy == nil || row.Proxy.ClientAuth != integration.ClientAuthPathToken {
		return plain
	}
	tok, err := proxyClientToken(cfg, false)
	if err != nil || tok == "" {
		return plain
	}
	return proxyauth.WithToken(plain, tok)
}

// launchProxyURLAt is launchProxyURL with the config at configPath; plain on
// a config that does not load.
func launchProxyURLAt(configPath, tool, plain string, override bool) string {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return plain
	}
	return launchProxyURL(cfg, tool, plain, override)
}

// proxyClientAuthFacts gathers what proxyauth.Enforce reads: every persisted
// route at this proxy's port still in the plain form (route inspection), and
// every installed tool whose Observer launcher writes the plain form (a
// launcher-applied route outside clientAuthLaunchers whose binary resolves on
// this host). sandboxActive reports that sandboxed terminals can run on this
// node: their proxy lanes (the Linux byte forwarders, the MXC port, the
// hosted relay) do not carry the client token in this release, so they hold
// enforcement off too. installed is injected for tests.
func proxyClientAuthFacts(cfg config.Config, token string, port int, routes []proxyroute.RouteStatus, installed func(integration.Capability) bool, sandboxActive bool) proxyauth.EnforceFacts {
	f := proxyauth.EnforceFacts{
		Requested:  cfg.Proxy.RequireClientAuth,
		TokenReady: proxyauth.ValidToken(token),
	}
	if !f.Requested {
		return f
	}
	seen := map[string]bool{}
	add := func(label string) {
		if !seen[label] {
			seen[label] = true
			f.PlainRoutes = append(f.PlainRoutes, label)
		}
	}
	for _, st := range routes {
		if st.State == proxyroute.RouteOurs && st.Port == port && !st.ClientAuth {
			add(st.Tool + " (config route)")
		}
	}
	for _, c := range integration.Capabilities() {
		if c.Proxy == nil || c.Proxy.Launcher == "" || clientAuthLaunchers[c.Tool] {
			continue
		}
		if installed != nil && installed(c) {
			add(c.Tool + " (launcher route)")
		}
	}
	if sandboxActive {
		add("sandboxed terminals (isolation component)")
	}
	sort.Strings(f.PlainRoutes)
	return f
}

// toolInstalledHere reports whether c's binary resolves on this host, the
// launcher's own resolution ladder (no install, no exec).
func toolInstalledHere(c integration.Capability) bool {
	if c.Binary == nil {
		return false
	}
	switch toolresolve.Resolve(*c.Binary, resolveEnv()).Verdict {
	case toolresolve.VerdictOK, toolresolve.VerdictOKOffPath, toolresolve.VerdictShadowed:
		return true
	}
	return false
}

// wireProxyClientAuth resolves the daemon's client token and the start-time
// enforcement decision for buildProxy, and logs the decision once. With both
// switches off it returns ("", not enforced) without touching the disk.
func wireProxyClientAuth(cfg config.Config, port int, logger *slog.Logger) (string, proxyauth.Enforcement) {
	if !cfg.Proxy.ClientAuthWanted() {
		// Both switches off: a token file left from an earlier opt-in is
		// still honoured read-only, so a route written in the token form
		// keeps working (the proxy accepts and strips a matching prefix and
		// refuses any other token-shaped one, audit F2). No file is created
		// and nothing is enforced.
		return existingProxyClientToken(cfg), proxyauth.Enforcement{}
	}
	tok, err := proxyClientToken(cfg, true)
	if err != nil {
		logger.Warn("proxy: client token file unusable; serving every local client", "file", cfg.Proxy.ClientTokenFile, "err", err)
	}
	var routes []proxyroute.RouteStatus
	if cfg.Proxy.RequireClientAuth {
		if home, herr := os.UserHomeDir(); herr == nil {
			routes = proxyroute.InspectRoutes(home)
		}
	}
	sandboxActive := cfg.Proxy.RequireClientAuth && componentSnapshotForConfig(cfg).ModuleActive(isolationModuleID)
	enf := proxyauth.Enforce(proxyClientAuthFacts(cfg, tok, port, routes, toolInstalledHere, sandboxActive))
	if cfg.Proxy.RequireClientAuth && !enf.Enforce {
		logger.Warn("proxy: client authentication requested but not enforced", "reason", enf.Reason)
	} else {
		logger.Info("proxy: client authentication", "token", tok != "", "enforced", enf.Enforce)
	}
	return tok, enf
}
