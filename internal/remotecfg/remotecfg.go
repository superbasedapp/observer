package remotecfg

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/remoteauth"
)

// EnableOptions parameterises Enable. Host is REQUIRED (the tailnet HTTPS host
// the browser sends — the Host allow-list has no fallback, plan §4.5).
type EnableOptions struct {
	Host          string
	AllowTerminal bool
	// AllowTerminalView is the independent remote-VIEW opt-in for attach/resume
	// terminals (session-attach design §3.2). Strictly weaker than AllowTerminal.
	//
	// A POINTER so "unset" is distinguishable from "explicitly false": nil means
	// INHERIT the caller's loaded/seed value (the seed default is now true, so a
	// plain arm through the CLI or the dashboard — neither of which sets this —
	// must NOT clobber that default back to false). Only a non-nil value writes.
	AllowTerminalView *bool
}

// PairingInfo is the result of an arm/rotate transaction. The encoded secret +
// pairing URL are returned here ONLY (the ONE place they cross a boundary,
// §11); a caller must never persist or re-fetch them. Never logs the secret.
type PairingInfo struct {
	Host          string
	BackendAddr   string
	EncodedSecret string
	PairingURL    string
	AllowTerminal bool
	// AllowTerminalView mirrors the persisted [remote].allow_terminal_view so a
	// caller can surface the remote-VIEW opt-in state alongside AllowTerminal.
	AllowTerminalView bool
	SecretPath        string
}

// SecretPath is the 0600 file holding the argon2id hash of the pairing secret
// at rest (plan §4.3). It lives beside the DB in the resolved data dir so it
// follows the operator's config, NOT hardcoded ~/.observer.
func SecretPath(cfg config.Config) string {
	return filepath.Join(filepath.Dir(cfg.Observer.DBPath), "remote-secret")
}

// Enable arms tailnet remote access as one atomic create-validate-persist
// transaction (plan §6/§B): pick a free loopback backend, mint + hash the
// pairing secret, write the hash atomically (0600) BEFORE the config so a
// mid-way crash never leaves an enabled config without a secret, then mutate +
// validate + persist [remote] — rolling back the secret file on any
// validate/persist failure. Returns the pairing URL + encoded secret (the only
// place they cross the boundary). Behaviour is identical to the pre-extraction
// `observer remote enable` transaction.
func Enable(cfg config.Config, cfgPath string, opts EnableOptions) (PairingInfo, error) {
	host := strings.TrimSpace(strings.TrimSuffix(opts.Host, "."))
	if host == "" {
		return PairingInfo{}, fmt.Errorf("remotecfg.Enable: tailnet host is required (the HTTPS host `tailscale serve` exposes; run `tailscale status` to find it)")
	}

	// (1) Pick a dedicated loopback backend port distinct from the owner-trusted
	// direct listener (plan §4.4).
	backendAddr, err := pickFreeLoopbackAddr()
	if err != nil {
		return PairingInfo{}, fmt.Errorf("remotecfg.Enable: reserve loopback backend port: %w", err)
	}

	// (2) Mint + hash the pairing secret.
	raw, enc, err := remoteauth.GenerateSecret()
	if err != nil {
		return PairingInfo{}, fmt.Errorf("remotecfg.Enable: generate pairing secret failed: %w", err)
	}
	hash, err := remoteauth.HashSecret(raw)
	if err != nil {
		return PairingInfo{}, fmt.Errorf("remotecfg.Enable: hash pairing secret failed: %w", err)
	}

	// (3) Write the secret hash atomically at 0600 (before config).
	secretPath := SecretPath(cfg)
	if err := writeRemoteSecretAtomic(secretPath, hash); err != nil {
		return PairingInfo{}, fmt.Errorf("remotecfg.Enable: write pairing secret failed: %w", err)
	}

	// (4) Mutate + validate config, then persist atomically. Roll back the
	// secret file if validation/persist fails.
	cfg.Remote.Enabled = true
	cfg.Remote.Mode = "tailscale"
	cfg.Remote.TailscaleBackendAddr = backendAddr
	cfg.Remote.RequireTLS = true
	cfg.Remote.AllowTerminal = opts.AllowTerminal
	// nil = inherit the loaded/seed default (now true); only an explicit value
	// overrides. This is what keeps a plain arm from writing allow_terminal_view
	// = false and defeating the default-visible flip.
	if opts.AllowTerminalView != nil {
		cfg.Remote.AllowTerminalView = *opts.AllowTerminalView
	}
	if cfg.Remote.RateLimitPerMin <= 0 {
		cfg.Remote.RateLimitPerMin = 6
	}
	cfg.Remote.TrustedHosts = appendUniqueHost(cfg.Remote.TrustedHosts, host)
	if err := config.Validate(cfg); err != nil {
		_ = os.Remove(secretPath)
		return PairingInfo{}, fmt.Errorf("remotecfg.Enable: config invalid after arming (rolled back secret): %w", err)
	}
	if err := config.WriteToml(cfgPath, cfg); err != nil {
		_ = os.Remove(secretPath)
		return PairingInfo{}, fmt.Errorf("remotecfg.Enable: persist config (rolled back secret): %w", err)
	}

	return PairingInfo{
		Host:              host,
		BackendAddr:       backendAddr,
		EncodedSecret:     enc,
		PairingURL:        pairingURL(host, enc),
		AllowTerminal:     opts.AllowTerminal,
		AllowTerminalView: cfg.Remote.AllowTerminalView,
		SecretPath:        secretPath,
	}, nil
}

// Disable closes remote access: flip [remote] back to loopback-only and REMOVE
// the pairing secret (true revocation). Returns whether a secret file was
// actually removed. Behaviour is identical to `observer remote disable`.
func Disable(cfg config.Config, cfgPath string) (removedSecret bool, err error) {
	cfg.Remote.Enabled = false
	cfg.Remote.Mode = "off"
	cfg.Remote.TailscaleBackendAddr = ""
	// The config write (enabled=false) is THE durable gate: buildRemoteController
	// refuses to build a controller when Enabled is false, so a successful
	// persist means remote access cannot resurrect on restart regardless of the
	// secret file (finding 2 residual). A persist FAILURE is the real error.
	if err := config.WriteToml(cfgPath, cfg); err != nil {
		return false, fmt.Errorf("remotecfg.Disable: persist config: %w", err)
	}
	// Secret unlink is BEST-EFFORT: the enabled=false gate already blocks reload,
	// so a leftover hash cannot resurrect access — a unlink failure must not
	// fail the disable (which would strand the caller on a fail-open error path).
	secretPath := SecretPath(cfg)
	if rmErr := os.Remove(secretPath); rmErr == nil {
		return true, nil
	}
	return false, nil
}

// Rotate mints a FRESH pairing secret, invalidating the old one (every paired
// device must re-pair). Requires remote access already enabled. Returns the new
// pairing URL + encoded secret (host may be empty when no trusted host is
// recorded). Behaviour is identical to `observer remote rotate`.
func Rotate(cfg config.Config, cfgPath string) (PairingInfo, error) {
	_ = cfgPath // rotate does not rewrite config; kept for signature symmetry with Enable/Disable
	if !cfg.Remote.Enabled {
		return PairingInfo{}, fmt.Errorf("remotecfg.Rotate: remote access is not enabled - run enable first")
	}
	host := firstTrustedHost(cfg.Remote.TrustedHosts)
	raw, enc, err := remoteauth.GenerateSecret()
	if err != nil {
		return PairingInfo{}, fmt.Errorf("remotecfg.Rotate: generate pairing secret failed: %w", err)
	}
	hash, err := remoteauth.HashSecret(raw)
	if err != nil {
		return PairingInfo{}, fmt.Errorf("remotecfg.Rotate: hash pairing secret failed: %w", err)
	}
	secretPath := SecretPath(cfg)
	if err := writeRemoteSecretAtomic(secretPath, hash); err != nil {
		return PairingInfo{}, fmt.Errorf("remotecfg.Rotate: write pairing secret failed: %w", err)
	}
	info := PairingInfo{
		Host:          host,
		BackendAddr:   cfg.Remote.TailscaleBackendAddr,
		EncodedSecret: enc,
		AllowTerminal: cfg.Remote.AllowTerminal,

		AllowTerminalView: cfg.Remote.AllowTerminalView,
		SecretPath:        secretPath,
	}
	if host != "" {
		info.PairingURL = pairingURL(host, enc)
	}
	return info, nil
}

// pairingURL renders the tailnet pairing URL. The secret rides the URL FRAGMENT
// (after #) so it is never sent to or logged by the server (plan §11).
func pairingURL(host, enc string) string {
	return fmt.Sprintf("https://%s/#pair=%s", host, enc)
}

// StandingInfo is the result of a standing terminal-control mint. The encoded
// secret is returned here ONLY (the ONE place it crosses a boundary, mirroring
// PairingInfo.EncodedSecret); a caller must never persist or re-fetch it. Only
// its argon2id hash is written at rest.
type StandingInfo struct {
	EncodedSecret string
	SecretPath    string
	// Rotated reports whether standing access was ALREADY enabled before this
	// mint (a rotate that invalidates a prior secret) vs a first enable — so the
	// caller can decide whether to kill writers acquired via the old secret.
	Rotated bool
}

// StandingTerminalSecretPath is the 0600 file holding the argon2id hash of the
// standing terminal-control secret at rest (standing-terminal-access §B). It is
// a SIBLING of the pairing secret in the resolved data dir (same storage
// discipline as SecretPath: hashed-at-rest, 0600, follows the operator's config
// — never hardcoded ~/.observer, never node-pushed).
func StandingTerminalSecretPath(cfg config.Config) string {
	return filepath.Join(filepath.Dir(cfg.Observer.DBPath), "remote-standing-terminal-secret")
}

// StandingTerminalEnable mints a FRESH standing terminal-control secret, writes
// its argon2id hash atomically (0600) BEFORE flipping the config so a mid-way
// crash never leaves an enabled config without a secret, sets
// [remote].allow_standing_terminal_control = true, then validates + persists —
// rolling back the secret file on any validate/persist failure. It doubles as
// ROTATE: when standing access is already enabled it simply mints a new secret
// (invalidating the old one). Requires remote access + allow_terminal already
// on (the standing secret only grants what allow_terminal permits). The encoded
// secret is returned once (the only place it crosses the boundary).
func StandingTerminalEnable(cfg config.Config, cfgPath string) (StandingInfo, error) {
	if !cfg.Remote.Enabled {
		return StandingInfo{}, fmt.Errorf("remotecfg.StandingTerminalEnable: remote access is not enabled - arm remote access first")
	}
	if !cfg.Remote.AllowTerminal {
		return StandingInfo{}, fmt.Errorf("remotecfg.StandingTerminalEnable: remote terminal control (allow_terminal) is off - enable it first; standing access only grants what allow_terminal permits")
	}
	rotated := cfg.Remote.AllowStandingTerminalControl

	raw, enc, err := remoteauth.GenerateStandingSecret()
	if err != nil {
		return StandingInfo{}, fmt.Errorf("remotecfg.StandingTerminalEnable: generate standing secret failed: %w", err)
	}
	hash, err := remoteauth.HashSecret(raw)
	if err != nil {
		return StandingInfo{}, fmt.Errorf("remotecfg.StandingTerminalEnable: hash standing secret failed: %w", err)
	}

	// ORDER (finding 7 residual): validate → PERSIST CONFIG → THEN swap the hash
	// file (write-new-LAST). A config-persist failure then leaves the hash file
	// UNTOUCHED (prior/operator-known secret keeps working on rotate; no file yet
	// on first enable), and a hash-write failure leaves the prior hash intact
	// (atomic temp+rename). There is NO window where a fresh, UNKNOWN hash is at
	// rest behind a persisted enabled=true — so no error-prone "restore the prior
	// hash" step (whose own failure was the residual).
	cfg.Remote.AllowStandingTerminalControl = true
	if err := config.Validate(cfg); err != nil {
		return StandingInfo{}, fmt.Errorf("remotecfg.StandingTerminalEnable: config invalid (secret untouched): %w", err)
	}
	secretPath := StandingTerminalSecretPath(cfg)
	if err := config.WriteToml(cfgPath, cfg); err != nil {
		// Config not persisted → hash file untouched → prior secret unaffected.
		return StandingInfo{}, fmt.Errorf("remotecfg.StandingTerminalEnable: persist config (secret untouched): %w", err)
	}
	if err := writeRemoteSecretAtomic(secretPath, hash); err != nil {
		// Config says enabled=true but the fresh hash is NOT at rest: first
		// enable → no hash (verifier denies on empty hash — safe); rotate → the
		// PRIOR hash is intact (the atomic rename never landed), so the
		// operator's known secret still works. No live-but-unknown secret. The
		// caller only hot-reloads on success, so the live verifier is unchanged.
		return StandingInfo{}, fmt.Errorf("remotecfg.StandingTerminalEnable: write standing secret (config persisted; prior secret intact): %w", err)
	}
	return StandingInfo{EncodedSecret: enc, SecretPath: secretPath, Rotated: rotated}, nil
}

// StandingTerminalDisable revokes standing terminal-control access: flip
// [remote].allow_standing_terminal_control back off and REMOVE the standing
// secret file (true revocation — a leaked secret is dead). Returns whether a
// secret file was actually removed. Mirrors Disable's config-then-secret order,
// but keeps the config write authoritative: a failed config persist aborts
// before the file is touched.
func StandingTerminalDisable(cfg config.Config, cfgPath string) (removedSecret bool, err error) {
	cfg.Remote.AllowStandingTerminalControl = false
	// The config write (allow_standing_terminal_control=false) is THE durable
	// gate: buildRemoteController passes StandingTerminalEnabled=false on restart
	// so the verifier denies even if a hash file lingers (finding 2 residual). A
	// persist FAILURE is the real error (surfaced 500; the caller has already
	// killed live access before calling this).
	if err := config.WriteToml(cfgPath, cfg); err != nil {
		return false, fmt.Errorf("remotecfg.StandingTerminalDisable: persist config: %w", err)
	}
	// Hash unlink is BEST-EFFORT: the enabled=false gate already blocks reload,
	// so an orphan hash cannot resurrect access — a unlink failure must not turn
	// a durably-disabled revoke into a fail-open error path.
	secretPath := StandingTerminalSecretPath(cfg)
	if rmErr := os.Remove(secretPath); rmErr == nil {
		return true, nil
	}
	return false, nil
}

// BackendPortOnly returns the ":<port>" form of a loopback host:port for the
// `tailscale serve` command line (it forwards to a local port).
func BackendPortOnly(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return ":" + port
	}
	return addr
}

// writeRemoteSecretAtomic writes the argon2id hash to path with 0600 perms via
// a same-dir temp file + atomic rename (plan §4.3). The temp file is
// owner-only on every OS (fsatomic.CreateTempOwnerOnly: 0600, or on Windows a
// protected DACL granting this user and SYSTEM only, R-160).
func writeRemoteSecretAtomic(path, hash string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("ensure secret dir: %w", err)
	}
	tmp, err := fsatomic.CreateTempOwnerOnly(filepath.Dir(path), ".remote-secret-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if _, statErr := os.Stat(tmpName); statErr == nil {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if _, err := tmp.WriteString(hash + "\n"); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s → %s: %w", tmpName, path, err)
	}
	return nil
}

// pickFreeLoopbackAddr reserves a free loopback TCP port by binding :0, reading
// the assigned port, and releasing it. The daemon rebinds the SAME port on
// start; a brief TOCTOU window is acceptable.
func pickFreeLoopbackAddr() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return l.Addr().String(), nil
}

// appendUniqueHost appends host to the list if a case-insensitive match is not
// already present.
func appendUniqueHost(hosts []string, host string) []string {
	for _, h := range hosts {
		if strings.EqualFold(strings.TrimSpace(h), host) {
			return hosts
		}
	}
	return append(hosts, host)
}

// firstTrustedHost returns the first non-empty trusted host, or "".
func firstTrustedHost(hosts []string) string {
	for _, h := range hosts {
		if s := strings.TrimSpace(h); s != "" {
			return s
		}
	}
	return ""
}
