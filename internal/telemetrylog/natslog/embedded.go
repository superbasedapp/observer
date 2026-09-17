package natslog

import (
	"context"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"

	natsserver "github.com/nats-io/nats-server/v2/server"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
)

// Embedded starts an IN-PROCESS nats-server with JetStream, its file store
// under dir, connects to it and returns a ready Log. Replicas is forced to 1
// (a single embedded server cannot replicate).
//
// dir MUST be a LOCAL directory — never Azure Files / NAS / any network share
// (plan O3: a JetStream file store on a network share corrupts). The adapter
// cannot detect the mount type, so the caller (and `observer-org doctor`) is
// responsible for the reminder.
//
// The embedded server's own logger is silenced (server NoLog); JetStream
// startup on a fresh dir is sub-second.
func Embedded(ctx context.Context, dir string, opts Options) (*Log, error) {
	o := opts.withDefaults()
	o.Replicas = 1 // a single embedded server is always R=1

	// The single-node profile must never become an unauthenticated network
	// broker by a config typo: a non-loopback embedded_listen with no
	// credentials is refused here (and, ahead of boot, by config.validateLog).
	if err := ValidateEmbeddedAuth(o.EmbeddedListen, o); err != nil {
		return nil, fmt.Errorf("natslog.Embedded: %w", err)
	}

	host, port, err := embeddedHostPort(o.EmbeddedListen)
	if err != nil {
		return nil, fmt.Errorf("natslog.Embedded: %w", err)
	}
	sopts := &natsserver.Options{
		ServerName: embeddedServerName(o),
		Host:       host,
		Port:       port,
		JetStream:  true,
		StoreDir:   dir,
		NoSigs:     true,
		NoLog:      true,
		DontListen: false,
		// The connection payload cap must clear the per-record cap plus header
		// slack, else a legal max-size record trips nats.ErrMaxPayload before
		// the stream's own MaxMsgSize check can classify it.
		MaxPayload: maxPayloadFor(o.MaxMsgBytes),
	}
	// An explicit pool, when the caller asked for one; otherwise the server
	// derives it from free disk as it always has (production default).
	if o.EmbeddedMaxStore > 0 {
		sopts.JetStreamMaxStore = o.EmbeddedMaxStore
	}
	// When a token or a user/password is configured, the embedded server
	// REQUIRES it, so the in-process client (connectNATS presents the same o)
	// and any external client must authenticate. NKey/creds-file auth needs
	// account setup beyond this single-node embedded profile: they are never
	// wired into the server here, and (as of the fix below) they no longer
	// satisfy the non-loopback exposure gate either — see
	// hasEnforcedEmbeddedCredentials.
	switch {
	case o.Token != "":
		sopts.Authorization = o.Token
	case o.User != "":
		sopts.Username = o.User
		sopts.Password = o.Password
	}
	srv, err := natsserver.NewServer(sopts)
	if err != nil {
		return nil, fmt.Errorf("natslog.Embedded: new server: %w", err)
	}
	srv.Start()
	if !srv.ReadyForConnections(o.ConnectTimeout) {
		srv.Shutdown()
		srv.WaitForShutdown()
		return nil, fmt.Errorf("natslog.Embedded: server not ready within %s: %w", o.ConnectTimeout, telemetrylog.ErrUnavailable)
	}
	o.URL = srv.ClientURL()

	nc, err := connectNATS(o)
	if err != nil {
		srv.Shutdown()
		srv.WaitForShutdown()
		return nil, fmt.Errorf("natslog.Embedded: %w: %w", err, telemetrylog.ErrUnavailable)
	}
	l, err := newLog(ctx, nc, o, srv)
	if err != nil {
		nc.Close()
		srv.Shutdown()
		srv.WaitForShutdown()
		return nil, err
	}
	return l, nil
}

// embeddedHostPort resolves the bind for the embedded server. "" means a random
// loopback port; a host:port lets an operator reach it with the nats CLI.
func embeddedHostPort(listen string) (string, int, error) {
	if listen == "" {
		return "127.0.0.1", natsserver.RANDOM_PORT, nil
	}
	host, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return "", 0, fmt.Errorf("parse embedded_listen %q (want host:port): %w", listen, err)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("parse embedded_listen port %q: %w", portStr, err)
	}
	return host, port, nil
}

// isLoopbackHost reports whether host names the local machine only: "localhost"
// by name, or any address in 127.0.0.0/8 or ::1. embeddedHostPort resolves an
// empty host to 127.0.0.1, so a bare ":port" listen is loopback by that
// resolution; only an explicit non-loopback host ("0.0.0.0", a LAN address) is
// an exposure. An empty string is treated as loopback here for the same reason.
func isLoopbackHost(host string) bool {
	switch host {
	case "", "localhost":
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// hasEnforcedEmbeddedCredentials reports whether o carries a credential shape
// that Embedded actually wires into the in-process nats-server's auth: a
// token, or a user+password pair (see the switch in Embedded above). This is
// deliberately NARROWER than "any usable NATS credential" — a creds file or
// an nkey seed file is a legitimate credential shape for the external "nats"
// engine, but the single-node embedded profile never provisions an nkey/JWT
// account for it, so a creds/nkey-only config on an embedded server would
// leave it unauthenticated despite looking configured.
func hasEnforcedEmbeddedCredentials(o Options) bool {
	return o.Token != "" || (o.User != "" && o.Password != "")
}

// hasUnenforcedCredentialFile reports whether o names a creds file or an nkey
// seed file: valid NATS credential material in general, but NOT wired into
// the embedded server's auth by Embedded (see hasEnforcedEmbeddedCredentials).
// Used only to give ValidateEmbeddedAuth a more actionable error for this
// specific, otherwise-easy-to-reach-for misconfiguration.
func hasUnenforcedCredentialFile(o Options) bool {
	return o.CredsFile != "" || o.NKeySeedFile != ""
}

// ValidateEmbeddedAuth enforces the single-node safety rule for the embedded
// engine: an embedded server bound on a NON-loopback host with no credential
// that the embedded server actually enforces would be an unauthenticated
// network broker reachable off-box, which the single-node profile never
// intends. listen is the [log].embedded_listen value ("" = a random loopback
// port, always safe); o carries the credential fields. It returns a wrapped
// error naming the offending listen when the host is not loopback and no
// ENFORCED credential (Token, or User+Password) is set, and nil otherwise.
// A creds_file / nkey_seed_file alone does NOT satisfy this gate — the
// embedded engine does not wire either into its auth (hasEnforcedEmbeddedCredentials) —
// so that shape is refused with a message naming the reason, not silently
// treated as "credentials present". Embedded and config.validateLog both call
// it so runtime and boot refuse the same shape.
func ValidateEmbeddedAuth(listen string, o Options) error {
	if listen == "" {
		return nil // a random loopback port
	}
	host, _, err := embeddedHostPort(listen)
	if err != nil {
		return err
	}
	if isLoopbackHost(host) {
		return nil
	}
	if hasEnforcedEmbeddedCredentials(o) {
		return nil
	}
	if hasUnenforcedCredentialFile(o) {
		return fmt.Errorf("natslog: embedded_listen %q is not loopback and only a creds_file/nkey_seed_file is configured; the embedded engine does not wire those into its auth — set [log].token or [log].user + user password (password_env), or use engine = \"nats\" with an authenticated external server", listen)
	}
	return fmt.Errorf("natslog: embedded_listen %q is not loopback and no credentials are configured; set [log].token/user or use engine = \"nats\" with an authenticated external server", listen)
}

// embeddedServerName returns a stable server name for the embedded instance.
func embeddedServerName(o Options) string {
	if o.Name != "" {
		return o.Name
	}
	return "observer-org-embedded-nats"
}

// maxPayloadFor returns a connection max-payload that clears the per-record cap
// plus header slack, floored at the NATS default (1 MiB) and capped at int32.
func maxPayloadFor(maxMsg int32) int32 {
	const oneMiB = int32(1 << 20)
	p := maxMsg
	if p < oneMiB {
		p = oneMiB
	}
	if p < math.MaxInt32-oneMiB {
		p += oneMiB // header slack
	}
	return p
}
