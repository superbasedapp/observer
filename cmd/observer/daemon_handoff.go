package main

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// daemon_handoff.go is the CLI's one seam for "hand this work to the running
// daemon" (decisions log L-125). Every CLI verb that asks the daemon to act
// on this machine over its owner-local dashboard routes (org push-now, the
// live sandboxed-run question and its end, the live sandbox apply, the
// update apply, the config reload poke) resolves its target here first. A
// CLI only hands work to a daemon that serves the same database: the daemon
// names its database (dashapi.DBIdentity) when asked, and the decision is
// the table in dashapi.DaemonHandoff. Anything else runs in this process, or
// reports no daemon, as it would with none running.

// daemonHandoffProbeTimeout bounds the one probe request.
const daemonHandoffProbeTimeout = 2 * time.Second

// daemonTarget is where a CLI may send work, and the identity it sends with
// every request so a newer daemon still refuses it if the address changed
// hands in between.
type daemonTarget struct {
	// Base is "http://host:port" of the daemon's dashboard.
	Base string
	// DBIdentity is this CLI's database identity, sent in
	// dashapi.DBIdentityRequestHeader on every request.
	DBIdentity string
	// Use: the daemon serves this database (or is the one recorded beside
	// it); hand it the work.
	Use bool
	// Listening: something answered at Base (false: nothing listens).
	Listening bool
	// Match is what the probe learned (dashapi.DBNoDaemon when nothing
	// listens or the config could not be loaded).
	Match dashapi.DBMatch
	// Reason is the handoff table's reason, for a note.
	Reason string
}

// setDBIdentity names the CLI's database on req.
func (t daemonTarget) setDBIdentity(req *http.Request) {
	if t.DBIdentity != "" {
		req.Header.Set(dashapi.DBIdentityRequestHeader, t.DBIdentity)
	}
}

// resolveDaemonHandoff resolves the daemon for the config at configPath
// ("" = the default lookup). A package seam so tests never dial.
var resolveDaemonHandoff = func(ctx context.Context, configPath string) daemonTarget {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		// No database to name: never hand work to whatever answers the
		// default address.
		return daemonTarget{Base: "http://" + daemonDashboardAddr(configPath), Reason: "the config could not be loaded"}
	}
	return daemonHandoffFor(ctx, cfg.Observer.DBPath, daemonDashboardAddrFor(cfg))
}

// daemonHandoffFor resolves the daemon at addr for the database at dbPath:
// one probe naming this database, then the handoff table.
func daemonHandoffFor(ctx context.Context, dbPath, addr string) daemonTarget {
	t := daemonTarget{Base: "http://" + addr, DBIdentity: dashapi.DBIdentity(dbPath)}
	match := probeDaemonDB(ctx, t.Base, t.DBIdentity)
	t.Match = match
	t.Listening = match != dashapi.DBNoDaemon
	t.Use, t.Reason = dashapi.DaemonHandoff(match, daemonRecordEvidence(dbPath))
	return t
}

// daemonRecordEvidence reports whether this database carries local evidence
// of its own running daemon: the dashboard listen record beside it and a
// live start lock for it. A package seam so tests need no live daemon.
var daemonRecordEvidence = func(dbPath string) bool {
	if strings.TrimSpace(dbPath) == "" {
		return false
	}
	if _, ok := readDashboardListenRecord(dbPath); !ok {
		return false
	}
	_, live := liveDaemonFor(dbPath)
	return live
}

// probeDaemonDB asks the dashboard at base which database it serves: a HEAD
// of the SPA shell (cheap on every build) naming this database. A refused
// connection is no daemon; any answer without an identity, or no answer in
// time, is unknown.
var probeDaemonDB = func(ctx context.Context, base, want string) dashapi.DBMatch {
	ctx, cancel := context.WithTimeout(ctx, daemonHandoffProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, base+"/", nil)
	if err != nil {
		return dashapi.DBUnknown
	}
	if want != "" {
		req.Header.Set(dashapi.DBIdentityRequestHeader, want)
	}
	resp, err := (&http.Client{Timeout: daemonHandoffProbeTimeout}).Do(req) //nolint:gosec // G704: this node's own dashboard address from its config or listen record
	if err != nil {
		if isConnRefused(err) {
			return dashapi.DBNoDaemon
		}
		return dashapi.DBUnknown
	}
	_ = resp.Body.Close()
	return dashapi.ClassifyDBIdentity(want, resp.Header.Get(dashapi.DBIdentityHeader))
}

// isDBIdentityRefusal reports whether resp is a daemon's refusal of a
// request that named another database (the address changed hands after the
// probe): the caller treats it as no daemon for this database.
func isDBIdentityRefusal(resp *http.Response, want string) bool {
	if resp == nil || resp.StatusCode != http.StatusConflict {
		return false
	}
	return dashapi.ClassifyDBIdentity(want, resp.Header.Get(dashapi.DBIdentityHeader)) == dashapi.DBOther
}
