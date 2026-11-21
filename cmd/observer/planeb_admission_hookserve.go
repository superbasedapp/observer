package main

import (
	"context"
	"log/slog"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/promptjudgeipc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// planeb_admission_hookserve.go is the daemon half of the hook lane of the
// organization's prompt judge (P-228 phase 2, lane adm-2): the owner-only
// ask endpoint (internal/promptjudgeipc) a prompt-gate hook dials, answered
// by the SAME node lane the proxy uses (planeBNodeLane.admitHook): one
// engine, one verdict cache, one negative cache, one secret gate and one
// audit seam.
//
// Why this channel: the hook process makes no network calls, so it needs a
// local request to the daemon. internal/localipc is the owner-only transport
// the security ask (internal/secask) and the MCP relay already use from the
// same hook and daemon processes; the attach socket was not reused because it
// belongs to the terminals component (a build may omit it) and carries PTY
// framing a one-line ask does not need. Its endpoint is derived from its own
// key beside the DB, so it never collides with the attach, relay or security
// endpoints.

// configurePlaneBNodeLane binds the lane's engine, org relay judge and audit
// writer (both builds: with and without the proxy).
func configurePlaneBNodeLane(relay orgJudgeRelayFunc, st *store.Store, logger *slog.Logger) {
	var persist func(context.Context, []guard.ActionVerdict) error
	if st != nil {
		persist = func(ctx context.Context, vs []guard.ActionVerdict) error {
			_, err := st.PersistGuardVerdicts(ctx, vs)
			return err
		}
	}
	processPlaneBLane.configure(relay, persist, logger)
}

// promptJudgeAnswerer adapts the lane to the ask channel.
func promptJudgeAnswerer(l *planeBNodeLane) promptjudgeipc.Answerer {
	return func(ctx context.Context, a promptjudgeipc.Asked) promptjudgeipc.Answer {
		o, active := l.admitHook(ctx, planeBPromptInput{SessionID: a.SessionID, Tool: a.Tool}, a.Prompt, a.Oversize)
		if !active {
			return promptjudgeipc.Answer{}
		}
		return promptjudgeipc.Answer{Active: true, Action: string(o.Action), Basis: string(o.Basis), Criterion: o.Criterion, Reason: o.Reason}
	}
}

// servePromptJudge serves the ask endpoint for the daemon's lifetime. It
// always listens (the answer says when no policy applies), so a hook that a
// fresh signed posture told to ask finds the daemon. A platform with no
// owner-only transport, or a second daemon on the same DB, logs and returns.
func servePromptJudge(ctx context.Context, configPath string, logger *slog.Logger) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		if logger != nil {
			logger.Warn("prompt judge: config load failed; the hook ask endpoint is not served", "err", err)
		}
		return
	}
	ln, ep, err := promptjudgeipc.Listen(cfg.Observer.DBPath)
	if err != nil {
		if logger != nil {
			logger.Warn("prompt judge: the hook ask endpoint is not served", "err", err)
		}
		return
	}
	if logger != nil {
		logger.Debug("prompt judge: serving the hook ask endpoint", "endpoint", ep)
	}
	if err := promptjudgeipc.Serve(ctx, ln, promptJudgeAnswerer(processPlaneBLane)); err != nil && logger != nil {
		logger.Warn("prompt judge: hook ask endpoint stopped", "err", err)
	}
}
