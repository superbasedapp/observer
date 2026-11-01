package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/delivery"
	"github.com/marmutapp/superbased-observer/internal/deliverynet"
	"github.com/marmutapp/superbased-observer/internal/deliverysvc"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/landingscan"
	"github.com/marmutapp/superbased-observer/internal/shimguard"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Delivery wiring (commit to PR to merge, D-689; docs/projects-page.md
// "Delivery"). This file is the one place the delivery I/O packages are
// composed: the egress (internal/deliverynet), the keychain
// (internal/keystore) and the store are handed to internal/deliverysvc,
// which owns no I/O of its own. tests/invariant/delivery_egress_test.go
// pins that only the service and this command import deliverynet.
//
// The poll loop always runs under `observer start`, and makes NO network
// call until the user connects a code host or opts a project into a
// mirror schedule: each tick reads two small local tables and stops.

// deliveryCredDir is the hardened file fallback for the keychain (unix
// only, keystore's fail-closed semantics elsewhere), next to the database.
func deliveryCredDir(cfg config.Config) string {
	return filepath.Join(filepath.Dir(cfg.Observer.DBPath), "delivery-cred")
}

// newDeliveryService composes the service over database.
func newDeliveryService(cfg config.Config, database *sql.DB, logger *slog.Logger) *deliverysvc.Service {
	home, _ := os.UserHomeDir()
	var exclude []string
	if home != "" {
		exclude = append(exclude, shimguard.DefaultShimDir(runtime.GOOS, home))
	}
	st := store.New(database)
	credDir := deliveryCredDir(cfg)
	return deliverysvc.New(deliverysvc.Options{
		Store: st,
		Net:   deliverynet.New(deliverynet.Options{Version: version, ExcludeDirs: exclude, Logger: logger}),
		OpenKeys: func() deliverysvc.KeyStore {
			return keystore.Open(deliverysvc.KeystoreService, credDir, logger)
		},
		Reevaluate:     deliveryReevaluateFunc(st, cfg, logger),
		PollEvery:      time.Duration(cfg.Delivery.PollMinutes) * time.Minute,
		MirrorCapBytes: int64(cfg.Delivery.MirrorCapMB) << 20,
		Logger:         logger,
	})
}

// processDelivery is the daemon's one service: the dashboard routes and the
// poll loop share it, so "Check now" and a scheduled pass serialise on the
// same lock. The first caller's database handle wins; every handle reaches
// the same file.
var (
	processDeliveryMu  sync.Mutex
	processDeliverySvc *deliverysvc.Service
)

func processDelivery(cfg config.Config, database *sql.DB, logger *slog.Logger) *deliverysvc.Service {
	processDeliveryMu.Lock()
	defer processDeliveryMu.Unlock()
	if processDeliverySvc == nil {
		processDeliverySvc = newDeliveryService(cfg, database, logger)
	}
	return processDeliverySvc
}

// deliveryLoop runs the provider and mirror poll loop until ctx ends.
// Fail-soft: a config or database error idles the loop, never the daemon.
func deliveryLoop(ctx context.Context, configPath string) {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return
	}
	defer cleanup()
	processDelivery(cfg, database, newLogger(cfg.Observer.LogLevel)).Run(ctx)
}

// deliveryDashOption is the dashapi.Options.DeliveryService value both
// dashboard.New call sites pass.
func deliveryDashOption(cfg config.Config, database *sql.DB) dashapi.DeliveryService {
	if database == nil {
		return nil
	}
	return deliveryDash{svc: processDelivery(cfg, database, newLogger(cfg.Observer.LogLevel))}
}

// landingStepOptions wires one landing step (internal/landingscan) over st:
// every git call goes through gitview.RunReadOnlyNoLazyFetch (read-only,
// never reaching the network), every write through the store's owner of
// each table. The same wiring as commitscan_wire.go's after-scan step.
func landingStepOptions(st *store.Store, dcfg config.DeliveryConfig, logger *slog.Logger) landingscan.Options {
	return landingscan.Options{
		Exec: func(ctx context.Context, dir string, maxBytes int, args ...string) ([]byte, bool, error) {
			return gitview.RunReadOnlyNoLazyFetch(ctx, dir, maxBytes, landingScanExecTimeout, args...)
		},
		ExitCode: func(err error) (int, bool) {
			f, ok := gitview.InspectError(err)
			return f.ExitCode, ok
		},
		ModTime: func(path string) (time.Time, bool) {
			fi, err := os.Stat(path)
			if err != nil {
				return time.Time{}, false
			}
			return fi.ModTime(), true
		},
		Commits:                st.LoadDeliveryCommits,
		Landings:               st.LoadProjectLandings,
		PullRequests:           st.LoadProjectPullRequests,
		PRCommits:              st.LoadPullRequestCommits,
		BranchTips:             st.LoadBranchTips,
		Mirrors:                st.ListDeliveryMirrors,
		SetFingerprint:         st.SetCommitPatchFingerprint,
		SetPRCommitFingerprint: st.SetPRCommitPatchFingerprint,
		SaveRemote:             st.UpsertProjectRemote,
		SaveBranchTips:         st.UpsertBranchTips,
		SaveLandings:           st.UpsertCommitLandings,
		PollInterval:           time.Duration(dcfg.PollMinutes) * time.Minute,
		AbandonAfter:           time.Duration(dcfg.AbandonAfterDays) * 24 * time.Hour,
		Logger:                 logger,
	}
}

// deliveryReevaluateFunc is deliverysvc.Options.Reevaluate: load the
// project's root and run the landing step on it once, so new provider or
// mirror evidence turns into landings now rather than on the next commit
// scan. A fresh Step per call, because the daemon step throttles a root
// whose HEAD and FETCH_HEAD did not move, which is exactly the case here.
// Nil-returning (a no-op) when [delivery].local is off.
func deliveryReevaluateFunc(st *store.Store, cfg config.Config, logger *slog.Logger) func(ctx context.Context, projectID int64) error {
	if !cfg.Delivery.Local {
		return nil
	}
	return func(ctx context.Context, projectID int64) error {
		root, err := st.ProjectRootByID(ctx, projectID)
		if err != nil {
			return err
		}
		if root == "" {
			return fmt.Errorf("no project with id %d", projectID)
		}
		// A stored root that is not a path (FU-193's "Xcode (project
		// unknown)") is no repository: git would run in the daemon's
		// working directory instead (audit row 7).
		if !git.HostRooted(root) {
			return fmt.Errorf("project %d has no folder (its root %q is not a path), so there is no repository to check", projectID, root)
		}
		step := landingscan.New(landingStepOptions(st, cfg.Delivery, logger))
		_, err = step.Run(ctx, landingscan.Target{ProjectID: projectID, RootPath: commitScanRoot(root)})
		return err
	}
}

// commitRescanWithDelivery is the Projects page "Rescan now" seam with the
// landing step after it: the commit scan (commitscan_wire.go's
// commitRescanOption), then one unthrottled landing evaluation of the same
// project, so the Delivery tab moves with the Commits tab. Nil when commit
// scanning is off (the page hides the action).
func commitRescanWithDelivery(cfg config.Config, database *sql.DB) func(ctx context.Context, projectID int64) error {
	rescan := commitRescanOption(cfg, database)
	if rescan == nil {
		return nil
	}
	reevaluate := deliveryReevaluateFunc(store.New(database), cfg, newLogger(cfg.Observer.LogLevel))
	if reevaluate == nil {
		return rescan
	}
	return func(ctx context.Context, projectID int64) error {
		if err := rescan(ctx, projectID); err != nil {
			return err
		}
		if err := reevaluate(ctx, projectID); err != nil {
			return fmt.Errorf("commits scanned; delivery evaluation failed: %w", err)
		}
		return nil
	}
}

// deliveryDash adapts *deliverysvc.Service to dashapi.DeliveryService,
// translating its errors into *dashapi.DeliveryError so the dashboard never
// matches on another package's sentinels.
type deliveryDash struct{ svc *deliverysvc.Service }

func (d deliveryDash) Connect(ctx context.Context, req dashapi.DeliveryConnectRequest) (delivery.ProviderLink, error) {
	l, err := d.svc.Connect(ctx, deliverysvc.ConnectRequest{
		Provider: delivery.Provider(req.Provider), Host: req.Host, AuthMode: req.AuthMode, Token: req.Token,
	})
	return l, deliveryDashErr(err)
}

func (d deliveryDash) TestLink(ctx context.Context, id int64) (delivery.ProviderLink, error) {
	l, err := d.svc.TestLink(ctx, id)
	return l, deliveryDashErr(err)
}

func (d deliveryDash) Disconnect(ctx context.Context, id int64) error {
	return deliveryDashErr(d.svc.Disconnect(ctx, id))
}

func (d deliveryDash) DeleteMirror(ctx context.Context, id int64) error {
	return deliveryDashErr(d.svc.DeleteMirror(ctx, id))
}

func (d deliveryDash) MirrorUsage(ctx context.Context) (int64, int64, []delivery.Mirror, error) {
	return d.svc.MirrorUsage(ctx)
}

func (d deliveryDash) CheckProject(ctx context.Context, projectID int64) (dashapi.DeliveryCheckResult, error) {
	res, err := d.svc.CheckProject(ctx, projectID)
	if err != nil {
		return dashapi.DeliveryCheckResult{}, deliveryDashErr(err)
	}
	return deliveryCheckWire(res), nil
}

// deliveryCheckWire shapes a service pass for the dashboard and the CLI.
func deliveryCheckWire(res deliverysvc.Result) dashapi.DeliveryCheckResult {
	out := dashapi.DeliveryCheckResult{CheckedAt: dashapi.FmtProjectTime(res.CheckedAt), Reevaluated: res.Reevaluated, Repos: []dashapi.DeliveryCheckRepo{}}
	for _, r := range res.Repos {
		out.Repos = append(out.Repos, dashapi.DeliveryCheckRepo{
			RemoteName: r.RemoteName, RepoSlug: r.RepoSlug, Source: string(r.Source), Status: r.Status,
			Detail: r.Detail, CommitsChecked: r.CommitsChecked, PRsUpserted: r.PRsUpserted,
		})
	}
	return out
}

// deliveryErrRule is one row of the error table: the first row whose match
// holds decides the status, kind and plain message.
type deliveryErrRule struct {
	match   func(err error) bool
	status  int
	kind    string
	message string
}

func netKind(k deliverynet.Kind) func(error) bool {
	return func(err error) bool {
		var e *deliverynet.Error
		return errors.As(err, &e) && e.Kind == k
	}
}

// deliveryErrRules is THE service error table (CLAUDE.md rule 5).
var deliveryErrRules = []deliveryErrRule{
	{
		func(err error) bool { return errors.Is(err, deliverysvc.ErrNoKeychain) }, http.StatusConflict, "no_keychain",
		"No secure keychain is available on this machine to hold the token. Use your gh login instead, or set up a system keychain.",
	},
	{
		func(err error) bool { return errors.Is(err, deliverysvc.ErrUnsupported) }, http.StatusBadRequest, "unsupported",
		"Only GitHub is supported in this release, through a fine-grained token or your gh login.",
	},
	{
		func(err error) bool { return errors.Is(err, deliverysvc.ErrInvalid) }, http.StatusBadRequest, "invalid",
		"That request is not valid: check the host name and the token.",
	},
	{
		func(err error) bool { return errors.Is(err, deliverysvc.ErrNotFound) }, http.StatusNotFound, "not_found",
		"No such connection or mirror. Refresh the page.",
	},
	{
		func(err error) bool { return errors.Is(err, deliverysvc.ErrOverCap) }, http.StatusConflict, "over_cap",
		"The mirror disk cap is reached. Delete a mirror or raise [delivery].mirror_cap_mb.",
	},
	{
		netKind(deliverynet.KindAuthFailed), http.StatusUnprocessableEntity, "auth_failed",
		"GitHub refused the credential. Check the token (or run gh auth login) and try again.",
	},
	{
		netKind(deliverynet.KindRateLimited), http.StatusTooManyRequests, "rate_limited",
		"GitHub is rate limiting this account. Try again after the reset.",
	},
	{
		netKind(deliverynet.KindUnavailable), http.StatusUnprocessableEntity, "unavailable",
		"The gh command is not installed or not signed in on this machine.",
	},
	{
		netKind(deliverynet.KindHostNotAllowed), http.StatusBadRequest, "host_not_allowed",
		"That host is not on the allowed list. Only github.com is supported in this release.",
	},
	{
		netKind(deliverynet.KindNeedsNonInteractive), http.StatusUnprocessableEntity, "needs_noninteractive_credentials",
		"git asked for a password or a key passphrase, which Observer never answers. Set up a credential helper or an SSH agent for this remote.",
	},
	{
		netKind(deliverynet.KindRepoMoved), http.StatusBadGateway, "repo_moved",
		"The repository moved. Update the remote URL in your clone.",
	},
	{
		netKind(deliverynet.KindWrongShape), http.StatusBadGateway, "wrong_shape",
		"GitHub answered in an unexpected shape.",
	},
	{
		func(err error) bool { var e *deliverynet.Error; return errors.As(err, &e) }, http.StatusBadGateway, "unreachable",
		"GitHub could not be reached. Check the network and try again.",
	},
}

// deliveryDashErr maps a service error through deliveryErrRules; an
// unmatched error passes through (the handler answers 500 with its text).
func deliveryDashErr(err error) error {
	if err == nil {
		return nil
	}
	for _, r := range deliveryErrRules {
		if r.match(err) {
			return &dashapi.DeliveryError{Status: r.status, Kind: r.kind, Message: r.message}
		}
	}
	return err
}
