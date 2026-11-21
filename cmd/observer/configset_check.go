package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/marmutapp/superbased-observer/internal/agentconfigsvc"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/configschema"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/textdiff"
)

// `observer config set` parity with the dashboard's PUT /api/config/keys
// (adapter-config plan section 5.5 item 4): the same pure key check
// (configschema.CheckKey: tier and governance), the same per-leaf validation,
// the same write (config.PatchFile, comment-preserving where it can) and the
// same read-back, so the CLI is not a way around the Settings page.

// cliKeyGovernance adapts the node's governance posture to the check,
// exempting the sections that can never be hidden (the dashboard guard's
// nodegov.IsUnhideableSettingsSection rule).
type cliKeyGovernance struct{ eff govern.Effective }

func (g cliKeyGovernance) IsSettingsSectionHidden(s string) bool {
	return !nodegov.IsUnhideableSettingsSection(s) && g.eff.IsSettingsSectionHidden(s)
}

func (g cliKeyGovernance) IsSettingsSectionReadOnly(s string) bool {
	return !nodegov.IsUnhideableSettingsSection(s) && g.eff.IsSettingsSectionReadOnly(s)
}

// configSetPostureInput is what `observer config set` learned about this
// machine's organization posture, resolved at the boundary (T-395).
type configSetPostureInput struct {
	// dbExists: the node database file exists. A node with no database has
	// never enrolled.
	dbExists bool
	// dbErr: opening the existing database failed.
	dbErr error
	// lkg: what the verified governance cache load found.
	lkg lkgStatus
	// visibility: the installed governance has dashboard visibility active.
	visibility bool
}

// configSetPostureVerdict is how a `config set` proceeds.
type configSetPostureVerdict int

const (
	// postureUngoverned: no organization pin or hide applies.
	postureUngoverned configSetPostureVerdict = iota
	// postureGoverned: check every key against the installed governance.
	postureGoverned
	// postureRefuse: the posture could not be read; write nothing.
	postureRefuse
)

// configSetPostureRule is one row of the posture table.
type configSetPostureRule struct {
	name    string
	match   func(configSetPostureInput) bool
	verdict configSetPostureVerdict
	// message is the refusal text (postureRefuse only).
	message func(configSetPostureInput) string
}

// configSetPostureRules is walked top-down; the first match wins. It FAILS
// CLOSED (T-395): before it, a database that would not open, an enrolment
// that would not read and a governance cache that would not verify were all
// "checked as an unmanaged machine", so a setting the organization pinned or
// hid could be written from the CLI with no check at all. Every state that
// was a valid save before (no database, not enrolled, no policy ever applied,
// the operator not accepting the governance family, governance without
// visibility) still saves.
var configSetPostureRules = []configSetPostureRule{
	{
		name:    "no database: this machine never enrolled",
		match:   func(in configSetPostureInput) bool { return !in.dbExists },
		verdict: postureUngoverned,
	},
	{
		name:    "database exists but does not open",
		match:   func(in configSetPostureInput) bool { return in.dbErr != nil },
		verdict: postureRefuse,
		message: func(in configSetPostureInput) string {
			return "could not read this machine's organization settings (" + in.dbErr.Error() + "), so a setting your organization pinned or hid cannot be checked; nothing was written. Retry when the database opens, or make the change from the dashboard's Settings page"
		},
	},
	{
		name:    "enrolment unreadable",
		match:   func(in configSetPostureInput) bool { return in.lkg == lkgEnrolmentUnreadable },
		verdict: postureRefuse,
		message: func(configSetPostureInput) string {
			return "could not read this machine's organization enrolment, so a setting your organization pinned or hid cannot be checked; nothing was written. Retry, or make the change from the dashboard's Settings page"
		},
	},
	{
		name:    "an organization policy was applied but does not verify",
		match:   func(in configSetPostureInput) bool { return in.lkg == lkgUnverified },
		verdict: postureRefuse,
		message: func(configSetPostureInput) string {
			return "this machine holds an organization policy whose saved copy is missing or does not verify, so a setting it pins or hides cannot be checked; nothing was written. Start the daemon (observer start) so it fetches the policy again, then retry"
		},
	},
	{
		name:    "governed with visibility active",
		match:   func(in configSetPostureInput) bool { return in.lkg == lkgInstalled && in.visibility },
		verdict: postureGoverned,
	},
	{
		name:    "not enrolled, no policy, family not accepted, or no visibility",
		match:   func(configSetPostureInput) bool { return true },
		verdict: postureUngoverned,
	},
}

// resolveConfigSetPosture walks configSetPostureRules. It returns the
// verdict and, for a refusal, the message.
func resolveConfigSetPosture(in configSetPostureInput) (configSetPostureVerdict, string) {
	for _, r := range configSetPostureRules {
		if !r.match(in) {
			continue
		}
		if r.message != nil {
			return r.verdict, r.message(in)
		}
		return r.verdict, ""
	}
	return postureRefuse, "could not classify this machine's organization posture; nothing was written"
}

// configSetGovernance reads the node's governance posture from its verified
// on-disk LKG (the `observer reprice` path) and resolves it through
// configSetPostureRules. A node with no database yet has never enrolled, so
// it is ungoverned; the DB is never created for this. An error means the
// posture could not be read and nothing may be written.
func configSetGovernance(ctx context.Context, cfg config.Config) (configschema.KeyGovernance, error) {
	in := configSetPostureInput{}
	if _, err := os.Stat(cfg.Observer.DBPath); err == nil {
		in.dbExists = true
	}
	var eff govern.Effective
	if in.dbExists {
		database, cleanup, err := openDBForConfig(ctx, cfg)
		if err != nil {
			in.dbErr = err
		} else {
			defer cleanup()
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			st := store.New(database)
			ngov := newNodeGovernanceHandle(governanceIdentityLoader(st), logger)
			in.lkg = loadNodeGovernanceLKGStatus(ctx, cfg, st, ngov, logger)
			eff = ngov.Effective(ctx)
			in.visibility = eff.VisibilityActive()
		}
	}
	switch verdict, msg := resolveConfigSetPosture(in); verdict {
	case postureRefuse:
		return nil, errors.New("refusing to set: " + msg)
	case postureGoverned:
		return cliKeyGovernance{eff: eff}, nil
	default:
		return nil, nil
	}
}

// configSetPlan is a checked, not yet written `config set`.
type configSetPlan struct {
	key          string
	cfg          config.Config
	patch        config.Patch
	warnings     []string
	secretShaped bool
}

// planConfigSet runs the checks and applies the value to a copy of cfg.
// confirmed is --yes (or --dry-run, which writes nothing).
func planConfigSet(cfg config.Config, key, value string, gov configschema.KeyGovernance, confirmed bool) (configSetPlan, error) {
	c := configschema.CheckKey(key, gov)
	if c.Verdict != configschema.KeyOK {
		return configSetPlan{}, fmt.Errorf("refusing to set %s: %s", key, c.Message)
	}
	if c.NeedsConfirm && !confirmed {
		return configSetPlan{}, fmt.Errorf("%s is a sensitive setting (it changes what Observer captures, shares or exposes); re-run with --yes to confirm, or --dry-run to preview", key)
	}
	if err := config.SetConfigKey(&cfg, key, value); err != nil {
		return configSetPlan{}, err
	}
	leaf := c.Leaf
	v := configschema.Get(&cfg, leaf)
	if leaf.Path == key {
		if err := configschema.ValidateLeaf(leaf, v); err != nil {
			return configSetPlan{}, fmt.Errorf("refusing to save: %w", err)
		}
	}
	// Validate the resulting config before persisting: a value that parses
	// but violates an invariant (port range, mode names) must not land.
	if err := config.Validate(cfg); err != nil {
		return configSetPlan{}, fmt.Errorf("refusing to save: %w", err)
	}
	p := configSetPlan{key: key, cfg: cfg, patch: config.Patch{Dotted: leaf.Path}}
	if rhs, ok := configschema.TOMLScalar(leaf, v); ok && leaf.Path == key {
		p.patch.RHS, p.patch.Scalar = rhs, true
	}
	if configschema.SecretShapedLeaf(leaf, v, agentconfigsvc.DefaultDetect) {
		p.secretShaped = true
		p.warnings = append(p.warnings, key+" looks like a credential; config.toml is plain text, so prefer an environment-variable reference")
	}
	return p, nil
}

// printConfigSetDryRun prints the masked diff of what the write would do.
func printConfigSetDryRun(out io.Writer, path string, p configSetPlan) error {
	current, err := os.ReadFile(path)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	text, res, err := config.RenderPatch(current, exists, p.cfg, []config.Patch{p.patch})
	if err != nil {
		return err
	}
	if !res.Wrote {
		fmt.Fprintf(out, "%s already says this; nothing would change\n", path)
		return nil
	}
	before := configschema.MaskTOMLSecrets(string(current), agentconfigsvc.DefaultDetect)
	after := configschema.MaskTOMLSecrets(string(text), agentconfigsvc.DefaultDetect)
	diff, stats := textdiff.Unified(path, path+" (after)", before, after, 3)
	fmt.Fprint(out, diff)
	mode := string(res.Mode)
	if res.Reason != "" {
		mode += " (" + res.Reason + ")"
	}
	fmt.Fprintf(out, "dry run: +%d -%d lines, write mode %s; nothing written\n", stats.Added, stats.Removed, mode)
	return nil
}

// writeConfigSet writes through config.PatchFile and verifies the file by
// reading it back; a file that does not load is restored from the .bak.
func writeConfigSet(path string, p configSetPlan) error {
	res, err := config.PatchFile(path, p.cfg, []config.Patch{p.patch})
	if err != nil {
		return err
	}
	if !res.Wrote {
		return nil
	}
	back, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err == nil {
		err = config.Validate(back)
	}
	if err != nil {
		if rerr := config.RestoreBackup(path); rerr != nil {
			return fmt.Errorf("the written config.toml did not read back (%w) and restoring %s.bak also failed: %w", err, path, rerr)
		}
		return fmt.Errorf("the written config.toml did not read back (%w); restored the previous file from %s.bak", err, path)
	}
	return nil
}

// openDBForConfig opens the node's existing database the way
// loadConfigAndDB does, for a config that is already loaded.
func openDBForConfig(ctx context.Context, cfg config.Config) (*sql.DB, func(), error) {
	database, err := db.Open(ctx, db.Options{
		Path:               cfg.Observer.DBPath,
		HardHeapLimitBytes: int64(cfg.Observer.DB.HardHeapLimitMB) * (1 << 20),
		TempStore:          cfg.Observer.DB.TempStore,
		MaxOpenConns:       cfg.Observer.DB.MaxOpenConns,
		ConnMaxIdleTime:    time.Duration(cfg.Observer.DB.ConnMaxIdleSeconds) * time.Second,
	})
	if err != nil {
		return nil, func() {}, err
	}
	return database, func() { _ = database.Close() }, nil
}
