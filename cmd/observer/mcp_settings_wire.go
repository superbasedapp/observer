//go:build !sbo_omit_integration_mcp_server

package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/agentconfigsvc"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/configschema"
	"github.com/marmutapp/superbased-observer/internal/mcp"
	"github.com/marmutapp/superbased-observer/internal/settingsgate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// set_setting result statuses.
const (
	setStatusApplied  = "applied"
	setStatusProposed = "proposed"
	setStatusRefused  = "refused"
)

// mcpSettingsBackend is the cmd-layer implementation of mcp.SettingsBackend
// (Plane A W2-8, ruling D19): get_settings reads through the same read model
// as `observer config get|list`; set_setting dispatches on settingsgate's
// verdict, applying an ordinary key through applySetting (the `config set`
// write) and filing a security-sensitive one as a settings_proposals row.
// The config file is re-read on every call, so a long-lived `observer serve`
// never answers from a stale copy.
type mcpSettingsBackend struct {
	configPath string
	db         *sql.DB
	now        func() time.Time
}

func newMCPSettingsBackend(configPath string, database *sql.DB) *mcpSettingsBackend {
	return &mcpSettingsBackend{configPath: configPath, db: database, now: time.Now}
}

// GetSettings implements mcp.SettingsBackend.
func (b *mcpSettingsBackend) GetSettings(ctx context.Context, q mcp.SettingsQuery) (any, error) {
	cfg, err := loadConfigFile(b.configPath)
	if err != nil {
		return nil, err
	}
	gov, err := configSetGovernance(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if q.Key != "" {
		return getSetting(&cfg, q.Key, gov)
	}
	views := listSettings(&cfg, settingsFilter{Prefix: q.Prefix, Section: q.Section, Primary: q.Primary}, gov)
	return map[string]any{"count": len(views), "settings": views}, nil
}

// SetSetting implements mcp.SettingsBackend.
func (b *mcpSettingsBackend) SetSetting(ctx context.Context, req mcp.SetSettingRequest) (mcp.SetSettingResult, error) {
	cfg, err := loadConfigFile(b.configPath)
	if err != nil {
		return mcp.SetSettingResult{}, err
	}
	gov, err := configSetGovernance(ctx, cfg)
	if err != nil {
		return mcp.SetSettingResult{}, err
	}
	d := settingsgate.Decide(req.Key, req.Value, gov)
	res := mcp.SetSettingResult{Status: setStatusRefused, Key: req.Key, Category: string(d.Category), Reason: d.Reason}
	// A credential-shaped value is never stored, applied or proposed from an
	// agent: config.toml and settings_proposals are plain text.
	if agentconfigsvc.DefaultDetect(req.Value) {
		res.Status = setStatusRefused
		res.Reason = "the value looks like a credential; put it in an environment variable and set the *_env key instead"
		return res, nil
	}
	switch d.Verdict {
	case settingsgate.Apply:
		applied, err := applySetting(ctx, b.configPath, req.Key, req.Value, true)
		if err != nil {
			res.Status = setStatusRefused
			res.Reason = err.Error()
			return res, nil
		}
		res.Status, res.Value, res.Warnings = setStatusApplied, applied.Shown, applied.Warnings
		if applied.Reloaded {
			res.Next = "saved; the running daemon reloaded"
		} else {
			res.Next = "saved; it applies when the daemon next starts or reloads"
		}
		return res, nil
	case settingsgate.Propose:
		return b.propose(ctx, cfg, gov, req, d)
	default:
		return res, nil
	}
}

// propose validates the value as a real write would (so the user is never
// asked to approve a value that cannot save) and files the proposal.
func (b *mcpSettingsBackend) propose(ctx context.Context, cfg config.Config, gov configschema.KeyGovernance, req mcp.SetSettingRequest, d settingsgate.Decision) (mcp.SetSettingResult, error) {
	res := mcp.SetSettingResult{Key: req.Key, Category: string(d.Category), Reason: d.Reason}
	prev := currentSettingValue(&cfg, req.Key, gov)
	if _, err := planConfigSet(cfg, req.Key, req.Value, gov, true); err != nil {
		res.Status = setStatusRefused
		res.Reason = err.Error()
		return res, nil
	}
	who := "mcp"
	if c := strings.TrimSpace(req.Client); c != "" {
		who = "mcp:" + c
	}
	id, err := store.New(b.db).FileSettingsProposal(ctx, store.NewSettingsProposal{
		Key: req.Key, Value: req.Value, PrevValue: prev, Category: string(d.Category),
		Reason: d.Reason, RequestedBy: who, Note: req.Note,
	}, b.now())
	if err != nil {
		return mcp.SetSettingResult{}, fmt.Errorf("set_setting: file the proposal: %w", err)
	}
	res.Status, res.Value, res.Proposal = setStatusProposed, req.Value, id
	res.Next = fmt.Sprintf("nothing changed yet: ask the user to approve proposal %d on the dashboard (Settings, Changes waiting for you) or with `observer config proposals approve %d --yes`; you cannot approve it yourself", id, id)
	return res, nil
}
