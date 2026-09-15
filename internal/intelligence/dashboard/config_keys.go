package dashboard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/config/schema"
	"github.com/marmutapp/superbased-observer/internal/configschema"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
)

// The generic, schema-driven config write route and its two companions
// (docs/plans/dashboard-config-management-plan-2026-08-28.md §2.2, items
// P1-3 / P1-5 / P1-6 / P0-8):
//
//	GET /api/config/schema   L  the embedded, doc-bearing schema
//	PUT /api/config/keys     L  batched dotted-key write
//	GET /api/admin/restart   L  live-proxy-traffic report for the confirm dialog
//
// The bespoke verbs (/api/terminal/policy, /api/terminal/limits,
// /api/terminal/sandbox/config, /api/process/enable-capture, /api/remote/*)
// stay: they carry semantics the generic route cannot (platform-honest
// refusals, live-apply hops, cross-key invariants). This route is the floor
// that guarantees coverage, not a replacement for a well-designed verb.

// configKeysPath is the generic write route. governanceGuard has a
// body-aware arm keyed on it (plan §4.5).
const configKeysPath = "/api/config/keys"

// configKeysMaxBody bounds the PUT body. 525 keys × a generous value is
// well under this; a bigger body is not a settings save.
const configKeysMaxBody = 1 << 20

// readBackConfig re-loads the file just written for verification. A
// package variable so a test can force the failure path (plan §2.2 step 9)
// without needing a filesystem that lies.
var readBackConfig = func(path string) (config.Config, error) {
	return config.Load(config.LoadOptions{GlobalPath: path})
}

// handleConfigSchema serves GET /api/config/schema — the generated schema
// (internal/config/schema/schema.gen.json). Class L: it describes the
// owner-local settings surface, and the routes it drives are all L.
func (s *Server) handleConfigSchema(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(schema.JSON)
}

// configEtag hashes the config file's bytes: "sha256:<hex>". A missing file
// hashes as empty content, so a first save against a not-yet-created file
// still has a well-defined base. Detects hand-edits and CLI writes as well
// as concurrent dashboard saves (plan §2.4 / Q3).
func configEtag(path string) (string, error) {
	body, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("hash config: %w", err)
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// configKeyPatch is one wire patch. Value is any JSON value the leaf's kind
// accepts (see configschema.ParseValue). Was, optional, is the value the
// client rendered — on an etag conflict the server reports which patched
// keys actually diverged from it, so the UI can say "changed from X to Y
// outside this page" instead of a bare "reload".
type configKeyPatch struct {
	Key   string          `json:"key"`
	Value json.RawMessage `json:"value"`
	Was   json.RawMessage `json:"was,omitempty"`
}

type configKeysRequest struct {
	BaseEtag string           `json:"base_etag"`
	Patches  []configKeyPatch `json:"patches"`
}

// keyError is a per-key failure the form renders inline.
type keyError struct {
	Key     string `json:"key"`
	Message string `json:"message"`
}

func writeKeyErrors(w http.ResponseWriter, status int, code string, errs []keyError) {
	writeJSONStatus(w, status, map[string]any{
		"error":      code,
		"message":    summarizeKeyErrors(errs),
		"key_errors": errs,
	})
}

func summarizeKeyErrors(errs []keyError) string {
	parts := make([]string, 0, len(errs))
	for _, e := range errs {
		parts = append(parts, e.Key+": "+e.Message)
	}
	return strings.Join(parts, "; ")
}

// resolvedPatch is a wire patch after schema lookup + parse.
type resolvedPatch struct {
	leaf  configschema.Leaf
	value any
	raw   configKeyPatch
}

// handleConfigKeys serves PUT /api/config/keys (plan §2.2). Every step is
// fail-closed and ordered so nothing touches the file until the batch has
// passed class, governance (in the guard), tier, per-key validation, the
// etag check and config.Validate:
//
//  1. decode + schema lookup (unknown key → 400 naming it)
//  2. tier gate: secret → 403 (never written, never read); owner-elsewhere
//     (incl. deprecated aliases and compound tables) → 409 naming the owner;
//     sensitive → the confirm-token double-submit (requireJSONConfirm)
//  3. per-key parse + ValidateLeaf → 400 with key_errors
//  4. remoteManageMu → configWriteMu (the one config-write lock domain)
//  5. etag check → 409 with the diverged keys
//  6. load → Set per patch → config.Validate → 400, file untouched
//  7. config.PatchFile (surgical where it can, re-serialize where it must)
//  8. read-back verification: re-Load + re-Validate; on failure restore the
//     .bak and answer 500 naming the failure
//  9. live seams (cost engine, terminal limits, OnConfigSaved) + audit row
//     (key NAMES and counts, never values)
//
// The response classifies every changed key by its restart class so the UI
// chip and the restart-pending banner are derived, never guessed.
func (s *Server) handleConfigKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "PUT only", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.ConfigPath == "" {
		http.Error(w, "config path not configured — server has no file to save to", http.StatusConflict)
		return
	}
	req, patches, ok := s.resolveConfigKeys(w, r)
	if !ok {
		return
	}

	// 4. One config-write lock domain, established order.
	remoteManageMu.Lock()
	defer remoteManageMu.Unlock()
	s.configWriteMu.Lock()
	defer s.configWriteMu.Unlock()

	// 5. Etag.
	current, err := configEtag(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, err)
		return
	}
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, fmt.Errorf("load current config: %w", err))
		return
	}
	if req.BaseEtag != current {
		writeJSONStatus(w, http.StatusConflict, map[string]any{
			"error":         "config_changed",
			"message":       "config.toml changed outside this page since it was loaded — reload, then re-apply your edits",
			"config_etag":   current,
			"diverged_keys": divergedKeys(&cfg, patches),
		})
		return
	}

	// 6. Apply on a deep copy of the loaded config, then validate.
	prev := cloneConfig(cfg)
	for _, p := range patches {
		if err := configschema.Set(&cfg, p.leaf, p.value); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if err := config.Validate(cfg); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{
			"error":   "invalid_config",
			"message": err.Error(),
		})
		return
	}
	changed := configschema.ChangedLeaves(&prev, &cfg)

	// 7. Write — surgical where it can, re-serialize where it must.
	res, err := config.PatchFile(s.opts.ConfigPath, cfg, filePatchesFor(patches))
	if err != nil {
		writeErr(w, err)
		return
	}

	// 8. Read-back verification.
	if res.Wrote && !s.verifyReadBack(w, res) {
		return
	}

	// 9. Live seams + audit.
	classes := s.applyLiveSeams(cfg, changed)
	s.notifyConfigSaved()
	newEtag, _ := configEtag(s.opts.ConfigPath)
	s.recordManageAudit(r, "config_keys", fmt.Sprintf("keys=%s changed=%d mode=%s comments_kept=%v",
		strings.Join(patchKeys(patches), ","), len(changed), res.Mode, res.CommentsKept))

	resp := map[string]any{
		"saved":                 true,
		"changed_keys":          orEmptyStrings(changed),
		"restart_required":      len(classes.restart) > 0,
		"restart_required_keys": orEmptyStrings(classes.restart),
		"applied_live_keys":     orEmptyStrings(classes.live),
		"next_spawn_keys":       orEmptyStrings(classes.nextSpawn),
		"comments_preserved":    res.CommentsKept,
		"write_mode":            string(res.Mode),
		"config_path":           s.opts.ConfigPath,
		"backup_path":           res.BackupPath,
		"config_etag":           newEtag,
	}
	if res.Reason != "" {
		resp["write_mode_reason"] = res.Reason
	}
	if !res.Wrote {
		resp["write_mode"] = "noop"
	}
	writeJSON(w, resp)
}

// resolveConfigKeys runs steps 1–3 of handleConfigKeys: decode, schema
// lookup, the tier gate (secret 403 / owner-elsewhere 409 / sensitive →
// confirm token) and per-key parse + validation. It writes the refusal
// itself and returns ok=false when the request must not proceed. Nothing
// here touches the lock or the file.
func (s *Server) resolveConfigKeys(w http.ResponseWriter, r *http.Request) (configKeysRequest, []resolvedPatch, bool) {
	var req configKeysRequest
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, configKeysMaxBody))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return req, nil, false
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return req, nil, false
	}
	if len(req.Patches) == 0 {
		http.Error(w, "no patches", http.StatusBadRequest)
		return req, nil, false
	}
	if strings.TrimSpace(req.BaseEtag) == "" {
		http.Error(w, "base_etag required — read GET /api/config first", http.StatusBadRequest)
		return req, nil, false
	}

	// 1. Lookup. 2. Tier gate.
	patches := make([]resolvedPatch, 0, len(req.Patches))
	var unknown, secret, owned []keyError
	seen := map[string]bool{}
	var needsConfirm bool
	for _, p := range req.Patches {
		if seen[p.Key] {
			http.Error(w, "duplicate key in batch: "+p.Key, http.StatusBadRequest)
			return req, nil, false
		}
		seen[p.Key] = true
		leaf, ok := configschema.Lookup(p.Key)
		if !ok {
			unknown = append(unknown, keyError{Key: p.Key, Message: "unknown config key"})
			continue
		}
		switch leaf.Tier {
		case configschema.TierSecret:
			secret = append(secret, keyError{Key: p.Key, Message: (&errSecretWrite{Key: p.Key, ConfigPath: s.opts.ConfigPath}).Error()})
		case configschema.TierOwnerElsewhere:
			owned = append(owned, keyError{Key: p.Key, Message: "read-only here — owned by " + leaf.OwnedBy})
		case configschema.TierSensitive:
			needsConfirm = true
		}
		patches = append(patches, resolvedPatch{leaf: leaf, raw: p})
	}
	switch {
	case len(unknown) > 0:
		writeKeyErrors(w, http.StatusBadRequest, "unknown_key", unknown)
		return req, nil, false
	case len(secret) > 0:
		// A credential in the batch refuses the WHOLE batch; nothing is
		// logged (the audit row is written only after a write).
		writeKeyErrors(w, http.StatusForbidden, "secret_write_refused", secret)
		return req, nil, false
	case len(owned) > 0:
		writeKeyErrors(w, http.StatusConflict, "owner_elsewhere", owned)
		return req, nil, false
	}
	if needsConfirm && !requireJSONConfirm(w, r) {
		return req, nil, false
	}

	// 3. Parse + validate per key.
	var invalid []keyError
	for i := range patches {
		v, err := configschema.ParseValue(patches[i].leaf, patches[i].raw.Value)
		if err == nil {
			err = configschema.ValidateLeaf(patches[i].leaf, v)
		}
		if err != nil {
			invalid = append(invalid, keyError{Key: patches[i].leaf.Path, Message: err.Error()})
			continue
		}
		patches[i].value = v
	}
	if len(invalid) > 0 {
		writeKeyErrors(w, http.StatusBadRequest, "invalid_value", invalid)
		return req, nil, false
	}
	return req, patches, true
}

// filePatchesFor renders the resolved patches for config.PatchFile: a TOML
// scalar RHS where the kind has one, Scalar=false (→ re-serialize) where
// it does not.
func filePatchesFor(patches []resolvedPatch) []config.Patch {
	out := make([]config.Patch, 0, len(patches))
	for _, p := range patches {
		fp := config.Patch{Dotted: p.leaf.Path}
		if rhs, ok := configschema.TOMLScalar(p.leaf, p.value); ok {
			fp.RHS, fp.Scalar = rhs, true
		}
		out = append(out, fp)
	}
	return out
}

// verifyReadBack is step 8: re-Load + re-Validate the file just written.
// On failure it restores the .bak, answers 500 naming both the failure and
// the restore outcome, and returns false.
func (s *Server) verifyReadBack(w http.ResponseWriter, res config.PatchResult) bool {
	back, rerr := readBackConfig(s.opts.ConfigPath)
	if rerr == nil {
		rerr = config.Validate(back)
	}
	if rerr == nil {
		return true
	}
	restoreErr := config.RestoreBackup(s.opts.ConfigPath)
	msg := "read-back verification failed after write: " + rerr.Error()
	if restoreErr != nil {
		msg += "; RESTORE FROM .bak ALSO FAILED: " + restoreErr.Error() + " — recover by hand from " + res.BackupPath
	} else {
		msg += "; restored the previous config.toml from " + res.BackupPath
	}
	s.opts.Logger.Error("config keys write rolled back", "error", rerr, "restore_error", restoreErr)
	writeJSONStatus(w, http.StatusInternalServerError, map[string]any{"error": "read_back_failed", "message": msg})
	return false
}

// restartClasses buckets changed keys by what happens to them now.
type restartClasses struct {
	live, nextSpawn, restart []string
}

// classifyChanged buckets changed dotted keys by their schema restart class.
// livePersistOK reports whether the live_persist seam for a key actually
// ran; when it did not, the key is honestly reported as restart-required.
func classifyChanged(changed []string, livePersistOK func(key string) bool) restartClasses {
	var c restartClasses
	for _, key := range changed {
		leaf, ok := configschema.Lookup(key)
		if !ok {
			c.restart = append(c.restart, key)
			continue
		}
		switch leaf.Restart {
		case configschema.RestartLive:
			c.live = append(c.live, key)
		case configschema.RestartLivePersist:
			if livePersistOK != nil && livePersistOK(key) {
				c.live = append(c.live, key)
			} else {
				c.restart = append(c.restart, key)
			}
		case configschema.RestartNextSpawn:
			c.nextSpawn = append(c.nextSpawn, key)
		default:
			c.restart = append(c.restart, key)
		}
	}
	return c
}

// applyLiveSeams runs the hot-reload seams a changed key set needs (plan
// §3.2) and returns the honest classification: a live_persist key whose
// seam is not wired on this server degrades to restart-required.
func (s *Server) applyLiveSeams(cfg config.Config, changed []string) restartClasses {
	var pricing, limits bool
	for _, key := range changed {
		switch {
		case strings.HasPrefix(key, "intelligence.pricing."):
			pricing = true
		case key == "terminal.max_concurrent" || key == "terminal.idle_timeout":
			limits = true
		}
	}
	if pricing && s.opts.CostEngine != nil {
		s.opts.CostEngine.Reload(cfg.Intelligence)
	}
	limitsApplied := false
	if limits {
		if setter, ok := s.opts.LaunchManager.(terminalLimitsSetter); ok {
			setter.SetTerminalLimits(cfg.Terminal.MaxConcurrent, parseIdleTimeout(cfg.Terminal.IdleTimeout))
			limitsApplied = true
		}
	}
	return classifyChanged(changed, func(key string) bool {
		switch key {
		case "terminal.max_concurrent", "terminal.idle_timeout":
			return limitsApplied
		}
		return false
	})
}

// divergedKeys reports which patched keys' CURRENT values differ from the
// value the client says it rendered (`was`). Keys without a `was` are
// skipped — there is nothing honest to compare them against.
func divergedKeys(cfg *config.Config, patches []resolvedPatch) []string {
	var out []string
	for _, p := range patches {
		if len(p.raw.Was) == 0 {
			continue
		}
		was, err := configschema.ParseValue(p.leaf, p.raw.Was)
		if err != nil {
			continue
		}
		cur := configschema.Get(cfg, p.leaf)
		if !reflect.DeepEqual(normalizeForCompare(cur), normalizeForCompare(was)) {
			out = append(out, p.leaf.Path)
		}
	}
	return orEmptyStrings(out)
}

// normalizeForCompare widens ints to int64 and nil slices/maps to empty so a
// parsed `was` compares against the struct value like for like.
func normalizeForCompare(v any) any {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int()
	case reflect.Float32, reflect.Float64:
		return rv.Float()
	case reflect.Slice:
		if rv.Len() == 0 {
			return []string{}
		}
		if rv.Type().Elem().Kind() == reflect.String {
			out := make([]string, rv.Len())
			for i := range out {
				out[i] = rv.Index(i).String()
			}
			return out
		}
	case reflect.Map:
		if rv.Len() == 0 {
			return map[string]string{}
		}
		if rv.Type().Key().Kind() == reflect.String && rv.Type().Elem().Kind() == reflect.String {
			out := make(map[string]string, rv.Len())
			for _, k := range rv.MapKeys() {
				out[k.String()] = rv.MapIndex(k).String()
			}
			return out
		}
	}
	return v
}

// cloneConfig deep-copies a Config through the TOML codec so the pre-update
// snapshot ChangedLeaves compares against cannot share a slice or map with
// the copy being patched. Falls back to a shallow struct copy if the codec
// fails (it does not for a Config the loader accepted).
func cloneConfig(cfg config.Config) config.Config {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(cfg); err != nil {
		return cfg
	}
	var out config.Config
	if _, err := toml.Decode(buf.String(), &out); err != nil {
		return cfg
	}
	return out
}

func patchKeys(patches []resolvedPatch) []string {
	out := make([]string, 0, len(patches))
	for _, p := range patches {
		out = append(out, p.leaf.Path)
	}
	sort.Strings(out)
	return out
}

func orEmptyStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// governanceConfigKeys is the body-aware arm of governanceGuard for the
// generic write route (plan §4.5): a batch has no <section> in its path, so
// every key's section is resolved from the schema and the WHOLE batch is
// refused if any is hidden (404) or read-only (409). An unmappable key fails
// closed (409 governance_unmappable) — a governed node must never write a
// key the guard could not classify. The body is re-attached for the
// handler. Returns true when the request was refused.
func governanceConfigKeys(w http.ResponseWriter, r *http.Request, eff interface {
	IsSettingsSectionHidden(string) bool
	IsSettingsSectionReadOnly(string) bool
}, refuse func(w http.ResponseWriter, status int, code, section, msg string),
) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, configKeysMaxBody))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return true
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	var req configKeysRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return true
	}
	for _, p := range req.Patches {
		section, ok := configschema.SectionOf(p.Key)
		if !ok {
			refuse(w, http.StatusConflict, "governance_unmappable", p.Key,
				"This key could not be mapped to a governed settings section on a managed node; the batch was not applied.")
			return true
		}
		if nodegov.IsUnhideableSettingsSection(section) {
			continue
		}
		if eff.IsSettingsSectionHidden(section) {
			refuse(w, http.StatusNotFound, "governance_hidden", section,
				"This page is managed by your organization and is not available on this machine.")
			return true
		}
		if eff.IsSettingsSectionReadOnly(section) {
			refuse(w, http.StatusConflict, "governance_read_only", section,
				"This setting is pinned by your organization and cannot be changed here.")
			return true
		}
	}
	return false
}

// handleAdminRestartStatus serves GET /api/admin/restart — the live-traffic
// report the restart confirm dialog shows (plan §3.3 item 3): proxied API
// turns in the last 60 seconds. The daemon IS the proxy on its port, so a
// restart drops in-flight proxy requests; the dialog says so with a number
// instead of a vague warning. Never automates the route OFF/ON dance
// (deliberately out of scope, plan §3.3).
func (s *Server) handleAdminRestartStatus(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"available":  s.opts.RestartFunc != nil,
		"proxy_port": s.opts.ProxyPort,
		"window_s":   60,
	}
	if st := s.remoteManageStore(); st != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if n, err := st.CountAPITurnsSince(ctx, time.Now().Add(-60*time.Second)); err == nil {
			resp["proxy_recent_requests"] = n
		}
	}
	writeJSON(w, resp)
}
