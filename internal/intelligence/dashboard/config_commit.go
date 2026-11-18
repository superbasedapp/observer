package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/agentconfigsvc"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/configschema"
	"github.com/marmutapp/superbased-observer/internal/textdiff"
)

// The ONE config.toml save pipeline (T-432). Both dashboard write routes,
// PUT /api/config/keys (dotted leaves) and PUT /api/config/section/<id>
// (a whole section body), decode their own request shape onto an in-memory
// copy of the config and then hand the result here. Everything after the
// decode is shared, so the two routes cannot drift apart again:
//
//   - the secret posture: a credential-shaped value is a warning, refused
//     where the node's posture says so (adapter-config plan section 5.5 item 2)
//   - the sensitive-tier confirm token (requireJSONConfirm)
//   - the dry run: the masked unified diff of the exact bytes the write would
//     produce (config.RenderPatch, the renderer config.PatchFile uses)
//   - the write (config.PatchFile), the read-back verification, the live
//     seams, the restart classification and the audit row
//
// Before T-432 the section route wrote with no dry run, no secret warning,
// no confirm token for sensitive keys and no audit row, and nine web call
// sites used it.

// configSave is one decoded, applied and validated config.toml save.
type configSave struct {
	// prev is the config as loaded; cfg the config after the request's
	// changes. Both are already validated by the caller.
	prev, cfg config.Config
	// changed is configschema.ChangedLeaves(prev, cfg).
	changed []string
	// patches is what config.PatchFile writes.
	patches []config.Patch
	// etag is the config file's etag at load time.
	etag string
	// needsConfirm reports a sensitive-tier key in the save.
	needsConfirm bool
	// secretWarnings are the credential-shaped values in the save.
	secretWarnings []keyError
	// dryRun renders the diff and writes nothing.
	dryRun bool
	// auditAction / auditDetail name the audit row (key NAMES, never values).
	auditAction, auditDetail string
	// extra fields merged into the response (the section route's "section").
	extra map[string]any
	// afterWrite, when set, runs after a real save (not a dry run) and its
	// fields are merged into the response after extra.
	afterWrite func() map[string]any
}

// leafValue is one leaf and the value a save would give it.
type leafValue struct {
	leaf  configschema.Leaf
	value any
}

// secretWarningsFor flags values that look like credentials (internal/scrub's
// pattern-certain detectors, or a credential-named map key). Key names only:
// the value is never echoed.
func secretWarningsFor(values []leafValue) []keyError {
	var out []keyError
	for _, v := range values {
		if configschema.SecretShapedLeaf(v.leaf, v.value, agentconfigsvc.DefaultDetect) {
			out = append(out, keyError{Key: v.leaf.Path, Message: "this value looks like a credential; config.toml is plain text, so prefer an environment-variable reference"})
		}
	}
	return out
}

// changedLeafValues resolves every changed dotted key to its leaf and the
// value cfg now holds. A key the schema cannot resolve is skipped (the
// restart classifier already reports it as restart-required).
func changedLeafValues(cfg *config.Config, changed []string) []leafValue {
	out := make([]leafValue, 0, len(changed))
	for _, key := range changed {
		leaf, ok := configschema.Lookup(key)
		if !ok {
			continue
		}
		out = append(out, leafValue{leaf: leaf, value: configschema.Get(cfg, leaf)})
	}
	return out
}

// changedNeedsConfirm reports whether any changed key is a sensitive-tier
// key (configschema.CheckKey's NeedsConfirm, the rule the keys route and
// `observer config set` apply).
func changedNeedsConfirm(changed []string) bool {
	for _, key := range changed {
		if configschema.CheckKey(key, nil).NeedsConfirm {
			return true
		}
	}
	return false
}

// refuseSecretPosture answers 422 secret_value_refused when the save carries
// a credential-shaped value and the node's posture refuses them. A dry run
// is never refused: it reports the warnings instead. Returns true when the
// request was refused.
func (s *Server) refuseSecretPosture(w http.ResponseWriter, r *http.Request, warnings []keyError, dryRun bool) bool {
	if len(warnings) == 0 || dryRun {
		return false
	}
	if s.agentConfigAccess(r.Context()).SecretsPosture != agentconfig.SecretsRefuse {
		return false
	}
	writeKeyErrors(w, http.StatusUnprocessableEntity, "secret_value_refused", warnings)
	return true
}

// writeConfigChanged answers the optimistic-concurrency conflict.
func writeConfigChanged(w http.ResponseWriter, current string, diverged []string) {
	writeJSONStatus(w, http.StatusConflict, map[string]any{
		"error":         "config_changed",
		"message":       "config.toml changed outside this page since it was loaded - reload, then re-apply your edits",
		"config_etag":   current,
		"diverged_keys": orEmptyStrings(diverged),
	})
}

// commitConfigSave runs the shared tail of every config.toml save: the
// secret posture, the confirm token, then either the dry run or the write,
// read-back, live seams, audit and response. The caller holds the config
// write locks (remoteManageMu then configWriteMu).
func (s *Server) commitConfigSave(w http.ResponseWriter, r *http.Request, sv configSave) {
	if s.refuseSecretPosture(w, r, sv.secretWarnings, sv.dryRun) {
		return
	}
	// A dry run writes nothing, so it reports needs_confirm instead of
	// demanding the token; the real save still demands it.
	if sv.needsConfirm && !sv.dryRun && !requireJSONConfirm(w, r) {
		return
	}
	if sv.dryRun {
		s.configDryRun(w, sv)
		return
	}

	res, err := config.PatchFile(s.opts.ConfigPath, sv.cfg, sv.patches)
	if err != nil {
		writeErr(w, err)
		return
	}
	if res.Wrote && !s.verifyReadBack(w, res) {
		return
	}

	classes := s.applyLiveSeams(sv.cfg, sv.changed)
	s.notifyConfigSaved()
	newEtag, _ := configEtag(s.opts.ConfigPath)
	s.recordManageAudit(r, sv.auditAction, fmt.Sprintf("%s changed=%d mode=%s comments_kept=%v",
		sv.auditDetail, len(sv.changed), res.Mode, res.CommentsKept))

	resp := map[string]any{
		"saved":                 true,
		"changed_keys":          orEmptyStrings(sv.changed),
		"restart_required":      len(classes.restart) > 0,
		"restart_required_keys": orEmptyStrings(classes.restart),
		"applied_live_keys":     orEmptyStrings(classes.live),
		"next_spawn_keys":       orEmptyStrings(classes.nextSpawn),
		"comments_preserved":    res.CommentsKept,
		"write_mode":            string(res.Mode),
		"config_path":           s.opts.ConfigPath,
		"backup_path":           s.opts.ConfigPath + ".bak",
		"config_etag":           newEtag,
		"secret_warnings":       orEmptyKeyErrors(sv.secretWarnings),
	}
	if res.Reason != "" {
		resp["write_mode_reason"] = res.Reason
	}
	if !res.Wrote {
		resp["write_mode"] = "noop"
	}
	for k, v := range sv.extra {
		resp[k] = v
	}
	if sv.afterWrite != nil {
		for k, v := range sv.afterWrite() {
			resp[k] = v
		}
	}
	keepRestartRequiredHonest(resp, classes)
	writeJSON(w, resp)
}

// keepRestartRequiredHonest applies the one rule after a route's extras
// (lane FU10, F-049): a route may raise restart_required (it knows the
// section binds at start), never lower it below a listed restart key, so
// the boolean and restart_required_keys cannot contradict each other.
func keepRestartRequiredHonest(resp map[string]any, classes restartClasses) {
	if len(classes.restart) > 0 {
		resp["restart_required"] = true
	}
}

// configDryRun answers a dry run: the masked unified diff of the bytes the
// save would write (config.RenderPatch, the same renderer PatchFile uses),
// the changed keys and their restart classes. Nothing is written and
// nothing is audited.
func (s *Server) configDryRun(w http.ResponseWriter, sv configSave) {
	current, err := os.ReadFile(s.opts.ConfigPath)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		writeErr(w, fmt.Errorf("read config: %w", err))
		return
	}
	text, res, err := config.RenderPatch(current, exists, sv.cfg, sv.patches)
	if err != nil {
		writeErr(w, err)
		return
	}
	before := configschema.MaskTOMLSecrets(string(current), agentconfigsvc.DefaultDetect)
	after := configschema.MaskTOMLSecrets(string(text), agentconfigsvc.DefaultDetect)
	diff, stats := textdiff.Unified("config.toml", "config.toml (after save)", before, after, 3)
	_, launchLive := s.opts.LaunchManager.(terminalLimitsSetter)
	classes := classifyChanged(sv.changed, func(key string) bool {
		return launchLive && (key == "terminal.max_concurrent" || key == "terminal.idle_timeout")
	})
	resp := map[string]any{
		"dry_run":               true,
		"would_write":           res.Wrote,
		"changed_keys":          orEmptyStrings(sv.changed),
		"restart_required":      len(classes.restart) > 0,
		"restart_required_keys": orEmptyStrings(classes.restart),
		"applied_live_keys":     orEmptyStrings(classes.live),
		"next_spawn_keys":       orEmptyStrings(classes.nextSpawn),
		"comments_preserved":    res.CommentsKept,
		"write_mode":            string(res.Mode),
		"config_path":           s.opts.ConfigPath,
		"config_etag":           sv.etag,
		"diff":                  diff,
		"diff_stats":            stats,
		"needs_confirm":         sv.needsConfirm,
		"secret_warnings":       orEmptyKeyErrors(sv.secretWarnings),
	}
	if res.Reason != "" {
		resp["write_mode_reason"] = res.Reason
	}
	for k, v := range sv.extra {
		resp[k] = v
	}
	keepRestartRequiredHonest(resp, classes)
	writeJSON(w, resp)
}

// editPatches is sectionFilePatches, except that an edit with keysOnNewFile
// writes only its changed keys into a file that does not exist yet.
func editPatches(ed configEdit, prev, cfg config.Config, fileExists bool) []config.Patch {
	if ed.keysOnNewFile && !fileExists {
		if patches, err := config.StructuralPatches(prev, cloneConfig(cfg)); err == nil && len(patches) > 0 {
			return patches
		}
	}
	return sectionFilePatches(ed.section, prev, cfg, fileExists)
}

// sectionFilePatches is what a whole-section save hands config.PatchFile.
// A section body can change values the schema does not model as scalar
// leaves (lists, tables, compound rule blocks). Since T-524 the save names
// exactly the keys it changed (config.StructuralPatches, the TOML-tree diff
// of the loaded and the edited config), and PatchFile applies them key by
// key through the comment-preserving cfgfmt engine, so the operator's
// comments and every untouched line survive; it falls back to the whole-file
// re-serialize (reported as write_mode "reserialize" with its reason) only
// when the file does not exist yet, when the diff cannot be computed, or when
// an edit cannot be made in place. When the re-encoded config is
// byte-identical to the loaded one (and the file exists) the save is a no-op
// and the file is not touched (no .bak churn).
func sectionFilePatches(section string, prev, cfg config.Config, fileExists bool) []config.Patch {
	// prev is a TOML-codec round trip (cloneConfig); compare like with like.
	edited := cloneConfig(cfg)
	if fileExists && configBytesEqual(prev, edited) {
		return nil
	}
	if fileExists {
		if patches, err := config.StructuralPatches(prev, edited); err == nil && len(patches) > 0 {
			return patches
		}
	}
	return []config.Patch{{Dotted: section, Scalar: false}}
}

// configBytesEqual compares two configs by their TOML encoding.
func configBytesEqual(a, b config.Config) bool {
	ea, errA := encodeConfig(a)
	eb, errB := encodeConfig(b)
	if errA != nil || errB != nil {
		return false
	}
	return ea == eb
}

func encodeConfig(cfg config.Config) (string, error) {
	var sb strings.Builder
	if err := toml.NewEncoder(&sb).Encode(cfg); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// configEdit is a dedicated editor's save of one config.toml section (the
// Terminals SSH profile editor, the launch policy, the sandbox editor, the
// profile assignments, the pricing table, the process-capture switch): the
// request was already decoded and validated by the route; apply (or edit)
// writes its values onto the loaded config.
type configEdit struct {
	// section is the dotted section the edit owns (the patch target).
	section string
	// apply writes the edit onto the loaded config.
	apply func(cfg *config.Config)
	// edit is apply's form for an editor whose change depends on the loaded
	// config (T-572). A non-nil err answers 400 with its message (or the
	// status a configEditRefusal carries, T-639); a non-nil
	// respond is answered as-is (an idempotent or refused edit). Either way
	// nothing is written. Exactly one of apply / edit is set.
	edit func(cfg *config.Config) (respond any, err error)
	// auditAction / auditDetail name the audit row (metadata only).
	auditAction, auditDetail string
	// auditDetailFor, when set, replaces auditDetail with a detail computed
	// from the edited config (metadata only).
	auditDetailFor func(cfg config.Config) string
	// extra builds the route's own response fields from the saved config.
	extra func(cfg config.Config) map[string]any
	// afterWrite runs after a real save (never a dry run) and returns
	// fields merged into the response (a live reload's warnings).
	afterWrite func(cfg config.Config) map[string]any
	// keysOnNewFile, when set, writes only the changed keys into a config
	// file that does not exist yet (config.StructuralPatches, T-741/D-551),
	// instead of the whole section's re-serialize that pins every default.
	// The launchpad's first-launch consent sets it: on a fresh machine its
	// preview shows the three keys it writes, not a 900-line file.
	keysOnNewFile bool
}

// configEditRefusal is an edit's refusal answered with its own status (a
// 409 duplicate, a 404 unknown name) rather than the default 400, so an
// editor moved onto the pipeline keeps the statuses its clients already
// handle (T-639).
type configEditRefusal struct {
	status int
	msg    string
}

// Error implements error.
func (e configEditRefusal) Error() string { return e.msg }

// responseFields renders a route's typed response struct as the map the
// save pipeline merges into its answer, so an editor keeps its established
// response shape.
func responseFields(v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]any{}
	}
	out := map[string]any{}
	if err := json.Unmarshal(b, &out); err != nil {
		return map[string]any{}
	}
	return out
}

// commitConfigEdit routes a dedicated editor's write through the ONE save
// pipeline (REVIEW-3 P3-18): `?dry_run=1` answers the masked diff of the
// bytes the save would write and writes nothing; `?base_etag=` refuses with
// 409 config_changed when config.toml changed since that preview; the write
// then gets the secret posture, read-back, live seams and the audit row like
// every section save. Before this the SSH profile and launch policy editors
// rewrote config.toml directly with no preview and no conflict check.
func (s *Server) commitConfigEdit(w http.ResponseWriter, r *http.Request, ed configEdit) {
	q := r.URL.Query()
	dryRun := q.Get("dry_run") == "1" || q.Get("dry_run") == "true"
	baseEtag := strings.TrimSpace(q.Get("base_etag"))

	// Same lock order as every whole-config read-modify-write:
	// remoteManageMu (outer), then configWriteMu (inner).
	remoteManageMu.Lock()
	defer remoteManageMu.Unlock()
	s.configWriteMu.Lock()
	defer s.configWriteMu.Unlock()

	current, err := configEtag(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, err)
		return
	}
	if baseEtag != "" && baseEtag != current {
		writeConfigChanged(w, current, nil)
		return
	}
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, fmt.Errorf("load current config: %w", err))
		return
	}
	prev := cloneConfig(cfg)
	if ed.edit != nil {
		respond, err := ed.edit(&cfg)
		if err != nil {
			status := http.StatusBadRequest
			var refusal configEditRefusal
			if errors.As(err, &refusal) {
				status = refusal.status
			}
			http.Error(w, err.Error(), status)
			return
		}
		if respond != nil {
			writeJSON(w, respond)
			return
		}
	} else {
		ed.apply(&cfg)
	}
	if err := config.Validate(cfg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, statErr := os.Stat(s.opts.ConfigPath)
	changed := configschema.ChangedLeaves(&prev, &cfg)
	var extra map[string]any
	if ed.extra != nil {
		extra = ed.extra(cfg)
	}
	if extra == nil {
		extra = map[string]any{}
	}
	extra["section"] = ed.section
	detail := ed.auditDetail
	if ed.auditDetailFor != nil {
		detail = ed.auditDetailFor(cfg)
	}
	var afterWrite func() map[string]any
	if ed.afterWrite != nil {
		saved := cfg
		afterWrite = func() map[string]any { return ed.afterWrite(saved) }
	}
	s.commitConfigSave(w, r, configSave{
		afterWrite:     afterWrite,
		prev:           prev,
		cfg:            cfg,
		changed:        changed,
		patches:        editPatches(ed, prev, cfg, statErr == nil),
		etag:           current,
		needsConfirm:   changedNeedsConfirm(changed),
		secretWarnings: secretWarningsFor(changedLeafValues(&cfg, changed)),
		dryRun:         dryRun,
		auditAction:    ed.auditAction,
		auditDetail:    detail,
		extra:          extra,
	})
}
