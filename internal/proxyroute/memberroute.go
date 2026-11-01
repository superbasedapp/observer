package proxyroute

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
	"github.com/marmutapp/superbased-observer/internal/credfile"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/regularfile"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

// The member-route writers (surface-gap lane w6-routes: OI-1, S-16, S-22,
// CLI-1a). Each writes a few members into a vendor file that also holds
// plaintext credentials, under decisions D9 / D16: surgical member edits
// through internal/credfile (SetMember, which verifies the decoded result),
// a declared credential-file row (integration.ProxyRoute.SharesCredentialFile,
// refused otherwise), never a whole-file read into any surface. The rules
// the probe writers follow (probe_write.go) apply: a symbolic link or a
// non-regular file is refused, the file is read through the capped,
// FIFO-safe regularfile.Read, the mode is kept, the write is atomic and
// abandoned if the file changed under it, no backup is left, and no error
// quotes the file. A writer never creates the file: the tool's own setup
// does, with the developer's key, and an absent file is the benign
// ConfigMissing skip.
//
// Every writer in this table is built switched OFF behind a live check
// (DEC-12): its registry row carries the gate, and the writer refuses
// before it reads anything (liveGateRefusal / defaultLiveGateRefusal).
//
// The rules are one data table, walked the same way for every tool
// (CLAUDE.md #5): a spec names the file, what must already be there, what
// must not be, and the members Observer owns, each with its kind.

// memberRouteMaxBytes caps the read of a member-route file (a vendor
// settings file is kilobytes).
const memberRouteMaxBytes int64 = 2 << 20

// memberKind is how one owned member is decided.
type memberKind int

const (
	// memberURL is a base URL: absent is added, any loopback Observer URL
	// is kept (another local port included), anything else is refused.
	memberURL memberKind = iota
	// memberFixed is a companion value written with the route (a wire
	// format, a display name): absent is added, an equal value is kept,
	// another value is refused.
	memberFixed
	// memberSelect selects Observer's provider entry: absent is set, the
	// same value is kept, another value is refused unless Force, and the
	// value replaced is reported (PriorProvider) for the remover.
	memberSelect
)

// routeMember is one member a writer owns.
type routeMember struct {
	path  cfgfmt.Path
	kind  memberKind
	value func(port int) any
}

// memberRequirement is a precondition on the file: path must exist, and
// when oneOf is set its string value must be one of them. A spec's
// requirements are ANY-of when anyOf is set on the spec.
type memberRequirement struct {
	path  cfgfmt.Path
	oneOf []string
	// what is the human name of the requirement for the refusal.
	what string
}

// peerRequirement is a member that must exist in ANOTHER file of the tool
// (the provider entry the launcher writes, which the default-provider
// writer selects). Only that member is looked up.
type peerRequirement struct {
	artifact string
	format   cfgfmt.Format
	path     cfgfmt.Path
	advice   string
}

// memberRouteSpec is one writer's row.
type memberRouteSpec struct {
	tool     string
	artifact string
	format   cfgfmt.Format
	// defaultProvider marks a default-provider writer
	// (integration.ProxyRoute.PersistedDefault), gated by its own gate.
	defaultProvider bool
	// require are the file's preconditions; anyOf makes them alternatives.
	require []memberRequirement
	anyOf   bool
	// forbid are paths whose presence makes the file one the tool would
	// not load with the route (Codex's reserved [model_providers.openai]).
	forbid []memberRequirement
	peer   *peerRequirement
	// members are the owned members; the first is the primary one whose
	// value is the result's BaseURL and the provenance value.
	members []routeMember
}

func fixedValue(v any) func(int) any { return func(int) any { return v } }

// memberRouteSpecs is the table. Each row's registry entry carries the live
// gate and the credential-file declaration.
var memberRouteSpecs = []memberRouteSpec{
	{
		// OI-1 (D16, LC11): Open Interpreter is a rebadged Codex build that
		// reads model_provider and [model_providers.<id>] from its own
		// config.toml (INTERPRETER_HOME). The same provider Codex's writer
		// adds, under the same name.
		tool: "open-interpreter", artifact: "open-interpreter/user-config", format: cfgfmt.FormatTOML,
		forbid: []memberRequirement{{path: cfgfmt.Path{"model_providers", "openai"}, what: "a [model_providers.openai] table (reserved by the Codex core, which refuses to load it)"}},
		members: []routeMember{
			{path: cfgfmt.Path{"model_providers", ProviderName, "base_url"}, kind: memberURL, value: func(p int) any { return codexBaseURL(p) }},
			{path: cfgfmt.Path{"model_providers", ProviderName, "name"}, kind: memberFixed, value: fixedValue(providerDisplayName)},
			{path: cfgfmt.Path{"model_providers", ProviderName, "wire_api"}, kind: memberFixed, value: fixedValue("responses")},
			{path: cfgfmt.Path{"model_providers", ProviderName, "requires_openai_auth"}, kind: memberFixed, value: fixedValue(true)},
			{path: cfgfmt.Path{"model_provider"}, kind: memberSelect, value: fixedValue(ProviderName)},
		},
	},
	{
		// S-22 (D9, LC37): a Stakpak profile provider's api_endpoint. Which
		// profile a run with neither --profile nor STAKPAK_PROFILE uses is
		// not grounded; the writer targets the "default" profile's openai
		// provider only, and only when the developer configured it.
		tool: "stakpak", artifact: "stakpak/user-config", format: cfgfmt.FormatTOML,
		require: []memberRequirement{{path: cfgfmt.Path{"profiles", "default", "providers", "openai"}, what: "[profiles.default.providers.openai] provider"}},
		members: []routeMember{
			{path: cfgfmt.Path{"profiles", "default", "providers", "openai", "api_endpoint"}, kind: memberURL, value: func(p int) any { return openAICompatProxyURL(p) }},
		},
	},
	{
		// S-16 (D9, LCR-1): Poolside's pool.api_url (personal file only),
		// through the /up/poolside/ lane whose upstream is Poolside's hosted
		// OpenAI-compatible inference host. Whether the agent's API speaks
		// that protocol is the live check.
		tool: "poolside", artifact: "poolside/personal-settings", format: cfgfmt.FormatYAML,
		members: []routeMember{
			{path: cfgfmt.Path{"pool", "api_url"}, kind: memberURL, value: poolsideProxyURL},
		},
	},
	{
		// CLI-1a (LC25): goose reads OPENAI_HOST from config.yaml as it does
		// from the environment (the variable the opt-in launcher injects),
		// so a bare `goose` routes when the active provider is openai.
		tool: "goose", artifact: "goose/user-config", format: cfgfmt.FormatYAML, defaultProvider: true, anyOf: true,
		require: []memberRequirement{
			{path: cfgfmt.Path{"active_provider"}, oneOf: []string{"openai"}, what: "active_provider: openai"},
			{path: cfgfmt.Path{"GOOSE_PROVIDER"}, oneOf: []string{"openai"}, what: "GOOSE_PROVIDER: openai"},
		},
		members: []routeMember{
			{path: cfgfmt.Path{"OPENAI_HOST"}, kind: memberURL, value: func(p int) any { return fmt.Sprintf("http://127.0.0.1:%d", p) }},
		},
	},
	{
		// CLI-1a (LC25): Hermes's default provider, set to the observer
		// provider entry `observer hermes` writes into the same file.
		tool: "hermes", artifact: "hermes/user-config", format: cfgfmt.FormatYAML, defaultProvider: true,
		require: []memberRequirement{{path: cfgfmt.Path{"providers", "observer"}, what: "the providers.observer entry (`observer hermes` writes it)"}},
		members: []routeMember{
			{path: cfgfmt.Path{"model", "provider"}, kind: memberSelect, value: fixedValue("observer")},
		},
	},
	{
		// CLI-1a (LC25): pi's defaultProvider (live key name), set to the
		// observer provider `observer pi` writes into models.json.
		tool: "pi", artifact: "pi/user-settings", format: cfgfmt.FormatJSON, defaultProvider: true,
		peer: &peerRequirement{artifact: "pi/user-models", format: cfgfmt.FormatJSON, path: cfgfmt.Path{"providers", "observer"}, advice: "run `observer pi` once; its launcher writes the observer provider"},
		members: []routeMember{
			{path: cfgfmt.Path{"defaultProvider"}, kind: memberSelect, value: fixedValue("observer")},
		},
	},
	{
		// CLI-1a (LC25): prime-agent's defaultProvider (live key name), the
		// same shape as pi (a hard fork).
		tool: "prime-agent", artifact: "prime-agent/user-settings", format: cfgfmt.FormatJSON, defaultProvider: true,
		peer: &peerRequirement{artifact: "prime-agent/user-models", format: cfgfmt.FormatJSON, path: cfgfmt.Path{"providers", "observer"}, advice: "run `observer prime-agent` once; its launcher writes the observer provider"},
		members: []routeMember{
			{path: cfgfmt.Path{"defaultProvider"}, kind: memberSelect, value: fixedValue("observer")},
		},
	},
}

// poolsideLaneID is the proxy lane the Poolside route rides.
const poolsideLaneID = "poolside"

// poolsideProxyURL is the Poolside route value: the poolside lane on
// loopback, with the OpenAI-compatible /v1 suffix.
func poolsideProxyURL(port int) any {
	return fmt.Sprintf("http://127.0.0.1:%d/up/%s/v1", port, poolsideLaneID)
}

// memberSpecFor returns tool's row.
func memberSpecFor(tool string, defaultProvider bool) (memberRouteSpec, bool) {
	for _, s := range memberRouteSpecs {
		if s.tool == tool && s.defaultProvider == defaultProvider {
			return s, true
		}
	}
	return memberRouteSpec{}, false
}

// MemberRouteTools lists the tools with a member-route writer, and
// DefaultProviderTools those with a default-provider writer, in table order.
func MemberRouteTools() []string { return memberTools(false) }

// DefaultProviderTools lists the tools with a default-provider writer.
func DefaultProviderTools() []string { return memberTools(true) }

func memberTools(defaultProvider bool) []string {
	var out []string
	for _, s := range memberRouteSpecs {
		if s.defaultProvider == defaultProvider {
			out = append(out, s.tool)
		}
	}
	return out
}

// RegisterMemberRoute runs tool's member-route writer (the registry row's
// ProxyProbe binding). An unknown tool is an error.
func (r *Registrar) RegisterMemberRoute(tool string) RegistrationResult {
	return r.registerMember(tool, false)
}

// RegisterDefaultProvider runs tool's default-provider writer (the
// registry route's PersistedDefault). An unknown tool is an error.
func (r *Registrar) RegisterDefaultProvider(tool string) RegistrationResult {
	return r.registerMember(tool, true)
}

func (r *Registrar) registerMember(tool string, defaultProvider bool) RegistrationResult {
	spec, ok := memberSpecFor(tool, defaultProvider)
	if !ok {
		return RegistrationResult{Tool: tool, DryRun: r.opts.DryRun, Error: fmt.Errorf("proxyroute: %s has no member-route writer", tool)}
	}
	res := r.writeMember(spec)
	if res.Error != nil || res.SkipReason != "" {
		return res
	}
	return r.note(res, res.BaseURL)
}

// what names a spec in errors.
func (s memberRouteSpec) what() string {
	if s.defaultProvider {
		return "proxyroute." + s.tool + ".default"
	}
	return "proxyroute." + s.tool
}

// writeMember is the writer core, without the provenance record.
func (r *Registrar) writeMember(spec memberRouteSpec) RegistrationResult {
	what := spec.what()
	want := fmt.Sprint(spec.members[0].value(r.opts.ProxyPort))
	// The record names the member the route lives at (FU-139), so Leave and
	// the port move read it with this row's reader even when another writer
	// later records a route for the same tool.
	res := RegistrationResult{Tool: spec.tool, BaseURL: want, DryRun: r.opts.DryRun, RouteKey: []string(spec.members[0].path)}
	path, err := routeArtifactPath(what, spec.artifact, r.opts.HomeDir, r.opts.Getenv)
	if err != nil {
		res.Error = err
		return res
	}
	res.ConfigPath = path
	refuse := r.liveGateRefusal
	if spec.defaultProvider {
		refuse = r.defaultLiveGateRefusal
	}
	if gated, ok := refuse(spec.tool, path); ok {
		gated.BaseURL = want
		return gated
	}
	if !integration.RouteSharesCredentialFile(spec.tool) {
		res.Error = credfile.SafeErrorf("%s: the registry row does not declare %s under the credential-file exception, so Observer does not edit it", what, path)
		return res
	}
	if r.opts.Lock != nil && !r.opts.DryRun {
		unlock, lerr := r.opts.Lock(path)
		if lerr != nil {
			res.Error = fmt.Errorf("%s: lock: %w", what, lerr)
			return res
		}
		defer unlock()
	}
	raw, err := readMemberRouteFile(what, path)
	if errors.Is(err, errRouteFileMissing) {
		res.ConfigMissing = true
		return res
	}
	if err != nil {
		res.Error = err
		return res
	}
	if err := spec.checkFile(what, path, raw); err != nil {
		res.Error = err
		return res
	}
	if spec.peer != nil {
		if err := r.checkPeer(what, spec.peer); err != nil {
			res.Error = err
			return res
		}
	}
	out, changed, prior, err := r.applyMembers(what, path, spec, raw)
	if err != nil {
		res.Error = err
		return res
	}
	res.PriorProvider = prior
	if !changed {
		res.AlreadySet = true
		if v, ok, _ := credfile.MemberValue(spec.format, raw, spec.members[0].path); ok {
			res.BaseURL = fmt.Sprint(v)
		}
		return res
	}
	res.Added = true
	if r.opts.DryRun {
		return res
	}
	if err := writeFileKeepModeIf(path, out, unchangedSince(path, raw)); err != nil {
		res.Added = false
		res.Error = credfile.Withhold(what, path, fmt.Errorf("write: %w", err))
	}
	return res
}

// readMemberRouteFile reads path when it is a layout the writers own: a
// regular file, not a symbolic link, within the cap, read without blocking
// on a FIFO. An absent file returns errRouteFileMissing.
func readMemberRouteFile(what, path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errRouteFileMissing
	}
	if err != nil {
		return nil, credfile.Withhold(what, path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, credfile.SafeErrorf("%s: %s is a symbolic link; Observer edits only a regular file it can replace in place, so nothing was written", what, path)
	}
	raw, err := regularfile.Read(path, memberRouteMaxBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errRouteFileMissing
	}
	if err != nil {
		return nil, credfile.SafeErrorf("%s: %s is not a regular settings file Observer can read (a FIFO, a device, a directory, or larger than %d bytes); nothing was written", what, path, memberRouteMaxBytes)
	}
	return raw, nil
}

// unchangedSince is the write precondition: the file still holds raw.
func unchangedSince(path string, raw []byte) func() error {
	return func() error {
		now, err := regularfile.Read(path, memberRouteMaxBytes)
		if err != nil || string(now) != string(raw) {
			return errors.New("the file changed while Observer edited it; nothing was written")
		}
		return nil
	}
}

// checkFile applies the spec's requirements and refusals to the file.
func (s memberRouteSpec) checkFile(what, path string, raw []byte) error {
	for _, f := range s.forbid {
		if _, found, err := credfile.MemberValue(s.format, raw, f.path); err != nil {
			return credfile.Withhold(what, path, err)
		} else if found {
			return credfile.SafeErrorf("%s: %s holds %s; nothing was written", what, path, f.what)
		}
	}
	if len(s.require) == 0 {
		return nil
	}
	var missing []string
	for _, q := range s.require {
		ok, err := q.met(s.format, raw)
		if err != nil {
			return credfile.Withhold(what, path, err)
		}
		if ok && s.anyOf {
			return nil
		}
		if !ok {
			missing = append(missing, q.what)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sep := " and "
	if s.anyOf {
		sep = " or "
	}
	return credfile.SafeErrorf("%s: %s has no %s to route; nothing was written", what, path, strings.Join(missing, sep))
}

// met reports whether the requirement holds. A value compared against
// oneOf is never quoted.
func (q memberRequirement) met(f cfgfmt.Format, raw []byte) (bool, error) {
	v, found, err := credfile.MemberValue(f, raw, q.path)
	if err != nil || !found {
		return false, err
	}
	if len(q.oneOf) == 0 {
		return true, nil
	}
	sv, _ := v.(string)
	for _, w := range q.oneOf {
		if strings.TrimSpace(sv) == w {
			return true, nil
		}
	}
	return false, nil
}

// checkPeer requires the peer member in the tool's other file.
func (r *Registrar) checkPeer(what string, p *peerRequirement) error {
	path, err := routeArtifactPath(what, p.artifact, r.opts.HomeDir, r.opts.Getenv)
	if err != nil {
		return err
	}
	raw, err := readMemberRouteFile(what, path)
	if errors.Is(err, errRouteFileMissing) {
		return credfile.SafeErrorf("%s: %s is missing, so %s is not there to select (%s); nothing was written", what, path, p.path, p.advice)
	}
	if err != nil {
		return err
	}
	_, found, err := credfile.MemberValue(p.format, raw, p.path)
	if err != nil {
		return credfile.Withhold(what, path, err)
	}
	if !found {
		return credfile.SafeErrorf("%s: %s has no %s to select (%s); nothing was written", what, path, p.path, p.advice)
	}
	return nil
}

// applyMembers decides every member and returns the edited bytes, whether
// anything changed, and the selector value replaced ("" when none).
func (r *Registrar) applyMembers(what, path string, spec memberRouteSpec, raw []byte) ([]byte, bool, string, error) {
	out := raw
	changed := false
	prior := ""
	for _, m := range spec.members {
		want := m.value(r.opts.ProxyPort)
		cur, found, err := credfile.MemberValue(spec.format, out, m.path)
		if err != nil {
			return nil, false, "", credfile.Withhold(what, path, err)
		}
		set, err := m.decide(what, path, cur, found, want, r.opts.Force)
		if err != nil {
			return nil, false, "", err
		}
		if !set {
			continue
		}
		if m.kind == memberSelect && found {
			prior, _ = cur.(string)
		}
		next, err := credfile.SetMember(spec.format, out, m.path, want, true)
		if err != nil {
			return nil, false, "", credfile.Withhold(what, path, err)
		}
		out, changed = next, true
	}
	return out, changed, prior, nil
}

// decide applies the member's kind rule: set reports whether to write want.
func (m routeMember) decide(what, path string, cur any, found bool, want any, force bool) (bool, error) {
	if !found || isEmptyValue(cur) {
		return true, nil
	}
	switch m.kind {
	case memberURL:
		s, ok := cur.(string)
		if !ok {
			return false, credfile.SafeErrorf("%s: %s in %s is not a string; nothing was written", what, m.path, path)
		}
		if strings.TrimSpace(s) == want || IsObserverBaseURL(strings.TrimSpace(s)) {
			return false, nil
		}
		return false, foreignRouteError(what, path, m.path)
	case memberFixed:
		if cfgfmt.Equal(cur, want) {
			return false, nil
		}
		return false, credfile.SafeErrorf("%s: %s in %s already holds another value; refusing to overwrite it", what, m.path, path)
	default: // memberSelect
		if cfgfmt.Equal(cur, want) {
			return false, nil
		}
		if force {
			return true, nil
		}
		return false, credfile.SafeErrorf("%s: %s in %s already selects another provider; refusing to switch it (pass --force)", what, m.path, path)
	}
}

func isEmptyValue(v any) bool {
	s, ok := v.(string)
	return v == nil || (ok && strings.TrimSpace(s) == "")
}

// readMemberRouteFor reads the primary member of tool's route at path, for
// Leave and the inspectors. A missing file is "not set".
func readMemberRouteFor(spec memberRouteSpec) func(path string) (string, bool, error) {
	return func(path string) (string, bool, error) {
		what := spec.what() + ".read"
		raw, err := readMemberRouteFile(what, path)
		if errors.Is(err, errRouteFileMissing) {
			return "", false, nil
		}
		if err != nil {
			return "", false, err
		}
		v, found, err := credfile.MemberValue(spec.format, raw, spec.members[0].path)
		if err != nil || !found {
			return "", false, err
		}
		s := strings.TrimSpace(fmt.Sprint(v))
		return s, s != "", nil
	}
}

// removeMemberRouteFor undoes exactly what the writer wrote, while the
// primary member still holds value: every owned member still holding the
// writer's value is removed, and a replaced selector is put back to prior.
func removeMemberRouteFor(spec memberRouteSpec, port func(value string) int) func(path, value, prior string) error {
	return func(path, value, prior string) error {
		what := spec.what() + ".remove"
		raw, err := readMemberRouteFile(what, path)
		if errors.Is(err, errRouteFileMissing) {
			return credfile.SafeErrorf("%s: %s is gone", what, path)
		}
		if err != nil {
			return err
		}
		cur, _, err := credfile.MemberValue(spec.format, raw, spec.members[0].path)
		if err != nil {
			return credfile.Withhold(what, path, err)
		}
		if strings.TrimSpace(fmt.Sprint(cur)) != value {
			return credfile.SafeErrorf("%s: %s in %s is no longer the value Observer wrote", what, spec.members[0].path, path)
		}
		p := port(value)
		out := raw
		for _, m := range spec.members {
			now, found, err := credfile.MemberValue(spec.format, out, m.path)
			if err != nil {
				return credfile.Withhold(what, path, err)
			}
			if !found || !cfgfmt.Equal(now, m.value(p)) {
				continue
			}
			restore := m.kind == memberSelect && prior != ""
			var next []byte
			if restore {
				next, err = credfile.SetMember(spec.format, out, m.path, prior, true)
			} else {
				next, err = deleteMember(spec.format, out, m.path)
			}
			if err != nil {
				return credfile.Withhold(what, path, err)
			}
			out = next
		}
		if string(out) == string(raw) {
			return nil
		}
		if err := writeFileKeepModeIf(path, out, unchangedSince(path, raw)); err != nil {
			return credfile.Withhold(what, path, fmt.Errorf("write: %w", err))
		}
		return nil
	}
}

// deleteMember removes path from out. When path is the only key of its
// parent table, the parent goes instead (and so on up), as deleteTOMLKey
// does for Codex: a table the writer created has no line of its own beyond
// its header, so removing its last key is the removal of the table, and a
// write then a removal leaves the file as it was.
func deleteMember(f cfgfmt.Format, out []byte, path cfgfmt.Path) ([]byte, error) {
	for len(path) > 1 {
		v, found, err := credfile.MemberValue(f, out, path[:len(path)-1])
		if err != nil {
			return nil, err
		}
		m, ok := v.(map[string]any)
		if !found || !ok || len(m) != 1 {
			break
		}
		if _, only := m[path[len(path)-1]]; !only {
			break
		}
		path = path[:len(path)-1]
	}
	return credfile.SetMember(f, out, path, nil, false)
}

// portOf is the proxy port a recorded route value names (0 for a value
// that is not a URL, such as a provider name).
func portOf(value string) int {
	u, err := url.Parse(value)
	if err != nil {
		return 0
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		return 0
	}
	return p
}

// specForRecord returns the row of tool a route record was written by: the
// row whose primary member is the record's RouteKey (FU-139), or, for a
// record with no RouteKey (none is written today; kept so an older record is
// still read the way it was), the tool's first row. ok is false for a key
// none of the tool's rows owns: that record is another writer's route.
func specForRecord(tool string, rec *routeprov.Record) (memberRouteSpec, bool) {
	var first *memberRouteSpec
	for i := range memberRouteSpecs {
		s := &memberRouteSpecs[i]
		if s.tool != tool {
			continue
		}
		if first == nil {
			first = s
		}
		if rec != nil && len(rec.RouteKey) > 0 && slices.Equal(rec.RouteKey, []string(s.members[0].path)) {
			return *s, true
		}
	}
	if first == nil || (rec != nil && len(rec.RouteKey) > 0) {
		return memberRouteSpec{}, false
	}
	return *first, true
}

// memberShape is the Leave / port-move shape of every member-route row of
// tool (FU-139). Each call resolves the row the record names
// (specForRecord); a record no row owns is refused, never read with another
// row's reader. A row whose primary member is a base URL (memberURL) moves
// with the proxy port: want is that row's value at a port and move rewrites
// the primary member in place while it still holds the recorded value. A
// selector row's value names a provider, not a port, so it never moves.
func memberShape(tool string) routeShape {
	resolve := func(rec *routeprov.Record) (memberRouteSpec, error) {
		spec, ok := specForRecord(tool, rec)
		if !ok {
			return memberRouteSpec{}, fmt.Errorf("proxyroute: the %s route record names a key no member-route writer of %s owns", tool, tool)
		}
		return spec, nil
	}
	return routeShape{
		read: func(path string, rec *routeprov.Record) (string, bool, error) {
			spec, err := resolve(rec)
			if err != nil {
				return "", false, err
			}
			return readMemberRouteFor(spec)(path)
		},
		remove: func(path string, rec routeprov.Record) error {
			spec, err := resolve(&rec)
			if err != nil {
				return err
			}
			return removeMemberRouteFor(spec, portOf)(path, rec.Value, rec.PriorProvider)
		},
		want: func(rec routeprov.Record, port int) (string, bool) {
			spec, err := resolve(&rec)
			if err != nil || spec.members[0].kind != memberURL {
				return "", false
			}
			return fmt.Sprint(spec.members[0].value(port)), true
		},
		move: func(path string, rec routeprov.Record, to string) error {
			spec, err := resolve(&rec)
			if err != nil {
				return err
			}
			if spec.members[0].kind != memberURL {
				return fmt.Errorf("proxyroute: the %s route is a provider selector; it has no port to move", tool)
			}
			return moveMemberRouteFor(spec)(path, rec, to)
		},
	}
}

// moveMemberRouteFor sets the row's primary member to `to` while it still
// holds the recorded value, through the same member edit the writer uses
// (credfile.SetMember: every other byte kept, the result verified), with the
// writer's file rules (readMemberRouteFile, the write abandoned if the file
// changed under it).
func moveMemberRouteFor(spec memberRouteSpec) func(path string, rec routeprov.Record, to string) error {
	return func(path string, rec routeprov.Record, to string) error {
		what := spec.what() + ".move"
		raw, err := readMemberRouteFile(what, path)
		if errors.Is(err, errRouteFileMissing) {
			return credfile.SafeErrorf("%s: %s is gone", what, path)
		}
		if err != nil {
			return err
		}
		cur, _, err := credfile.MemberValue(spec.format, raw, spec.members[0].path)
		if err != nil {
			return credfile.Withhold(what, path, err)
		}
		if strings.TrimSpace(fmt.Sprint(cur)) != rec.Value {
			return credfile.SafeErrorf("%s: %s in %s is no longer the value Observer wrote", what, spec.members[0].path, path)
		}
		out, err := credfile.SetMember(spec.format, raw, spec.members[0].path, to, true)
		if err != nil {
			return credfile.Withhold(what, path, err)
		}
		if err := writeFileKeepModeIf(path, out, unchangedSince(path, raw)); err != nil {
			return credfile.Withhold(what, path, fmt.Errorf("write: %w", err))
		}
		return nil
	}
}

// The member-route rows join Leave's reader / remover table (routeShapes in
// provenance.go), so a route the organization wrote leaves with it like
// every other, and the port move (portmove.go) moves a base-URL row. One
// shape per tool, dispatching on the record (memberShape). Registered here
// so the table and its writers have one owner.
func init() {
	for _, spec := range memberRouteSpecs {
		if _, taken := routeShapes[spec.tool]; taken {
			continue
		}
		routeShapes[spec.tool] = memberShape(spec.tool)
	}
}
