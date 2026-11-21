//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"runtime"
	"slices"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/componentsvc"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxkey"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	"github.com/marmutapp/superbased-observer/internal/sandboxsetup"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/toolinstall"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// sandbox_setup_facts.go gathers the PASSIVE facts of one registry row
// (sandbox installation lifecycle plan section 3.4) into a
// sandboxsetup.PlanInput: host kind and family, the registry and org gates,
// the component selection, the config lists, the recorded installs, where
// each prerequisite's programs resolve (the login-shell PATH capture the tool
// preflight already runs; it starts the user's shell, never the program),
// content presence, hosted credential and consent presence, and the live-run
// count. No sandbox program is executed and nothing is dialed: every I/O is
// one field of sandboxSetupHost, and the passive test injects fields that
// fail the test if a probe or a version run is attempted.

// sandboxSetupHost is the injected I/O of sandbox setup. The production
// value is productionSandboxSetupHost; tests replace any field.
type sandboxSetupHost struct {
	// loadConfig reads the local config.
	loadConfig func() (config.Config, error)
	// hostKind classifies the daemon's host.
	hostKind func() sandboxbackend.HostKind
	// goos and arch are the build's.
	goos, arch string
	// readOSRelease reads /etc/os-release ("" when unreadable).
	readOSRelease func() string
	// snapshot resolves the component selection for cfg.
	snapshot func(cfg config.Config) componentstate.Snapshot
	// governed reports that the organization refuses adding component on
	// this node (componentsvc's managed preview), so the step is set by the
	// organization.
	governed func(ctx context.Context, component string) bool
	// floors are the org floors in force.
	floors func(ctx context.Context, cfg config.Config) (sandboxselect.Floors, error)
	// resolveProgram resolves one program name passively, shims excluded
	// ("" when not found). It never executes the program.
	resolveProgram func(name string) string
	// contentPresent reports whether a content kind is installed and loads.
	contentPresent func(cfg config.Config, kind string) bool
	// hostedCredential, hostedConsent and hostedAccount read presence for a
	// hosted row (provider id = row id) without opening the keychain.
	hostedCredential func(provider string) bool
	hostedConsent    func(provider string) bool
	// hostedConsentChange is the consent verdict of a recorded consent
	// whose launch-independent facts no longer match cfg (a changed
	// custody, region, endpoint, box binary or cap: the probe's own
	// comparison), "" when it matches or none is recorded. Nil reads "".
	hostedConsentChange func(cfg config.Config, provider string) string
	// hostedAccount answers (present, known): known false leaves the step
	// unknown.
	hostedAccount func(provider string) (bool, bool)
	// liveRuns counts the live sandboxed runs on a backend; an error means
	// the count could not be learned (undo and update are then refused).
	liveRuns func(ctx context.Context, backend string) (int, error)
	// engineSocket is the first container engine socket that exists for cfg
	// ("" when none); a stat, never a dial.
	engineSocket func(cfg config.Config) string
	// dockerAccess reads Docker's rootful socket and the engine socket the
	// row will use (stats and the process's own ids, never a dial); ok false
	// means no fact.
	dockerAccess func(cfg config.Config) (sandboxsetup.DockerAccess, bool)
	// statFile reports whether path is a regular file (a stat, no exec).
	statFile func(path string) bool
	// fileDigest is the sha256 of a file Observer placed (a read, no exec).
	fileDigest func(path string) (string, error)
	// records are the latest sandbox install records.
	records func(ctx context.Context) ([]store.ToolInstallRow, error)

	// probeRow runs the row's driver probe once (the ACTIVE check only;
	// sandbox_setup_check.go). ok false: the row has no probe in this build.
	probeRow func(ctx context.Context, backend string, cfg config.Config) (sandboxselect.Probe, bool)
	// runVersion runs `<path> --version` with a short timeout (the ACTIVE
	// check only).
	runVersion func(ctx context.Context, path string) (string, error)
}

// productionSandboxSetupHost wires the real I/O for configPath.
func productionSandboxSetupHost(configPath string, ledger *toolInstallLedger) sandboxSetupHost {
	return sandboxSetupHost{
		loadConfig: func() (config.Config, error) {
			return config.Load(config.LoadOptions{GlobalPath: configPath})
		},
		hostKind: sandboxHostKind,
		goos:     runtime.GOOS,
		arch:     runtime.GOARCH,
		readOSRelease: func() string {
			b, err := os.ReadFile("/etc/os-release")
			if err != nil {
				return ""
			}
			return string(b)
		},
		snapshot: componentSnapshotForConfig,
		governed: func(ctx context.Context, component string) bool {
			svc, err := newComponentsService(configPath, nil)
			if err != nil {
				return false
			}
			p, err := svc.Preview(ctx, componentsvc.Change{Add: []string{component}})
			return err == nil && len(p.ManagedRefused) > 0
		},
		floors:           sandboxOrgFloorsFor,
		resolveProgram:   passiveResolveProgram,
		contentPresent:   sandboxSetupContentPresent,
		hostedCredential: sandboxSetupHostedCredential,
		hostedConsent:    sandboxSetupHostedConsent,
		// The consent step reopens when a fact it bound changed (the
		// custody step's remedy changes one), so the new facts are
		// disclosed before the next upload.
		hostedConsentChange: sandboxSetupHostedConsentChange,
		hostedAccount:       sandboxSetupHostedAccount,
		liveRuns:            sandboxSetupLiveRunsFor(configPath),
		engineSocket:        sandboxSetupEngineSocket,
		dockerAccess:        sandboxSetupDockerAccess,
		statFile:            sandboxSetupStatFile,
		fileDigest:          sandboxSetupFileSHA256,
		records: func(ctx context.Context) ([]store.ToolInstallRow, error) {
			return ledger.SandboxRecords(ctx)
		},
		probeRow:   sandboxSetupProbeRow,
		runVersion: sandboxSetupRunVersion,
	}
}

// passiveProbeDirs are the dirs off PATH a passive resolve also looks in:
// the system sbin dirs a package manager installs into and the libexec
// dirs of helpers.
var passiveProbeDirs = []integration.ProbeDir{
	{OS: integration.ProbeUnix, Rel: "/usr/sbin", Abs: true},
	{OS: integration.ProbeUnix, Rel: "/sbin", Abs: true},
	// Helpers a package installs off PATH (Debian and Ubuntu's
	// virtiofsd in /usr/libexec, older QEMU packaging in
	// /usr/lib/qemu), where the vm driver itself looks.
	{OS: integration.ProbeUnix, Rel: "/usr/libexec", Abs: true},
	{OS: integration.ProbeUnix, Rel: "/usr/lib/qemu", Abs: true},
	{OS: integration.ProbeDarwin, Rel: "/usr/sbin", Abs: true},
}

// passiveResolveProgram resolves name through the same host env the tool
// preflight uses (dashResolveEnv: the login-shell PATH capture, Observer's
// shims excluded), never npm's prefix probe or a foreign Windows home, and
// with the system sbin dirs a package manager installs into. It executes
// nothing it resolves.
func passiveResolveProgram(name string) string {
	env := dashResolveEnv()
	env.NpmPrefix = nil
	env.ForeignHomes = nil
	env.WSL = false
	spec := integration.BinaryResolveSpec{
		Names:     integration.BinaryNames{Unix: []string{name}, Windows: []string{name + ".exe"}},
		ProbeDirs: passiveProbeDirs,
	}
	r := toolresolve.Resolve(spec, env)
	if guiPreflightLaunchable[r.Verdict] {
		return r.Bin
	}
	return ""
}

// sandboxSetupContentPresent reports whether kind is installed in the node's
// sandbox content store and loads under the vendor keys (a read of the
// store's own files; no fetch).
func sandboxSetupContentPresent(cfg config.Config, kind string) bool {
	env := sandboxContentEnvFor(cfg, "")
	_, err := env.store.Load(content.Kind(kind), env.trust, 0)
	return err == nil
}

// sandboxSetupHostedCredential reports a stored or environment credential
// for provider without opening the keychain (the connected marker).
func sandboxSetupHostedCredential(provider string) bool {
	v, ok := sandboxremote.VendorFor(provider)
	if !ok {
		return false
	}
	obs, err := hostedObserverDir()
	if err != nil {
		return false
	}
	return hostedCredentialSource(obs, v) != ""
}

// sandboxSetupHostedConsent reports a recorded consent for provider.
func sandboxSetupHostedConsent(provider string) bool {
	obs, err := hostedObserverDir()
	if err != nil {
		return false
	}
	return hostedLoadConsent(obs, provider) != nil
}

// sandboxSetupHostedConsentChange judges provider's recorded consent
// against cfg's launch-independent facts, exactly as the hosted probe does
// (hostedStaticConsentVerdict): "" when it matches or none is recorded,
// else the verdict naming what changed.
func sandboxSetupHostedConsentChange(cfg config.Config, provider string) string {
	v, ok := sandboxremote.VendorFor(provider)
	if !ok {
		return ""
	}
	obs, err := hostedObserverDir()
	if err != nil {
		return ""
	}
	rec := hostedLoadConsent(obs, provider)
	if rec == nil {
		return ""
	}
	static, ok := (&hostedDriver{cfg: cfg.Terminal.Sandbox.Hosted, vendor: v}).consentFactsStatic()
	if !ok {
		return ""
	}
	if verdict := hostedStaticConsentVerdict(*rec, static, v, cfg.Terminal.Sandbox.Hosted); verdict != sandboxremote.ConsentOK {
		return verdict
	}
	return ""
}

// consentChangeWords are the plain words for what a recorded consent no
// longer matches, by the consent verdict (the closed sandboxremote
// spellings); a verdict absent here reads "your settings".
var consentChangeWords = map[string]string{
	sandboxremote.ConsentChangedPrefix + "provider":      "the provider",
	sandboxremote.ConsentChangedPrefix + "endpoint":      "the provider's address",
	sandboxremote.ConsentChangedPrefix + "region":        "the region",
	sandboxremote.ConsentChangedPrefix + "custody":       "how the agent gets its model key",
	sandboxremote.ConsentChangedPrefix + "box_binary":    "the observer copied into the box",
	sandboxremote.ConsentChangedPrefix + "memory_images": "the memory image setting",
	sandboxremote.ConsentChangedPrefix + "cap":           "the box time limits",
	// SBXD-7: the private-range deny of the internet tier.
	sandboxremote.ConsentChangedPrefix + "private_ranges": "whether the box may reach private network addresses",
	// Decisions SBXD-3 and SBXD-4: bound only while a key can be put in
	// the box.
	sandboxremote.ConsentChangedPrefix + "in_box_keys": "the keys stored on this machine that can be put in the box",
	sandboxremote.ConsentChangedPrefix + "tool_keys":   "which agents' own saved keys can be put in the box",
	sandboxremote.ConsentChangedPrefix + "login_seed":  "which agents' logins are copied into the box",
}

// consentChangeReason is the consent step's sentence for a recorded
// consent that no longer matches.
func consentChangeReason(verdict string) string {
	const again = " Read what leaves this machine and agree again."
	switch verdict {
	case sandboxremote.ConsentStaleVersion:
		return "Your consent was recorded by an older version of Observer." + again
	case sandboxremote.ConsentTampered:
		return "Your recorded consent does not match its own check." + again
	}
	what, ok := consentChangeWords[verdict]
	if !ok {
		what = "your settings"
	}
	return "Your consent no longer matches: " + what + " changed since you agreed." + again
}

// sandboxSetupHostedAccount: an account is known to exist once a credential
// for it is present; otherwise it is not known (Observer never checks a
// vendor account itself).
func sandboxSetupHostedAccount(provider string) (bool, bool) {
	if sandboxSetupHostedCredential(provider) {
		return true, true
	}
	return false, false
}

// sandboxSetupLiveRunsFor counts the live sandboxed runs on a backend. In
// the daemon (which holds the terminal stack) it reads the stack's own
// source. In any other process (the CLI) the runs live in the daemon, so it
// asks the running daemon over loopback, as `observer stop` does: no daemon
// listening means nothing is live; a daemon that does not answer is an
// error, so an undo or update refuses rather than guess (fail closed).
func sandboxSetupLiveRunsFor(configPath string) func(ctx context.Context, backend string) (int, error) {
	return func(ctx context.Context, backend string) (int, error) {
		var runs []dashapi.LiveSandboxRun
		if src := currentLiveRunSource(); src != nil {
			runs = src.liveRuns(sandboxSetupNow())
		} else {
			rep, err := newDaemonLiveRunsClient(configPath).query(ctx)
			if err != nil {
				return 0, err
			}
			runs = rep.Runs
		}
		n := 0
		for _, r := range runs {
			if r.Backend == backend {
				n++
			}
		}
		return n, nil
	}
}

// sandboxSetupEngineSocket is the first container engine socket that exists
// ("" when none), set by the oci driver's file (sandbox_setup_oci.go) so a
// build without that driver does not link it; nil means no fact.
var sandboxSetupEngineSocket func(cfg config.Config) string

// sandboxSetupDockerAccess reads the docker-group step's facts, set by the
// oci driver's Linux file (sandbox_setup_oci_linux.go); nil means no fact.
var sandboxSetupDockerAccess func(cfg config.Config) (sandboxsetup.DockerAccess, bool)

// sandboxSetupStatFile reports whether path is a regular file.
func sandboxSetupStatFile(path string) bool {
	fi, err := os.Stat(path) //nolint:gosec // G703: a metadata read of a path the local config names; no privilege boundary is crossed
	return err == nil && fi.Mode().IsRegular()
}

// sandboxSetupComponentFor is the component a row's driver registers: the
// registration's own, bwrap's is the sandbox module itself, and a row with no
// driver in this build has none.
func sandboxSetupComponentFor(id string) (component string, inBuild bool) {
	if reg, ok := sandboxDriverRegs[id]; ok {
		return reg.component, true
	}
	if id == sandboxbackend.BackendBwrap {
		return sandboxComponent, true
	}
	return "", false
}

// sandboxSetupComponentSelected applies the opt-in rule: bwrap is selected
// with the module, every driver by its own selection.
func sandboxSetupComponentSelected(snap componentstate.Snapshot, id, component string) bool {
	if component == "" {
		return false
	}
	if component == sandboxComponent {
		return sandboxModuleActive(snap)
	}
	return sandboxDriverSelected(snap, component)
}

// sandboxSetupListed is the local [terminal.sandbox] backends list as the
// config holds it (independent of the master switch): backends, else the
// legacy single backend key, else bwrap.
func sandboxSetupListed(sb config.TerminalSandboxConfig) []string {
	if len(sb.Backends) > 0 {
		out := make([]string, 0, len(sb.Backends))
		for _, b := range sb.Backends {
			if b = strings.TrimSpace(b); b != "" {
				out = append(out, b)
			}
		}
		return out
	}
	if b := strings.TrimSpace(sb.Backend); b != "" {
		return []string{b}
	}
	return []string{sandboxbackend.BackendBwrap}
}

// sandboxSetupInUseBy is, per prerequisite of row, the OTHER rows listed in
// [terminal.sandbox].backends whose Setup names the same id (plan section
// 4.9): a shared prerequisite is never offered for undo while another
// set-up row uses it. It is read again at click time by the undo path.
func sandboxSetupInUseBy(row sandboxbackend.Capability, listed []string) map[string][]string {
	var out map[string][]string
	for _, id := range row.Setup {
		for _, other := range listed {
			if other == row.ID {
				continue
			}
			oc, ok := sandboxbackend.Get(other)
			if !ok || !slices.Contains(oc.Setup, id) {
				continue
			}
			if out == nil {
				out = map[string][]string{}
			}
			if !slices.Contains(out[id], other) {
				out[id] = append(out[id], other)
			}
		}
	}
	return out
}

// sandboxRecordName is the tool column a step's record is kept under: the
// prerequisite id (one record per prerequisite, shared across rows), or for
// the generic component and enable steps the id scoped to the backend, so one
// row's component record never stands for another's.
func sandboxRecordName(prereq, backend string) string {
	if prereq == sandboxsetup.PrereqComponent || prereq == sandboxsetup.PrereqEnable {
		return prereq + ":" + backend
	}
	return prereq
}

// sandboxSetupRecords maps the latest records onto row's prerequisite ids.
func sandboxSetupRecords(rows []store.ToolInstallRow, backend string) map[string]sandboxsetup.Record {
	out := map[string]sandboxsetup.Record{}
	for _, r := range rows {
		id := r.Tool
		for _, generic := range []string{sandboxsetup.PrereqComponent, sandboxsetup.PrereqEnable} {
			if r.Tool == generic+":"+backend {
				id = generic
			} else if strings.HasPrefix(r.Tool, generic+":") {
				id = ""
			}
		}
		if id == "" {
			continue
		}
		if _, seen := out[id]; seen {
			continue // rows are newest first
		}
		out[id] = sandboxsetup.Record{
			ID: r.ID, Status: toolinstall.Status(r.Status), Channel: r.Channel, Digest: r.Digest,
			PlacedPath: r.PlacedPath, Elevated: r.Elevated, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
		}
	}
	return out
}

// sandboxSetupDownloadSource is the download source rule (decisions O2=B,
// O3=B): an individual node fetches the vendor's release asset by its
// compiled pin; a managed node fetches only from the org mirror, and no
// mirror kind for sandbox host tools exists yet, so there it is none.
func sandboxSetupDownloadSource(managed bool) string {
	if managed {
		return ""
	}
	return sandboxsetup.SourceVendorRelease
}

// factRule is one row of the passive fact table: a prerequisite whose
// Detect shape matches gets its fact from the rule (no fact: the step stays
// unknown until the active check or the probe judges it). Dispatch is on the
// prerequisite's shape, never its id.
type factRule struct {
	name  string
	match func(p sandboxsetup.Prereq) bool
	fact  func(fc factCtx, p sandboxsetup.Prereq) (sandboxsetup.Fact, bool)
}

// factCtx is what a fact rule reads.
type factCtx struct {
	h   sandboxSetupHost
	cfg config.Config
	row sandboxbackend.Capability
	// records are the row's latest setup records (nil: not read).
	records map[string]sandboxsetup.Record
	// engine is a check's finding about the engine socket (unknown on a
	// passive read, R1).
	engine sandboxsetup.EngineAnswer
}

// checkedFactRules name the fact rules whose answer can change with a
// check's finding (factCtx.engine); activeCheck runs them again with it.
var checkedFactRules = map[string]bool{"docker_socket_access": true}

// sandboxPathKeys are the config keys a Detect.PathKey may name, each read
// from the local config.
var sandboxPathKeys = map[string]func(config.Config) string{
	"terminal.sandbox.vm.cloud_hypervisor_path": func(c config.Config) string { return c.Terminal.Sandbox.VM.CloudHypervisorPath },
	"terminal.sandbox.vm.virtiofsd_path":        func(c config.Config) string { return c.Terminal.Sandbox.VM.VirtiofsdPath },
}

// sandboxConfigKeyFacts are the disclosed config keys a KindConfig
// prerequisite names, read from the local config: whether the step is done
// and, when it is not, the plain sentence that says why ("" for the
// generic "<key> is off").
var sandboxConfigKeyFacts = map[string]func(config.Config) (bool, string){
	"terminal.sandbox.oci.allow_rootful": func(c config.Config) (bool, string) { return c.Terminal.Sandbox.OCI.AllowRootful, "" },
	// The hosted model key's custody: done when the configured custody can
	// reach the agent on this node (the one table, sandboxkey.HomeKey;
	// the list of stored provider ids is a file Observer wrote, read
	// without opening a key).
	"terminal.sandbox.hosted.key_custody": func(c config.Config) (bool, string) {
		v := sandboxkey.HomeKey(hostedHomeKeyFacts(c))
		return v.OK, v.Message
	},
}

// sandboxArgKeys are the config keys a command step's last argument may
// come from (sandboxsetup.Remedy.ArgKey), each with how to read it. A key
// absent here reads empty, so its step is a guide naming the key.
var sandboxArgKeys = map[string]func(config.Config) string{
	"terminal.sandbox.apple_container.image": func(c config.Config) string { return c.Terminal.Sandbox.AppleContainer.Image },
}

// sandboxSetupArgValues reads every sandboxArgKeys key from cfg.
func sandboxSetupArgValues(cfg config.Config) map[string]string {
	out := make(map[string]string, len(sandboxArgKeys))
	for k, get := range sandboxArgKeys {
		out[k] = get(cfg)
	}
	return out
}

// factRules are walked top-down; the first matching row decides.
var factRules = []factRule{
	{"engine_socket", func(p sandboxsetup.Prereq) bool { return p.Detect.EngineSocket }, func(fc factCtx, _ sandboxsetup.Prereq) (sandboxsetup.Fact, bool) {
		if fc.h.engineSocket == nil {
			return sandboxsetup.Fact{}, false
		}
		if path := fc.h.engineSocket(fc.cfg); path != "" {
			return sandboxsetup.Fact{Present: true, Path: path}, true
		}
		return sandboxsetup.Fact{Reason: "No Docker or Podman socket is listening for this user."}, true
	}},
	{"docker_socket_access", func(p sandboxsetup.Prereq) bool { return p.Detect.DockerSocketAccess }, func(fc factCtx, _ sandboxsetup.Prereq) (sandboxsetup.Fact, bool) {
		if fc.h.dockerAccess == nil {
			return sandboxsetup.Fact{}, false
		}
		a, ok := fc.h.dockerAccess(fc.cfg)
		if !ok {
			return sandboxsetup.Fact{}, false
		}
		a.EngineAnswered = fc.engine
		return sandboxsetup.DockerAccessFact(a)
	}},
	{"configured_path", func(p sandboxsetup.Prereq) bool { return configuredPath(p) != nil }, configuredPathFact},
	{"programs", func(p sandboxsetup.Prereq) bool { return len(p.Detect.Programs) > 0 }, programFact},
	{"content", func(p sandboxsetup.Prereq) bool { return len(p.Detect.Content) > 0 }, func(fc factCtx, p sandboxsetup.Prereq) (sandboxsetup.Fact, bool) {
		for _, k := range p.Detect.Content {
			if !fc.h.contentPresent(fc.cfg, k) {
				return sandboxsetup.Fact{Reason: "Not installed: " + k + "."}, true
			}
		}
		return sandboxsetup.Fact{Present: true}, true
	}},
	{"config_key", func(p sandboxsetup.Prereq) bool {
		return p.Kind == sandboxsetup.KindConfig && sandboxConfigKeyFacts[p.Detect.ConfigKey] != nil
	}, func(fc factCtx, p sandboxsetup.Prereq) (sandboxsetup.Fact, bool) {
		done, why := sandboxConfigKeyFacts[p.Detect.ConfigKey](fc.cfg)
		if done {
			return sandboxsetup.Fact{Present: true}, true
		}
		if why == "" {
			why = p.Detect.ConfigKey + " is off."
		}
		return sandboxsetup.Fact{Reason: why}, true
	}},
	{"credential", func(p sandboxsetup.Prereq) bool { return p.Kind == sandboxsetup.KindCredential }, func(fc factCtx, _ sandboxsetup.Prereq) (sandboxsetup.Fact, bool) {
		if fc.h.hostedCredential(fc.row.ID) {
			return sandboxsetup.Fact{Present: true}, true
		}
		return sandboxsetup.Fact{Reason: "No key is stored for this provider."}, true
	}},
	{"consent", func(p sandboxsetup.Prereq) bool { return p.Kind == sandboxsetup.KindConsent }, func(fc factCtx, _ sandboxsetup.Prereq) (sandboxsetup.Fact, bool) {
		if fc.h.hostedConsent(fc.row.ID) {
			if fc.h.hostedConsentChange != nil {
				if change := fc.h.hostedConsentChange(fc.cfg, fc.row.ID); change != "" {
					return sandboxsetup.Fact{Reason: consentChangeReason(change)}, true
				}
			}
			return sandboxsetup.Fact{Present: true}, true
		}
		return sandboxsetup.Fact{Reason: "No consent is recorded for this provider."}, true
	}},
	{"account", func(p sandboxsetup.Prereq) bool { return p.Kind == sandboxsetup.KindAccount }, func(fc factCtx, _ sandboxsetup.Prereq) (sandboxsetup.Fact, bool) {
		present, known := fc.h.hostedAccount(fc.row.ID)
		if !known {
			return sandboxsetup.Fact{}, false
		}
		return sandboxsetup.Fact{Present: present}, true
	}},
}

// configuredPath is the reader of p's Detect.PathKey (nil when p names none
// this table knows).
func configuredPath(p sandboxsetup.Prereq) func(config.Config) string {
	if p.Detect.PathKey == "" {
		return nil
	}
	return sandboxPathKeys[p.Detect.PathKey]
}

// configuredPathFact reads a program from the config key that names its
// path (a placed download writes it): an unset key falls back to resolving
// Programs; a set key must name a regular file, and a file Observer placed
// must still have the sha256 it was placed with, so a changed file reads
// missing and Repair places it again.
func configuredPathFact(fc factCtx, p sandboxsetup.Prereq) (sandboxsetup.Fact, bool) {
	path := strings.TrimSpace(configuredPath(p)(fc.cfg))
	if path == "" {
		if len(p.Detect.Programs) > 0 {
			return programFact(fc, p)
		}
		return sandboxsetup.Fact{}, false
	}
	if fc.h.statFile == nil || !fc.h.statFile(path) {
		return sandboxsetup.Fact{Reason: "The file " + path + " named by " + p.Detect.PathKey + " is not on this machine."}, true
	}
	if rec, ok := fc.records[p.ID]; ok && rec.PlacedPath == path && rec.Digest != "" && fc.h.fileDigest != nil {
		sum, err := fc.h.fileDigest(path)
		if err != nil {
			return sandboxsetup.Fact{Reason: "The file Observer placed at " + path + " could not be read to check its sha256."}, true
		}
		if !strings.EqualFold(sum, rec.Digest) {
			return sandboxsetup.Fact{Reason: "The file Observer placed at " + path + " changed since it was placed (its sha256 no longer matches the pinned one); Repair places it again."}, true
		}
	}
	return sandboxsetup.Fact{Present: true, Path: path}, true
}

// programFact resolves every Detect.Programs entry (an entry may list
// alternatives with toolinstall.AltSep; one of them must resolve).
func programFact(fc factCtx, p sandboxsetup.Prereq) (sandboxsetup.Fact, bool) {
	f := sandboxsetup.Fact{Present: true}
	for _, entry := range p.Detect.Programs {
		found := ""
		for _, alt := range strings.Split(entry, toolinstall.AltSep) {
			if alt = strings.TrimSpace(alt); alt == "" {
				continue
			}
			if path := fc.h.resolveProgram(alt); path != "" {
				found = path
				break
			}
		}
		if found == "" {
			return sandboxsetup.Fact{Reason: "Not found on this machine: " + strings.ReplaceAll(entry, toolinstall.AltSep, " or ") + "."}, true
		}
		if f.Path == "" {
			f.Path = found
		}
	}
	return f, true
}

// passiveFacts are the per-prerequisite facts of row (no exec, no dial).
// records may be nil (a placed file is then not re-hashed).
func passiveFacts(h sandboxSetupHost, cfg config.Config, row sandboxbackend.Capability, records map[string]sandboxsetup.Record) map[string]sandboxsetup.Fact {
	return rowFacts(factCtx{h: h, cfg: cfg, row: row, records: records}, nil)
}

// checkedFacts runs the checkedFactRules again with a check's engine
// finding: each prerequisite they decide maps to its new fact, or is absent
// from the map with decided true when the rule now has no fact.
func checkedFacts(h sandboxSetupHost, cfg config.Config, row sandboxbackend.Capability, records map[string]sandboxsetup.Record, engine sandboxsetup.EngineAnswer) (facts map[string]sandboxsetup.Fact, decided map[string]bool) {
	decided = map[string]bool{}
	facts = rowFacts(factCtx{h: h, cfg: cfg, row: row, records: records, engine: engine}, func(rule, id string) bool {
		if checkedFactRules[rule] {
			decided[id] = true
			return true
		}
		return false
	})
	return facts, decided
}

// rowFacts walks factRules for each of row's prerequisites (first matching
// rule decides). keep, when set, limits the walk to the rules it accepts.
func rowFacts(fc factCtx, keep func(rule, id string) bool) map[string]sandboxsetup.Fact {
	out := map[string]sandboxsetup.Fact{}
	row := fc.row
	for _, id := range row.Setup {
		p, ok := sandboxsetup.Lookup(id)
		if !ok {
			continue
		}
		for _, r := range factRules {
			if !r.match(p) {
				continue
			}
			if keep != nil && !keep(r.name, id) {
				break
			}
			if f, has := r.fact(fc, p); has {
				out[id] = f
			}
			break
		}
	}
	return out
}

// sandboxSetupInput is one row's passive plan input, plus whether the row's
// driver is in this build.
type sandboxSetupInput struct {
	in      sandboxsetup.PlanInput
	inBuild bool
	cfg     config.Config
}

// gatherSandboxSetupInput builds row's PlanInput from passive facts only.
func gatherSandboxSetupInput(ctx context.Context, h sandboxSetupHost, row sandboxbackend.Capability) (sandboxSetupInput, error) {
	cfg, err := h.loadConfig()
	if err != nil {
		return sandboxSetupInput{}, err
	}
	in := sandboxsetup.PlanInput{Row: row, Host: h.hostKind(), Arch: h.arch}
	var pm toolinstall.PackageManager
	if h.goos == "linux" && h.readOSRelease != nil {
		pm = toolinstall.PackageManagerFor(h.goos, toolinstall.ParseOSRelease(h.readOSRelease()))
	} else {
		pm = toolinstall.PackageManagerFor(h.goos, nil)
	}
	in.Family = sandboxsetup.FamilyFor(h.goos, pm)

	snap := h.snapshot(cfg)
	in.Managed = snap.Governed.OrgManaged
	floors, ferr := h.floors(ctx, cfg)
	// A floor that cannot be read is treated as refusing the row (the
	// sandbox's own fail-closed rule): nothing is set up against a floor
	// the node cannot show it meets.
	in.OrgAllowed = ferr == nil && (len(floors.AllowedBackends) == 0 || slices.Contains(floors.AllowedBackends, row.ID))

	comp, inBuild := sandboxSetupComponentFor(row.ID)
	in.ComponentID = comp
	in.ComponentSelected = sandboxSetupComponentSelected(snap, row.ID, comp)
	if comp != "" && !in.ComponentSelected && in.Managed && h.governed != nil {
		in.ComponentGoverned = h.governed(ctx, comp)
	}

	sb := cfg.Terminal.Sandbox
	listed := sandboxSetupListed(sb)
	in.SandboxOn = sb.Enabled
	in.Listed = slices.Contains(listed, row.ID)
	in.AllowInstall = cfg.Terminal.Launch.AllowInstall
	in.AllowElevated = sb.Setup.AllowElevated
	in.DownloadSource = sandboxSetupDownloadSource(in.Managed)
	if n, lerr := h.liveRuns(ctx, row.ID); lerr != nil {
		in.LiveRunsUnknown = true
	} else {
		in.LiveRuns = n
	}
	// The enable step's undo would change nothing when the list without the
	// row still names it (the empty list's default).
	if in.Listed {
		without := sb
		without.Backends = slices.DeleteFunc(slices.Clone(listed), func(b string) bool { return b == row.ID })
		without.Backend = ""
		in.UnlistRelists = slices.Contains(sandboxSetupListed(without), row.ID)
	}
	// InUseBy reads the listed rows whatever the master switch says: a row
	// still listed while the sandbox is off is turned back on with the
	// switch, so its shared prerequisite must not be undone (P-254).
	in.InUseBy = sandboxSetupInUseBy(row, listed)
	in.ArgValues = sandboxSetupArgValues(cfg)

	rows, err := h.records(ctx)
	if err != nil {
		return sandboxSetupInput{}, err
	}
	in.Records = sandboxSetupRecords(rows, row.ID)
	in.Facts = passiveFacts(h, cfg, row, in.Records)
	return sandboxSetupInput{in: in, inBuild: inBuild, cfg: cfg}, nil
}
