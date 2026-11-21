package cloudsession

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/textdiff"
)

// PlanOptions are the inputs of PlanInit.
type PlanOptions struct {
	// Agent is the agent id (--agent).
	Agent string
	// Destination is where the committed flush hooks deliver.
	Destination DestinationKind
	// DestinationURL, when set, is baked into the flush hooks (it is not a
	// secret); otherwise flush reads SBO_CLOUD_SESSION_URL at run time.
	DestinationURL string
	// Share is the share posture baked into the flush hooks (decision
	// CA-D19): the posture the org server returned at mint for the org
	// destination; "" takes the destination's default (node: full content,
	// org: metadata only). The resolved value is always written into the
	// committed command, so a reviewer sees what the sandbox ships.
	Share SharePosture
	// ObserverVersion is the release tag the setup script pins (vX.Y.Z).
	ObserverVersion string
	// VendorKeys are the accepted base64 Ed25519 vendor keys, newest first.
	VendorKeys []string
	// InstallSource is where the setup script fetches observer from
	// (zero value: InstallNpm).
	InstallSource InstallSource
	// NpmRegistry overrides DefaultNpmRegistry (an https mirror).
	NpmRegistry string
	// NpmPins are the pinned dist.integrity values of the platform
	// packages for ObserverVersion (InstallNpm only).
	NpmPins []NpmPin
	// ReleaseBaseURL overrides DefaultReleaseBaseURL (an https mirror).
	ReleaseBaseURL string
	// InstallDir overrides DefaultInstallDir.
	InstallDir string
	// FlushEvery overrides DefaultFlushEvery on the periodic flush hook.
	FlushEvery int
	// Reformat allows editing a shared JSON file that does not round-trip
	// byte-for-byte; it is then rewritten in the two-space layout and the
	// change is reported as a reformat.
	Reformat bool
	// Guard turns the sandbox guard on (--guard, lane CA-C2): the signed
	// policy file and the gate hooks. Nil = off.
	Guard *GuardSetup
	// MCP registers Observer's MCP server for the agent (--mcp, lane CA-C2)
	// and has the setup script build the database during setup.
	MCP bool
	// CodeIntel has the setup step build the repository's code-intelligence
	// index and the MCP server read it (--codeintel; needs MCP). Off by
	// default, like code intelligence everywhere (D-307).
	CodeIntel bool
}

// enabled reports whether a feature-tagged entry or file is planned.
func (o PlanOptions) enabled(f Feature) bool {
	switch f {
	case "":
		return true
	case FeatureGuard:
		return o.Guard != nil
	case FeatureMCP:
		return o.MCP
	}
	return false
}

func (o PlanOptions) installDir() string {
	if o.InstallDir != "" {
		return strings.TrimRight(o.InstallDir, "/")
	}
	return DefaultInstallDir
}

func (o PlanOptions) installSource() InstallSource {
	if o.InstallSource == "" {
		return InstallNpm
	}
	return o.InstallSource
}

func (o PlanOptions) npmRegistry() string {
	if o.NpmRegistry != "" {
		return strings.TrimRight(o.NpmRegistry, "/")
	}
	return DefaultNpmRegistry
}

func (o PlanOptions) releaseBaseURL() string {
	if o.ReleaseBaseURL != "" {
		return strings.TrimRight(o.ReleaseBaseURL, "/")
	}
	return DefaultReleaseBaseURL
}

// ReadFile is the injected repository reader: the current content of a
// slash-separated repository path and whether it exists.
type ReadFile func(path string) (content string, exists bool, err error)

// FileChange is one planned repository file write.
type FileChange struct {
	// Path is slash-separated, relative to the repository root.
	Path string
	// Before is the current content ("" when absent).
	Before string
	// Existed reports whether the file existed.
	Existed bool
	// After is the planned content (unused when Delete).
	After string
	// Delete reports that the file is removed.
	Delete bool
	// Executable asks for mode 0755 instead of 0644.
	Executable bool
	// Note explains a non-obvious outcome (a reformat, a kept file).
	Note string
}

// Changed reports whether the change does anything.
func (c FileChange) Changed() bool {
	if c.Delete {
		return c.Existed
	}
	return !c.Existed || c.After != c.Before
}

// RepoPlan is the full set of repository edits for one init or remove.
type RepoPlan struct {
	Agent   Agent
	Changes []FileChange
	// Manual are steps the developer must do outside the repository, or by
	// hand where init refused to edit a file.
	Manual []string
}

// Diff renders every changed file as a unified diff, in plan order.
func (p RepoPlan) Diff() string {
	var b strings.Builder
	for _, c := range p.Changes {
		if !c.Changed() {
			continue
		}
		before, after := c.Before, c.After
		nameA, nameB := "a/"+c.Path, "b/"+c.Path
		if !c.Existed {
			nameA = "/dev/null"
		}
		if c.Delete {
			after, nameB = "", "/dev/null"
		}
		d, _ := textdiff.Unified(nameA, nameB, before, after, 3)
		b.WriteString(d)
		if d != "" && !strings.HasSuffix(d, "\n") {
			b.WriteString("\n")
		}
	}
	return b.String()
}

// Changed reports whether any file changes.
func (p RepoPlan) Changed() bool {
	for _, c := range p.Changes {
		if c.Changed() {
			return true
		}
	}
	return false
}

// fileRenderer is one row of the renderer table: how a format is written by
// init and taken back out by remove.
type fileRenderer struct {
	format     FileFormat
	executable bool
	insert     func(a Agent, opts PlanOptions, before string, existed bool) (after, note string, manual []string, err error)
	remove     func(a Agent, before string) (after string, del bool, note string, err error)
	// owned reports whether content still holds Observer's cloud-session
	// output (used to tell whether an agent is still set up).
	owned func(content string) bool
	// block returns the canonical lines of the owned hook entries (the
	// self-modification guard's input, guard.go); nil for a format that
	// holds no hooks.
	block func(content string) []string
}

// renderers is THE renderer table.
var renderers = []fileRenderer{
	{format: FormatClaudeSettings, insert: insertClaudeSettings, remove: removeClaudeSettings, owned: holdsOwnerTag, block: claudeBlock},
	{format: FormatCopilotHooks, insert: insertCopilotHooks, remove: removeCopilotHooks, owned: holdsOwnerTag, block: copilotBlock},
	{format: FormatSetupScript, executable: true, insert: insertGenerated(func(_ Agent, o PlanOptions) string { return renderSetupScript(o) }), remove: removeGenerated, owned: isGenerated},
	{format: FormatCopilotSetupSteps, insert: insertSetupSteps, remove: removeGenerated, owned: isGenerated},
	{format: FormatPolicyFile, insert: insertPolicyFile, remove: removePolicyFile, owned: isPolicyFile},
	{format: FormatClaudeMCP, insert: insertClaudeMCP, remove: removeClaudeMCP, owned: holdsOwnedMCP},
}

func claudeBlock(c string) []string  { return ownedBlockLines(c, true, "command") }
func copilotBlock(c string) []string { return ownedBlockLines(c, false, "bash") }

func holdsOwnerTag(content string) bool { return strings.Contains(content, OwnerTag) }

func isGenerated(content string) bool {
	gen, _ := ownedUnedited(content)
	return gen
}

func rendererFor(f FileFormat) (fileRenderer, error) {
	for _, r := range renderers {
		if r.format == f {
			return r, nil
		}
	}
	return fileRenderer{}, fmt.Errorf("cloudsession: no renderer for format %q", f)
}

// validateInit checks the options before anything is rendered.
func validateInit(a Agent, opts PlanOptions) error {
	if !a.Supported() {
		return fmt.Errorf("cloudsession: %s is not supported yet: %s", a.DisplayName, a.Unsupported)
	}
	found := false
	for _, r := range destinations {
		if r.kind == opts.Destination && r.network {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("cloudsession: --destination must be org or node for committed hooks, got %q", opts.Destination)
	}
	if opts.DestinationURL != "" {
		if _, err := ResolveDestination(opts.Destination, opts.DestinationURL); err != nil {
			return err
		}
	}
	if _, err := ResolveShare(opts.Destination, opts.Share); err != nil {
		return err
	}
	if !releaseTag.MatchString(opts.ObserverVersion) {
		return fmt.Errorf("cloudsession: the setup script must pin a release tag like v1.37.0, got %q (a development build needs --observer-version)", opts.ObserverVersion)
	}
	switch opts.installSource() {
	case InstallNpm:
		if err := validateNpm(opts.NpmRegistry, opts.NpmPins); err != nil {
			return err
		}
	case InstallRelease:
		if opts.ReleaseBaseURL != "" && (!strings.HasPrefix(opts.ReleaseBaseURL, "https://") || strings.ContainsAny(opts.ReleaseBaseURL, " \t\n'\"$`\\")) {
			return fmt.Errorf("cloudsession: --release-base-url must be a plain https URL")
		}
	default:
		return fmt.Errorf("cloudsession: --install-source must be one of %v, got %q", InstallSources(), opts.InstallSource)
	}
	if opts.InstallDir != "" && (!strings.HasPrefix(opts.InstallDir, "/") || strings.ContainsAny(opts.InstallDir, " \t\n'\"$`\\")) {
		return fmt.Errorf("cloudsession: --install-dir must be an absolute path without spaces or shell characters")
	}
	if err := validateGuard(opts.Guard); err != nil {
		return err
	}
	if opts.CodeIntel && !opts.MCP {
		return fmt.Errorf("cloudsession: --codeintel builds the index the MCP server reads; it needs --mcp")
	}
	return validateVendorKeys(opts.VendorKeys)
}

// PlanInit plans the repository files for one agent.
func PlanInit(opts PlanOptions, read ReadFile) (RepoPlan, error) {
	a, err := AgentByID(opts.Agent)
	if err != nil {
		return RepoPlan{}, err
	}
	if err := validateInit(a, opts); err != nil {
		return RepoPlan{}, err
	}
	plan := RepoPlan{Agent: a}
	for _, f := range a.Files {
		r, err := rendererFor(f.Format)
		if err != nil {
			return RepoPlan{}, err
		}
		before, existed, err := read(f.Path)
		if err != nil {
			return RepoPlan{}, fmt.Errorf("cloudsession: read %s: %w", f.Path, err)
		}
		if !opts.enabled(f.Feature) {
			// A feature that is off: take back out what an earlier init
			// with the feature on wrote, so init converges on the flags.
			if c, ok, err := planFeatureOff(a, f, r, before, existed, read); err != nil {
				return RepoPlan{}, err
			} else if ok {
				plan.Changes = append(plan.Changes, c)
			}
			continue
		}
		after, note, manual, err := r.insert(a, opts, before, existed)
		if err != nil {
			return RepoPlan{}, fmt.Errorf("cloudsession: %s: %w", f.Path, err)
		}
		plan.Manual = append(plan.Manual, manual...)
		plan.Changes = append(plan.Changes, FileChange{
			Path: f.Path, Before: before, Existed: existed, After: after,
			Executable: r.executable, Note: note,
		})
	}
	plan.Manual = append(plan.Manual, a.ManualSteps...)
	if opts.MCP && a.MCPSettings != "" {
		plan.Manual = append(plan.Manual, mcpManualStep(a, opts))
	}
	if step := egressStep(a, opts); step != "" {
		plan.Manual = append(plan.Manual, step)
	}
	return plan, nil
}

// planFeatureOff plans removing a feature file an earlier init wrote. A file
// another set-up agent still uses, or one that is not Observer's, is left
// alone; ok=false when there is nothing to do.
func planFeatureOff(a Agent, f RepoFile, r fileRenderer, before string, existed bool, read ReadFile) (FileChange, bool, error) {
	if !existed || !r.owned(before) {
		return FileChange{}, false, nil
	}
	if other, err := sharedWithOtherAgent(a, f.Path, read); err != nil || other != "" {
		return FileChange{}, false, err
	}
	after, del, note, err := r.remove(a, before)
	if err != nil {
		return FileChange{}, false, fmt.Errorf("cloudsession: %s: %w", f.Path, err)
	}
	return FileChange{Path: f.Path, Before: before, Existed: true, After: after, Delete: del, Note: note}, true, nil
}

// egressStep is the manual step naming the hosts an allow-listed sandbox
// must reach: the install source's host, and the destination's (which the
// environment refuses at CONNECT until it is allowed, CA-A2), worded in the
// agent's own network vocabulary (Agent.Egress).
func egressStep(a Agent, opts PlanOptions) string {
	if a.EgressSetting == "" {
		return ""
	}
	installHost := hostOf(opts.npmRegistry())
	install := installHost + " (" + a.Egress.Packages + ")"
	if opts.installSource() == InstallRelease {
		installHost = hostOf(opts.releaseBaseURL())
		install = installHost + " and its release-asset download host (a cloud session refuses GitHub release assets of a repository not attached to it; allow the hosts or use --install-source npm)"
	}
	dest := "your destination host"
	if opts.DestinationURL != "" {
		dest = hostOf(opts.DestinationURL)
	}
	return "In " + a.EgressSetting + ", let the setup script reach " + install +
		" and let the flush reach " + dest + ": a host that is not allowed is refused with 403 at CONNECT, so " + fmt.Sprintf(a.Egress.AddHost, dest) +
		". Until then the flush records coverage \"Not established: environment network level blocks " + dest + "\" and keeps the rows."
}

// hostOf returns the host of a URL, or the URL itself when it has none.
func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Hostname()
	}
	return raw
}

// PlanRemove plans taking one agent's files back out. A file shared with
// another agent that is still set up (the setup script) is kept.
func PlanRemove(agentID string, read ReadFile) (RepoPlan, error) {
	a, err := AgentByID(agentID)
	if err != nil {
		return RepoPlan{}, err
	}
	plan := RepoPlan{Agent: a}
	for _, f := range a.Files {
		r, err := rendererFor(f.Format)
		if err != nil {
			return RepoPlan{}, err
		}
		before, existed, err := read(f.Path)
		if err != nil {
			return RepoPlan{}, fmt.Errorf("cloudsession: read %s: %w", f.Path, err)
		}
		if !existed {
			continue
		}
		if other, err := sharedWithOtherAgent(a, f.Path, read); err != nil {
			return RepoPlan{}, err
		} else if other != "" {
			plan.Changes = append(plan.Changes, FileChange{
				Path: f.Path, Before: before, Existed: true, After: before,
				Note: "kept: still used by the " + other + " setup",
			})
			continue
		}
		after, del, note, err := r.remove(a, before)
		if err != nil {
			return RepoPlan{}, fmt.Errorf("cloudsession: %s: %w", f.Path, err)
		}
		plan.Changes = append(plan.Changes, FileChange{Path: f.Path, Before: before, Existed: true, After: after, Delete: del, Note: note})
	}
	return plan, nil
}

// sharedWithOtherAgent returns the id of another agent that lists path and
// still has its own (non-shared) files in place.
func sharedWithOtherAgent(a Agent, path string, read ReadFile) (string, error) {
	for _, other := range agents {
		if other.ID == a.ID || !listsPath(other, path) {
			continue
		}
		for _, f := range other.Files {
			if listsPathInOthers(other, f.Path) {
				continue
			}
			content, exists, err := read(f.Path)
			if err != nil {
				return "", fmt.Errorf("cloudsession: read %s: %w", f.Path, err)
			}
			r, err := rendererFor(f.Format)
			if err != nil {
				return "", err
			}
			if exists && r.owned(content) {
				return other.ID, nil
			}
		}
	}
	return "", nil
}

func listsPath(a Agent, path string) bool {
	for _, f := range a.Files {
		if f.Path == path {
			return true
		}
	}
	return false
}

// listsPathInOthers reports whether some other agent also lists path (a
// shared file says nothing about which agent is still set up).
func listsPathInOthers(a Agent, path string) bool {
	for _, other := range agents {
		if other.ID != a.ID && listsPath(other, path) {
			return true
		}
	}
	return false
}

// insertGenerated is the insert of a dedicated generated file: written when
// absent or still unedited Observer output, refused when someone else's
// file sits at the path.
func insertGenerated(render func(Agent, PlanOptions) string) func(Agent, PlanOptions, string, bool) (string, string, []string, error) {
	return func(a Agent, opts PlanOptions, before string, existed bool) (string, string, []string, error) {
		if existed {
			gen, unedited := ownedUnedited(before)
			switch {
			case !gen:
				return "", "", nil, fmt.Errorf("a file Observer did not generate is already at this path; move it or remove it first")
			case !unedited:
				return "", "", nil, fmt.Errorf("Observer's generated file was edited since init; restore it or delete it, then run init again")
			}
		}
		return render(a, opts), "", nil, nil
	}
}

// insertSetupSteps writes the Copilot setup workflow when absent (or when it
// is still Observer's unedited output). An existing workflow of the team's
// own is never edited: the step to add is reported instead.
func insertSetupSteps(_ Agent, _ PlanOptions, before string, existed bool) (string, string, []string, error) {
	if existed {
		gen, unedited := ownedUnedited(before)
		if !gen || !unedited {
			return before, "kept: existing workflow is not edited", []string{
				"Add this step to the copilot-setup-steps job in " + CopilotSetupStepsPath + " (after actions/checkout):\n" + copilotSetupStepSnippet,
			}, nil
		}
	}
	return renderCopilotSetupSteps(), "", nil, nil
}

// removeGenerated deletes a dedicated generated file when its body is
// unedited, and keeps (and reports) an edited one.
func removeGenerated(_ Agent, before string) (string, bool, string, error) {
	gen, unedited := ownedUnedited(before)
	switch {
	case !gen:
		return before, false, "kept: not generated by Observer", nil
	case !unedited:
		return before, false, "kept: edited since init, remove it by hand", nil
	}
	return "", true, "", nil
}
