package sandboxoci

import (
	"fmt"
	"regexp"
	"sort"
)

// The run labels (sandbox plan v2 section 4.6): every container carries
// the run id AND the node's install id, so a shared Docker host never
// reaps another install's runs, and the orphan sweep filters on them.
const (
	LabelRole    = "app.superbased.observer.role"
	LabelInstall = "app.superbased.observer.install"
	LabelRun     = "app.superbased.observer.run"
	// RoleSandbox is the LabelRole value of a sandbox run container.
	RoleSandbox = "sandbox"
	// RoleABIProbe is the LabelRole value of the tool-delivery loader probe:
	// a created, never-started container the driver removes itself. The
	// orphan sweep selects RoleSandbox only, so it never removes a probe in
	// the middle of its check (SBX-P3A merge finding F5).
	RoleABIProbe = "abi-probe"
	// NamePrefix starts every container name.
	NamePrefix = "observer-sbx-"
)

// tokenRE is the shape of a run id (16 random bytes, base64url) and of an
// install id (hex): letters, digits, dash and underscore, never a leading
// dash.
var tokenRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{7,63}$`)

// ValidToken reports whether s is a clean run or install id.
func ValidToken(s string) bool { return tokenRE.MatchString(s) }

// Labels returns the labels of one run's container.
func Labels(installID, runID string) map[string]string {
	return map[string]string{LabelRole: RoleSandbox, LabelInstall: installID, LabelRun: runID}
}

// ProbeLabels returns the labels of one loader probe container: this
// install, the probe's own id, and the probe role (never RoleSandbox).
func ProbeLabels(installID, probeID string) map[string]string {
	return map[string]string{LabelRole: RoleABIProbe, LabelInstall: installID, LabelRun: probeID}
}

// ContainerName is the container name of a run: the prefix, a short form
// of the install id and the run id, so `docker ps` says whose run it is.
func ContainerName(installID, runID string) string {
	short := installID
	if len(short) > 8 {
		short = short[:8]
	}
	return NamePrefix + short + "-" + runID
}

// InstallFilter is the label filter (the Engine API `filters` value) that
// selects every sandbox container of this install, and only those.
func InstallFilter(installID string) map[string][]string {
	return map[string][]string{"label": {LabelRole + "=" + RoleSandbox, LabelInstall + "=" + installID}}
}

// ContainerFact is one container the sweep sees: its id, labels and
// whether it is running.
type ContainerFact struct {
	ID      string
	Labels  map[string]string
	Running bool
}

// Orphans returns the ids of this install's containers whose run is not
// live, sorted; live reports whether a run id still has a live run. A
// container that does not carry this install's labels is never returned,
// whatever else it says.
func Orphans(installID string, have []ContainerFact, live func(runID string) bool) []string {
	var out []string
	for _, c := range have {
		if c.Labels[LabelRole] != RoleSandbox || c.Labels[LabelInstall] != installID {
			continue
		}
		run := c.Labels[LabelRun]
		if run != "" && live != nil && live(run) {
			continue
		}
		out = append(out, c.ID)
	}
	sort.Strings(out)
	return out
}

// checkLabels is the read-back rule for the labels: exactly this run and
// install.
func checkLabels(installID, runID string, got map[string]string) error {
	for k, want := range Labels(installID, runID) {
		if got[k] != want {
			return fmt.Errorf("label %s is %q, planned %q", k, got[k], want)
		}
	}
	return nil
}
