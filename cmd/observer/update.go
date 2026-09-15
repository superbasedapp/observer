package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// update.go is the READ-ONLY half of the `observer update` command family
// (docs/plans/enterprise-update-management-plan-2026-09-07.md §3.10):
//
//   - `observer update status` — local state only, no network, no DB.
//   - `observer update check`  — the same local read, said out loud: the
//     manifest FETCH belongs to the daemon's push cycle, and this command
//     deliberately opens no second fetch path on the node (ruling R8).
//
// The effectful verbs (`apply`, `rollback`, `history`) live in the sibling
// update_verbs.go with the drain, the fork-exec-and-watch handshake and
// agent migration 105. Nothing HERE opens a socket: this file COMPOSES
// internal/update (pure decisions) with the filesystem, and the only bytes
// it reads are the node's own state and the running executable's path.
//
// STATE STORAGE, stated plainly because it changes in W3: agent
// migration 105 (`update_state` / `update_events`) is a W3 item, so W1
// keeps the node's update state in a JSON file at
// <state_dir>/state.json, where state_dir is the plan's [update].state_dir
// (default ~/.observer/updates). The [update] config SECTION also lands
// in W3, so this file resolves the default location directly and reads
// the OBSERVER_UPDATE_STATE_DIR override for tests and for an operator
// running a relocated home. The document's field set is already the one
// migration 105 will carry (update.NodeState), so W3 moves the storage
// without moving the shape.

// updateStateDirEnv relocates the update state directory. It exists for
// the same reason the LOC editor-token path is overridable: a node
// whose home is on a network mount needs the state somewhere local.
const updateStateDirEnv = "OBSERVER_UPDATE_STATE_DIR"

// updateStateFileName is the W1 state document's name inside state_dir.
const updateStateFileName = "state.json"

// newUpdateCmd builds `observer update`.
func newUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Inspect and apply this node's org-served updates",
		Long: `observer update reports what this node knows about updates, and applies
what its org has published.

` + "`status`" + `, ` + "`check`" + ` and ` + "`history`" + ` are LOCAL reads: no network call, nothing
downloaded, nothing changed. ` + "`apply`" + ` and ` + "`rollback`" + ` are the effectful pair;
they ask the running daemon over loopback, because the drain and the
fork-exec-and-watch handshake are only meaningful in the process that owns
the listeners.

Updates are served by the org server a node is enrolled with — never by
GitHub, npm or a CDN — so a node that is not enrolled has nothing to
check. The dashboard's click-gated "Check for updates" button remains
the independent freshness oracle for standalone installs.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newUpdateStatusCmd())
	cmd.AddCommand(newUpdateCheckCmd())
	// W3's effectful verbs. They land together because they are one
	// mechanism: an apply that cannot be undone is not something to ship,
	// and a rollback nobody can inspect afterwards is not one either.
	cmd.AddCommand(newUpdateApplyCmd())
	cmd.AddCommand(newUpdateRollbackCmd())
	cmd.AddCommand(newUpdateHistoryCmd())
	return cmd
}

// updateStatusReport is the JSON shape of `observer update status
// --json`. It is a REPORT, not the wire: the org-bound posture row is a
// narrower, enum-only subset composed in internal/store (W3).
type updateStatusReport struct {
	// InstalledVersion is this binary's version.
	InstalledVersion string `json:"installed_version"`
	// Channel is the channel this node is assigned to, or "" when the
	// org has not assigned one.
	Channel string `json:"channel,omitempty"`
	// State / Reason / ErrorClass are the recorded posture.
	State      string `json:"state"`
	Reason     string `json:"reason,omitempty"`
	ErrorClass string `json:"error_class,omitempty"`
	// TargetVersion is the version this node is trying to reach.
	TargetVersion string `json:"target_version,omitempty"`
	// LastManifestVersion / LastManifestSeenAt describe the newest
	// manifest this node has accepted.
	LastManifestVersion int64  `json:"last_manifest_version,omitempty"`
	LastManifestSeenAt  string `json:"last_manifest_seen_at,omitempty"`
	// InstallMethod / SelfApply / Advice come from the install-method
	// table (§3.7).
	InstallMethod string `json:"install_method"`
	SelfApply     bool   `json:"self_apply"`
	Advice        string `json:"advice,omitempty"`
	// AutoApply and AutoApplyWhy report whether zero-touch updates are
	// on, and WHY — a surface that says "off" without saying who
	// decided is the kind of thing an admin cannot act on.
	AutoApply    bool   `json:"auto_apply"`
	AutoApplyWhy string `json:"auto_apply_why"`
	// Window is the local maintenance window, "any time" when unset.
	Window string `json:"window"`
	// NextWindowOpen is when the window next permits an apply.
	NextWindowOpen string `json:"next_window_open,omitempty"`
	// StatePath is where the state document lives.
	StatePath string `json:"state_path"`
	// ExecPath is the running executable.
	ExecPath string `json:"exec_path"`
	// VendorKeyPlaceholder reports that this build carries no real
	// vendor artifact-verification key yet (W6). While it is true, an
	// apply of an unsigned artifact is refused rather than downgraded.
	VendorKeyPlaceholder bool `json:"vendor_key_placeholder"`
}

// newUpdateStatusCmd builds `observer update status`.
func newUpdateStatusCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Print this node's update state (local only, no network)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rep, err := buildUpdateStatus()
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(rep)
			}
			writeUpdateStatus(cmd.OutOrStdout(), rep)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the report as JSON")
	return cmd
}

// newUpdateCheckCmd builds `observer update check`.
func newUpdateCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Report what this node knows about updates (local read, no network)",
		Long: `observer update check prints the manifest state this node currently holds.

The manifest FETCH belongs to the daemon: it rides the push cycle the node
already runs, on the connection it already makes, and only when the push
acknowledgment says the org has published something newer. This command adds
no request of its own - a second fetch path would be a second trust story on
the node - so it reports what the daemon last verified and says plainly that
it asked nobody.

Run it with the daemon running and enrolled; if this node is not enrolled,
there is nothing to check.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rep, err := buildUpdateStatus()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if rep.LastManifestVersion == 0 {
				fmt.Fprintln(out, "update check: no manifest — this node has never accepted one.")
			} else {
				fmt.Fprintf(out, "update check: last accepted manifest %d (%s), target %s.\n",
					rep.LastManifestVersion, orDash(rep.LastManifestSeenAt), orDash(rep.TargetVersion))
			}
			fmt.Fprintln(out, "This is a LOCAL read: nothing was requested and nothing changed. The daemon")
			fmt.Fprintln(out, "fetches the signed manifest on its push cycle, and only when the org says it")
			fmt.Fprintln(out, "has published something newer. Updates are served only by the org server this")
			fmt.Fprintln(out, "node is enrolled with; if this node is not enrolled, there is nothing to check.")
			fmt.Fprintf(out, "Installed version: %s. Run `observer update status` for the full state.\n", rep.InstalledVersion)
			return nil
		},
	}
	return cmd
}

// buildUpdateStatus assembles the report from the node's own state
// document, the running executable, and the pure install-method table.
func buildUpdateStatus() (updateStatusReport, error) {
	statePath, err := updateStatePath()
	if err != nil {
		return updateStatusReport{}, err
	}
	// W3 moved the durable state into agent migration 105. The JSON document
	// stays as a ONE-RELEASE fallback so a node that has not yet run the new
	// binary reports the truth rather than "idle"; loadUpdateStateForCLI
	// prefers the database and says which it read.
	st, source, err := loadUpdateStateForCLI(context.Background())
	if err != nil {
		return updateStatusReport{}, err
	}
	if source == "database" {
		statePath = "(agent database: update_state)"
	}
	execPath := resolvedExecutablePath()
	det := update.Detect(update.PathProbe{
		ExecPath:      execPath,
		GOOS:          runtime.GOOS,
		Writable:      pathIsReplaceable(execPath),
		SiblingExists: fileExistsIn,
	})

	// [update].window and [update].auto_apply, resolved against the
	// managed-fleet carve-out (§3.9). A status line that says "off" without
	// saying WHO decided is something an admin cannot act on, so the reason
	// is carried beside the value.
	cfg, cfgErr := config.Load(config.LoadOptions{})
	win, _ := update.ParseWindow("")
	autoApply, autoWhy := false, update.AutoApplyReason(false, false, update.ManagedPosture{})
	channel := string(st.Channel)
	if cfgErr == nil {
		win, _ = update.ParseWindow(cfg.Update.Window)
		// EnterpriseGranted lives on the RUNTIME enrolment grant, not in
		// the TOML, so a CLI with no daemon can only see admin_managed.
		// The daemon resolves the full posture (see start.go); reporting
		// the half this process can actually observe is better than
		// inventing the other half.
		posture := update.ManagedPosture{AdminManaged: cfg.OrgClient.Share.AdminManaged}
		effective, explicit := cfg.Update.EffectiveAutoApply(update.AutoApplyDefault(posture))
		autoApply, autoWhy = effective, update.AutoApplyReason(explicit, effective, posture)
		if strings.TrimSpace(cfg.Update.Channel) != "" {
			channel = cfg.Update.Channel
		}
	}
	now := time.Now()

	rep := updateStatusReport{
		InstalledVersion:     version,
		Channel:              channel,
		State:                string(st.State),
		Reason:               string(st.Reason),
		ErrorClass:           string(st.ErrorClass),
		TargetVersion:        st.TargetVersion,
		LastManifestVersion:  st.LastManifestVersion,
		LastManifestSeenAt:   st.LastManifestSeenAt,
		InstallMethod:        string(det.Method),
		SelfApply:            det.SelfApply,
		Advice:               update.AdviceFor(det, st.TargetVersion),
		AutoApply:            autoApply,
		AutoApplyWhy:         autoWhy,
		Window:               win.String(),
		NextWindowOpen:       win.NextOpen(now).Format(time.RFC3339),
		StatePath:            statePath,
		ExecPath:             execPath,
		VendorKeyPlaceholder: update.VendorKeyIsPlaceholder(),
	}
	return rep, nil
}

// writeUpdateStatus renders the report as aligned text.
func writeUpdateStatus(w io.Writer, rep updateStatusReport) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SuperBased update status\t")
	fmt.Fprintf(tw, "  installed version\t%s\n", rep.InstalledVersion)
	fmt.Fprintf(tw, "  channel\t%s\n", orText(rep.Channel, "(unassigned — the org assigns one)"))
	fmt.Fprintf(tw, "  state\t%s\n", stateText(rep))
	fmt.Fprintf(tw, "  target version\t%s\n", orDash(rep.TargetVersion))
	fmt.Fprintf(tw, "  last manifest\t%s\n", manifestText(rep))
	fmt.Fprintf(tw, "  install method\t%s\n", methodText(rep))
	fmt.Fprintf(tw, "  auto-apply\t%s\n", rep.AutoApplyWhy)
	fmt.Fprintf(tw, "  maintenance window\t%s\n", rep.Window)
	fmt.Fprintf(tw, "  executable\t%s\n", rep.ExecPath)
	fmt.Fprintf(tw, "  state file\t%s\n", rep.StatePath)
	_ = tw.Flush()
	if rep.Advice != "" {
		fmt.Fprintf(w, "\nThis node cannot update itself: %s\n", rep.Advice)
	}
	if rep.VendorKeyPlaceholder {
		fmt.Fprintln(w, "\nNote: this build carries no vendor artifact-verification key yet, so an")
		fmt.Fprintln(w, "artifact without a vendor signature is refused rather than applied.")
	}
	fmt.Fprintln(w, "\nThis command made no network call. Updates are served by the org server")
	fmt.Fprintln(w, "this node is enrolled with, never by GitHub, npm or a CDN.")
}

// stateText renders the state with its qualifier.
func stateText(rep updateStatusReport) string {
	s := rep.State
	if s == "" {
		s = string(update.StateIdle)
	}
	switch {
	case rep.Reason != "" && rep.ErrorClass != "":
		return fmt.Sprintf("%s (%s, last error class %s)", s, rep.Reason, rep.ErrorClass)
	case rep.Reason != "":
		return fmt.Sprintf("%s (%s)", s, rep.Reason)
	case rep.ErrorClass != "":
		return fmt.Sprintf("%s (last error class %s)", s, rep.ErrorClass)
	default:
		return s
	}
}

// manifestText renders the last accepted manifest.
func manifestText(rep updateStatusReport) string {
	if rep.LastManifestVersion == 0 {
		return "none accepted yet"
	}
	if rep.LastManifestSeenAt == "" {
		return fmt.Sprintf("#%d", rep.LastManifestVersion)
	}
	return fmt.Sprintf("#%d seen %s", rep.LastManifestVersion, rep.LastManifestSeenAt)
}

// methodText renders the install method and whether it self-applies.
func methodText(rep updateStatusReport) string {
	if rep.SelfApply {
		return rep.InstallMethod + " (can update itself)"
	}
	return rep.InstallMethod + " (cannot update itself)"
}

// orDash renders an empty string as a dash.
func orDash(s string) string { return orText(s, "—") }

// orText renders an empty string as alt.
func orText(s, alt string) string {
	if strings.TrimSpace(s) == "" {
		return alt
	}
	return s
}

// updateStatePath resolves <state_dir>/state.json.
func updateStatePath() (string, error) {
	if dir := strings.TrimSpace(os.Getenv(updateStateDirEnv)); dir != "" {
		return filepath.Join(dir, updateStateFileName), nil
	}
	cfgPath, err := config.ResolveGlobalPath("")
	if err != nil {
		return "", fmt.Errorf("observer update: locating the observer home: %w", err)
	}
	return filepath.Join(filepath.Dir(cfgPath), "updates", updateStateFileName), nil
}

// loadUpdateNodeState reads the state document, treating a missing file
// as an idle node. A node that has never seen a manifest is not an
// error condition, and reporting one would be the notify path failing
// closed — the opposite of §2.4.
func loadUpdateNodeState(path string) (update.NodeState, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return update.DefaultNodeState(), nil
		}
		return update.NodeState{}, fmt.Errorf("observer update: reading %s: %w", path, err)
	}
	st, err := update.ParseNodeState(b)
	if err != nil {
		return update.NodeState{}, fmt.Errorf("observer update: %s: %w", path, err)
	}
	return st, nil
}

// resolvedExecutablePath returns the running executable with symlinks
// resolved, or "" when it cannot be determined (which Detect reports
// honestly as "unknown", never as a self-applying binary).
func resolvedExecutablePath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		return resolved
	}
	return exe
}

// pathIsReplaceable reports whether the atomic swap of §3.7 step 6
// could succeed: it probes the executable's DIRECTORY, because the swap
// is a rename INTO that directory, not a write THROUGH the old file.
//
// Probing the file itself would be wrong twice over. On Linux, opening
// a running executable for writing fails with ETXTBSY even when the uid
// owns it — a check that would report every self-updatable node as
// read-only. And mode bits are not the question either: an ACL, a
// read-only mount or a container user mapping all make them a lie. So
// the probe is the operation that will actually be performed.
func pathIsReplaceable(execPath string) bool {
	if execPath == "" {
		return false
	}
	if _, err := os.Stat(execPath); err != nil {
		return false
	}
	return dirIsWritable(filepath.Dir(execPath))
}

// dirIsWritable probes a directory by creating and removing an entry in
// it. It leaves nothing behind on success or failure.
func dirIsWritable(dir string) bool {
	probe, err := os.CreateTemp(dir, ".observer-update-probe-*")
	if err != nil {
		return false
	}
	name := probe.Name()
	_ = probe.Close()
	return os.Remove(name) == nil
}

// fileExistsIn is the SiblingExists seam for the install-method table's
// virtualenv rule.
func fileExistsIn(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}
