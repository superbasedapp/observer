package main

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// orgenrol_core.go is the ONE enrolment sequence (T-642). `observer enroll`
// (org.go) and Settings > Enrolment (orgenrol_dashboard.go) both run
// runEnrolSequence for the part that changes this machine: exchange the
// one-time code, bind a managed machine, write the default [org_client]
// block. Each surface then only renders the result and runs its own consent
// conversation (a TTY prompt, or the dashboard's parked consent screen), and
// both record an accepted grant through storeGrantOffer and
// writeAcceptedGrantPolicy. A change to what enrolling DOES lands here, so the
// CLI and the dashboard cannot drift apart.

// enrolSequence is what runEnrolSequence did, for the caller to render. It
// carries no rendering of its own: the CLI prints it as lines, the dashboard
// turns it into notes.
type enrolSequence struct {
	enr     *store.Enrolment
	offer   *orgclient.GrantOffer
	managed bool
	// posture is the [org_client.share] default this tenancy writes
	// (enrolShareDefaults), reported whether or not the block was written.
	posture enrolShareDefault
	// bindTried is true for a managed enrolment (the only kind that binds);
	// bindRes / bindErr are BindMachine's answer, rendered by
	// managedBindNote / printManagedBindOutcome.
	bindTried bool
	bindRes   orgcontract.ManagedBindResponse
	bindErr   error
	// pushEnabled is [org_client].enabled as the bundle loaded it.
	pushEnabled bool
	// blockSkipped: the caller asked for no block write (--write-block=false).
	blockSkipped bool
	// cfgPath / cfgPathErr: the config.toml the block went to.
	cfgPath    string
	cfgPathErr error
	// blockAdded / blockErr: ensureOrgClientBlock's answer. Not added and no
	// error means a block was already present (never rewritten).
	blockAdded bool
	blockErr   error
	// cfgEdit / cfgEditErr: the one-line edits an existing block got
	// (enabled = true, org_server_url = the server joined; T-728).
	// pushEnabledNow is true when the file now says enabled = true.
	cfgEdit        orgClientCfgEdit
	cfgEditErr     error
	pushEnabledNow bool
}

// cfgEditNote renders the existing-block edit for both surfaces: the line to
// show and whether it is a warning. Empty when there is nothing to say.
func (s enrolSequence) cfgEditNote() (text string, warn bool) {
	switch {
	case s.cfgEditErr != nil:
		return fmt.Sprintf("could not update the existing [org_client] block in %s (%v); set enabled = true and org_server_url = %q yourself", s.cfgPath, s.cfgEditErr, s.enr.OrgServerURL), true
	case s.cfgEdit.Wrote && !s.pushEnabled:
		return fmt.Sprintf("Updated the existing [org_client] block in %s (enabled = true, org_server_url = %s). It said enabled = false, so a daemon started with it runs no push loop: restart the daemon to begin pushing.", s.cfgPath, s.enr.OrgServerURL), false
	case s.cfgEdit.Wrote:
		return fmt.Sprintf("Updated the existing [org_client] block in %s (enabled = true, org_server_url = %s).", s.cfgPath, s.enr.OrgServerURL), false
	}
	return "", false
}

// runEnrolSequence exchanges token at orgURL for this machine's enrolment and
// applies the enrolment's own local writes. An Enroll error is returned as is
// (the CLI shows it, the dashboard classifies it); nothing after the exchange
// can fail the enrolment, because the code is spent by then. configPath is
// the explicit --config (empty = ~/.observer/config.toml).
func runEnrolSequence(ctx context.Context, b orgBundle, configPath, orgURL, token string, writeBlock bool) (enrolSequence, error) {
	enr, offer, err := b.client.Enroll(ctx, orgURL, token)
	if err != nil {
		return enrolSequence{}, err
	}
	seq := enrolSequence{
		enr:         enr,
		offer:       offer,
		managed:     enr.IsManaged(),
		pushEnabled: b.cfg.OrgClient.Enabled,
	}
	seq.posture = enrolShareDefaultFor(seq.managed)
	// Arc 4 P6a: a managed enrolment binds this machine (plan section 9).
	// The fingerprint is computed and sent ONLY for a managed node; an
	// individual node never emits a machine identity. Best effort: never
	// fails the enrolment.
	if seq.managed {
		seq.bindTried = true
		seq.bindRes, seq.bindErr = b.client.BindMachine(ctx)
	}
	if !writeBlock {
		seq.blockSkipped = true
		return seq, nil
	}
	// W4f (R9.5 / PR-014): the enrolment's TENANCY decides the share default
	// this node-authored block carries. Still a node-side write, never a
	// remote toggle; an existing block's share and scope settings are never
	// rewritten (only its enabled / org_server_url lines, below).
	seq.cfgPath, seq.cfgPathErr = resolveConfigPath(configPath)
	if seq.cfgPathErr == nil {
		seq.blockAdded, seq.blockErr = ensureOrgClientBlock(seq.cfgPath, enr.OrgServerURL, seq.managed)
		// T-728: an EXISTING block (a node that left, or re-enrols) gets its
		// push switch back on and the address of the server just joined, as
		// one-line edits (orgClientCfgRows); its share and scope settings
		// are never rewritten.
		if !seq.blockAdded && seq.blockErr == nil {
			seq.cfgEdit, seq.cfgEditErr = applyOrgClientConfigEdge(seq.cfgPath, orgClientCfgEnrol, enr.OrgServerURL)
			if seq.cfgEditErr == nil && !seq.cfgEdit.NoBlock {
				seq.pushEnabledNow = true
			}
		}
	}
	return seq, nil
}

// printEnrolBlockOutcome is the CLI's rendering of the [org_client] block
// step: the block was written (managed writes full_content = true,
// individual keeps the opt-in false), or an existing block got its enabled /
// org_server_url lines (T-728; its share and scope are never rewritten, the
// already-enrolled raise rides the signed grant instead), or a note that
// sharing is off. enabled is [org_client].enabled as the CLI loaded it.
func printEnrolBlockOutcome(out io.Writer, seq enrolSequence, cfgPath string, enabled bool) {
	if werr := seq.blockErr; werr != nil {
		fmt.Fprintf(out, "\nWarn: could not write [org_client] block to %s: %v\n", cfgPath, werr)
		return
	}
	if seq.blockAdded {
		fmt.Fprintf(out, "\nWrote default [org_client] block to %s - start `observer start` to begin pushing.\n", cfgPath)
		fmt.Fprintf(out, "  share.full_content = %t: %s\n", seq.posture.fullContent, seq.posture.summary)
		fmt.Fprintln(out, "  (A daemon already running with org push enabled picks up a re-enrolment within one push interval - no restart needed.)")
		return
	}
	if note, warn := seq.cfgEditNote(); note != "" {
		if warn {
			fmt.Fprintf(out, "\nWarn: %s\n", note)
		} else {
			fmt.Fprintf(out, "\n%s\n", note)
		}
		return
	}
	if !enabled && !seq.pushEnabledNow {
		fmt.Fprintln(out, "\nNote: [org_client] enabled = false - set it to true and restart `observer start` to begin pushing.")
	}
}

// blockConfigPath is the config.toml the grant's policy block may follow the
// [org_client] block into: empty when the block step was skipped or its path
// could not be resolved, which also skips the policy write (as the CLI always
// did).
func (s enrolSequence) blockConfigPath() string {
	if s.blockSkipped || s.cfgPathErr != nil {
		return ""
	}
	return s.cfgPath
}

// writeAcceptedGrantPolicy is the W-5 step both surfaces run after an
// accepted grant: on a MANAGED enrolment whose authority governs a policy
// family, write the node-side [org_client.policy] keys.
// managedPolicyFamiliesToWrite owns the gate; an empty cfgPath writes
// nothing. families is nil when nothing was due.
func writeAcceptedGrantPolicy(cfgPath string, g grantOutcome) (families []string, added bool, err error) {
	families = managedPolicyFamiliesToWrite(g)
	if len(families) == 0 || cfgPath == "" {
		return nil, false, nil
	}
	added, err = ensureManagedPolicyBlock(cfgPath, families)
	return families, added, err
}

// enrolWireRule is one row of the --wire-clients binary choice (T-642).
// Rows are walked top-down; the first whose when() holds decides.
type enrolWireRule struct {
	name string
	when func(in enrolWireInput) bool
	pick func(in enrolWireInput) (binary, note string)
}

// enrolWireInput is what enrolWireBinary decides on: this process's binary,
// the binaries of the live `observer start` daemons on the same database, and
// whether a path exists on disk.
type enrolWireInput struct {
	self    string
	daemons []string
	exists  func(string) bool
	// goos decides how two paths compare (samePathOn).
	goos string
}

// samePathOn reports whether two cleaned paths name the same file on goos:
// Windows file names are case-insensitive, so C:\Tools\observer.exe and
// c:\tools\OBSERVER.EXE are one binary there (WINFIX2 audit finding 10).
func samePathOn(goos, a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if goos == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// enrolWireRules: `observer enroll --wire-clients` registers hooks and MCP
// against the RUNNING DAEMON's binary when one runs on this database, not
// against whichever binary ran the enrol. Before T-642 it always used its own
// binary, so an enrol run from another build (2026-10-07: bin/observer while
// the daemon ran hotfix-bin/observer.stall4) silently moved the daemon's
// hooks onto a different build until the next `observer start` re-registered
// them. `observer init` keeps meaning "point the hooks at THIS binary".
var enrolWireRules = []enrolWireRule{
	{
		name: "no daemon running",
		when: func(in enrolWireInput) bool { return len(in.daemons) == 0 },
		pick: func(in enrolWireInput) (string, string) { return in.self, "" },
	},
	{
		name: "daemons disagree",
		when: func(in enrolWireInput) bool {
			for _, d := range in.daemons[1:] {
				if !samePathOn(in.goos, d, in.daemons[0]) {
					return true
				}
			}
			return false
		},
		pick: func(in enrolWireInput) (string, string) {
			return in.self, "Note: more than one observer daemon is running on this database from different binaries; hooks and MCP point at this command's binary " + in.self + "."
		},
	},
	{
		name: "daemon is this binary",
		when: func(in enrolWireInput) bool { return samePathOn(in.goos, in.daemons[0], in.self) },
		pick: func(in enrolWireInput) (string, string) { return in.self, "" },
	},
	{
		name: "daemon binary gone",
		when: func(in enrolWireInput) bool { return !in.exists(in.daemons[0]) },
		pick: func(in enrolWireInput) (string, string) {
			return in.self, "Note: the running daemon's binary " + in.daemons[0] + " is no longer on disk; hooks and MCP point at this command's binary " + in.self + "."
		},
	},
	{
		name: "daemon runs another binary",
		when: func(enrolWireInput) bool { return true },
		pick: func(in enrolWireInput) (string, string) {
			return in.daemons[0], "Hooks and MCP point at the running daemon's binary " + in.daemons[0] +
				" (this command ran from " + in.self + "). Run `observer init` from the binary you want them to use to change that."
		},
	},
}

// enrolWireBinary picks the binary the enrolment's --wire-clients step
// registers against (enrolWireRules). dbPath filters the live locks to the
// daemons serving this machine's database; an empty dbPath keeps them all.
func enrolWireBinary(self, dbPath string, live []diag.LockInfo, exists func(string) bool) (binary, note string) {
	return enrolWireBinaryOn(runtime.GOOS, self, dbPath, live, exists)
}

// enrolWireBinaryOn is enrolWireBinary with the path comparison of goos.
func enrolWireBinaryOn(goos, self, dbPath string, live []diag.LockInfo, exists func(string) bool) (binary, note string) {
	if self != "" {
		// The same cleaned form as the daemons' paths below, or this
		// binary never matches its own daemon on Windows (Windows 11 Pro
		// rerun 2026-10-25, D5 group 4).
		self = filepath.Clean(self)
	}
	in := enrolWireInput{self: self, exists: exists, goos: goos}
	for _, l := range live {
		if l.BinaryPath == "" || (dbPath != "" && l.DBPath != "" && !samePathOn(goos, l.DBPath, dbPath)) {
			continue
		}
		in.daemons = append(in.daemons, filepath.Clean(l.BinaryPath))
	}
	if in.self == "" && len(in.daemons) > 0 {
		in.self = in.daemons[0]
	}
	for _, r := range enrolWireRules {
		if r.when(in) {
			return r.pick(in)
		}
	}
	return in.self, ""
}

// enrolWireBinaryFor is the enrol command's call into enrolWireRules: this
// process's binary against the live daemon locks beside dbPath, printing the
// rule's note (if any) to out.
func enrolWireBinaryFor(out io.Writer, dbPath string) string {
	self, _ := absoluteBinaryPath()
	locks, _ := diag.LiveLocks(filepath.Dir(dbPath))
	bin, note := enrolWireBinary(self, dbPath, locks, fileExists)
	if note != "" {
		fmt.Fprintln(out, "  "+note)
	}
	return bin
}
