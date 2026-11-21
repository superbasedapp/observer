//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"fmt"
	"io"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
)

// security_osv_os_status.go is the OS release databases' accept and state
// on the two surfaces (CLI `observer security scan db accept --os` and
// `scan status`, the dashboard's /api/security/scanners/db and the Scanners
// card's /api/security/scanners): the same record (osvdb.RecordOSConsent),
// the same gate (osFetchGate) and the same words (osvdb.OSConsentText).

// osAcceptHint is the one sentence every surface shows before the OS
// accept.
var osAcceptHint = "OS release databases not downloaded: accept once to let Observer fetch, on demand, the release databases your scanned images use from " +
	osvdb.OSSource + " (`observer security scan db accept --os`, or the Scanners card on the dashboard's Code security page)"

// runDBAcceptOS shows the OS accept text and records the accept on a yes:
// it asks on a terminal, records with yes, and without a terminal and
// without yes records nothing.
func runDBAcceptOS(w io.Writer, in io.Reader, e *depsScanEnv, yes, isTerminal bool, now time.Time) error {
	if e.managed {
		fmt.Fprintln(w, "This is a managed node: its OS release databases come from your organization's mirror only, so there is nothing to accept here.")
		return nil
	}
	fmt.Fprintln(w, osvdb.OSConsentText)
	if e.osConsent.Accepted() {
		fmt.Fprintf(w, "\nAlready accepted %s (%s); the release databases your images use download when a scan needs them.\n", e.osConsent.AcceptedAt.Local().Format(time.RFC3339), e.osConsent.Surface)
		return nil
	}
	if !yes && isTerminal {
		fmt.Fprintf(w, "\nLet Observer download the OS release databases your images use from %s, on demand? [y/N] ", osvdb.OSSource)
		yes = depsReadYes(in)
	}
	if !yes {
		fmt.Fprintln(w, "\nNothing recorded. Accept on the dashboard's Code security page (Scanners), or re-run with --os --yes.")
		return nil
	}
	key, err := depsRecordSigningKey(e.dir)
	if err != nil {
		return err
	}
	c, err := osvdb.RecordOSConsent(e.dir, "cli", depsLocalAccount(), now, key)
	if err != nil {
		return err
	}
	e.osConsent = c
	fmt.Fprintln(w, "\nRecorded. A release database downloads the first time a scanned image needs it.")
	return nil
}

// osDBStatus assembles the OS databases' state for the dashboard.
func osDBStatus(e *depsScanEnv) *dashapi.ScannerOSDBStatus {
	out := &dashapi.ScannerOSDBStatus{
		Accepted: !e.managed && e.osConsent.Accepted(), Text: osvdb.OSConsentText, Source: osvdb.OSSource,
		Managed: e.managed, Blocked: e.osBlocked(), Installed: []dashapi.ScannerOSRelease{}, DiskBytes: e.db.OSDiskBytes(),
	}
	if out.Accepted {
		out.AcceptedAt, out.AcceptedOn, out.By = e.osConsent.AcceptedAt.UTC().Format(time.RFC3339), e.osConsent.Surface, e.osConsent.By
	}
	for _, s := range osvdb.OSDistroSizes() {
		out.Sizes = append(out.Sizes, dashapi.ScannerOSDistroSize{Name: s.Name, ApproxMB: s.ApproxMB})
	}
	for _, ir := range e.db.OSReleasesInstalled() {
		row := dashapi.ScannerOSRelease{
			Distro: ir.Release.Distro, Version: ir.Release.Version, Artifact: ir.Release.Artifact,
			Epoch: ir.Epoch.String(), Source: ir.Epoch.Source, Bytes: ir.Bytes, LastError: ir.Epoch.LastError,
			FixedOnly: ir.Release.FixedOnly, KnownGap: ir.Release.KnownGap,
		}
		if !ir.Epoch.FetchedAt.IsZero() {
			row.FetchedAt = ir.Epoch.FetchedAt.UTC().Format(time.RFC3339)
		}
		if !ir.Epoch.CheckedAt.IsZero() {
			row.CheckedAt = ir.Epoch.CheckedAt.UTC().Format(time.RFC3339)
		}
		out.Installed = append(out.Installed, row)
	}
	return out
}

// writeOSDBState prints the OS databases' state for `observer security scan
// status`: the accept, the gate, each installed release with its epoch and
// size, and the disk they take.
func writeOSDBState(w io.Writer, e *depsScanEnv) {
	switch r := e.osBlocked(); {
	case e.managed && r == "":
		fmt.Fprintln(w, "OS release databases: from your organization's mirror only, fetched when a scanned image needs a release")
	case e.managed:
		fmt.Fprintf(w, "OS release databases: not available (%s): a managed node takes them from its organization's mirror only\n", r)
	case r == osReasonNotAccepted:
		fmt.Fprintln(w, osAcceptHint)
	case r == "":
		fmt.Fprintf(w, "OS release databases: on demand from %s, installed releases checked every 6 h; accepted %s (%s", osvdb.OSSource, e.osConsent.AcceptedAt.Local().Format(time.RFC3339), e.osConsent.Surface)
		if e.osConsent.By != "" {
			fmt.Fprintf(w, ", by %s", e.osConsent.By)
		}
		fmt.Fprintln(w, ")")
	default:
		fmt.Fprintf(w, "OS release databases: not fetched (%s); they come from %s only\n", r, osvdb.OSSource)
	}
	installed := e.db.OSReleasesInstalled()
	if len(installed) == 0 {
		fmt.Fprintln(w, "  no OS release database installed")
		return
	}
	for _, ir := range installed {
		fmt.Fprintf(w, "  %-18s %s, %d bytes, fetched %s", ir.Release.Artifact, ir.Epoch.String(), ir.Bytes, ir.Epoch.FetchedAt.Format("2006-01-02 15:04"))
		if ir.Epoch.LastError != "" {
			fmt.Fprintf(w, " (last refresh failed: %s; the installed database stays in use)", ir.Epoch.LastError)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "  on disk: %d bytes\n", e.db.OSDiskBytes())
}
