package diag

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern/sidecar"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// checkGovernance is the §1.7 disclosure surface for the admin-controlled
// Plane B sidecar
// (docs/plans/admin-controlled-plane-b-phase-1b-mini-spec-2026-08-15.md
// §1.4.1, §1.7, §8.3): whether governance-effective.json is present,
// absent, stale/orphaned, or unreadable, whether its directory is
// currently writable, and the live grant's days-to-expiry.
//
// It deliberately avoids internal/store and internal/orgclient — the same
// "keep diag standalone" discipline checkOrgEnrolment already set — and
// reads org_enrolment_grant with one raw SELECT, following
// checkOrgEnrolment's LIMIT 1 precedent: a node holds at most one live
// grant in practice.
//
// The orphan/stale determination (case 3) is judged against the LIVE
// org_enrolment_grant row, NOT sidecar.Read's own verdict on the file's
// embedded grant_expires_at copy: §8.3 describes exactly the failure mode
// where a downgraded or dead daemon never rewrites the file, so the DB row
// — not the file's stale copy of it — is the source of truth for whether
// this machine is still governed.
//
// Per review n6 it reuses DetectCrossEnvSiblingDBs rather than growing a
// second cross-OS probe: the sidecar sits beside the DB
// (config.ResolveGovernanceSidecarPath), so a stranded foreign-OS DB names
// a stranded foreign-OS sidecar too.
//
// homeOverride is the caller's raw DoctorOptions.HomeDir (see Run) — used
// only to decide whether cross-OS auto-detection must stay off for a
// sandboxed doctor run.
func checkGovernance(ctx context.Context, database *sql.DB, cfg config.Config, homeOverride string) Check {
	const name = "governance"
	now := time.Now().UTC()

	grantExpiresAt, hasGrant, err := loadLatestGrantExpiry(ctx, database)
	if err != nil {
		return Check{Name: name, Status: StatusFail, Message: "read org_enrolment_grant: " + err.Error()}
	}
	grantExpired := hasGrant && !grantExpiresAt.IsZero() && now.After(grantExpiresAt)
	governed := hasGrant && !grantExpired

	path := config.ResolveGovernanceSidecarPath(cfg, "")
	sidecarPresent := path != "" && fileExists(path)

	status := StatusOK
	var details []string

	if crossmount.AutoDetectSuppressed(homeOverride, "") {
		details = append(details,
			"cross-env: not inspected — this doctor run pinned HomeDir, so cross-OS auto-detection is suppressed (incident 2026-07-31)")
	} else if sibs := DetectCrossEnvSiblingDBs(cfg.Observer.DBPath, crossmount.AllHomes()); len(sibs) > 0 {
		status = worseStatus(status, StatusWarn)
		for _, sib := range sibs {
			details = append(details, fmt.Sprintf(
				"cross-env: foreign-OS observer.db at %s (%s) carries its own sidecar this daemon never reads — see `observer start`'s cross-env warning",
				sib.Path, sib.Origin,
			))
		}
	}

	// Case 1: nothing to govern this node, nothing written. Correct.
	if !sidecarPresent && !governed {
		return Check{Name: name, Status: status, Message: "not governed; no sidecar (correct)", Details: details}
	}

	// Case 3: a sidecar has outlived (or never had) a live grant. Judged
	// against the DB row, per the package doc above.
	if sidecarPresent && !governed {
		status = worseStatus(status, StatusWarn)
		why := "no grant is on record for this machine"
		if hasGrant && grantExpired {
			why = fmt.Sprintf("the recorded grant expired %s", grantExpiresAt.Format(time.RFC3339))
		}
		details = append(
			details,
			fmt.Sprintf("sidecar: %s", path),
			fmt.Sprintf("%s, but a sidecar is still present — a downgraded or dead daemon never rewrites it (§8.3)", why),
			"remedy: delete the file, or run `observer unenroll` if this machine should no longer be governed at all",
		)
		return Check{Name: name, Status: status, Message: "orphaned/stale sidecar at " + path, Details: details}
	}

	// From here the node IS governed: a live, non-expired grant is on
	// record. hasGrant is true and grantExpired is false.
	details = append(details, fmt.Sprintf("sidecar path: %s", path), expiryDetail(grantExpiresAt))

	// Track C item 1: re-verify the STORED grant document. A grant that no
	// longer verifies is a FAIL and returns immediately — it outranks every
	// sidecar question below, because a rewritten authority record makes the
	// posture this node is pinning meaningless. "Unchecked" is only a
	// detail line: it is the honest answer for a node with no key material,
	// not a finding.
	integrity, integrityDetail := checkStoredGrantIntegrity(ctx, database)
	if integrityDetail != "" {
		details = append(details, integrityDetail)
	}
	if integrity == grantIntegrityInvalid {
		return Check{
			Name: name, Status: StatusFail,
			Message: "the recorded organisation grant does NOT verify against this machine's pinned organisation key — " +
				"the stored authority record has been altered; re-enrol (`observer unenroll` then `observer enroll`) to re-establish it",
			Details: details,
		}
	}

	// §1.4.1: probe writability whenever governed, regardless of whether a
	// sidecar currently exists. doctor runs OUT of the daemon's process and
	// cannot read its in-memory write-failure state (nodegov_wire.go's
	// SidecarWriteErr), so this probe is the one place left that can answer
	// "why" a governed node still reports effective while nothing on the
	// machine can read the pins.
	if path != "" {
		if perr := probeGovernanceDirWritable(filepath.Dir(path)); perr != nil {
			details = append(details, "write probe: "+errnoDetail(perr))
			return Check{
				Name: name, Status: StatusFail,
				Message: fmt.Sprintf("sidecar directory %s is not writable (%s) — the daemon cannot pin governance here",
					filepath.Dir(path), errnoDetail(perr)),
				Details: details,
			}
		}
		details = append(details, "write probe: ok")
	}

	if !sidecarPresent {
		status = worseStatus(status, StatusWarn)
		details = append(details, "no sidecar written yet — start the daemon (`observer start`) so it can resolve and write one")
		return Check{Name: name, Status: status, Message: "governed, but no sidecar written yet", Details: details}
	}

	f, reason := sidecar.Read(path, now)
	switch reason {
	case sidecar.ReasonUnreadable, sidecar.ReasonOversize, sidecar.ReasonMalformed, sidecar.ReasonSchemaTooNew:
		status = worseStatus(status, StatusWarn)
		details = append(details, "reason: "+reason)
		return Check{Name: name, Status: status, Message: fmt.Sprintf("sidecar at %s is %s", path, humanSidecarReason(reason)), Details: details}
	case sidecar.ReasonGrantExpired:
		// The sidecar's OWN embedded grant_expires_at disagrees with the
		// live grant table (a stale copy) — still an orphan condition.
		status = worseStatus(status, StatusWarn)
		details = append(details, "reason: the sidecar's own grant_expires_at has passed (a stale copy — the live grant table disagrees)")
		return Check{Name: name, Status: status, Message: "orphaned/stale sidecar at " + path, Details: details}
	}

	// reason is ReasonNone (live) or ReasonNotApplied (validly parsed,
	// dormant) — either way the file is intact and current.
	pinsApplied := f != nil && len(f.Pinned) > 0
	details = append(details, fmt.Sprintf("pins applied: %t", pinsApplied))

	// Case 7: expiry warning inside 7 days.
	if !grantExpiresAt.IsZero() {
		if days := daysUntil(grantExpiresAt, now); days <= 7 {
			status = worseStatus(status, StatusWarn)
			return Check{
				Name: name, Status: status,
				Message: fmt.Sprintf("grant expires in %d day(s) (%s) — sidecar %s, pins applied=%t",
					days, grantExpiresAt.Format(time.RFC3339), path, pinsApplied),
				Details: details,
			}
		}
	}

	// Case 2: OK — governed, sidecar live, comfortably inside its window.
	msg := fmt.Sprintf("sidecar live at %s, pins applied=%t", path, pinsApplied)
	if grantExpiresAt.IsZero() {
		msg += " (grant has no expiry)"
	} else {
		msg += fmt.Sprintf(", expires in %d day(s)", daysUntil(grantExpiresAt, now))
	}
	return Check{Name: name, Status: status, Message: msg, Details: details}
}

// loadLatestGrantExpiry reads the most recent org_enrolment_grant row's
// expires_at, mirroring checkOrgEnrolment's LIMIT 1 simplification: a node
// realistically holds at most one live grant, and computing the exact
// org_key would require importing internal/orgclient's OrgKey derivation,
// which internal/diag deliberately does not depend on.
//
// An unparseable stored time is treated as "no TTL" (ok=true, zero
// time.Time), matching store.parseGrantTime's own fail-safe direction — a
// hand-edited row must never wedge doctor into reporting a phantom expiry.
func loadLatestGrantExpiry(ctx context.Context, database *sql.DB) (time.Time, bool, error) {
	var expiresRaw string
	err := database.QueryRowContext(ctx,
		`SELECT expires_at FROM org_enrolment_grant ORDER BY generation DESC LIMIT 1`).Scan(&expiresRaw)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return time.Time{}, false, nil
	case err != nil:
		return time.Time{}, false, err
	}
	if expiresRaw == "" {
		return time.Time{}, true, nil
	}
	t, perr := time.Parse(time.RFC3339, expiresRaw)
	if perr != nil {
		return time.Time{}, true, nil
	}
	return t.UTC(), true, nil
}

// probeGovernanceDirWritable is the §1.4.1 writability probe: create and
// immediately remove a uniquely-named temp file in dir. It never touches
// the sidecar file itself — only proves the directory accepts a write —
// and the returned error is inspected by errnoDetail so doctor can name
// the OS-level reason (permissions, read-only filesystem, missing
// directory, …) in one command.
func probeGovernanceDirWritable(dir string) error {
	if dir == "" {
		return errors.New("no sidecar directory configured")
	}
	f, err := os.CreateTemp(dir, ".governance-doctor-probe-*")
	if err != nil {
		return err
	}
	name := f.Name()
	if cerr := f.Close(); cerr != nil {
		_ = os.Remove(name)
		return cerr
	}
	if rerr := os.Remove(name); rerr != nil {
		return rerr
	}
	return nil
}

// errnoDetail renders err with its OS errno when one is available (the
// precedent set by internal/processobs/etw's errnoFromCall), falling back
// to the plain error string on platforms/errors where none unwraps.
func errnoDetail(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return fmt.Sprintf("errno %d: %s", int(errno), errno.Error())
	}
	return err.Error()
}

// humanSidecarReason renders a sidecar.Reason* constant as a short
// user-facing clause, mirroring cmd/observer/orggrant.go's
// pinnedAbsenceReason wording without importing cmd/observer.
func humanSidecarReason(reason string) string {
	switch reason {
	case sidecar.ReasonUnreadable:
		return "unreadable (permissions or an I/O error)"
	case sidecar.ReasonOversize:
		return fmt.Sprintf("oversize (over %dKB) and being ignored", sidecar.MaxBytes/1024)
	case sidecar.ReasonMalformed:
		return "malformed (bad JSON or an unknown field) and being ignored"
	case sidecar.ReasonSchemaTooNew:
		return "written by a newer observer build (schema too new for this binary) and being ignored"
	default:
		return reason
	}
}

// expiryDetail renders a grant's expiry as a detail line, for the "no TTL"
// and "N day(s) remaining" cases doctor reports either way.
func expiryDetail(expiresAt time.Time) string {
	if expiresAt.IsZero() {
		return "grant expiry: none (no TTL)"
	}
	return fmt.Sprintf("grant expiry: %s", expiresAt.Format(time.RFC3339))
}

// daysUntil truncates toward zero, matching the "days remaining" figure an
// operator reads off a calendar rather than a fractional day count.
func daysUntil(t, now time.Time) int {
	return int(t.Sub(now) / (24 * time.Hour))
}

// fileExists reports whether path exists and is a regular (non-directory)
// file. dirExists is doctor.go's directory counterpart.
func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}
