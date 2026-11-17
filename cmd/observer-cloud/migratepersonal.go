package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/personalmig"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// migratepersonal.go is `observer-cloud migrate-personal`, the cloud half of
// stage E3 (managed-SaaS plan 06 9.4; plan 07 M9.3;
// docs/plans/managed-saas/individuals/inventory.md D-IND-4, D-IND-5,
// D-IND-6; docs/security.md IND-5).
//
// The control plane holds no credential to tenant data, so this command moves
// each personal-plane account onto its personal org (found or created),
// re-keys its live plus_beta subscription onto the org, and writes one bundle
// per org (internal/cloudcontract personalimport.go) the operator carries to
// the tenant host, where `observer-org tenant import-intel` imports it and
// writes receipt.json. `verify` reads the receipts back.
//
// Every decision is the pure internal/cloudserver/personalmig package's;
// every write goes through the store seam store/personalmig.go, which records
// each account's stage in the personal_migrations ledger (cloud 0134) before
// the run moves on, so a rerun resumes where it stopped. No Paddle or WorkOS
// call is made; nothing tenant-side is touched.

// migratePersonalStore is the store seam the command uses (store.Store).
type migratePersonalStore interface {
	ListPersonalMigrationAccounts(ctx context.Context, after string, limit int) ([]store.PersonalMigrationAccount, error)
	PersonalMigrationFootprint(ctx context.Context, accountID string, now time.Time) (personalmig.Footprint, error)
	PersonalMigrationResults(ctx context.Context, accountID string) ([]personalmig.ResultFacts, error)
	GetPersonalMigration(ctx context.Context, accountID string) (store.PersonalMigrationRow, bool, error)
	ListPersonalMigrations(ctx context.Context) ([]store.PersonalMigrationRow, error)
	RecordPersonalMigration(ctx context.Context, row store.PersonalMigrationRow) (bool, error)
	RecordPersonalMigrationError(ctx context.Context, accountID, msg string) (bool, error)
	EnsurePersonalOrgForMigration(ctx context.Context, accountID, tenantDomain string) (personalmig.PersonalOrg, bool, error)
	RekeyPersonalSubscription(ctx context.Context, accountID string, org personalmig.PersonalOrg, base store.PersonalMigrationRow, now time.Time) (store.RekeyOutcome, error)
	RecordAudit(ctx context.Context, accountID, eventType, detailJSON string) error
}

// Bundle file names (cloudcontract personalimport.go) and the receipt the
// tenant importer writes beside them.
const (
	bundleManifestFile = "manifest.json"
	bundleRecordsFile  = "results.ndjson"
	bundleReceiptFile  = "receipt.json"
	migrateWalkPage    = 200
)

// migratePersonalOptions are the flags of plan and run.
type migratePersonalOptions struct {
	Out          string
	Apply        bool
	Replace      bool
	Limit        int
	Account      string
	TenantDomain string
}

// migrateAccount is one account the walk produced, with its ledger row.
type migrateAccount struct {
	ID       string
	Row      store.PersonalMigrationRow
	HasRow   bool
	Footprnt personalmig.Footprint
	Decision personalmig.Decision
	// Read is true once the footprint is read; every account is read, a
	// verified one too (FR-13: the personal plane keeps serving, so it may drift).
	Read bool
}

// stage is the account's ledger stage (StageNone without a row).
func (a migrateAccount) stage() personalmig.Stage {
	if !a.HasRow {
		return personalmig.StageNone
	}
	return a.Row.Stage
}

// walkAccounts visits every account (or only opts.Account) in account_id
// order, page by page, reading its ledger row, its footprint and
// its decision (a verified account is re-read for drift, FR-13). fn returns false to stop.
func walkAccounts(ctx context.Context, s migratePersonalStore, only string, now time.Time, fn func(migrateAccount) (bool, error)) error {
	visit := func(id string) (bool, error) {
		row, has, err := s.GetPersonalMigration(ctx, id)
		if err != nil {
			return false, err
		}
		a := migrateAccount{ID: id, Row: row, HasRow: has}
		f, err := s.PersonalMigrationFootprint(ctx, id, now)
		if err != nil {
			return false, fmt.Errorf("account %s: %w", id, err)
		}
		a.Footprnt, a.Read = f, true
		if a.stage() == personalmig.StageVerified {
			a.Decision = personalmig.DecideVerified(f, personalmig.Recorded{ResultsTotal: row.ResultsTotal})
		} else {
			a.Decision = personalmig.Decide(f)
		}
		if !a.Decision.InScope && has {
			// A ledger row keeps the account in the run even when its
			// footprint has gone (its last steps are idempotent).
			a.Decision.InScope, a.Decision.ScopeReason = true, "ledger"
		}
		return fn(a)
	}
	if only != "" {
		if _, err := uuid.Parse(only); err != nil {
			return fmt.Errorf("--account %q is not an account UUID", only)
		}
		_, err := visit(only)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("no account %s", only)
		}
		return err
	}
	after := ""
	for {
		page, err := s.ListPersonalMigrationAccounts(ctx, after, migrateWalkPage)
		if err != nil {
			return err
		}
		for _, acct := range page {
			more, err := visit(acct.AccountID)
			if err != nil {
				return err
			}
			if !more {
				return nil
			}
		}
		if len(page) < migrateWalkPage {
			return nil
		}
		after = page[len(page)-1].AccountID
	}
}

// stepChain is the steps `run` would take for a from its current stage, to
// the first step that waits or ends (dry run and plan output).
func stepChain(a migrateAccount) []personalmig.Step {
	var out []personalmig.Step
	cur := a.stage()
	for i := 0; i < 8; i++ {
		step := personalmig.NextStep(cur, a.Decision)
		out = append(out, step)
		next, ok := personalmig.StageAfter(step)
		if !ok || step == personalmig.StepSkip {
			return out
		}
		cur = next
		if next == personalmig.StageExported || next == personalmig.StageVerified {
			return out
		}
	}
	return out
}

// accountLine is one account's plan line.
func accountLine(a migrateAccount) string {
	var b strings.Builder
	stage := string(a.stage())
	if stage == "" {
		stage = "none"
	}
	fmt.Fprintf(&b, "  %s  stage=%s", a.ID, stage)
	if !a.Read {
		fmt.Fprintf(&b, "  org=%s  bundle=%s  done", dash(a.Row.OrgID), short(a.Row.BundleSHA256))
		return b.String()
	}
	f, d := a.Footprnt, a.Decision
	org := a.Row.OrgID
	if f.Org != nil {
		org = f.Org.OrgID
	}
	fmt.Fprintf(&b, "  org=%s  results=%d  devices=%d  plan=%s", dash(org), f.Results, f.Devices, dash(f.PlanName))
	if d.Rekey != nil {
		fmt.Fprintf(&b, "  rekey=%s", d.Rekey.ID)
	}
	var steps []string
	for _, s := range stepChain(a) {
		steps = append(steps, string(s))
	}
	fmt.Fprintf(&b, "  next=%s", strings.Join(steps, ">"))
	if len(d.Drift) > 0 {
		fmt.Fprintf(&b, "  drift: %s", strings.Join(d.Drift, "; "))
	}
	if d.Skip != "" {
		fmt.Fprintf(&b, "  skip: %s", d.Skip)
	}
	if a.Row.LastError != "" {
		fmt.Fprintf(&b, "  last error: %s", a.Row.LastError)
	}
	for _, n := range d.Notes {
		fmt.Fprintf(&b, "\n      note: %s", n)
	}
	return b.String()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return dash(sha)
}

// stageCounts prints counts per stage in lifecycle order.
func stageCounts(counts map[personalmig.Stage]int) string {
	parts := []string{fmt.Sprintf("none %d", counts[personalmig.StageNone])}
	for _, s := range personalmig.KnownStages() {
		parts = append(parts, fmt.Sprintf("%s %d", s, counts[s]))
	}
	return strings.Join(parts, ", ")
}

// runMigratePersonalPlan is `plan`: read-only, it walks every account and
// prints the per-stage counts and one line per in-scope account.
func runMigratePersonalPlan(ctx context.Context, out io.Writer, s migratePersonalStore, account string, now time.Time) error {
	walked, inScope := 0, 0
	stages := map[personalmig.Stage]int{}
	nexts := map[personalmig.Step]int{}
	var lines []string
	err := walkAccounts(ctx, s, account, now, func(a migrateAccount) (bool, error) {
		walked++
		if a.Read && !a.Decision.InScope {
			if account != "" {
				lines = append(lines, "  "+a.ID+"  out of scope (no personal-plane footprint)")
			}
			return true, nil
		}
		inScope++
		stages[a.stage()]++
		nexts[personalmig.NextStep(a.stage(), a.Decision)]++
		lines = append(lines, accountLine(a))
		return true, nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "observer-cloud migrate-personal plan (read-only: nothing was written)")
	fmt.Fprintf(out, "accounts: %d walked, %d in scope, %d out of scope\n", walked, inScope, walked-inScope)
	fmt.Fprintf(out, "stage: %s\n", stageCounts(stages))
	var np []string
	for _, st := range []personalmig.Step{
		personalmig.StepPlan, personalmig.StepEnsureOrg, personalmig.StepRekey,
		personalmig.StepExport, personalmig.StepFinish, personalmig.StepAwaitReceipt, personalmig.StepSkip, personalmig.StepDone,
	} {
		np = append(np, fmt.Sprintf("%s %d", st, nexts[st]))
	}
	fmt.Fprintf(out, "next step: %s\n", strings.Join(np, ", "))
	for _, l := range lines {
		fmt.Fprintln(out, l)
	}
	return nil
}

// runTotals counts what one `run` did.
type runTotals struct {
	Accounts        int `json:"accounts"`
	OrgsCreated     int `json:"orgs_created"`
	Rekeyed         int `json:"subscriptions_rekeyed"`
	Exported        int `json:"bundles_written"`
	BundlesKept     int `json:"bundles_unchanged"`
	RecordsExported int `json:"records_exported"`
	Finished        int `json:"finished_without_results"`
	Skipped         int `json:"skipped"`
	Failed          int `json:"failed"`
	Reopened        int `json:"reopened"`
}

// runMigratePersonal is `run`. Without opts.Apply it is the dry run: it
// prints what each account would go through and writes nothing.
func runMigratePersonal(ctx context.Context, out io.Writer, s migratePersonalStore, opts migratePersonalOptions, now func() time.Time) error {
	if opts.Apply && strings.TrimSpace(opts.Out) == "" {
		return errors.New("--out is required with --apply (the directory the per-org bundles are written to)")
	}
	if opts.Limit < 0 {
		return errors.New("--limit must be 0 (no limit) or more")
	}
	mode := "dry run: nothing is written; add --apply to run it"
	if opts.Apply {
		mode = "applying; bundles under " + opts.Out
	}
	fmt.Fprintf(out, "observer-cloud migrate-personal run (%s)\n", mode)
	var tot runTotals
	err := walkAccounts(ctx, s, opts.Account, now(), func(a migrateAccount) (bool, error) {
		if a.Read && !a.Decision.InScope {
			return true, nil
		}
		step := personalmig.NextStep(a.stage(), a.Decision)
		if step == personalmig.StepAwaitReceipt && opts.Replace {
			step = personalmig.StepExport
		}
		if step == personalmig.StepDone || step == personalmig.StepAwaitReceipt {
			return true, nil
		}
		if opts.Limit > 0 && tot.Accounts >= opts.Limit {
			return false, nil
		}
		tot.Accounts++
		if !opts.Apply {
			var steps []string
			for _, st := range stepChain(a) {
				steps = append(steps, string(st))
			}
			if opts.Replace && a.stage() == personalmig.StageExported {
				steps = []string{string(personalmig.StepExport)}
			}
			fmt.Fprintf(out, "  %s  would: %s\n", a.ID, strings.Join(steps, " > "))
			return true, nil
		}
		m := &accountRun{s: s, out: out, opts: opts, now: now, a: a, tot: &tot}
		if err := m.drive(ctx, step); err != nil {
			tot.Failed++
			fmt.Fprintf(out, "  %s  FAILED: %v\n", a.ID, err)
			if _, nerr := s.RecordPersonalMigrationError(ctx, a.ID, err.Error()); nerr != nil {
				fmt.Fprintf(out, "  %s  could not note the error on the ledger: %v\n", a.ID, nerr)
			}
		}
		return true, nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "accounts %d: orgs created %d, subscriptions re-keyed %d, bundles written %d (unchanged %d, %d records), finished with no results %d, skipped %d, failed %d\n",
		tot.Accounts, tot.OrgsCreated, tot.Rekeyed, tot.Exported, tot.BundlesKept, tot.RecordsExported, tot.Finished, tot.Skipped, tot.Failed)
	if opts.Apply {
		detail, _ := json.Marshal(tot)
		if err := s.RecordAudit(ctx, "", store.PersonalMigrationRunAudit, string(detail)); err != nil {
			return fmt.Errorf("record the run audit: %w", err)
		}
	}
	if tot.Failed > 0 {
		return &exitCodeError{code: 1, msg: fmt.Sprintf("migrate-personal run: %d account(s) failed; their stage is kept, rerun to resume", tot.Failed)}
	}
	return nil
}

// accountRun drives one account through its steps.
type accountRun struct {
	s    migratePersonalStore
	out  io.Writer
	opts migratePersonalOptions
	now  func() time.Time
	a    migrateAccount
	tot  *runTotals
	org  *personalmig.PersonalOrg
	// reopened is true when the account was reopened for drift this run.
	reopened bool
}

// drive runs steps from first until one waits or ends. Each step records its
// stage before the next starts.
func (m *accountRun) drive(ctx context.Context, first personalmig.Step) error {
	row := m.a.Row
	row.AccountID = m.a.ID
	if m.a.Footprnt.Org != nil {
		o := *m.a.Footprnt.Org
		m.org = &o
	}
	step := first
	for i := 0; i < 8; i++ {
		var err error
		switch step {
		case personalmig.StepSkip:
			row.Stage, row.SkipReason = personalmig.StageSkipped, m.a.Decision.Skip
			if err = m.record(ctx, row); err == nil {
				m.tot.Skipped++
				fmt.Fprintf(m.out, "  %s  skipped: %s\n", m.a.ID, row.SkipReason)
			}
			return err
		case personalmig.StepReopen:
			// A verified account that drifted goes round again; the export it
			// ends in replaces its earlier bundle (the records differ).
			fmt.Fprintf(m.out, "  %s  drift after verification: %s; reopened\n", m.a.ID, strings.Join(m.a.Decision.Drift, "; "))
			m.a.Decision.Drift = nil
			m.reopened = true
			row.Stage, row.SkipReason, row.LastError = personalmig.StagePlanned, "", ""
			m.tot.Reopened++
			err = m.record(ctx, row)
		case personalmig.StepPlan:
			row.Stage, row.SkipReason, row.LastError = personalmig.StagePlanned, "", ""
			err = m.record(ctx, row)
		case personalmig.StepEnsureOrg:
			org, created, e := m.s.EnsurePersonalOrgForMigration(ctx, m.a.ID, m.opts.TenantDomain)
			if e != nil {
				return e
			}
			m.org = &org
			if created {
				m.tot.OrgsCreated++
			}
			row.Stage, row.OrgID = personalmig.StageOrgReady, org.OrgID
			err = m.record(ctx, row)
			if err == nil {
				fmt.Fprintf(m.out, "  %s  personal org %s (%s)%s\n", m.a.ID, org.OrgID, org.Slug, map[bool]string{true: " created", false: ""}[created])
			}
		case personalmig.StepRekey:
			if m.org == nil {
				return errors.New("no personal org to re-key onto")
			}
			res, e := m.s.RekeyPersonalSubscription(ctx, m.a.ID, *m.org, row, m.now())
			if e != nil {
				return e
			}
			if res.Refused != "" {
				row.Stage, row.SkipReason = personalmig.StageSkipped, "re-key refused: "+res.Refused
				if err = m.record(ctx, row); err == nil {
					m.tot.Skipped++
					fmt.Fprintf(m.out, "  %s  skipped: %s\n", m.a.ID, row.SkipReason)
				}
				return err
			}
			row = res.Row
			if res.Rekeyed {
				m.tot.Rekeyed++
				fmt.Fprintf(m.out, "  %s  subscription %s re-keyed to org %s as %s v%d (%d account plan row(s) closed)\n",
					m.a.ID, res.SubscriptionID, m.org.OrgID, personalmig.OrgPlanName, personalmig.OrgPlanVersion, res.ClosedPlanRows)
			}
		case personalmig.StepExport:
			row, err = m.export(ctx, row)
		case personalmig.StepFinish:
			row.Stage = personalmig.StageVerified
			if err = m.record(ctx, row); err == nil {
				m.tot.Finished++
				fmt.Fprintf(m.out, "  %s  no results to carry; verified\n", m.a.ID)
			}
			return err
		default:
			return nil
		}
		if err != nil {
			return err
		}
		next := personalmig.NextStep(row.Stage, m.a.Decision)
		if next == personalmig.StepAwaitReceipt || next == personalmig.StepDone {
			return nil
		}
		step = next
	}
	return errors.New("step loop did not settle")
}

func (m *accountRun) record(ctx context.Context, row store.PersonalMigrationRow) error {
	_, err := m.s.RecordPersonalMigration(ctx, row)
	return err
}

// export builds the account's records, writes (or keeps) its bundle and
// records exported, or verified when no result is left to carry.
func (m *accountRun) export(ctx context.Context, row store.PersonalMigrationRow) (store.PersonalMigrationRow, error) {
	if m.org == nil {
		return row, errors.New("no personal org to export for")
	}
	facts, err := m.s.PersonalMigrationResults(ctx, m.a.ID)
	if err != nil {
		return row, err
	}
	exp, err := personalmig.BuildExport(facts)
	if err != nil {
		return row, err
	}
	row.ResultsTotal, row.ResultsExported, row.ResultsSkipped = exp.Total, len(exp.Records), exp.SkippedTotal()
	if len(exp.Records) == 0 {
		if row.Stage == personalmig.StageExported {
			return row, errors.New("no result is left to export, but a bundle was exported before; resolve by hand")
		}
		row.Stage, row.BundleSHA256 = personalmig.StageVerified, ""
		if err := m.record(ctx, row); err != nil {
			return row, err
		}
		m.tot.Finished++
		fmt.Fprintf(m.out, "  %s  %d result(s), none exportable (%s); verified\n", m.a.ID, exp.Total, skippedText(exp.Skipped))
		return row, nil
	}
	data, sha, err := cloudcontract.EncodePersonalImportRecords(exp.Records)
	if err != nil {
		return row, err
	}
	man := personalmig.NewManifest(m.a.ID, *m.org, m.a.Footprnt.OwnerSubject, len(exp.Records), sha, m.now())
	if err := man.Validate(); err != nil {
		return row, err
	}
	action, err := writeBundle(m.opts.Out, man, data, m.opts.Replace || m.reopened)
	if err != nil {
		return row, err
	}
	if row.BundleSHA256 != sha {
		row.ReceiptInserted, row.ReceiptAlreadyPresent, row.ReceiptPresent = nil, nil, nil
	}
	row.Stage, row.BundleSHA256, row.OrgID, row.LastError = personalmig.StageExported, sha, m.org.OrgID, ""
	if err := m.record(ctx, row); err != nil {
		return row, err
	}
	if action == personalmig.BundleKeep {
		m.tot.BundlesKept++
	} else {
		m.tot.Exported++
	}
	m.tot.RecordsExported += len(exp.Records)
	fmt.Fprintf(m.out, "  %s  bundle %s: %d record(s) of %d (%s), sha256 %s (%s)\n",
		m.a.ID, m.org.OrgID, len(exp.Records), exp.Total, skippedText(exp.Skipped), sha, action)
	return row, nil
}

func skippedText(sk map[string]int) string {
	if len(sk) == 0 {
		return "none left out"
	}
	keys := make([]string, 0, len(sk))
	for k := range sk {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, sk[k]))
	}
	return "left out: " + strings.Join(parts, ", ")
}

// readExistingBundle reads what is in an org's bundle directory.
func readExistingBundle(dir string) (personalmig.ExistingBundle, error) {
	var e personalmig.ExistingBundle
	raw, err := os.ReadFile(filepath.Join(dir, bundleManifestFile))
	if errors.Is(err, fs.ErrNotExist) {
		return e, nil
	}
	if err != nil {
		return e, err
	}
	e.Found = true
	// An unreadable manifest is a different bundle (refused unless
	// --replace), never an error that hides it.
	_ = json.Unmarshal(raw, &e.Manifest)
	recs, err := os.ReadFile(filepath.Join(dir, bundleRecordsFile))
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return e, err
	default:
		sum := sha256.Sum256(recs)
		e.RecordsSHA256 = hex.EncodeToString(sum[:])
	}
	return e, nil
}

// writeBundle writes man and data as <out>/<org_id>/ (directories 0700,
// files 0600; the records first, the manifest last, each through a temporary
// file and a rename). The same bundle already there is kept; a different one
// is refused unless replace.
func writeBundle(out string, man cloudcontract.PersonalImportManifest, data []byte, replace bool) (personalmig.BundleAction, error) {
	if _, err := uuid.Parse(man.OrgID); err != nil {
		return "", fmt.Errorf("org id %q is not a uuid", man.OrgID)
	}
	dir := filepath.Join(out, man.OrgID)
	existing, err := readExistingBundle(dir)
	if err != nil {
		return "", fmt.Errorf("read the bundle in %s: %w", dir, err)
	}
	action := personalmig.DecideBundle(existing, man.OrgID, man.RecordsSHA256, replace)
	switch action {
	case personalmig.BundleKeep:
		return action, nil
	case personalmig.BundleRefuse:
		return action, fmt.Errorf("%s holds a different bundle (sha256 %s, this run %s); pass --replace to overwrite it", dir, dash(existing.RecordsSHA256), man.RecordsSHA256)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	manJSON, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return "", err
	}
	if err := writeFileAtomic(filepath.Join(dir, bundleRecordsFile), data); err != nil {
		return "", err
	}
	if err := writeFileAtomic(filepath.Join(dir, bundleManifestFile), append(manJSON, '\n')); err != nil {
		return "", err
	}
	// Read it back: what is on disk is what the ledger records.
	back, err := readExistingBundle(dir)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(back.RecordsSHA256, man.RecordsSHA256) || back.Manifest.RecordsSHA256 != man.RecordsSHA256 {
		return "", fmt.Errorf("the bundle in %s did not read back with sha256 %s", dir, man.RecordsSHA256)
	}
	return action, nil
}

// writeFileAtomic writes data to path through a 0600 temporary file in the
// same directory and a rename.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := io.Copy(tmp, bytes.NewReader(data)); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// verifyTotals counts what `verify` found.
type verifyTotals struct {
	Exported        int
	VerifiedNow     int
	AlreadyVerified int
	Incomplete      int
	Expected        int
	Present         int
	Inserted        int
	AlreadyPresent  int
}

// runMigratePersonalVerify is `verify`: for every exported account it reads
// <receipts>/<org_id>/receipt.json, compares it with the bundle the ledger
// recorded (PersonalImportReceipt.Complete), records the receipt's counts,
// and moves a complete account to verified. Any incomplete account is a
// non-zero exit.
func runMigratePersonalVerify(ctx context.Context, out io.Writer, s migratePersonalStore, receipts string) error {
	if strings.TrimSpace(receipts) == "" {
		return errors.New("--receipts is required (the directory holding <org_id>/receipt.json)")
	}
	rows, err := s.ListPersonalMigrations(ctx)
	if err != nil {
		return err
	}
	var t verifyTotals
	for _, row := range rows {
		switch row.Stage {
		case personalmig.StageVerified:
			t.AlreadyVerified++
			continue
		case personalmig.StageExported:
		default:
			continue
		}
		t.Exported++
		t.Expected += row.ResultsExported
		man := cloudcontract.PersonalImportManifest{
			Format: cloudcontract.PersonalImportFormat, AccountID: row.AccountID, OrgID: row.OrgID,
			RecordCount: row.ResultsExported, RecordsSHA256: row.BundleSHA256,
		}
		rec, gap, err := readReceipt(receipts, row.OrgID)
		if err == nil && gap == "" {
			gap = personalmig.ReceiptGap(man, rec)
			ins, ap, pr := rec.Inserted, rec.AlreadyPresent, rec.Present
			row.ReceiptInserted, row.ReceiptAlreadyPresent, row.ReceiptPresent = &ins, &ap, &pr
			t.Present += rec.Present
			t.Inserted += rec.Inserted
			t.AlreadyPresent += rec.AlreadyPresent
		}
		if err != nil {
			gap = err.Error()
		}
		if gap == "" && rec.Complete(man) {
			row.Stage, row.LastError = personalmig.StageVerified, ""
			t.VerifiedNow++
			fmt.Fprintf(out, "  %s  org %s  verified: %d of %d present (%d inserted, %d already there)\n",
				row.AccountID, row.OrgID, rec.Present, row.ResultsExported, rec.Inserted, rec.AlreadyPresent)
		} else {
			row.LastError = "verify: " + gap
			t.Incomplete++
			fmt.Fprintf(out, "  %s  org %s  INCOMPLETE: %s\n", row.AccountID, row.OrgID, gap)
		}
		if _, err := s.RecordPersonalMigration(ctx, row); err != nil {
			return fmt.Errorf("record %s: %w", row.AccountID, err)
		}
	}
	fmt.Fprintf(out, "observer-cloud migrate-personal verify: %d exported account(s): %d verified now, %d incomplete; %d verified before\n",
		t.Exported, t.VerifiedNow, t.Incomplete, t.AlreadyVerified)
	fmt.Fprintf(out, "records: %d expected, %d present on the tenants (%d inserted, %d already there)\n",
		t.Expected, t.Present, t.Inserted, t.AlreadyPresent)
	detail, _ := json.Marshal(map[string]int{
		"exported": t.Exported, "verified_now": t.VerifiedNow, "incomplete": t.Incomplete,
		"records_expected": t.Expected, "records_present": t.Present,
	})
	if err := s.RecordAudit(ctx, "", store.PersonalMigrationRunAudit, string(detail)); err != nil {
		return fmt.Errorf("record the verify audit: %w", err)
	}
	if t.Incomplete > 0 {
		return &exitCodeError{code: 1, msg: fmt.Sprintf("migrate-personal verify: %d account(s) incomplete", t.Incomplete)}
	}
	return nil
}

// readReceipt reads <dir>/<org>/receipt.json. A missing or malformed receipt
// is a gap (the account stays exported), not an error.
func readReceipt(dir, org string) (cloudcontract.PersonalImportReceipt, string, error) {
	var r cloudcontract.PersonalImportReceipt
	if _, err := uuid.Parse(org); err != nil {
		return r, "", fmt.Errorf("org id %q is not a uuid", org)
	}
	raw, err := os.ReadFile(filepath.Join(dir, org, bundleReceiptFile))
	if errors.Is(err, fs.ErrNotExist) {
		return r, "no " + bundleReceiptFile + " for this org", nil
	}
	if err != nil {
		return r, "", err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return cloudcontract.PersonalImportReceipt{}, "malformed " + bundleReceiptFile + ": " + err.Error(), nil
	}
	return r, "", nil
}

// runMigratePersonalStatus is `status`: the ledger's counts per stage and
// every row that is skipped or carries an error.
func runMigratePersonalStatus(ctx context.Context, out io.Writer, s migratePersonalStore) error {
	rows, err := s.ListPersonalMigrations(ctx)
	if err != nil {
		return err
	}
	counts := map[personalmig.Stage]int{}
	exported, present := 0, 0
	for _, r := range rows {
		counts[r.Stage]++
		exported += r.ResultsExported
		if r.ReceiptPresent != nil {
			present += *r.ReceiptPresent
		}
	}
	fmt.Fprintf(out, "observer-cloud migrate-personal status: %d account(s) in the ledger\n", len(rows))
	var parts []string
	for _, st := range personalmig.KnownStages() {
		parts = append(parts, fmt.Sprintf("%s %d", st, counts[st]))
	}
	fmt.Fprintf(out, "stage: %s\n", strings.Join(parts, ", "))
	fmt.Fprintf(out, "records: %d exported, %d confirmed present by receipts\n", exported, present)
	for _, r := range rows {
		switch {
		case r.Stage == personalmig.StageSkipped:
			fmt.Fprintf(out, "  %s  skipped: %s\n", r.AccountID, r.SkipReason)
		case r.LastError != "":
			fmt.Fprintf(out, "  %s  stage=%s  last error: %s\n", r.AccountID, r.Stage, r.LastError)
		}
	}
	return nil
}

// runMigratePersonalCheckDrift is `check-drift`, the retirement gate (FR-13):
// read-only, it walks every in-scope account and exits non-zero unless every
// one is verified with nothing created since. Run it before the 410 switch
// and before any table drop; a skipped account blocks too unless allowSkipped
// (the operator accepts that the drop discards that account's data).
func runMigratePersonalCheckDrift(ctx context.Context, out io.Writer, s migratePersonalStore, allowSkipped bool, now time.Time) error {
	counts := map[personalmig.Gate]int{}
	var lines []string
	err := walkAccounts(ctx, s, "", now, func(a migrateAccount) (bool, error) {
		if a.Read && !a.Decision.InScope {
			return true, nil
		}
		g := personalmig.RetirementGate(a.stage(), a.Decision)
		counts[g]++
		switch g {
		case personalmig.GateDrift:
			lines = append(lines, fmt.Sprintf("  %s  DRIFT: %s", a.ID, strings.Join(a.Decision.Drift, "; ")))
		case personalmig.GateUnfinished:
			lines = append(lines, fmt.Sprintf("  %s  UNFINISHED: stage=%s next=%s", a.ID, dash(string(a.stage())), personalmig.NextStep(a.stage(), a.Decision)))
		case personalmig.GateSkipped:
			lines = append(lines, fmt.Sprintf("  %s  SKIPPED: %s", a.ID, dash(a.Decision.Skip)))
		}
		return true, nil
	})
	if err != nil {
		return err
	}
	blocked := counts[personalmig.GateDrift] + counts[personalmig.GateUnfinished]
	if !allowSkipped {
		blocked += counts[personalmig.GateSkipped]
	}
	fmt.Fprintln(out, "observer-cloud migrate-personal check-drift (read-only: nothing was written)")
	fmt.Fprintf(out, "in scope: clear %d, drift %d, unfinished %d, skipped %d\n",
		counts[personalmig.GateClear], counts[personalmig.GateDrift], counts[personalmig.GateUnfinished], counts[personalmig.GateSkipped])
	for _, l := range lines {
		fmt.Fprintln(out, l)
	}
	if blocked > 0 {
		return &exitCodeError{code: 1, msg: fmt.Sprintf("migrate-personal check-drift: %d account(s) block retirement; run `run --apply` and `verify` again, then recheck", blocked)}
	}
	fmt.Fprintln(out, "no drift: the plane may be retired")
	return nil
}

// newMigratePersonalCmd is `observer-cloud migrate-personal`.
func newMigratePersonalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate-personal",
		Short: "move personal-plane accounts onto their personal orgs (E3, the cloud half)",
		Long: "Move every personal-plane account onto its personal org (managed-SaaS stage E3,\n" +
			"plan 07 M9.3; D-IND-4, D-IND-5, D-IND-6).\n\n" +
			"The control plane holds no credential to tenant data, so this command does the\n" +
			"cloud half: it finds or creates each account's personal org, re-keys a live\n" +
			"plus_beta subscription onto the org as personal_pro (one subscription, billed\n" +
			"once; no Paddle call), and writes <out>/<org_id>/manifest.json + results.ndjson,\n" +
			"which the operator carries to the tenant host for\n" +
			"`observer-org tenant import-intel`. `verify` reads the receipts back.\n\n" +
			"Every account's stage is kept in the personal_migrations ledger, so a rerun\n" +
			"resumes where it stopped. Run against the admin DSN (SBCI_PG_DSN).",
	}
	var account string
	plan := &cobra.Command{
		Use:   "plan",
		Short: "print what the migration would do, per stage and per account (read-only)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer s.Pool().Close()
			return runMigratePersonalPlan(cmd.Context(), cmd.OutOrStdout(), s, account, time.Now())
		},
	}
	plan.Flags().StringVar(&account, "account", "", "only this account UUID")

	var opts migratePersonalOptions
	run := &cobra.Command{
		Use:   "run",
		Short: "run the migration (a dry run unless --apply)",
		Long: "Run the migration for every in-scope account (or --account), up to --limit\n" +
			"accounts. Without --apply it prints what it would do and writes nothing.\n" +
			"With --apply it writes the ledger, the personal orgs, the re-keyed\n" +
			"subscriptions and the bundles under --out. A bundle already there with the\n" +
			"same records is kept; a different one is refused unless --replace (which\n" +
			"also re-exports accounts already exported and not yet verified).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer s.Pool().Close()
			opts.TenantDomain = strings.TrimSpace(os.Getenv("SBCI_TENANT_DOMAIN"))
			return runMigratePersonal(cmd.Context(), cmd.OutOrStdout(), s, opts, time.Now)
		},
	}
	run.Flags().StringVar(&opts.Out, "out", "", "directory the per-org bundles are written to (required with --apply)")
	run.Flags().BoolVar(&opts.Apply, "apply", false, "write (without it, the dry run)")
	run.Flags().BoolVar(&opts.Replace, "replace", false, "overwrite a different bundle for the same org, and re-export exported accounts")
	run.Flags().IntVar(&opts.Limit, "limit", 0, "at most this many accounts this run (0: no limit)")
	run.Flags().StringVar(&opts.Account, "account", "", "only this account UUID")

	var receipts string
	verify := &cobra.Command{
		Use:   "verify",
		Short: "check the tenant receipts and move complete accounts to verified",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer s.Pool().Close()
			return runMigratePersonalVerify(cmd.Context(), cmd.OutOrStdout(), s, receipts)
		},
	}
	verify.Flags().StringVar(&receipts, "receipts", "", "directory holding <org_id>/receipt.json from the tenant importer (required)")

	status := &cobra.Command{
		Use:   "status",
		Short: "print the ledger: counts per stage, skipped accounts and errors",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer s.Pool().Close()
			return runMigratePersonalStatus(cmd.Context(), cmd.OutOrStdout(), s)
		},
	}
	var allowSkipped bool
	checkDrift := &cobra.Command{
		Use:   "check-drift",
		Short: "retirement gate: fail unless every in-scope account is verified with no drift (read-only)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer s.Pool().Close()
			return runMigratePersonalCheckDrift(cmd.Context(), cmd.OutOrStdout(), s, allowSkipped, time.Now())
		},
	}
	checkDrift.Flags().BoolVar(&allowSkipped, "allow-skipped", false, "do not block on accounts the migration skipped (their data is discarded by the drop)")
	cmd.AddCommand(plan, run, verify, status, checkDrift)
	return cmd
}
