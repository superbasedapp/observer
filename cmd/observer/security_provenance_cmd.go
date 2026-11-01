//go:build !sbo_omit_security

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/secchange"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_provenance_cmd.go is `observer security provenance status |
// records | consent | rotate-key` (component security.provenance, lane
// sec-f2a), the CLI twin of the dashboard's AI change records card (the
// same functions behind both), plus the hidden `trailer` step the
// prepare-commit-msg block runs.

func securityProvenanceSubcommands() []*cobra.Command {
	return []*cobra.Command{newSecurityProvenanceCmd()}
}

func newSecurityProvenanceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "provenance",
		Short: "Signed AI change records per commit (security.provenance, opt-in)",
		Long: "For each commit the attribution ties to agent activity, a signed record of the sessions,\n" +
			"agents, models, line split, guard, scanner and finding summary (never prompt text),\n" +
			"labelled node-reported attribution: a signed claim by this device, never proof of\n" +
			"authorship. Component security.provenance, off unless you select it. Records stay on\n" +
			"this node and ship with the security rows; a repository gets a git note\n" +
			"(refs/notes/observer) or an Assisted-by trailer only on your per-repository consent.",
	}
	cmd.AddCommand(newProvenanceStatusCmd(), newProvenanceRecordsCmd(), newProvenanceConsentCmd(),
		newProvenanceRotateCmd(), newProvenanceTrailerCmd(), newProvenanceExportCmd())
	return cmd
}

// provenanceStatus is the status report (the dashboard card reads the same).
type provenanceStatus struct {
	Selected   bool                    `json:"selected"`
	Key        *provenanceKeyView      `json:"key,omitempty"`
	Records    store.ChangeRecordStats `json:"records"`
	Consents   []provenanceConsentView `json:"consents"`
	RetiredKey int                     `json:"retired_keys"`
}

type provenanceKeyView struct {
	ID          string `json:"id"`
	Storage     string `json:"storage"`
	Attestation string `json:"attestation"`
	CreatedAt   string `json:"created_at"`
	Rotation    string `json:"rotation"`
	// StorageReason is the named reason a file_key key is in the 0600 file
	// fallback (keystore.Reason*, "" when none was recorded), and
	// StorageDetail the same in plain words.
	StorageReason string `json:"storage_reason,omitempty"`
	StorageDetail string `json:"storage_detail,omitempty"`
}

type provenanceConsentView struct {
	Root    string `json:"root"`
	Notes   bool   `json:"notes"`
	Trailer bool   `json:"trailer"`
	GivenAt string `json:"given_at,omitempty"`
}

// readProvenanceStatus is the one status read. keyDir is the key fallback
// directory, where the named reason a file_key key is there is kept ("":
// not read).
func readProvenanceStatus(ctx context.Context, st *store.Store, keyDir string, selected bool, now time.Time) (provenanceStatus, error) {
	out := provenanceStatus{Selected: selected, Consents: []provenanceConsentView{}}
	keys, err := st.ChangeKeys(ctx)
	if err != nil {
		return out, err
	}
	for _, k := range keys {
		if k.RetiredAt != "" {
			out.RetiredKey++
			continue
		}
		if out.Key == nil {
			created, _ := time.Parse(time.RFC3339, k.CreatedAt)
			rot := secchange.RotationDue(secchange.KeyState{Exists: true, CreatedAt: created, Enrolment: k.Enrolment, CurrentEnrolment: k.Enrolment}, now)
			out.Key = &provenanceKeyView{ID: k.KeyID, Storage: k.Storage, Attestation: k.Attestation, CreatedAt: k.CreatedAt, Rotation: string(rot)}
			if k.Storage == secchange.StorageFileKey {
				if r := provenanceStorageReason(keyDir); r != "" {
					out.Key.StorageReason, out.Key.StorageDetail = r, keystore.FallbackDetail(r)
				}
			}
		}
	}
	if out.Records, err = st.ChangeRecordStatsNow(ctx); err != nil {
		return out, err
	}
	cs, err := st.ChangeConsents(ctx)
	if err != nil {
		return out, err
	}
	for _, c := range cs {
		if c.Notes || c.Trailer {
			out.Consents = append(out.Consents, provenanceConsentView{Root: c.RootPath, Notes: c.Notes, Trailer: c.Trailer, GivenAt: c.GivenAt})
		}
	}
	return out, nil
}

// provenanceKeysFile renders a keys file (secchange.TrustFile) with every
// key this node ever signed with, for `observer security verify --keys`.
// A retired key carries not_after = retired_at, so a record its seed signs
// after retirement fails verification; a key rotated by hand is also
// revoked, so every record it signed fails (audit finding F1: a person
// rotates a key they suspect).
func provenanceKeysFile(ctx context.Context, st *store.Store) (secchange.TrustFile, error) {
	keys, err := st.ChangeKeys(ctx)
	f := secchange.TrustFile{Version: secchange.TrustVersion, Keys: []secchange.TrustKey{}, Revoked: []secchange.Revocation{}}
	for _, k := range keys {
		tk := secchange.TrustKey{KeyID: k.KeyID, PublicKey: k.PublicKey}
		if k.RetiredAt != "" {
			tk.NotAfter = k.RetiredAt
			if k.RetireReason == provenanceRotatedByHand {
				f.Revoked = append(f.Revoked, secchange.Revocation{KeyID: k.KeyID, RevokedAt: k.RetiredAt, Reason: provenanceRotatedByHand})
			}
		}
		f.Keys = append(f.Keys, tk)
	}
	return f, err
}

// provenanceVerifyStored checks one stored record the way `observer
// security verify` checks a note, against this node's own keys file and
// the commit and tree the record was made for: "verified", or
// "verification_failed" with the closed code (decision log P-059: a record
// that is present and fails is shown as failed, never as unknown).
func provenanceVerifyStored(trust secchange.TrustSet, r store.ChangeRecordRow) (state, code string) {
	env, err := secchange.ParseEnvelope(r.Envelope)
	if err == nil {
		var v secchange.Verified
		if v, err = secchange.Verify(env, trust); err == nil {
			if c := secchange.BindingRefusal(v.Record.Binding, secchange.CommitFacts{SHA: r.CommitSHA, Tree: r.TreeSHA}); c != "" {
				return string(secchange.ProvenanceFailed), c
			}
			return string(secchange.ProvenanceVerified), ""
		}
	}
	return string(secchange.ProvenanceFailed), secchange.RefusalCode(err)
}

// provenanceRecordViews renders stored records with their verification.
func provenanceRecordViews(ctx context.Context, st *store.Store, recs []store.ChangeRecordRow) ([]provenanceRecordView, error) {
	out := make([]provenanceRecordView, 0, len(recs))
	f, err := provenanceKeysFile(ctx, st)
	if err != nil {
		return out, err
	}
	trust, err := secchange.NewTrustSet(f)
	if err != nil {
		return out, err
	}
	for _, r := range recs {
		v := provenanceRecordViewOf(r)
		v.Verification, v.VerificationReason = provenanceVerifyStored(trust, r)
		out = append(out, v)
	}
	return out, nil
}

func writeProvenanceStatus(w io.Writer, s provenanceStatus) {
	state := "off (select security.provenance to turn it on)"
	if s.Selected {
		state = "on"
	}
	fmt.Fprintf(w, "AI change records: %s\n", state)
	if s.Key != nil {
		fmt.Fprintf(w, "Signing key: %s (%s, %s), made %s, rotation: %s\n", s.Key.ID, s.Key.Storage, s.Key.Attestation, s.Key.CreatedAt, s.Key.Rotation)
		if s.Key.StorageReason != "" {
			fmt.Fprintf(w, "Key storage: the 0600 file fallback, because %s (%s)\n", s.Key.StorageDetail, s.Key.StorageReason)
		}
	} else {
		fmt.Fprintln(w, "Signing key: none (made when the daemon starts with the component selected)")
	}
	fmt.Fprintf(w, "Records: %d in %d projects, %d written as git notes", s.Records.Records, s.Records.Projects, s.Records.NotesWritten)
	if s.Records.Newest != "" {
		fmt.Fprintf(w, ", newest %s", s.Records.Newest)
	}
	fmt.Fprintln(w)
	if len(s.Consents) == 0 {
		fmt.Fprintln(w, "Repository writes: none (no repository has your consent)")
	}
	for _, c := range s.Consents {
		fmt.Fprintf(w, "Repository writes: %s notes=%v trailer=%v (consented %s)\n", c.Root, c.Notes, c.Trailer, c.GivenAt)
	}
	fmt.Fprintln(w, "Records are node-reported attribution: a signed claim by this device, never proof of authorship.")
}

func newProvenanceStatusCmd() *cobra.Command {
	var configPath string
	var asJSON, exportKeys bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the signing key, the record counts and the repositories with your consent",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			if exportKeys {
				f, err := provenanceKeysFile(cmd.Context(), st)
				if err != nil {
					return err
				}
				// The org's certificates for these keys and their org root
				// (a managed node, lane SEC-F2B).
				keys, _ := st.ChangeKeys(cmd.Context())
				provenanceAddCertificates(&f, provenanceKeyDir(cfg), keys)
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(f)
			}
			s, err := readProvenanceStatus(cmd.Context(), st, provenanceKeyDir(cfg), provenanceSelected(componentSnapshotFor(configPath)), time.Now())
			if err != nil {
				return err
			}
			if asJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(s)
			}
			writeProvenanceStatus(cmd.OutOrStdout(), s)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "config file path")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	cmd.Flags().BoolVar(&exportKeys, "export-keys", false, "print a keys file (every key this node signed with) for `observer security verify --keys`")
	return cmd
}

func newProvenanceRecordsCmd() *cobra.Command {
	var configPath, dir string
	var limit int
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "records",
		Short: "List the stored change records (newest first)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			hash := ""
			if dir != "" {
				root, err := provenanceResolveRoot(cmd.Context(), gitview.RunReadOnlyTimeout, dir)
				if err != nil {
					return err
				}
				hash = secposture.ProjectRootHash(root)
			}
			st := store.New(database)
			recs, err := st.ListChangeRecords(cmd.Context(), hash, limit)
			if err != nil {
				return err
			}
			views, err := provenanceRecordViews(cmd.Context(), st, recs)
			if err != nil {
				return err
			}
			if asJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(views)
			}
			for _, r := range views {
				note := ""
				if r.NoteWritten {
					note = ", git note written"
				}
				if r.Verification != string(secchange.ProvenanceVerified) {
					note += ", " + r.Verification + " (" + r.VerificationReason + ")"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s %s ai=%d human=%d unknown=%d (%s) sessions=%d key=%s%s\n",
					r.Commit[:12], r.CommittedAt, r.AILines, r.HumanLines, r.UnknownLines, r.HumanCapture, len(r.Sessions), r.KeyID, note)
			}
			if len(recs) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No change records.")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "config file path")
	cmd.Flags().StringVar(&dir, "dir", "", "only this repository")
	cmd.Flags().IntVar(&limit, "limit", 50, "at most this many")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

// provenanceRecordView is one record as the CLI and the dashboard show it.
type provenanceRecordView struct {
	Commit       string   `json:"commit"`
	CommittedAt  string   `json:"committed_at"`
	RecordedAt   string   `json:"recorded_at"`
	AILines      int64    `json:"ai_lines"`
	HumanLines   int64    `json:"human_lines"`
	UnknownLines int64    `json:"unknown_lines"`
	HumanCapture string   `json:"human_capture"`
	Sessions     []string `json:"sessions"`
	Models       []string `json:"models"`
	Agents       []string `json:"agents"`
	KeyID        string   `json:"key_id"`
	Digest       string   `json:"digest"`
	NoteWritten  bool     `json:"note_written"`
	// Verification is "verified" or "verification_failed" (decision log
	// P-059), checked against this node's own keys file; the reason is the
	// closed code of a failure.
	Verification       string `json:"verification"`
	VerificationReason string `json:"verification_reason,omitempty"`
}

func provenanceRecordViewOf(r store.ChangeRecordRow) provenanceRecordView {
	return provenanceRecordView{
		Commit: r.CommitSHA, CommittedAt: r.CommittedAt, RecordedAt: r.RecordedAt,
		AILines: r.AILines, HumanLines: r.HumanLines, UnknownLines: r.UnknownLines, HumanCapture: r.HumanCapture,
		Sessions: r.Sessions, Models: r.Models, Agents: r.Tools, KeyID: r.KeyID, Digest: r.RecordDigest,
		NoteWritten: r.NoteWrittenAt != "",
	}
}

// provenanceLayoutDir is the security layout directory for configPath.
func provenanceLayoutDir(configPath string) (string, error) {
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return "", err
	}
	return secposture.LayoutFor(resolved).Dir, nil
}

func newProvenanceConsentCmd() *cobra.Command {
	var configPath, dir string
	var notes, trailer, withdrawAll bool
	cmd := &cobra.Command{
		Use:   "consent --notes=<true|false> --trailer=<true|false> [--dir <repository>] | --withdraw-all",
		Short: "Give or withdraw your consent for the repository writers (git notes, the commit trailer)",
		Long: "Your per-repository consent for the two writers: --notes writes each record as a git note\n" +
			"under refs/notes/observer (a separate ref: history is never rewritten), --trailer adds an\n" +
			"`Assisted-by: AGENT:MODEL` trailer to the commits the agent itself makes, through a marked\n" +
			"block in the prepare-commit-msg hook. Both false withdraws consent and removes the block\n" +
			"byte-exactly. --withdraw-all does that for every repository with your consent (the\n" +
			"component's teardown step). A person's decision: an agent asking for it is refused\n" +
			"(guard R-165).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if withdrawAll {
				return provenanceWithdrawAllCmd(cmd, configPath)
			}
			if !cmd.Flags().Changed("notes") && !cmd.Flags().Changed("trailer") {
				return fmt.Errorf("name --notes and/or --trailer (true or false), or --withdraw-all")
			}
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			layoutDir, err := provenanceLayoutDir(configPath)
			if err != nil {
				return err
			}
			root, err := provenanceResolveRoot(cmd.Context(), gitview.RunReadOnlyTimeout, dir)
			if err != nil {
				return err
			}
			cur, err := st.ChangeConsentFor(cmd.Context(), secposture.ProjectRootHash(root))
			if err != nil {
				return err
			}
			if !cmd.Flags().Changed("notes") {
				notes = cur.Notes
			}
			if !cmd.Flags().Changed("trailer") {
				trailer = cur.Trailer
			}
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			if trailer && !cur.Trailer {
				// PR11: a repository write is shown before it is made (audit
				// finding F7).
				pv, err := provenanceTrailerPreview(cmd.Context(), gitview.RunReadOnlyTimeout, root, exe)
				if err != nil {
					return err
				}
				if pv.Refusal == "" && !pv.Installed {
					fmt.Fprintf(cmd.OutOrStdout(), "Writing this block into %s:\n\n%s\n", pv.HookPath, pv.Block)
				}
			}
			res, err := provenanceSetConsent(cmd.Context(), st, layoutDir, gitview.RunReadOnlyTimeout, root, notes, trailer, "cli",
				provenanceSelected(componentSnapshotFor(configPath)), exe)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s: git notes %v, commit trailer %v\n", res.Root, res.Notes, res.Trailer)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "config file path")
	cmd.Flags().StringVar(&dir, "dir", ".", "the repository")
	cmd.Flags().BoolVar(&notes, "notes", false, "write each change record as a git note under refs/notes/observer")
	cmd.Flags().BoolVar(&trailer, "trailer", false, "add an Assisted-by trailer to the agent's own commits")
	cmd.Flags().BoolVar(&withdrawAll, "withdraw-all", false, "withdraw consent in every repository and remove the trailer blocks byte-exactly (teardown)")
	return cmd
}

// provenanceWithdrawAllCmd is `consent --withdraw-all`, the component's
// teardown step (lane SEC-F2B).
func provenanceWithdrawAllCmd(cmd *cobra.Command, configPath string) error {
	_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
	if err != nil {
		return err
	}
	defer cleanup()
	layoutDir, err := provenanceLayoutDir(configPath)
	if err != nil {
		return err
	}
	res, failed, err := provenanceWithdrawAll(cmd.Context(), store.New(database), layoutDir, gitview.RunReadOnlyTimeout)
	for _, r := range res {
		fmt.Fprintf(cmd.OutOrStdout(), "%s: consent withdrawn, trailer block removed\n", r.Root)
	}
	for root, why := range failed {
		fmt.Fprintf(cmd.OutOrStdout(), "%s: not changed (%s)\n", root, why)
	}
	if len(res) == 0 && len(failed) == 0 && err == nil {
		fmt.Fprintln(cmd.OutOrStdout(), "No repository has your consent; nothing to remove.")
	}
	return err
}

// provenanceRotate retires the active key and makes the next one (the CLI
// and the dashboard's Rotate key).
func provenanceRotate(ctx context.Context, cfg config.Config, st *store.Store) (old, next string, err error) {
	svc := newProvenanceSvc(st, provenanceKeyDir(cfg), 0, nil)
	if old, err = svc.rotateKey(ctx); err != nil {
		return "", "", err
	}
	_, k, err := svc.signingKey(ctx)
	return old, k.KeyID, err
}

func newProvenanceRotateCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "rotate-key",
		Short: "Retire the signing key now and make a new one (keys also rotate every 90 days and on re-enrolment)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			snap := componentSnapshotFor(configPath)
			if !provenanceSelected(snap) {
				return errProvenanceOff
			}
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			old, next, err := provenanceRotate(cmd.Context(), cfg, store.New(database))
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Retired and revoked %q (its secret is deleted; records it signed now fail verification against a freshly exported keys file); new signing key %s.\n", old, next)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "config file path")
	return cmd
}

func newProvenanceTrailerCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:    "trailer <commit message file> [<source> [<sha>]]",
		Short:  "The prepare-commit-msg step: add the Assisted-by trailer to an agent's own commit",
		Hidden: true,
		Args:   cobra.RangeArgs(1, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage, cmd.SilenceErrors = true, true
			source := ""
			if len(args) > 1 {
				source = args[1]
			}
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return nil
			}
			defer cleanup()
			layoutDir, err := provenanceLayoutDir(configPath)
			if err != nil {
				return nil
			}
			msg, _ := filepath.Abs(args[0])
			reason, err := provenanceTrailerStep(cmd.Context(), store.New(database), layoutDir, gitview.RunReadOnlyTimeout,
				provenanceSelected(componentSnapshotFor(configPath)), msg, source, time.Now())
			if err != nil {
				reason = "error: " + err.Error()
			}
			fmt.Fprintln(cmd.OutOrStdout(), reason)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "config file path")
	return cmd
}

// provenanceDash binds the dashboard's AI change records card to the same
// functions the CLI runs (one consent seam). nil database: nothing to
// read.
func provenanceDash(configPath string, database *sql.DB) *dashapi.Provenance {
	if database == nil {
		return nil
	}
	st := store.New(database)
	selected := func() bool { return provenanceSelected(componentSnapshotFor(configPath)) }
	return &dashapi.Provenance{
		Status: func(ctx context.Context) (any, error) {
			return readProvenanceStatus(ctx, st, provenanceKeyDirFor(configPath), selected(), time.Now())
		},
		Records: func(ctx context.Context, root string, limit int) (any, error) {
			hash := ""
			if root != "" {
				hash = secposture.ProjectRootHash(root)
			}
			recs, err := st.ListChangeRecords(ctx, hash, limit)
			if err != nil {
				return []provenanceRecordView{}, err
			}
			return provenanceRecordViews(ctx, st, recs)
		},
		TrailerPreview: func(ctx context.Context, root string) (dashapi.ProvenanceHookPreview, error) {
			exe, err := os.Executable()
			if err != nil {
				return dashapi.ProvenanceHookPreview{}, err
			}
			return provenanceTrailerPreview(ctx, gitview.RunReadOnlyTimeout, root, exe)
		},
		Consent: func(ctx context.Context, root string, notes, trailer bool) (any, error) {
			layoutDir, err := provenanceLayoutDir(configPath)
			if err != nil {
				return nil, err
			}
			exe, err := os.Executable()
			if err != nil {
				return nil, err
			}
			return provenanceSetConsent(ctx, st, layoutDir, gitview.RunReadOnlyTimeout, root, notes, trailer, "dashboard", selected(), exe)
		},
		ConsentFor: func(ctx context.Context, root string) (bool, bool, error) {
			c, err := st.ChangeConsentFor(ctx, secposture.ProjectRootHash(root))
			return c.Notes, c.Trailer, err
		},
		RotateKey: func(ctx context.Context) (any, error) {
			if !selected() {
				return nil, errProvenanceOff
			}
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return nil, err
			}
			old, next, err := provenanceRotate(ctx, cfg, st)
			return map[string]string{"retired": old, "key_id": next}, err
		},
	}
}

// provenanceDoctorDetail is doctor's AI change records line (inside the
// `security` check): off, or on with the key's storage, the record count
// and the consented repositories. warn is set when the component is on but
// no key could be stored (no record is signed until one can).
func provenanceDoctorDetail(ctx context.Context, configPath string, st *store.Store) (line string, warn bool) {
	selected := provenanceSelected(componentSnapshotFor(configPath))
	if !selected {
		return "AI change records (security.provenance): off", false
	}
	s, err := readProvenanceStatus(ctx, st, provenanceKeyDirFor(configPath), true, time.Now())
	if err != nil {
		return "AI change records: state not readable: " + err.Error(), true
	}
	if s.Key == nil {
		return "AI change records: on, but no signing key is stored yet (the daemon makes it at start; with no keychain and no protected file fallback none can be made)", true
	}
	line = fmt.Sprintf("AI change records: on, key %s (%s, rotation %s), %d record(s), %d repository(ies) with your consent",
		s.Key.ID[:12], s.Key.Storage, s.Key.Rotation, s.Records.Records, len(s.Consents))
	if s.Key.StorageReason != "" {
		line += "; key in the 0600 file fallback because " + s.Key.StorageDetail + " (" + s.Key.StorageReason + ")"
	}
	return line, false
}

// provenanceKeyDirFor is provenanceKeyDir for a config path ("" when the
// config cannot be read: the storage reason is then not shown).
func provenanceKeyDirFor(configPath string) string {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return ""
	}
	return provenanceKeyDir(cfg)
}
