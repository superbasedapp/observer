package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/signerd"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// signer_document_floor.go is `observer-cloud signer document raise-floor`
// (managed-SaaS plan 07 wave 16 lane control-plane; lead decision W16-D6;
// docs/security.md CPSIGN-6; runbook
// docs/saas-platform-control-plane-runbook.md section 7, step 3).
//
// After the database is restored to a point before the document signer's
// version record, the worker would ask the signer for versions it already
// signed, the signer would refuse them, and those streams would stall. This
// verb reads a copy of the record (the export the backup takes, never the
// live file), and for every (kind, scope) whose record version is above
// both the database's stored maximum and its current floor it appends a
// floor row (cloud 0097). The worker then asks for
// max(latest stored version, floor) + 1, and the store refuses a version at
// or below the floor.
//
// Dry run by default; --apply writes. It never touches the record: it
// raises the database, never the record. A floor never lowers, and a second
// run with the same record changes nothing. Every applied row names the
// operator (--operator) and the sha256 of the record file. It runs with the
// admin DSN (SBCI_PG_DSN, the sbci_app role), like the other operator verbs;
// there is no HTTP route.

// maxRecordFile bounds the record read (the signer's own bound).
const maxRecordFile = 64 << 20

// floorStore is the operator store's floor seam (*store.Store, sbci_app).
type floorStore interface {
	RaiseDocumentFloors(ctx context.Context, in store.RaiseDocumentFloorsInput, now time.Time) ([]store.DocumentFloorResult, error)
	DocumentFloorHistory(ctx context.Context) ([]store.DocumentFloorRow, error)
}

// raiseFloorRequest is one raise-floor invocation.
type raiseFloorRequest struct {
	RecordPath string
	Operator   string
	Apply      bool
}

// readRecord reads the record file and returns its entries and the sha256
// of its bytes.
func readRecord(path string, readFile func(string) ([]byte, error)) ([]store.DocumentFloorEntry, string, error) {
	raw, err := readFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read the record: %w", err)
	}
	if len(raw) > maxRecordFile {
		return nil, "", fmt.Errorf("the record %s is over %d bytes", path, maxRecordFile)
	}
	entries, err := signerd.DecodeVersionRecord(raw)
	if err != nil {
		return nil, "", fmt.Errorf("the record %s is not a document signer version record: %w", path, err)
	}
	sum := sha256.Sum256(raw)
	out := make([]store.DocumentFloorEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, store.DocumentFloorEntry{Kind: e.Kind, Scope: e.Scope, Version: e.Version})
	}
	return out, hex.EncodeToString(sum[:]), nil
}

// runRaiseFloor reads the record, decides every entry against the database
// and, with Apply, appends the floors. It prints one line per entry and a
// summary; "no change" when nothing is (or would be) raised.
func runRaiseFloor(ctx context.Context, out io.Writer, s floorStore, req raiseFloorRequest, readFile func(string) ([]byte, error), now time.Time) error {
	if strings.TrimSpace(req.RecordPath) == "" {
		return errors.New("--record is required (a copy of the signer's versions.json, e.g. the decrypted backup export)")
	}
	if strings.TrimSpace(req.Operator) == "" {
		return errors.New("--operator is required (who runs this; kept with every floor row)")
	}
	entries, digest, err := readRecord(req.RecordPath, readFile)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Fprintf(out, "observer-cloud: the record %s (sha256 %s) has no entries: no change\n", req.RecordPath, digest)
		return nil
	}
	res, err := s.RaiseDocumentFloors(ctx, store.RaiseDocumentFloorsInput{
		Entries: entries, RecordSHA256: digest, Operator: strings.TrimSpace(req.Operator), Apply: req.Apply,
	}, now)
	if err != nil {
		return err
	}
	mode := "dry run"
	if req.Apply {
		mode = "applied"
	}
	fmt.Fprintf(out, "observer-cloud: %s against record %s (sha256 %s), %d entries\n", mode, req.RecordPath, digest, len(entries))
	raised := 0
	for _, r := range res {
		if r.Action == store.FloorRaise {
			raised++
		}
		fmt.Fprintf(out, "  %s %s: record v%d, database v%d, floor v%d: %s\n",
			r.Entry.Kind, r.Entry.Scope, r.Entry.Version, r.Stored, r.Floor, floorActionText(r.Action, req.Apply))
	}
	switch {
	case raised == 0:
		fmt.Fprintln(out, "observer-cloud: no change: the database is at or past the record for every entry")
	case req.Apply:
		fmt.Fprintf(out, "observer-cloud: %d floors raised; the worker asks for floor + 1 at its next pass\n", raised)
	default:
		fmt.Fprintf(out, "observer-cloud: %d floors would be raised; run again with --apply to write them\n", raised)
	}
	return nil
}

// floorActionText words one action.
func floorActionText(a store.FloorAction, apply bool) string {
	switch a {
	case store.FloorRaise:
		if apply {
			return "raised to the record"
		}
		return "would raise to the record"
	case store.FloorDatabaseAhead:
		return "no change (the database is at or past the record)"
	case store.FloorAlreadyRaised:
		return "no change (a floor at or past the record is in force)"
	default:
		return string(a)
	}
}

// runFloorHistory prints every floor row, newest first.
func runFloorHistory(ctx context.Context, out io.Writer, s floorStore) error {
	rows, err := s.DocumentFloorHistory(ctx)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Fprintln(out, "observer-cloud: no version floor was ever raised")
		return nil
	}
	for _, r := range rows {
		fmt.Fprintf(out, "  %s  %s %s floor v%d  by %s  record sha256 %s\n",
			r.At.UTC().Format(time.RFC3339), r.Kind, r.Scope, r.FloorVersion, r.Operator, r.RecordSHA256)
	}
	return nil
}

// newSignerDocumentRaiseFloorCmd is `signer document raise-floor` and its
// history verb.
func newSignerDocumentRaiseFloorCmd() *cobra.Command {
	var req raiseFloorRequest
	cmd := &cobra.Command{
		Use:   "raise-floor",
		Short: "raise the database's document versions past a signer record after a restore (dry run by default)",
		Long: "After a database restore to a point before the document signer's version\n" +
			"record, raise each stream's version floor to the record so the worker asks\n" +
			"for a version the signer has not signed (lead decision W16-D6; runbook\n" +
			"section 7, step 3).\n\n" +
			"--record is a copy of versions.json (the decrypted backup export), never the\n" +
			"live file; it is only read. Dry run by default; --apply appends the floor\n" +
			"rows, each naming --operator and the record's sha256. A floor never lowers\n" +
			"and a repeated run changes nothing. Runs with the admin DSN (SBCI_PG_DSN).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer s.Pool().Close()
			return runRaiseFloor(cmd.Context(), cmd.OutOrStdout(), s, req, os.ReadFile, time.Now())
		},
	}
	cmd.Flags().StringVar(&req.RecordPath, "record", "", "a copy of the signer's versions.json (required)")
	cmd.Flags().StringVar(&req.Operator, "operator", "", "who runs this, 1 to 64 of [A-Za-z0-9._@-] (required)")
	cmd.Flags().BoolVar(&req.Apply, "apply", false, "write the floor rows (default: dry run)")

	history := &cobra.Command{
		Use:   "history",
		Short: "print every raised floor, newest first",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer s.Pool().Close()
			return runFloorHistory(cmd.Context(), cmd.OutOrStdout(), s)
		},
	}
	cmd.AddCommand(history)
	return cmd
}
