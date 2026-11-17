package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// newStaffCmd is the staff console's command group (managed-SaaS M6.8;
// rulings A2 and A3 of 2026-11-13): the separate staff process (`serve`,
// staffserve.go) and the operator's passkey management, which is the ONLY
// way a staff credential comes to exist or is recovered (design m6.0 4.9:
// "staff_enrolments ... minted only by observer-cloud staff enrol run by the
// operator (no web path creates the first credential)").
//
// The operator commands connect with the staff login (SBCI_STAFF_PG_DSN)
// when it is set, else the admin SBCI_PG_DSN (dev: a superuser), run as
// sbci_staff (store.WithStaff), and add no SQL of their own.
//
// Passkey policy: a staff member may hold several passkeys (register at
// least two, a primary and a backup, each with its own code from `enrol
// --staff-id`). A lost or compromised one is revoked with
// `revoke-credential`, which also ends every session it signed in; the
// replacement is registered with a fresh code.
func newStaffCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "staff",
		Short: "the staff console: its process and the operator's passkey management",
	}
	cmd.AddCommand(newStaffServeCmd(), newStaffEnrolCmd(), newStaffCredentialsCmd(), newStaffRevokeCredentialCmd(),
		newStaffTeamAllowlistCmd())
	return cmd
}

// openOperatorStaffStore opens the store the operator's staff commands use.
func openOperatorStaffStore(ctx context.Context) (*store.Store, error) {
	dsn, err := staffStoreDSN()
	if err != nil {
		return nil, err
	}
	return openStaffStore(ctx, dsn)
}

func newStaffCredentialsCmd() *cobra.Command {
	var staffID string
	cmd := &cobra.Command{
		Use:   "credentials",
		Short: "list a staff member's passkeys (public halves only)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(staffID) == "" {
				return fmt.Errorf("--staff-id is required")
			}
			ctx := cmd.Context()
			s, err := openOperatorStaffStore(ctx)
			if err != nil {
				return err
			}
			defer s.Pool().Close()
			return runStaffCredentials(ctx, s, strings.TrimSpace(staffID), cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&staffID, "staff-id", "", "the staff member")
	return cmd
}

// staffCredentialLister is the store method runStaffCredentials needs.
type staffCredentialLister interface {
	ListStaffCredentials(ctx context.Context, staffID string) ([]store.StaffCredential, error)
}

// runStaffCredentials prints one line per passkey: id (hex), state, label,
// created and last-used times, and how many remain active.
func runStaffCredentials(ctx context.Context, s staffCredentialLister, staffID string, out io.Writer) error {
	creds, err := s.ListStaffCredentials(ctx, staffID)
	if err != nil {
		return err
	}
	active := 0
	for _, c := range creds {
		state := "active"
		if !c.Active() {
			state = "revoked " + c.RevokedAt.UTC().Format(time.RFC3339)
		} else {
			active++
		}
		used := "never used"
		if c.LastUsedAt != nil {
			used = "last used " + c.LastUsedAt.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(out, "%s  %s  label=%q  created %s  %s\n", hex.EncodeToString(c.ID), state, c.Label, c.CreatedAt.UTC().Format(time.RFC3339), used)
	}
	fmt.Fprintf(out, "observer-cloud: %d active passkey(s) for staff member %s", active, staffID)
	if active < 2 {
		fmt.Fprint(out, " (register a backup: `observer-cloud staff enrol --staff-id "+staffID+"`)")
	}
	fmt.Fprintln(out)
	return nil
}

// staffRevokeFlags are the revoke-credential command's inputs.
type staffRevokeFlags struct {
	staffID    string
	credential string
	reason     string
}

func newStaffRevokeCredentialCmd() *cobra.Command {
	var f staffRevokeFlags
	cmd := &cobra.Command{
		Use:   "revoke-credential",
		Short: "revoke a staff passkey and end every session it signed in (recovery)",
		Long: "Revoke one passkey of a staff member (lost, stolen or retired), ending every\n" +
			"session it signed in. This is the staff console's only recovery path: register\n" +
			"the replacement with a fresh code from `observer-cloud staff enrol --staff-id`.\n" +
			"The credential id is the hex `observer-cloud staff credentials` prints.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			s, err := openOperatorStaffStore(ctx)
			if err != nil {
				return err
			}
			defer s.Pool().Close()
			return runStaffRevoke(ctx, s, f, time.Now(), cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&f.staffID, "staff-id", "", "the staff member")
	cmd.Flags().StringVar(&f.credential, "credential", "", "the credential id, hex")
	cmd.Flags().StringVar(&f.reason, "reason", "", "why (required; written to the staff action log)")
	return cmd
}

// staffCredentialRevoker is the store method runStaffRevoke needs.
type staffCredentialRevoker interface {
	RevokeStaffCredential(ctx context.Context, staffID string, credentialID []byte, reason string, now time.Time) error
}

// runStaffRevoke validates the flags and revokes.
func runStaffRevoke(ctx context.Context, s staffCredentialRevoker, f staffRevokeFlags, now time.Time, out io.Writer) error {
	staffID := strings.TrimSpace(f.staffID)
	if staffID == "" {
		return fmt.Errorf("--staff-id is required")
	}
	id, err := hex.DecodeString(strings.TrimSpace(f.credential))
	if err != nil || len(id) == 0 {
		return fmt.Errorf("--credential must be the credential id in hex")
	}
	if _, err := staffauth.ValidateReason(f.reason); err != nil {
		return fmt.Errorf("--reason: %w", err)
	}
	if err := s.RevokeStaffCredential(ctx, staffID, id, f.reason, now); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("staff member %s holds no active passkey %s", staffID, strings.TrimSpace(f.credential))
		}
		return err
	}
	fmt.Fprintf(out, "observer-cloud: passkey %s of staff member %s revoked; its sessions are ended\n", strings.TrimSpace(f.credential), staffID)
	return nil
}

// staffEnrolFlags are the enrol command's inputs.
type staffEnrolFlags struct {
	displayName string
	role        string
	staffID     string
	reason      string
	ttl         time.Duration
}

func newStaffEnrolCmd() *cobra.Command {
	var f staffEnrolFlags
	cmd := &cobra.Command{
		Use:   "enrol",
		Short: "create a staff member (or pick one) and print a one-time enrolment code",
		Long: "Create a staff console member, or with --staff-id issue a fresh code to an\n" +
			"existing one, and print a ONE-TIME enrolment code. The code is printed once\n" +
			"and stored only as a hash. The staff member registers a passkey with it at\n" +
			"POST /staff/auth/webauthn/register/begin; the code then cannot be used again,\n" +
			"and it expires after --ttl (default 30m, at most 1h) if unused.\n\n" +
			"Staff members are keyed by a staff id, never by an email address.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			s, err := openOperatorStaffStore(ctx)
			if err != nil {
				return err
			}
			defer s.Pool().Close()
			return runStaffEnrol(ctx, s, f, time.Now(), cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&f.displayName, "display-name", "", "the new staff member's display name (not an email)")
	cmd.Flags().StringVar(&f.role, "role", "", "the new staff member's role: support, ops or admin")
	cmd.Flags().StringVar(&f.staffID, "staff-id", "", "issue a code to this existing staff member instead of creating one")
	cmd.Flags().StringVar(&f.reason, "reason", "", "why (required; written to the staff action log)")
	cmd.Flags().DurationVar(&f.ttl, "ttl", store.DefaultStaffEnrolmentTTL, "how long the code stays valid (at most 1h)")
	return cmd
}

// staffEnroller is the store method runStaffEnrol needs.
type staffEnroller interface {
	EnrolStaff(ctx context.Context, in store.EnrolStaffInput) (store.StaffEnrolment, error)
}

// runStaffEnrol validates the flags, enrols, and prints the code once.
func runStaffEnrol(ctx context.Context, s staffEnroller, f staffEnrolFlags, now time.Time, out io.Writer) error {
	in := store.EnrolStaffInput{
		StaffID: strings.TrimSpace(f.staffID), DisplayName: strings.TrimSpace(f.displayName),
		TTL: f.ttl, Reason: f.reason, Now: now,
	}
	if in.StaffID == "" {
		if in.DisplayName == "" {
			return fmt.Errorf("--display-name is required (or --staff-id for an existing staff member)")
		}
		role, err := staffauth.ParseRole(strings.TrimSpace(f.role))
		if err != nil {
			return fmt.Errorf("--role: %w", err)
		}
		in.Role = role
	} else if in.DisplayName != "" || f.role != "" {
		return fmt.Errorf("--staff-id excludes --display-name and --role")
	}
	if _, err := staffauth.ValidateReason(f.reason); err != nil {
		return fmt.Errorf("--reason: %w", err)
	}
	res, err := s.EnrolStaff(ctx, in)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "observer-cloud: staff member %s (%s, role %s)\n", res.Staff.StaffID, res.Staff.DisplayName, res.Staff.Role)
	fmt.Fprintf(out, "  one-time enrolment code (shown once, expires %s):\n", res.ExpiresAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(out, "  %s\n", res.RawCode)
	return nil
}
