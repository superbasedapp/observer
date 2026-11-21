//go:build !sbo_omit_terminals_sandbox_openshell_org && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	osorg "github.com/marmutapp/superbased-observer/internal/openshellorg"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/openshellorg"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// sandbox_orgshell_login.go is the node's sign-in to the org-hosted
// OpenShell gateway (tracker F-019, g1-design.md sections 3.5, 3.7, 5.3 to
// 5.5, lane G4): `observer sandbox org-shell login | logout | status | check |
// opt-in | opt-out`, the grant handle's custody, and the refreshable run-token
// source the host helper hands the wire client.
//
// Custody (section 5.3): the grant handle is stored only in the OS keystore
// under orgShellGrantService (the keystore's owner-only file fallback on a
// host with no keychain), bound to the org origin, the org and the member it
// was issued for. Beside it, a marker file holds only the binding and the
// expiry (no secret), so the probe's local row R3 never opens the keychain.
// Run tokens live in the host helper's memory only. No handle, token or
// device code is ever in an argv, an environment, a log line or an error.

// orgShellGrantService is the keystore service of the grant handle (the
// registry row's KeystoreServices; `observer uninstall --all` removes it).
const orgShellGrantService = "sbo-openshell-org-grant-v1"

// orgShellGrantName is the keystore record name.
const orgShellGrantName = "grant"

func init() {
	sandboxSubcommands = append(sandboxSubcommands, newOrgShellCmd)
	orgclient.SetOpenShellNodeMessage(osorg.NodeMessage)
	orgclient.AdvertiseManagedPullCapability("sandbox", orgcontract.SandboxCapabilityOrgOpenShell)
}

// orgShellDir is the row's node-local state directory (no secret in it).
func orgShellDir(observerDir string) string {
	return hostedProviderDir(observerDir, sandboxremote.VendorOpenShellOrg)
}

// orgShellGrantRecord is the keystore value.
type orgShellGrantRecord struct {
	Version   int       `json:"version"`
	OrgURL    string    `json:"org_url"`
	OrgID     string    `json:"org_id"`
	UserID    string    `json:"user_id"`
	Handle    string    `json:"handle"`
	ExpiresAt time.Time `json:"expires_at"`
}

// String names the record without its handle.
func (g orgShellGrantRecord) String() string {
	return "grant(" + g.OrgURL + ", " + g.UserID + ", expires " + g.ExpiresAt.UTC().Format(time.RFC3339) + ")"
}

// GoString is String.
func (g orgShellGrantRecord) GoString() string { return g.String() }

// orgShellSignIn is the marker: the binding and the expiry, no handle.
type orgShellSignIn struct {
	OrgURL    string    `json:"org_url"`
	OrgID     string    `json:"org_id"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	// SignedInAt is when this sign-in was saved: a sign-in refusal the
	// node saw after it supersedes it on the status (FX3 item 12).
	SignedInAt time.Time `json:"signed_in_at,omitempty"`
}

func orgShellSignInPath(observerDir string) string {
	return filepath.Join(orgShellDir(observerDir), "signin.json")
}

// orgShellKeystoreOpen opens the grant keystore (a variable so tests never
// touch the OS keychain).
var orgShellKeystoreOpen = func(observerDir string) keystore.Store {
	return keystore.Open(orgShellGrantService, filepath.Join(orgShellDir(observerDir), "cred"), slog.Default())
}

// orgShellSaveGrant stores the handle and writes the marker.
func orgShellSaveGrant(observerDir string, enr *store.Enrolment, g orgclient.OpenShellGrant) error {
	rec := orgShellGrantRecord{Version: 1, OrgURL: enr.OrgServerURL, OrgID: enr.OrgID, UserID: enr.UserID, Handle: g.GrantHandle, ExpiresAt: g.ExpiresAt}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := orgShellKeystoreOpen(observerDir).Set(orgShellGrantName, string(b)); err != nil {
		return fmt.Errorf("store the sign-in grant in the keystore: %w", err)
	}
	return hostedWithState(observerDir, true, func() error {
		return hostedWriteOwned(orgShellSignInPath(observerDir), orgShellSignIn{OrgURL: rec.OrgURL, OrgID: rec.OrgID, UserID: rec.UserID, ExpiresAt: rec.ExpiresAt, SignedInAt: time.Now().UTC()})
	})
}

// errOrgShellSignIn is the closed "sign in first" refusal.
var errOrgShellSignIn = errors.New("org_signin_required: sign in to your organization's sandboxes with `observer sandbox org-shell login`")

// orgShellLoadGrant reads the handle, refusing one bound to another org,
// member or origin, or past its recorded expiry.
func orgShellLoadGrant(observerDir string, enr *store.Enrolment, now time.Time) (orgShellGrantRecord, error) {
	raw, err := orgShellKeystoreOpen(observerDir).Get(orgShellGrantName)
	if errors.Is(err, keystore.ErrNotFound) {
		return orgShellGrantRecord{}, errOrgShellSignIn
	}
	if err != nil {
		return orgShellGrantRecord{}, fmt.Errorf("read the sign-in grant from the keystore: %w", err)
	}
	var rec orgShellGrantRecord
	if json.Unmarshal([]byte(raw), &rec) != nil || rec.Version != 1 || rec.Handle == "" {
		return orgShellGrantRecord{}, errOrgShellSignIn
	}
	if enr == nil || rec.OrgURL != enr.OrgServerURL || rec.OrgID != enr.OrgID || rec.UserID != enr.UserID {
		return orgShellGrantRecord{}, errOrgShellSignIn
	}
	if !rec.ExpiresAt.After(now) {
		return orgShellGrantRecord{}, errors.New("org_signin_expired: your sign-in to your organization's sandboxes has expired; run `observer sandbox org-shell login` again")
	}
	return rec, nil
}

// orgShellForgetGrant removes the handle and the marker.
func orgShellForgetGrant(observerDir string) error {
	err := orgShellKeystoreOpen(observerDir).Delete(orgShellGrantName)
	_ = hostedWithState(observerDir, false, func() error {
		if rerr := os.Remove(orgShellSignInPath(observerDir)); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			return rerr
		}
		return nil
	})
	return err
}

// orgShellLoadSignIn reads the marker (nil when none).
func orgShellLoadSignIn(observerDir string) *orgShellSignIn {
	var out *orgShellSignIn
	_ = hostedWithState(observerDir, false, func() error {
		b, err := hostedReadOwned(orgShellSignInPath(observerDir))
		if err != nil {
			return nil
		}
		var s orgShellSignIn
		if json.Unmarshal(b, &s) == nil {
			out = &s
		}
		return nil
	})
	return out
}

// ---- the org client in a CLI or helper process -------------------------------

// orgShellOrgClient opens the node's org client and its enrolment (the
// caller closes it).
var orgShellOrgClient = func(ctx context.Context) (*orgclient.Client, *store.Enrolment, config.Config, func(), error) {
	cfg, database, closeDB, err := loadConfigAndDB(ctx, daemonConfigPath())
	if err != nil {
		return nil, nil, config.Config{}, func() {}, err
	}
	st := store.New(database)
	enr, err := st.LoadEnrolment(ctx)
	if err != nil {
		closeDB()
		return nil, nil, config.Config{}, func() {}, err
	}
	if enr == nil {
		closeDB()
		return nil, nil, config.Config{}, func() {}, errors.New("node_not_managed: this machine is not enrolled with an organization")
	}
	bs := orgclient.OpenBearerStore(cfg.OrgClient.KeychainID, filepath.Dir(cfg.Observer.DBPath), slog.Default())
	return orgclient.New(cfg.OrgClient, st, bs, version, nil, nil), enr, cfg, closeDB, nil
}

// ---- the run-token source ---------------------------------------------------

// orgShellTokens is the run's refreshable token source (design 5.4): it
// mints a token for the purpose a call names (the call's context), reuses
// one until 60 s before its expiry, and holds every token in memory only. It
// implements sandboxremote.CredentialSource and names the box for the wire
// client.
type orgShellTokens struct {
	mint  func(ctx context.Context, req orgclient.OpenShellMintRequest) (orgclient.OpenShellMint, error)
	base  orgclient.OpenShellMintRequest
	now   func() time.Time
	mu    sync.Mutex
	cache map[string]orgclient.OpenShellMint
	first orgclient.OpenShellMint
}

// orgShellTokenSlack is how long before its expiry a token is minted again.
const orgShellTokenSlack = 60 * time.Second

// Token returns a token for the call's purpose (attach when none).
func (s *orgShellTokens) Token(ctx context.Context) (string, error) {
	p := sandboxremote.TokenPurpose(ctx)
	if p == "" {
		p = string(osorg.PurposeAttach)
	}
	m, err := s.tokenFor(ctx, p)
	return m.Token, err
}

func (s *orgShellTokens) tokenFor(ctx context.Context, purpose string) (orgclient.OpenShellMint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := s.cache[purpose]; ok && m.ExpiresAt.Sub(s.now()) > orgShellTokenSlack {
		return m, nil
	}
	req := s.base
	req.Purpose = purpose
	if purpose != string(osorg.PurposeResume) {
		req.BoxRunID = ""
	}
	m, err := s.mint(ctx, req)
	if err != nil {
		return orgclient.OpenShellMint{}, err
	}
	if s.cache == nil {
		s.cache = map[string]orgclient.OpenShellMint{}
	}
	s.cache[purpose] = m
	return m, nil
}

// BoxName is the box the org named at the first mint.
func (s *orgShellTokens) BoxName() string { return s.first.BoxName }

// RunID is the node's run id.
func (s *orgShellTokens) RunID() string { return s.base.RunID }

// First is the first mint's answer (the run's recorded facts).
func (s *orgShellTokens) First() orgclient.OpenShellMint { return s.first }

// String names the source without any token.
func (s *orgShellTokens) String() string { return "org-shell tokens(" + s.base.RunID + ")" }

// newOrgShellTokens mints the first token (create, or resume for a resume
// launch) and returns the source.
func newOrgShellTokens(ctx context.Context, mint func(context.Context, orgclient.OpenShellMintRequest) (orgclient.OpenShellMint, error), base orgclient.OpenShellMintRequest, firstPurpose string, now func() time.Time) (*orgShellTokens, error) {
	s := &orgShellTokens{mint: mint, base: base, now: now}
	m, err := s.tokenFor(ctx, firstPurpose)
	if err != nil {
		return nil, err
	}
	if m.BoxName == "" {
		return nil, errors.New("the organization's mint named no box")
	}
	s.first = m
	return s, nil
}

// ---- the CLI ----------------------------------------------------------------

// orgShellDisclosure is the laptop-relay opt-in disclosure (design 3.7),
// shown verbatim by the CLI and the Settings card.
const orgShellDisclosure = "Model requests and hook events from your org sandbox runs will travel through this laptop, which must stay online for the run. The code and files the agent reads are part of those requests. If this laptop goes offline, the run is held (if your organization allows holding) and you can resume it later from any of your managed machines."

func newOrgShellCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "org-shell",
		Short: "Your organization's hosted OpenShell sandboxes: sign in, check, opt in, and held runs",
	}
	cmd.AddCommand(newOrgShellLoginCmd(), newOrgShellLogoutCmd(), newOrgShellStatusCmd(), newOrgShellCheckCmd(),
		newOrgShellOptCmd("opt-in", true), newOrgShellOptCmd("opt-out", false))
	for _, sub := range orgShellHoldSubcommands {
		cmd.AddCommand(sub())
	}
	return cmd
}

// orgShellHoldSubcommands are the held-state verbs (sandbox_orgshell_hold.go).
var orgShellHoldSubcommands []func() *cobra.Command

func newOrgShellLoginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Approve this machine for your organization's sandboxes (once per machine; opens a code to type in the dashboard)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			c, enr, cfg, done, err := orgShellOrgClient(ctx)
			if err != nil {
				return err
			}
			defer done()
			return orgShellLogin(ctx, c, enr, filepath.Dir(cfg.Observer.DBPath), cmd.OutOrStdout(), time.Sleep)
		},
	}
}

// orgShellLogin runs the device approval: print the page and the code, poll
// until the grant, store it.
func orgShellLogin(ctx context.Context, c *orgclient.Client, enr *store.Enrolment, observerDir string, out io.Writer, sleep func(time.Duration)) error {
	l, err := c.OpenShellLoginStart(ctx, "")
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Open %s in your browser, sign in to your organization's dashboard, and type this code: %s\n", l.VerificationURI, l.UserCode)
	fmt.Fprintf(out, "Waiting for the approval (the code expires in %d minutes) ...\n", max(l.ExpiresIn/60, 1))
	interval := time.Duration(max(l.Interval, 2)) * time.Second
	deadline := time.Now().Add(time.Duration(max(l.ExpiresIn, 60)) * time.Second)
	for time.Now().Before(deadline) {
		g, err := c.OpenShellLoginPoll(ctx, l.DeviceCode)
		var ref *orgclient.OpenShellRefusal
		switch {
		case err == nil:
			if err := orgShellSaveGrant(observerDir, enr, g); err != nil {
				return err
			}
			fmt.Fprintf(out, "Signed in: this machine may start sandboxes on your organization's compute as you until %s.\n", g.ExpiresAt.Local().Format(time.RFC1123))
			return nil
		case errors.As(err, &ref) && ref.Reason == string(osorg.ReasonDeviceCodePending):
		default:
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		sleep(interval)
	}
	return errors.New("device_code_expired: the approval code expired; run `observer sandbox org-shell login` again")
}

func newOrgShellLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Sign this machine out of your organization's sandboxes (live runs end at their next token; held runs stay held)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			c, enr, cfg, done, err := orgShellOrgClient(ctx)
			if err != nil {
				return err
			}
			defer done()
			dir := filepath.Dir(cfg.Observer.DBPath)
			rec, gerr := orgShellLoadGrant(dir, enr, time.Now())
			var serr error
			if gerr == nil {
				serr = c.OpenShellLogout(ctx, rec.Handle)
			}
			if err := orgShellForgetGrant(dir); err != nil {
				return err
			}
			if serr != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Signed out here; the organization could not be told (%v): the grant expires by itself.\n", serr)
				return nil
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Signed out.")
			return nil
		},
	}
}

func newOrgShellStatusCmd() *cobra.Command {
	var offline bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show whether your organization offers hosted sandboxes here, your sign-in (confirmed with your organization), the opt-in and the last check",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _, done, err := loadConfigAndDBNoCreate(cmd.Context(), daemonConfigPath())
			if err != nil {
				return err
			}
			eff := cliOrgShellEffective(cmd.Context(), cfg)
			dir := filepath.Dir(cfg.Observer.DBPath)
			done()
			probe := orgShellStatusProbe
			if offline {
				probe = nil
			}
			fmt.Fprint(cmd.OutOrStdout(), orgShellStatus(cmd.Context(), eff, dir, time.Now(), probe))
			return nil
		},
	}
	cmd.Flags().BoolVar(&offline, "offline", false, "do not ask the organization; show this machine's own record of the sign-in")
	return cmd
}

// orgShellStatusProbeTimeout bounds the status's sign-in check.
const orgShellStatusProbeTimeout = 10 * time.Second

// orgShellStatusProbe asks the organization whether this machine's sign-in
// still stands: one probe-purpose mint (no box, no ledger write; the
// check's row R4). It answers the mint's error (a refusal, or the
// organization not answering). A variable for tests.
var orgShellStatusProbe = func(ctx context.Context) error {
	c, enr, cfg, done, err := orgShellOrgClient(ctx)
	if err != nil {
		return err
	}
	defer done()
	now := time.Now()
	rec, err := orgShellLoadGrant(filepath.Dir(cfg.Observer.DBPath), enr, now)
	if err != nil {
		return err
	}
	_, err = c.OpenShellMintToken(ctx, orgclient.OpenShellMintRequest{
		GrantHandle: rec.Handle, RunID: "probe-" + osorgRunIDNow(now), Purpose: string(osorg.PurposeProbe),
		LaptopRelay: cfg.Terminal.Sandbox.Hosted.OpenShellOrg.LaptopRelay,
	})
	return err
}

// orgShellStatus is the status: when this machine holds an unexpired
// sign-in and probe is set, it first asks the organization (FX4 fix round
// 1, F-L4P5-6: FX3's status said "signed in" after an admin revoke or a
// drain until a launch from this machine happened to be refused, because it
// only read a refusal a launch had cached, and a drain's refusal was not
// counted as one). A sign-in refusal is cached as the last check, as a
// launch's is; an organization that does not answer leaves this machine's
// own record, and the status says it was not confirmed.
func orgShellStatus(ctx context.Context, o config.TerminalSandboxHostedOrgShellConfig, observerDir string, now time.Time, probe func(context.Context) error) string {
	unconfirmed := ""
	if s := orgShellLoadSignIn(observerDir); probe != nil && o.Published.Offered && s != nil && s.ExpiresAt.After(now) {
		pctx, cancel := context.WithTimeout(ctx, orgShellStatusProbeTimeout)
		err := probe(pctx)
		cancel()
		var ref *orgclient.OpenShellRefusal
		switch {
		case err == nil:
			// Accepted now: an older refusal cached after this sign-in
			// (a member re-allowed, a drain reopened) no longer stands.
			if last := orgShellLoadCheck(observerDir); last != nil && orgShellSignInRefused(last.Verdict) {
				orgShellSaveCheck(observerDir, orgShellCheck{At: now, Verdict: "ok", Reason: "the organization accepted the sign-in when the status asked"})
			}
		case errors.As(err, &ref) && orgShellSignInRefused(ref.Reason):
			orgShellSaveCheck(observerDir, orgShellCheck{At: now, Verdict: ref.Reason, Reason: "the organization refused the sign-in when the status asked"})
		case errors.As(err, &ref):
			// The organization answered with a refusal that is not the
			// sign-in's (a quota, say): the sign-in stands.
		default:
			unconfirmed = "sign-in not confirmed now: the organization did not answer (" + sandboxremote.Redact(err.Error(), nil) + "); the line above is this machine's own record\n"
		}
	}
	text := orgShellStatusText(o, observerDir, now)
	if unconfirmed == "" {
		return text
	}
	// The note follows the sign-in line.
	if i := strings.Index(text, "sign-in: "); i >= 0 {
		if j := strings.Index(text[i:], "\n"); j >= 0 {
			k := i + j + 1
			return text[:k] + unconfirmed + text[k:]
		}
	}
	return text + unconfirmed
}

// cliOrgShellEffective is the CLI's effective org-shell block: the local keys
// with the verified managed body composed (the CLI launch's composition).
func cliOrgShellEffective(ctx context.Context, cfg config.Config) config.TerminalSandboxHostedOrgShellConfig {
	eff, _ := cliEffectiveSandbox(ctx, cfg, nil)
	return eff.Hosted.OpenShellOrg
}

// orgShellStatusText renders the status lines.
func orgShellStatusText(o config.TerminalSandboxHostedOrgShellConfig, observerDir string, now time.Time) string {
	var b strings.Builder
	p := o.Published
	if !p.Offered {
		b.WriteString("openshell-org: offered only by an organization that runs an org-hosted gateway (none is published to this machine)\n")
		return b.String()
	}
	fmt.Fprintf(&b, "gateway: %s (OpenShell %s) through %s\n", p.GatewayID, p.Version, p.FrontURL)
	fmt.Fprintf(&b, "tiers: %s; hold policy: %s (at most %d h); work returned to this machine: %v\n", strings.Join(p.Tiers, ", "), p.HoldPolicy, p.MaxHoldHours, p.ReturnToNode)
	last := orgShellLoadCheck(observerDir)
	switch s := orgShellLoadSignIn(observerDir); {
	case s == nil:
		b.WriteString("sign-in: not signed in (`observer sandbox org-shell login`)\n")
	case !s.ExpiresAt.After(now):
		b.WriteString("sign-in: expired (`observer sandbox org-shell login`)\n")
	case last != nil && orgShellSignInRefused(last.Verdict) && last.At.After(s.SignedInAt):
		// The organization refused the grant after this sign-in (an admin
		// revoke, a drain; FX3 item 12, F-L4P5-6): the local expiry is no
		// longer the truth.
		fmt.Fprintf(&b, "sign-in: refused by your organization at %s (%s); sign in again with `observer sandbox org-shell login`\n", last.At.Local().Format("15:04"), last.Verdict)
	default:
		fmt.Fprintf(&b, "sign-in: signed in until %s\n", s.ExpiresAt.Local().Format(time.RFC1123))
	}
	relay := "not opted in (`observer sandbox org-shell opt-in`)"
	if o.LaptopRelay {
		relay = "opted in"
	}
	if p.LaptopRelay == string(osorg.LaptopRelayForbidden) {
		relay = "forbidden by your organization"
	}
	fmt.Fprintf(&b, "laptop relay: %s\nhold on end: %v\n", relay, o.HoldOnEnd)
	if c := last; c != nil {
		fmt.Fprintf(&b, "last checked %s: %s %s\n", c.At.Local().Format("15:04"), c.Verdict, c.Reason)
	}
	return b.String()
}

// orgShellSignInRefusals are the mint refusals that end a sign-in: the
// grant's own (T3, T4), a drain (T1: a drain revokes every grant, and its
// mint refusal is answered before the grant's; FX4 fix round 1, F-L4P5-6)
// and a member no longer allowed (T5).
var orgShellSignInRefusals = []osorg.Reason{osorg.ReasonSigninRequired, osorg.ReasonSigninExpired, osorg.ReasonSigninRevoked, osorg.ReasonDraining, osorg.ReasonMemberNotAllowed}

// orgShellSignInRefused reports whether a verdict is a sign-in refusal.
func orgShellSignInRefused(verdict string) bool {
	return slices.Contains(orgShellSignInRefusals, osorg.Reason(verdict))
}

// orgShellNoteRefusal records a sign-in refusal a mint answered (a launch's,
// not only the explicit check's) as the last check, so the status says the
// sign-in is gone instead of its local expiry.
func orgShellNoteRefusal(observerDir string, err error, now time.Time) {
	var ref *orgclient.OpenShellRefusal
	if errors.As(err, &ref) && orgShellSignInRefused(ref.Reason) {
		orgShellSaveCheck(observerDir, orgShellCheck{At: now, Verdict: ref.Reason, Reason: "the organization refused a mint"})
	}
}

// ---- check (probe rows R4 to R8, an explicit action) -------------------------

// orgShellCheck is the cached result of the last explicit check.
type orgShellCheck struct {
	At             time.Time `json:"at"`
	Verdict        string    `json:"verdict"`
	Reason         string    `json:"reason,omitempty"`
	GatewayVersion string    `json:"gateway_version,omitempty"`
}

func orgShellCheckPath(observerDir string) string {
	return filepath.Join(orgShellDir(observerDir), "check.json")
}

func orgShellLoadCheck(observerDir string) *orgShellCheck {
	var out *orgShellCheck
	_ = hostedWithState(observerDir, false, func() error {
		if b, err := hostedReadOwned(orgShellCheckPath(observerDir)); err == nil {
			var c orgShellCheck
			if json.Unmarshal(b, &c) == nil {
				out = &c
			}
		}
		return nil
	})
	return out
}

func orgShellSaveCheck(observerDir string, c orgShellCheck) {
	_ = hostedWithState(observerDir, true, func() error { return hostedWriteOwned(orgShellCheckPath(observerDir), c) })
}

// orgShellHealth asks the front's health service (a variable for tests).
var orgShellHealth = func(ctx context.Context, front, spki string, src sandboxremote.CredentialSource) (openshellorg.HealthReport, error) {
	c, err := openshellorg.New(openshellorg.Options{FrontURL: front, SPKISHA256: spki, Source: src})
	if err != nil {
		return openshellorg.HealthReport{}, err
	}
	defer func() { _ = c.Close() }()
	return c.Health(ctx)
}

// The check's verdicts (design 3.5 rows R5 to R8).
const (
	verdictOrgFrontUnreachable  = "org_front_unreachable"
	verdictOrgFrontUnauth       = "org_front_unauthenticated"
	verdictOrgGatewayUnsound    = "org_gateway_unsound"
	verdictOpenShellVersionSkew = "openshell_version_untested"
)

// orgShellRunCheck walks rows R4 to R8 with network calls (an explicit user
// action only), first refusal wins, and caches the result.
func orgShellRunCheck(ctx context.Context, c *orgclient.Client, enr *store.Enrolment, o config.TerminalSandboxHostedOrgShellConfig, observerDir string, now time.Time) orgShellCheck {
	res := orgShellCheck{At: now, Verdict: "ok"}
	defer func() { orgShellSaveCheck(observerDir, res) }()
	if v, why := orgShellLocalVerdict(o, observerDir, enr, now); v != "" {
		res.Verdict, res.Reason = v, why
		return res
	}
	rec, err := orgShellLoadGrant(observerDir, enr, now)
	if err != nil {
		res.Verdict, res.Reason = string(osorg.ReasonSigninRequired), err.Error()
		return res
	}
	// R4: a probe-purpose mint (no box), kept for the health call.
	probe := &orgShellProbeSource{mint: c.OpenShellMintToken, req: orgclient.OpenShellMintRequest{
		GrantHandle: rec.Handle, RunID: "probe-" + osorgRunIDNow(now), Purpose: string(osorg.PurposeProbe), LaptopRelay: o.LaptopRelay,
	}}
	if _, err := probe.Token(ctx); err != nil {
		var ref *orgclient.OpenShellRefusal
		if errors.As(err, &ref) {
			res.Verdict, res.Reason = ref.Reason, "the organization refused the probe mint"
		} else {
			res.Verdict, res.Reason = verdictOrgFrontUnreachable, "the organization's server did not answer the probe mint"
		}
		return res
	}
	var tokSrc sandboxremote.CredentialSource = probe
	// R5, R6: the front over TLS (and its pin), the token accepted.
	h, err := orgShellHealth(ctx, o.Published.FrontURL, o.Published.FrontSPKISHA256, tokSrc)
	switch {
	case err != nil && strings.Contains(err.Error(), "Unauthenticated"):
		res.Verdict, res.Reason = verdictOrgFrontUnauth, "the front did not accept the run token"
		return res
	case err != nil:
		res.Verdict, res.Reason = verdictOrgFrontUnreachable, "the front did not answer over TLS (or its certificate does not match the published pin)"
		return res
	}
	res.GatewayVersion = h.GatewayVersion
	// R7: the gateway version is tested and equals the body's.
	if _, ok := osorg.TransportFor(h.GatewayVersion); !ok || h.GatewayVersion != o.Published.Version {
		res.Verdict, res.Reason = verdictOpenShellVersionSkew, "the gateway reports OpenShell "+h.GatewayVersion+", the tested and published version is "+o.Published.Version
		return res
	}
	// R8: the org's last sync said the gateway is sound.
	if !h.Serving || h.Sync != "sound" {
		res.Verdict, res.Reason = verdictOrgGatewayUnsound, "the organization's last check of its gateway was not sound ("+h.Sync+")"
		return res
	}
	return res
}

// osorgRunIDNow is a probe's throwaway run id (no box is made for it).
func osorgRunIDNow(now time.Time) string { return now.UTC().Format("20060102T150405") }

// orgShellProbeSource mints one probe token and reuses it.
type orgShellProbeSource struct {
	mint func(context.Context, orgclient.OpenShellMintRequest) (orgclient.OpenShellMint, error)
	req  orgclient.OpenShellMintRequest
	mu   sync.Mutex
	tok  string
}

func (p *orgShellProbeSource) Token(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.tok != "" {
		return p.tok, nil
	}
	m, err := p.mint(ctx, p.req)
	if err != nil {
		return "", err
	}
	p.tok = m.Token
	return p.tok, nil
}

func newOrgShellCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Check your organization's sandbox front now: the sign-in, a probe token, TLS, the gateway version and soundness",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			c, enr, cfg, done, err := orgShellOrgClient(ctx)
			if err != nil {
				return err
			}
			defer done()
			res := orgShellRunCheck(ctx, c, enr, cliOrgShellEffective(ctx, cfg), filepath.Dir(cfg.Observer.DBPath), time.Now())
			fmt.Fprintf(cmd.OutOrStdout(), "checked %s: %s %s\n", res.At.Local().Format("15:04"), res.Verdict, res.Reason)
			if res.Verdict != "ok" {
				return errors.New(res.Verdict)
			}
			return nil
		},
	}
}

// ---- opt-in and opt-out (design 3.7) -----------------------------------------

func newOrgShellOptCmd(use string, on bool) *cobra.Command {
	var yes bool
	short := "Opt in to running org sandboxes through this laptop (shows what that means and asks)"
	if !on {
		short = "Opt out of running org sandboxes through this laptop"
	}
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if on {
				fmt.Fprintln(cmd.OutOrStdout(), orgShellDisclosure)
				if !yes {
					fmt.Fprint(cmd.OutOrStdout(), "Type yes to opt in: ")
					line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
					if strings.TrimSpace(line) != "yes" {
						return errors.New("not opted in")
					}
				}
			}
			if err := orgShellSetKey("", func(o *config.TerminalSandboxHostedOrgShellConfig) { o.LaptopRelay = on }); err != nil {
				return err
			}
			if on {
				fmt.Fprintln(cmd.OutOrStdout(), "Opted in: org sandbox runs may use this laptop as their relay.")
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "Opted out: org sandbox runs are no longer offered on this laptop.")
			}
			return nil
		},
	}
	if on {
		cmd.Flags().BoolVar(&yes, "yes", false, "agree to the disclosure without the prompt")
	}
	return cmd
}

// orgShellSetKey changes the row's node-local block in the config file with
// a structural patch (comments and every other key stay as they are).
func orgShellSetKey(configPath string, change func(*config.TerminalSandboxHostedOrgShellConfig)) error {
	if configPath == "" {
		configPath = daemonConfigPath()
	}
	path, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return err
	}
	mu := config.WriteLock()
	mu.Lock()
	defer mu.Unlock()
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		return err
	}
	next := cfg
	change(&next.Terminal.Sandbox.Hosted.OpenShellOrg)
	patches, err := config.StructuralPatches(cfg, next)
	if err != nil {
		return err
	}
	_, err = config.PatchFile(path, next, patches)
	return err
}
