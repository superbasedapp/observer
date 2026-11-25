package sdkcredsvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/applane"
	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/pastedsecret"
)

// Keystore names. KeystoreService is listed in keystore's service table.
const (
	KeystoreService  = "sbo-sdk-credential-v1"
	RecordCredential = "sdk-credential" //nolint:gosec // G101: a keystore record name, not a credential
	RecordMeta       = "sdk-credential-meta"
)

// DiscoveryAPIVersion is the contract version of the discovery body.
const DiscoveryAPIVersion = 1

// CredentialFileGatewayField is the name of the delivery file's gateway line
// (review E-04, ruling D29): the file's first line is the key, and a line
// "gateway_url=<base>" names the only address the SDKs send it to. The SDKs
// read the address from this owner-only file, never from the loopback
// discovery answer, so a process that answers discovery in the machine's
// place cannot steer the key. Contract destination.md section 6.
const CredentialFileGatewayField = "gateway_url"

// ExpiryWarningWindow is how long before the SDK key expires the machine
// starts warning (discovery, `observer sdk status`, the dashboard's SDK card
// and the `observer doctor` row sdk.key; review E-59).
const ExpiryWarningWindow = 14 * 24 * time.Hour

// ErrNoHeldKey is returned by SignOut when this machine holds no described
// SDK key and the caller did not ask to revoke every key (review E-28):
// nothing is revoked at the organization.
var ErrNoHeldKey = errors.New("this machine holds no SDK key, so nothing was revoked at your organization; to revoke every SDK key you have on every machine, run `observer sdk sign-out --all`")

// Minter is the org call (orgclient.Client).
type Minter interface {
	// MintSDKCredential mints a key, replacing only the one this machine
	// names; RevokeSDKCredential revokes only the one it names ("" for every
	// key of the member). Review finding R-B05.
	MintSDKCredential(ctx context.Context, in orgcontract.SDKCredentialRequest) (orgcontract.SDKCredentialMinted, error)
	RevokeSDKCredential(ctx context.Context, in orgcontract.SDKCredentialRequest) (orgcontract.SDKCredentialRevoked, error)
}

// Meta is the non-secret description of the stored key.
type Meta struct {
	CredID        string   `json:"cred_id"`
	KeyID         string   `json:"key_id"`
	OrgID         string   `json:"org_id"`
	WorkspaceID   string   `json:"workspace_id"`
	EnvironmentID string   `json:"environment_id"`
	Scopes        []string `json:"scopes"`
	Signals       []string `json:"signals"`
	GatewayURL    string   `json:"gateway_url"`
	MintedAt      string   `json:"minted_at"`
	ExpiresAt     string   `json:"expires_at"`
	// CaptureLevel is the key's workspace capture level as the org reported
	// it at sign-in ("metadata_only", "classified_safe", "full_redacted";
	// "" when the org did not say). Review L-23.
	CaptureLevel string `json:"capture_level,omitempty"`
	// Origin is where the key came from: KeyOriginSignIn (minted for the
	// member by `observer sdk sign-in`; "" on a description written before
	// origins were recorded) or KeyOriginAdminIssued (a machine-identity key
	// an admin issued, installed by `observer sdk use-key`). It decides what
	// sign-out may do: only a sign-in key is revoked on the organization.
	Origin string `json:"origin,omitempty"`
	// InstalledAt is when `observer sdk use-key` installed an admin-issued
	// key (RFC 3339; "" for a sign-in key, which has MintedAt).
	InstalledAt string `json:"installed_at,omitempty"`
}

// Key origins (Meta.Origin, Discovery's online.key_origin).
const (
	// KeyOriginSignIn is the member's own key, minted on the organization by
	// `observer sdk sign-in`.
	KeyOriginSignIn = "sign_in"
	// KeyOriginAdminIssued is a machine-identity key an admin issued (web2
	// Settings > Machine identities, or the one-click key), installed by
	// `observer sdk use-key`. This machine never revokes it.
	KeyOriginAdminIssued = "admin_issued"
)

// KeyOrigin is the key's origin, a description from before origins were
// recorded reading as a sign-in key (only sign-in wrote one then).
func (m Meta) KeyOrigin() string {
	if m.Origin == KeyOriginAdminIssued {
		return KeyOriginAdminIssued
	}
	return KeyOriginSignIn
}

// AdminIssued reports whether the key was issued by an admin and installed
// with `observer sdk use-key`.
func (m Meta) AdminIssued() bool { return m.KeyOrigin() == KeyOriginAdminIssued }

// keyOriginTexts names each origin in plain words and says how to put the
// key back, for `observer sdk status`, the doctor row and the problem lines.
var keyOriginTexts = []struct{ origin, text, again string }{
	{KeyOriginSignIn, "your own key, from `observer sdk sign-in`", "sign in again (`observer sdk sign-in`)"},
	{KeyOriginAdminIssued, "issued by an admin, installed with `observer sdk use-key`", "install the key again (`observer sdk use-key`)"},
}

// KeyOriginText is the key's origin in plain words.
func (m Meta) KeyOriginText() string { return keyOriginRow(m.KeyOrigin()).text }

// againHint says how to put the key back on this machine.
func (m Meta) againHint() string { return keyOriginRow(m.KeyOrigin()).again }

func keyOriginRow(origin string) struct{ origin, text, again string } {
	for _, r := range keyOriginTexts {
		if r.origin == origin {
			return r
		}
	}
	return keyOriginTexts[0]
}

// Capture level wire tokens (the org gateway's classify.Level names).
const (
	CaptureMetadataOnly   = "metadata_only"
	CaptureClassifiedSafe = "classified_safe"
	CaptureFullRedacted   = "full_redacted"
)

// captureLevelTexts names each capture level in plain words, for the sign-in
// output, `observer sdk status` and the dashboard (review L-23).
var captureLevelTexts = []struct{ level, text string }{
	{CaptureMetadataOnly, "L0, metadata only: no prompt or response text, no end user or tenant"},
	{CaptureClassifiedSafe, "L1, classified-safe fields: no prompt or response text"},
	{CaptureFullRedacted, "L2, full content with secrets and personal data redacted"},
}

// CaptureLevelText is level in plain words; an empty or unknown level says
// the organization did not report one.
func CaptureLevelText(level string) string {
	for _, r := range captureLevelTexts {
		if r.level == level {
			return r.text
		}
	}
	return "not reported by your organization"
}

// Status is what the machine knows about its SDK key, never the key.
type Status struct {
	// SignedIn: a key is stored and its delivery file reads back.
	SignedIn bool `json:"signed_in"`
	Meta
	// CredentialFile is the delivery file's path ("" when this platform has
	// no hardened file store).
	CredentialFile string `json:"credential_file"`
	// Problem is a plain sentence when a key is described but its file does
	// not read back (moved, wrong mode, wrong owner), or the key expired.
	Problem string `json:"problem,omitempty"`
	// KeyGatewayURL is the address stored with the key in its delivery file
	// (the gateway_url line), the only one the SDKs send it to ("" when the
	// file names none).
	KeyGatewayURL string `json:"key_gateway_url,omitempty"`
	// Expired: the key is past its expiry. The machine stays signed in (the
	// default destination stays both, review E-59) but the key is not offered
	// to the SDKs, which report the online copy as degraded.
	Expired bool `json:"expired,omitempty"`
	// ExpiresSoon: the key expires within ExpiryWarningWindow; Notice then
	// says when and what to do.
	ExpiresSoon bool   `json:"expires_soon,omitempty"`
	Notice      string `json:"notice,omitempty"`
}

// Usable reports whether the SDKs may be handed the key: signed in and not
// expired.
func (st Status) Usable() bool { return st.SignedIn && !st.Expired }

// Service holds the machine's SDK key.
type Service struct {
	// Dir is the private directory of the delivery file (~/.observer/sdk).
	Dir string
	// Keychain, when non-nil, is the keystore the key is also kept in
	// (keystore.Open(KeystoreService, Dir, ...)); nil keeps the file only.
	Keychain keystore.Store
	Logger   *slog.Logger
	// GatewayOverride is observability.sdk.gateway_url: when set, sign-in
	// stores it with the key instead of the organization's address.
	GatewayOverride string
	// Now is the clock (time.Now when nil).
	Now func() time.Time
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// DefaultDir is the SDK key directory under the observer directory.
func DefaultDir(observerDir string) string { return filepath.Join(observerDir, "sdk") }

func (s Service) file() keystore.FileBackend {
	return keystore.FileBackend{Dir: s.Dir, Service: KeystoreService}
}

// CredentialFile is the delivery file's path, or "" when the platform has no
// hardened file store (the SDK then needs SUPERBASED_API_KEY).
func (s Service) CredentialFile() string {
	if !keystore.FileFallbackSecure() || s.Dir == "" {
		return ""
	}
	return s.file().Path(RecordCredential)
}

func (s Service) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// ErrNoHardenedFile is returned on a platform with no hardened file store.
var ErrNoHardenedFile = errors.New("sdkcredsvc: this platform has no hardened file store for the SDK key; set SUPERBASED_API_KEY for your app instead")

// NoKeyFileProblem is Status.Problem on a platform with no hardened file
// store (Windows today; review finding R-B06, recorded as a stated limit
// until a Windows delivery path and matching SDK reads exist): sign-in
// cannot store a key here, so the signed-in default (both) never applies and
// an app's data stays on this machine unless the app sets SUPERBASED_API_KEY.
const NoKeyFileProblem = "this machine cannot keep an SDK key file (Windows is not supported yet), so `observer sdk sign-in` does not apply here and the destination stays local unless you set it; to send an app's data to your organization, give the app an admin-issued key in SUPERBASED_API_KEY"

// SignIn mints the member's SDK key on the org and stores it. The key is
// written to the delivery file first (what the SDK reads), then to the
// keychain, then the description; a failure after the mint leaves the org
// holding a key this machine does not, which the next sign-in replaces.
func (s Service) SignIn(ctx context.Context, m Minter) (Status, error) {
	if s.CredentialFile() == "" {
		return Status{}, ErrNoHardenedFile
	}
	// Name the key this machine already holds, so the org replaces only it
	// and a sign-in here never ends another machine's key (R-B05).
	minted, err := m.MintSDKCredential(ctx, orgcontract.SDKCredentialRequest{KeyID: s.heldKeyID()})
	if err != nil {
		return Status{}, err
	}
	if !validCompound(minted.Credential) {
		return Status{}, errors.New("sdkcredsvc: the organization answered a key in an unexpected shape; nothing was stored")
	}
	if err := validOrgGatewayURL(minted.GatewayURL); err != nil {
		return Status{}, fmt.Errorf("sdkcredsvc: the organization's gateway address is not usable (%w); nothing was stored; ask your admin to fix [gateway] public_url, or set observability.sdk.gateway_url", err)
	}
	// The address the key goes to is stored with it (E-04): the machine's
	// override when set, else the organization's.
	keyGateway := strings.TrimRight(strings.TrimSpace(minted.GatewayURL), "/")
	if o := strings.TrimRight(strings.TrimSpace(s.GatewayOverride), "/"); o != "" {
		if err := validOrgGatewayURL(o); err != nil {
			return Status{}, fmt.Errorf("sdkcredsvc: observability.sdk.gateway_url is not usable for the SDK key (%w); nothing was stored", err)
		}
		keyGateway = o
	}
	if err := s.file().Write(RecordCredential, deliveryFile(minted.Credential, keyGateway)); err != nil {
		return Status{}, fmt.Errorf("sdkcredsvc: write the SDK key file: %w", err)
	}
	if s.Keychain != nil && s.Keychain.Backend() == "keychain" {
		if err := s.Keychain.Set(RecordCredential, minted.Credential); err != nil {
			s.logger().Warn("sdk key: keychain copy not written; the 0600 file holds it", "err", err)
		}
	}
	meta := Meta{
		CredID: minted.CredID, KeyID: minted.KeyID, OrgID: minted.OrgID, WorkspaceID: minted.WorkspaceID,
		EnvironmentID: minted.EnvironmentID, Scopes: minted.Scopes, Signals: minted.Signals,
		GatewayURL: minted.GatewayURL, MintedAt: minted.MintedAt, ExpiresAt: minted.ExpiresAt,
		CaptureLevel: minted.CaptureLevel, Origin: KeyOriginSignIn,
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return Status{}, err
	}
	if err := s.file().Write(RecordMeta, raw); err != nil {
		return Status{}, fmt.Errorf("sdkcredsvc: write the SDK key description: %w", err)
	}
	return s.Status(), nil
}

// deliveryFile is the delivery file's content: the key on the first line,
// then "gateway_url=<base>" when an address is known (contract
// destination.md section 6).
func deliveryFile(compound, gateway string) []byte {
	out := compound + "\n"
	if gateway != "" {
		out += CredentialFileGatewayField + "=" + gateway + "\n"
	}
	return []byte(out)
}

// parseDeliveryFile splits the delivery file into the key and the gateway
// line's address. ok is false when the first line is not a key; unknown
// "name=value" lines are ignored (forward compatible), any other line is
// refused.
func parseDeliveryFile(raw []byte) (compound, gateway string, ok bool) {
	text := strings.TrimSuffix(string(raw), "\n")
	lines := strings.Split(text, "\n")
	compound = lines[0]
	if !validCompound(compound) {
		return "", "", false
	}
	for _, l := range lines[1:] {
		name, value, found := strings.Cut(l, "=")
		if !found || name == "" {
			return "", "", false
		}
		if name == CredentialFileGatewayField {
			gateway = value
		}
	}
	return compound, gateway, true
}

// validOrgGatewayURL checks the gateway address the organization returned at
// sign-in (review E-58), the one the SDKs send the key to as a Bearer token.
// Empty is allowed (the org set none; discovery then warns). Otherwise it
// must pass the same shape check as the config override
// (config.ValidateSDKGatewayURL) and use https, unless it names this machine
// (a loopback host, a local test org): plain http to a remote host would send
// the key in clear text.
func validOrgGatewayURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if err := config.ValidateSDKGatewayURL(raw); err != nil {
		return err
	}
	u, _ := url.Parse(raw)
	if u.Scheme != "https" && !loopbackHost(u.Hostname()) {
		return fmt.Errorf("%q is plain http to a remote host, which would send the SDK key unencrypted; it must be https", raw)
	}
	return nil
}

// loopbackHost reports whether host names this machine.
func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && ip.Unmap().IsLoopback()
}

// heldMeta is the description of the key this machine holds (ok false when
// none is described).
func (s Service) heldMeta() (Meta, bool) {
	if s.CredentialFile() == "" {
		return Meta{}, false
	}
	raw, err := s.file().Read(RecordMeta)
	if err != nil {
		return Meta{}, false
	}
	var m Meta
	if json.Unmarshal(raw, &m) != nil || strings.TrimSpace(m.KeyID) == "" {
		return Meta{}, false
	}
	return m, true
}

// heldKeyID is the key id of the member's own (sign-in) key this machine
// holds: the only key this machine names to the organization, for a mint to
// replace or a sign-out to revoke. "" when none is described, or when the
// key held is an admin-issued one (never this machine's to revoke).
func (s Service) heldKeyID() string {
	m, ok := s.heldMeta()
	if !ok || m.AdminIssued() {
		return ""
	}
	return strings.TrimSpace(m.KeyID)
}

// SignOut revokes this machine's SDK key on the org (when m is non-nil) and
// removes every local copy. Only the key this machine holds is revoked, so a
// sign-out here leaves the member's other machines signed in (R-B05). A
// machine that holds no described key revokes nothing at the org unless all
// is set (review E-28, ruling D29): all is the explicit, confirmed "sign out
// everywhere", which asks the org to revoke every SDK key of the member.
// Without it, SignOut still removes the local copies and returns
// ErrNoHeldKey. Local copies are removed even when the org call fails; the
// error says so.
//
// An admin-issued key (installed by InstallKey) is never revoked from here:
// SignOut removes its local copies and returns ErrAdminIssuedKeyKept, and the
// organization is not asked anything unless all is set (which revokes the
// member's own sign-in keys, never the admin's).
func (s Service) SignOut(ctx context.Context, m Minter, all bool) (int, error) {
	revoked := 0
	var errs []error
	meta, described := s.heldMeta()
	adminIssued := described && meta.AdminIssued()
	held := s.heldKeyID()
	req := orgcontract.SDKCredentialRequest{KeyID: held}
	if all {
		req = orgcontract.SDKCredentialRequest{All: true}
	}
	switch {
	case m == nil:
	case adminIssued && !req.All:
		// Nothing of the member's to revoke: the admin owns this key.
	case req.KeyID == "" && !req.All:
		errs = append(errs, ErrNoHeldKey)
	default:
		r, err := m.RevokeSDKCredential(ctx, req)
		revoked = r.Revoked
		if err != nil {
			errs = append(errs, fmt.Errorf("the organization did not revoke the key (%w); the local copies are removed anyway", err))
		}
	}
	for _, rec := range []string{RecordCredential, RecordMeta} {
		if err := s.file().Remove(rec); err != nil && !errors.Is(err, keystore.ErrNotFound) {
			errs = append(errs, fmt.Errorf("remove %s: %w", rec, err))
		}
	}
	if s.Keychain != nil && s.Keychain.Backend() == "keychain" {
		if err := s.Keychain.Delete(RecordCredential); err != nil && !errors.Is(err, keystore.ErrNotFound) {
			errs = append(errs, fmt.Errorf("remove the keychain copy: %w", err))
		}
	}
	if adminIssued {
		errs = append(errs, ErrAdminIssuedKeyKept)
	}
	return revoked, errors.Join(errs...)
}

// ErrAdminIssuedKeyKept is joined into SignOut's error when the key this
// machine held was issued by an admin: its local copies are removed, but it
// is not revoked, so it keeps working wherever else it is used. It is a
// notice, not a failure (the CLI prints it and exits 0).
var ErrAdminIssuedKeyKept = errors.New("the SDK key on this machine was issued by an admin, so it was removed from this machine only and not revoked: it keeps working wherever else it is used until an admin revokes it (Machine identities, in the organization's dashboard settings)")

// InstallInput is an admin-issued SDK key a member installs on this machine
// (`observer sdk use-key`, the dashboard's "Use an SDK key from my admin").
type InstallInput struct {
	// Compound is the key, "<key_id>.<secret>", exactly as the admin's
	// dialog showed it (what a paste wraps around it is removed first,
	// internal/pastedsecret). It is never
	// logged, returned or written anywhere but the two hardened copies.
	Compound string
	// GatewayURL is the organization's gateway address the key is sent to
	// (the admin's dialog shows it; SUPERBASED_ORG_URL). Empty uses
	// GatewayOverride (observability.sdk.gateway_url).
	GatewayURL string
}

// Install refusals. None of them carries the key.
var (
	// ErrKeyShape: the input is not "<key_id>.<secret>"; the returned error
	// wraps it with the one rule the input broke (installKeyRules).
	ErrKeyShape = errors.New("that is not an SDK key")
	// ErrNoGatewayURL: neither the input nor the config names the gateway.
	ErrNoGatewayURL = errors.New("name the organization's gateway address the key is sent to (--gateway-url https://...; the admin's dialog shows it beside the key); nothing was stored")
	// ErrSignInKeyHeld: this machine holds the member's own sign-in key,
	// which installing another key would leave live on the organization with
	// no machine holding it.
	ErrSignInKeyHeld = errors.New("this machine holds your own SDK key from `observer sdk sign-in`; run `observer sdk sign-out` first (it revokes that key on your organization), then install the admin's key; nothing was stored")
)

// CheckInstall runs every InstallKey check that does not need the key (a
// hardened file store, the gateway address, no held sign-in key) and returns
// the gateway address the key would be stored with, so the CLI can refuse
// before it asks for the key. InstallKey runs it again.
func (s Service) CheckInstall(gatewayURL string) (string, error) {
	if s.CredentialFile() == "" {
		return "", ErrNoHardenedFile
	}
	gateway := strings.TrimRight(strings.TrimSpace(gatewayURL), "/")
	if gateway == "" {
		gateway = strings.TrimRight(strings.TrimSpace(s.GatewayOverride), "/")
	}
	if gateway == "" {
		return "", ErrNoGatewayURL
	}
	if err := validOrgGatewayURL(gateway); err != nil {
		return "", fmt.Errorf("sdkcredsvc: the gateway address is not usable for the SDK key (%w); nothing was stored", err)
	}
	if s.heldKeyID() != "" {
		return "", ErrSignInKeyHeld
	}
	return gateway, nil
}

// InstallKey stores an SDK key an admin issued (a machine-identity key from
// web2's Settings > Machine identities or the one-click key) as this
// machine's SDK key, through the same hardened writes as SignIn: the
// delivery file first (the key, then the gateway_url line; directory 0700,
// file 0600, owner-checked, no symlinks, atomic), then the keychain copy,
// then the description, marked KeyOriginAdminIssued. No network: the key is
// not checked against the organization here; an app's first export is the
// check (a wrong key gets 401 there, counted by the SDK's diagnostics).
//
// The gateway address follows the same rule as sign-in's (https, or plain
// http only to this machine's loopback). An installed admin key replaces an
// earlier installed one; a held sign-in key is refused (ErrSignInKeyHeld).
// After it, discovery reports the credential present and the machine default
// destination is both, as after a sign-in.
func (s Service) InstallKey(in InstallInput) (Status, error) {
	gateway, err := s.CheckInstall(in.GatewayURL)
	if err != nil {
		return Status{}, err
	}
	compound := pastedsecret.Clean(in.Compound)
	if problem := installKeyProblem(compound); problem != "" {
		return Status{}, fmt.Errorf("%w: %s; an SDK key is <key_id>.<secret>, exactly as the admin's dialog shows it; nothing was stored", ErrKeyShape, problem)
	}
	keyID, _, _ := strings.Cut(compound, ".")
	if err := s.file().Write(RecordCredential, deliveryFile(compound, gateway)); err != nil {
		return Status{}, fmt.Errorf("sdkcredsvc: write the SDK key file: %w", err)
	}
	if s.Keychain != nil && s.Keychain.Backend() == "keychain" {
		if err := s.Keychain.Set(RecordCredential, compound); err != nil {
			s.logger().Warn("sdk key: keychain copy not written; the 0600 file holds it", "err", err)
		}
	}
	raw, err := json.Marshal(Meta{
		KeyID: keyID, GatewayURL: gateway, Origin: KeyOriginAdminIssued,
		InstalledAt: s.now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return Status{}, err
	}
	if err := s.file().Write(RecordMeta, raw); err != nil {
		return Status{}, fmt.Errorf("sdkcredsvc: write the SDK key description: %w", err)
	}
	return s.Status(), nil
}

// HoldsKey reports whether this machine describes an SDK key it holds, a
// sign-in key or an admin-issued one.
func (s Service) HoldsKey() bool {
	_, ok := s.heldMeta()
	return ok
}

// Status describes the stored key without returning it.
func (s Service) Status() Status {
	st := Status{CredentialFile: s.CredentialFile()}
	if st.CredentialFile == "" {
		if !keystore.FileFallbackSecure() {
			st.Problem = NoKeyFileProblem
		}
		return st
	}
	raw, err := s.file().Read(RecordMeta)
	if err != nil {
		return st
	}
	if json.Unmarshal(raw, &st.Meta) != nil {
		st.Problem = "the SDK key description does not parse; " + Meta{}.againHint()
		return st
	}
	// The delivery file is read only to check it (the keystore's hardened
	// read: mode, owner, no symlink) and for its gateway line; the key is
	// never returned.
	raw, err = s.file().Read(RecordCredential)
	if err != nil {
		st.Problem = "the SDK key file does not read back (" + err.Error() + "); " + st.againHint()
		return st
	}
	_, gw, ok := parseDeliveryFile(raw)
	if !ok {
		st.Problem = "the SDK key file is not in the expected shape; " + st.againHint()
		return st
	}
	st.SignedIn, st.KeyGatewayURL = true, gw
	now := s.now()
	if exp, ok := st.expiry(); ok {
		switch {
		case !exp.After(now):
			// Still signed in (the destination default stays both); the key is
			// not offered to the SDKs (E-59).
			st.Expired = true
			st.Problem = "the SDK key expired on " + exp.UTC().Format("2006-01-02") + ", so the online copy of your apps' data is not sent; run `observer sdk sign-in` to get a new key"
		case exp.Sub(now) <= ExpiryWarningWindow:
			st.ExpiresSoon, st.Notice = true, expiryNotice(exp, now)
		}
	}
	return st
}

// expiry is the parsed ExpiresAt (ok false when unset or unparseable).
func (st Status) expiry() (time.Time, bool) {
	if st.ExpiresAt == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, st.ExpiresAt)
	return t, err == nil
}

// expiryNotice is the plain-language warning for a key that expires at exp.
func expiryNotice(exp, now time.Time) string {
	days := int(exp.Sub(now).Hours() / 24)
	when := "in " + strconv.Itoa(days) + " days"
	switch days {
	case 0:
		when = "today"
	case 1:
		when = "tomorrow"
	}
	return "the SDK key expires on " + exp.UTC().Format("2006-01-02") + " (" + when + "); run `observer sdk sign-in` to renew it before the online copy of your apps' data stops"
}

// KeyCheck is the `observer doctor` row sdk.key (E-59): Level is "ok",
// "warn" or "fail".
type KeyCheck struct {
	Level   string
	Message string
	Details []string
}

// DoctorCheck describes the stored key for `observer doctor`. Pure.
func DoctorCheck(st Status) KeyCheck {
	switch {
	case st.Expired:
		return KeyCheck{Level: "fail", Message: st.Problem, Details: []string{"key " + st.KeyID + ", expired " + st.ExpiresAt}}
	case st.Problem != "":
		return KeyCheck{Level: "warn", Message: st.Problem}
	case !st.SignedIn:
		return KeyCheck{Level: "ok", Message: "no SDK key on this machine (not signed in; SDKs send to this machine only unless an app sets its own key)"}
	case st.ExpiresSoon:
		return KeyCheck{Level: "warn", Message: st.Notice, Details: []string{"key " + st.KeyID}}
	}
	msg := "SDK key " + st.KeyID + " held (" + st.KeyOriginText() + ")"
	if st.ExpiresAt != "" {
		msg += ", expires " + st.ExpiresAt
	}
	return KeyCheck{Level: "ok", Message: msg}
}

// installKeyRules is the check an installed key passes, in order; the first
// rule broken is the one named (never the key). Stricter than validCompound
// on the key id, which a minted key id always meets (hex), so a pasted
// variable assignment or header is named rather than stored.
var installKeyRules = []struct {
	problem string
	breaks  func(string) bool
}{
	{"nothing was read (the key is empty)", func(k string) bool { return k == "" }},
	{"it holds a line break (paste one key)", func(k string) bool { return strings.ContainsAny(k, "\r\n") }},
	{"it holds a space (paste the key alone, without `Bearer` or a variable name)", func(k string) bool { return strings.ContainsAny(k, " \t") }},
	{"it carries a variable name or a header (paste only the key, not SUPERBASED_API_KEY=...)", func(k string) bool { return strings.ContainsAny(k, "=:") }},
	{"it is not two parts joined by a dot", func(k string) bool { return !validCompound(k) }},
	{"its key id (before the dot) holds a character a key id never has", func(k string) bool {
		id, _, _ := strings.Cut(k, ".")
		return strings.IndexFunc(id, func(r rune) bool {
			return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-'
		}) >= 0
	}},
}

// installKeyProblem names the first install rule compound breaks, or "".
func installKeyProblem(compound string) string {
	for _, r := range installKeyRules {
		if r.breaks(compound) {
			return r.problem
		}
	}
	return ""
}

// validCompound is the "<key_id>.<secret>" shape: one dot, both halves
// non-empty, printable ASCII without spaces.
func validCompound(c string) bool {
	id, secret, ok := strings.Cut(c, ".")
	if !ok || id == "" || secret == "" || len(c) > 512 {
		return false
	}
	for _, r := range c {
		if r <= ' ' || r > '~' {
			return false
		}
	}
	return true
}

// Discovery is the GET /api/sdk/destination body (contract section 4.1).
type Discovery struct {
	APIVersion  int             `json:"api_version"`
	Destination string          `json:"destination"`
	Source      string          `json:"source"`
	Configured  string          `json:"configured"`
	SignedIn    bool            `json:"signed_in"`
	Local       DiscoveryLocal  `json:"local"`
	Online      DiscoveryOnline `json:"online"`
	Warnings    []string        `json:"warnings"`
}

// DiscoveryLocal is where the machine receives an app's data.
type DiscoveryLocal struct {
	// Enabled: this machine keeps an app's spans, which needs AI Apps both
	// in this build (Compiled) and turned on ([observability] enabled).
	Enabled bool `json:"enabled"`
	// Compiled: this build includes AI Apps on the machine (review E-29). A
	// minimal build, or one without app observability, refuses an app's
	// spans whatever the config says.
	Compiled       bool   `json:"compiled"`
	OTLPTracesURL  string `json:"otlp_traces_url"`
	OTLPLogsURL    string `json:"otlp_logs_url"`
	OTLPMetricsURL string `json:"otlp_metrics_url"`
	AdmissionURL   string `json:"admission_url"`
	// AppLanes are this machine's local app lanes (hosted AI gateway plan
	// L7): the /up/<id> routes on the proxy an app points its model client
	// at, each with its client base URL. Additive (api_version stays 1);
	// the SDK helpers' gateway_base_url falls back to it (L8). Empty when
	// the user has added no lane or the proxy is off (decision 8).
	AppLanes []DiscoveryAppLane `json:"app_lanes"`
}

// DiscoveryAppLane is one local app lane in the discovery body.
type DiscoveryAppLane struct {
	// ID is the lane id (the /up/<id> segment).
	ID string `json:"id"`
	// Kind is the client shape: openai, anthropic, openrouter, gemini or
	// openai_compatible.
	Kind string `json:"kind"`
	// BaseURL is the lane root (http://127.0.0.1:<port>/up/<id>).
	BaseURL string `json:"base_url"`
	// ClientBaseURL is the base URL for a model client of the lane's kind
	// (an OpenAI client's ends in /v1).
	ClientBaseURL string `json:"client_base_url"`
}

// DiscoveryOnline describes the org gateway and the stored key (never the
// key itself).
type DiscoveryOnline struct {
	GatewayURL        string   `json:"gateway_url"`
	GatewayURLSource  string   `json:"gateway_url_source"`
	CredentialPresent bool     `json:"credential_present"`
	CredentialFile    string   `json:"credential_file"`
	CredID            string   `json:"cred_id"`
	KeyID             string   `json:"key_id"`
	Scopes            []string `json:"scopes"`
	Signals           []string `json:"signals"`
	WorkspaceID       string   `json:"workspace_id"`
	EnvironmentID     string   `json:"environment_id"`
	// CaptureLevel is the workspace's capture level as reported at sign-in
	// (Meta.CaptureLevel; review L-23).
	CaptureLevel string `json:"capture_level"`
	OrgID        string `json:"org_id"`
	MintedAt     string `json:"minted_at"`
	ExpiresAt    string `json:"expires_at"`
	// KeyOrigin is where the held key came from: KeyOriginSignIn or
	// KeyOriginAdminIssued ("" when no key is held). Additive (api_version
	// stays 1): the SDKs do not read it; the machine's Settings card does, to
	// offer "Remove" instead of "Revoke" for a key the member does not own.
	KeyOrigin string `json:"key_origin"`
	// DashboardURL is the base of the organization's own dashboard for the
	// held key, for links to an app's trace (SDK quickstart plan 3.8:
	// <dashboard_url>/trajectories?trace=<id>); never a place the key goes.
	// "" when no key is offered or the machine knows no address that is the
	// key's organization's (BuildDiscoveryWithOrg, dashboardurl.go).
	// Additive (api_version stays 1).
	DashboardURL string `json:"dashboard_url"`
}

// obsCompiledIn reports whether this build includes app observability (the
// obs component). A variable so tests can stand in a build without it.
var obsCompiledIn = func() bool {
	return slices.Contains(components.Compiled(components.BinaryNode), "obs")
}

// Gateway URL sources in the discovery body.
const (
	GatewaySourceCredentialFile = "credential_file" //nolint:gosec // G101: a discovery source label, not a credential
	GatewaySourceConfig         = "config"
	GatewaySourceOrg            = "org"
)

// BuildDiscovery composes the discovery body from the config, the key's
// status and the dashboard's own base URL (scheme://host:port of the request
// that asked). Pure apart from reading the build's compiled-in component
// list.
func BuildDiscovery(cfg config.Config, st Status, dashboardBase string) Discovery {
	compiled := obsCompiledIn()
	localOn := compiled && cfg.Observability.Enabled
	res := config.ResolveSDKDestination(cfg.Observability.SDK, st.SignedIn, localOn)
	d := Discovery{
		APIVersion: DiscoveryAPIVersion, Destination: res.Destination, Source: res.Source,
		Configured: res.Configured, SignedIn: st.SignedIn, Warnings: []string{},
	}
	otlp := localOTLPBase(cfg.Ingest.OTel.HTTPAddr)
	d.Local = DiscoveryLocal{
		Enabled:        localOn,
		Compiled:       compiled,
		OTLPTracesURL:  otlp + "/v1/traces",
		OTLPLogsURL:    otlp + "/v1/logs",
		OTLPMetricsURL: otlp + "/v1/metrics",
		AdmissionURL:   strings.TrimRight(dashboardBase, "/") + "/api/obs/admission/check",
		AppLanes:       discoveryAppLanes(cfg),
	}
	on := DiscoveryOnline{CredentialFile: st.CredentialFile, Scopes: nonNil(st.Scopes), Signals: nonNil(st.Signals)}
	if st.SignedIn {
		// An expired key is described but not offered (E-59).
		on.CredentialPresent = st.Usable()
		on.CredID, on.KeyID, on.WorkspaceID, on.EnvironmentID = st.CredID, st.KeyID, st.WorkspaceID, st.EnvironmentID
		on.OrgID, on.MintedAt, on.ExpiresAt = st.OrgID, st.MintedAt, st.ExpiresAt
		on.CaptureLevel = st.CaptureLevel
		on.KeyOrigin = st.KeyOrigin()
	}
	// Informational: the SDKs take the address from the key file itself
	// (E-04). With a key, that file's address is the one apps use.
	override := strings.TrimRight(strings.TrimSpace(cfg.Observability.SDK.GatewayURL), "/")
	switch {
	case st.SignedIn && st.KeyGatewayURL != "":
		on.GatewayURL, on.GatewayURLSource = strings.TrimRight(st.KeyGatewayURL, "/"), GatewaySourceCredentialFile
	case override != "":
		on.GatewayURL, on.GatewayURLSource = override, GatewaySourceConfig
	case st.SignedIn && st.GatewayURL != "":
		on.GatewayURL, on.GatewayURLSource = strings.TrimRight(st.GatewayURL, "/"), GatewaySourceOrg
	}
	d.Online = on
	d.Warnings = discoveryWarnings(d, st, override, compiled)
	return d
}

// discoveryWarnings is the table of plain-language warnings.
func discoveryWarnings(d Discovery, st Status, override string, compiled bool) []string {
	online := config.SDKDestinationSendsOnline(d.Destination)
	sendsLocal := d.Destination != config.SDKDestinationOnline
	keyGateway := strings.TrimRight(st.KeyGatewayURL, "/")
	rows := []struct {
		when bool
		text string
	}{
		{st.Problem != "", st.Problem},
		{st.ExpiresSoon, st.Notice},
		{online && !d.SignedIn, "the destination sends data online but this machine holds no SDK key; run `observer sdk sign-in`, install a key an admin issued you with `observer sdk use-key --gateway-url <address>`, or set SUPERBASED_API_KEY"},
		{online && !d.SignedIn && d.Online.GatewayURL == "", "the destination sends data online but no gateway address is known; set observability.sdk.gateway_url or ask your admin to set [gateway] public_url"},
		{online && st.Usable() && keyGateway == "", "the SDK key was stored without a gateway address, so apps cannot send online; set observability.sdk.gateway_url (or ask your admin to set [gateway] public_url), then run `observer sdk sign-in` again"},
		{st.SignedIn && override != "" && keyGateway != "" && override != keyGateway, "observability.sdk.gateway_url (" + override + ") differs from the address stored with the SDK key (" + keyGateway + "); apps send to the stored address until you " + st.againHint()},
		{online && d.SignedIn && d.Online.CaptureLevel == CaptureMetadataOnly, "your organization keeps only metadata for workspace " + d.Online.WorkspaceID + " (capture level L0): no prompt or response text and no end user reach it; an admin raises the level in the workspace's capture settings"},
		{sendsLocal && !compiled, "this build of Observer does not include AI Apps observability, so it cannot receive an app's spans; choose destination online, or install an edition that includes it"},
		{sendsLocal && compiled && !d.Local.Enabled, "observability is off on this machine ([observability] enabled = false), so it refuses an app's spans; turn it on in Settings"},
		{d.Source == config.SDKSourceSignedInNoLocal, "this machine does not receive app data (AI Apps observability is off or not in this build), so a signed-in SDK sends online only"},
	}
	out := []string{}
	for _, r := range rows {
		if r.when && r.text != "" {
			out = append(out, r.text)
		}
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// localOTLPBase is the http base of the local OTLP/HTTP receiver. A
// wildcard bind host is advertised as 127.0.0.1.
func localOTLPBase(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		addr = config.DefaultIngestOTelHTTPAddr
	}
	u, err := url.Parse("http://" + addr)
	if err != nil || u.Port() == "" {
		return "http://" + config.DefaultIngestOTelHTTPAddr
	}
	host := u.Hostname()
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "http://" + host + ":" + u.Port()
}

// discoveryAppLanes lists the local app lanes for the discovery body: the
// [proxy.upstreams] lanes, only while the proxy is on (a lane needs it). No
// upstream URL is advertised: an SDK needs the client base URL, not where the
// lane forwards.
func discoveryAppLanes(cfg config.Config) []DiscoveryAppLane {
	out := []DiscoveryAppLane{}
	if !cfg.Proxy.Enabled {
		return out
	}
	for _, l := range applane.List(cfg.Proxy.Upstreams, nil, cfg.Proxy.Port) {
		out = append(out, DiscoveryAppLane{ID: l.ID, Kind: l.Kind, BaseURL: l.BaseURL, ClientBaseURL: l.ClientBaseURL})
	}
	return out
}
