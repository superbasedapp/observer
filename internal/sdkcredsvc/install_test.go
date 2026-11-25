package sdkcredsvc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// adminKey is an obviously fake admin-issued key.
const adminKey = "ik_admin1.fakeAdminSecretValue"

// TestInstallKeyRows is the install table: what InstallKey accepts and what
// it refuses, and that a refusal stores nothing and never names the key.
func TestInstallKeyRows(t *testing.T) {
	cases := []struct {
		name     string
		in       InstallInput
		override string
		wantErr  error  // errors.Is target, or nil
		wantText string // a substring of the refusal
		wantGW   string // the stored gateway line on success
	}{
		{name: "https gateway", in: InstallInput{Compound: adminKey, GatewayURL: "https://acme.superbased.app"}, wantGW: "https://acme.superbased.app"},
		{name: "trailing slash and white space are trimmed", in: InstallInput{Compound: "  " + adminKey + "\n", GatewayURL: " https://gw.example.com:4318/ "}, wantGW: "https://gw.example.com:4318"},
		{name: "plain http to loopback", in: InstallInput{Compound: adminKey, GatewayURL: "http://127.0.0.1:4318"}, wantGW: "http://127.0.0.1:4318"},
		{name: "plain http to localhost", in: InstallInput{Compound: adminKey, GatewayURL: "http://localhost:4318"}, wantGW: "http://localhost:4318"},
		{name: "no flag uses the config override", in: InstallInput{Compound: adminKey}, override: "https://override.example.com", wantGW: "https://override.example.com"},
		{name: "the flag wins over the override", in: InstallInput{Compound: adminKey, GatewayURL: "https://flag.example.com"}, override: "https://override.example.com", wantGW: "https://flag.example.com"},
		{name: "no gateway anywhere", in: InstallInput{Compound: adminKey}, wantErr: ErrNoGatewayURL},
		{name: "plain http to a remote host", in: InstallInput{Compound: adminKey, GatewayURL: "http://gw.example.com"}, wantText: "unencrypted"},
		{name: "a path is not a base address", in: InstallInput{Compound: adminKey, GatewayURL: "https://gw.example.com/v1/traces"}, wantText: "without a path"},
		{name: "credentials in the URL", in: InstallInput{Compound: adminKey, GatewayURL: "https://u:p@gw.example.com"}, wantText: "user name"},
		{name: "not a URL scheme", in: InstallInput{Compound: adminKey, GatewayURL: "gw.example.com"}, wantText: "http:// or https://"},
		{name: "empty key", in: InstallInput{Compound: "", GatewayURL: "https://gw.example.com"}, wantErr: ErrKeyShape},
		{name: "no dot", in: InstallInput{Compound: "nodotfakevalue", GatewayURL: "https://gw.example.com"}, wantErr: ErrKeyShape},
		{name: "empty key id", in: InstallInput{Compound: ".fakevalue", GatewayURL: "https://gw.example.com"}, wantErr: ErrKeyShape},
		{name: "empty secret", in: InstallInput{Compound: "ik_x.", GatewayURL: "https://gw.example.com"}, wantErr: ErrKeyShape},
		{name: "inner space", in: InstallInput{Compound: "ik_x.fake value", GatewayURL: "https://gw.example.com"}, wantErr: ErrKeyShape},
		{name: "two lines", in: InstallInput{Compound: "ik_x.fakeA\nik_y.fakeB", GatewayURL: "https://gw.example.com"}, wantErr: ErrKeyShape, wantText: "line break"},
		{name: "a pasted export line", in: InstallInput{Compound: "SUPERBASED_API_KEY=ik_x.fakevalue", GatewayURL: "https://gw.example.com"}, wantErr: ErrKeyShape, wantText: "variable name"},
		{name: "a pasted header value", in: InstallInput{Compound: "Bearer ik_x.fakevalue", GatewayURL: "https://gw.example.com"}, wantErr: ErrKeyShape, wantText: "a space"},
		{name: "a key id with a slash", in: InstallInput{Compound: "ik/x.fakevalue", GatewayURL: "https://gw.example.com"}, wantErr: ErrKeyShape, wantText: "key id"},
		{name: "a bracketed paste is cleaned", in: InstallInput{Compound: "\x1b[200~" + adminKey + "\x1b[201~\r\n", GatewayURL: "https://gw.example.com"}, wantGW: "https://gw.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newSvc(t)
			s.GatewayOverride = tc.override
			st, err := s.InstallKey(tc.in)
			if tc.wantErr != nil || tc.wantText != "" {
				if err == nil {
					t.Fatalf("accepted: %+v", st)
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if tc.wantText != "" && !strings.Contains(err.Error(), tc.wantText) {
					t.Fatalf("err = %v, want it to say %q", err, tc.wantText)
				}
				if strings.Contains(err.Error(), "fake") {
					t.Fatalf("a refusal must never carry the key: %v", err)
				}
				if _, statErr := os.Stat(s.CredentialFile()); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatal("a refused install stores nothing")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			body, _ := os.ReadFile(st.CredentialFile)
			if string(body) != adminKey+"\ngateway_url="+tc.wantGW+"\n" {
				t.Fatalf("delivery file = %q", body)
			}
			if !st.SignedIn || st.KeyID != "ik_admin1" || st.KeyGatewayURL != tc.wantGW || st.Origin != KeyOriginAdminIssued || st.InstalledAt == "" {
				t.Fatalf("status = %+v", st)
			}
		})
	}
}

// TestInstallKeyIsHardenedAndDiscoverable: the installed key lands in the
// same 0600 file in a 0700 directory as a sign-in key, is never in the
// status or discovery body, and makes the machine default both.
func TestInstallKeyIsHardenedAndDiscoverable(t *testing.T) {
	s := newSvc(t)
	s.Now = func() time.Time { return time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC) }
	st, err := s.InstallKey(InstallInput{Compound: adminKey, GatewayURL: "https://acme.superbased.app"})
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(st.CredentialFile)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("delivery file mode: %v %v", fi, err)
	}
	if di, _ := os.Stat(s.Dir); di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", di.Mode().Perm())
	}
	if st.InstalledAt != "2026-11-25T09:00:00Z" || st.MintedAt != "" || st.ExpiresAt != "" {
		t.Fatalf("times: %+v", st)
	}
	cfg := config.Default()
	cfg.Observability.Enabled = true
	d := BuildDiscovery(cfg, st, "http://127.0.0.1:8081")
	for _, v := range []any{st, d} {
		raw, _ := json.Marshal(v)
		if strings.Contains(string(raw), "fakeAdminSecretValue") {
			t.Fatalf("never the key: %s", raw)
		}
	}
	if d.Destination != "both" || d.Source != "default_signed_in" || !d.Online.CredentialPresent ||
		d.Online.GatewayURL != "https://acme.superbased.app" || d.Online.GatewayURLSource != GatewaySourceCredentialFile ||
		d.Online.KeyOrigin != KeyOriginAdminIssued || d.Online.KeyID != "ik_admin1" || len(d.Warnings) != 0 {
		t.Fatalf("discovery = %+v", d)
	}
	if !s.HoldsKey() {
		t.Fatal("an installed key is a held key (the enrol hint's has_key row)")
	}
	if kc := DoctorCheck(s.Status()); kc.Level != "ok" || !strings.Contains(kc.Message, "issued by an admin") {
		t.Fatalf("doctor row = %+v", kc)
	}
	// A loosened file mode stops reading as held, and the remedy is the
	// install, not a sign-in.
	if err := os.Chmod(st.CredentialFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := s.Status(); got.SignedIn || !strings.Contains(got.Problem, "observer sdk use-key") {
		t.Fatalf("a group-readable key file: %+v", got)
	}
}

// TestInstallKeyOverTheHeldKeys: an installed key replaces an earlier
// installed one, but not the member's own sign-in key (which would stay
// live on the organization with no machine holding it).
func TestInstallKeyOverTheHeldKeys(t *testing.T) {
	s := newSvc(t)
	if _, err := s.InstallKey(InstallInput{Compound: "ik_old.fakeOldValue", GatewayURL: "https://gw.example.com"}); err != nil {
		t.Fatal(err)
	}
	st, err := s.InstallKey(InstallInput{Compound: adminKey, GatewayURL: "https://gw2.example.com"})
	if err != nil || st.KeyID != "ik_admin1" || st.KeyGatewayURL != "https://gw2.example.com" {
		t.Fatalf("replace an installed key: %+v %v", st, err)
	}

	s2 := newSvc(t)
	m := &fakeMinter{minted: orgcontract.SDKCredentialMinted{CredID: "c1", KeyID: "ik_abc", Credential: secret, GatewayURL: "https://gw.example.com"}}
	if _, err := s2.SignIn(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.InstallKey(InstallInput{Compound: adminKey, GatewayURL: "https://gw.example.com"}); !errors.Is(err, ErrSignInKeyHeld) {
		t.Fatalf("over a sign-in key: %v", err)
	}
	if got := s2.Status(); got.KeyID != "ik_abc" || got.KeyOrigin() != KeyOriginSignIn {
		t.Fatalf("the sign-in key is untouched: %+v", got)
	}
}

// TestSignOutOfAnAdminIssuedKeyNeverRevokesIt: sign-out removes an
// installed key's local copies and does not ask the organization to revoke
// it; with all, it revokes the member's own keys only.
func TestSignOutOfAnAdminIssuedKeyNeverRevokesIt(t *testing.T) {
	for _, all := range []bool{false, true} {
		s := newSvc(t)
		st, err := s.InstallKey(InstallInput{Compound: adminKey, GatewayURL: "https://gw.example.com"})
		if err != nil {
			t.Fatal(err)
		}
		m := &fakeMinter{}
		_, err = s.SignOut(context.Background(), m, all)
		if !errors.Is(err, ErrAdminIssuedKeyKept) {
			t.Fatalf("all=%v: err = %v, want the kept notice", all, err)
		}
		if errors.Is(err, ErrNoHeldKey) {
			t.Fatalf("all=%v: an installed key is a held key: %v", all, err)
		}
		if all {
			if len(m.revokeReq) != 1 || !m.revokeReq[0].All || m.revokeReq[0].KeyID != "" {
				t.Fatalf("--all asks for the member's own keys only: %+v", m.revokeReq)
			}
		} else if len(m.revokeReq) != 0 {
			t.Fatalf("an admin-issued key is never sent for revocation: %+v", m.revokeReq)
		}
		if _, err := os.Stat(st.CredentialFile); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("all=%v: the delivery file is removed", all)
		}
		if s.Status().SignedIn || s.HoldsKey() {
			t.Fatalf("all=%v: nothing held after sign-out", all)
		}
	}
}

// TestSignInAfterAnInstalledKeyNamesNoKey: a later sign-in replaces the
// installed key locally but never names it to the organization (it is not
// the member's to replace).
func TestSignInAfterAnInstalledKeyNamesNoKey(t *testing.T) {
	s := newSvc(t)
	if _, err := s.InstallKey(InstallInput{Compound: adminKey, GatewayURL: "https://gw.example.com"}); err != nil {
		t.Fatal(err)
	}
	m := &fakeMinter{minted: orgcontract.SDKCredentialMinted{CredID: "c1", KeyID: "ik_abc", Credential: secret, GatewayURL: "https://gw.example.com"}}
	st, err := s.SignIn(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.mintReq) != 1 || m.mintReq[0].KeyID != "" {
		t.Fatalf("the mint names no admin key: %+v", m.mintReq)
	}
	if st.KeyID != "ik_abc" || st.KeyOrigin() != KeyOriginSignIn {
		t.Fatalf("status = %+v", st)
	}
}

// TestKeyOriginRows: the origin's words, and a description written before
// origins were recorded reading as a sign-in key.
func TestKeyOriginRows(t *testing.T) {
	cases := []struct {
		origin, want, again string
		admin               bool
	}{
		{"", KeyOriginSignIn, "observer sdk sign-in", false},
		{KeyOriginSignIn, KeyOriginSignIn, "observer sdk sign-in", false},
		{KeyOriginAdminIssued, KeyOriginAdminIssued, "observer sdk use-key", true},
		{"something-else", KeyOriginSignIn, "observer sdk sign-in", false},
	}
	for _, tc := range cases {
		m := Meta{Origin: tc.origin}
		if m.KeyOrigin() != tc.want || m.AdminIssued() != tc.admin || !strings.Contains(m.againHint(), tc.again) || m.KeyOriginText() == "" {
			t.Errorf("origin %q: %q admin=%v again=%q", tc.origin, m.KeyOrigin(), m.AdminIssued(), m.againHint())
		}
	}
}
