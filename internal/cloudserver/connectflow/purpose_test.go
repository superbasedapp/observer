package connectflow

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// purpose_test.go pins the SDK key purpose's tables (purpose.go): one case
// per row of each.

func TestPurposeRows(t *testing.T) {
	t.Parallel()
	cases := []struct {
		purpose Purpose
		auth    AuthKind
		answer  Answer
		notNow  bool
		ok      bool
	}{
		{"", AuthPoP, AnswerSignIn, true, true},
		{PurposeMachine, AuthPoP, AnswerSignIn, true, true},
		{PurposeSDKKey, AuthDeviceCode, AnswerKeyGrant, false, true},
		{"other", "", "", false, false},
	}
	for _, c := range cases {
		auth, ok := AuthFor(c.purpose)
		answer, _ := AnswerFor(c.purpose)
		if auth != c.auth || answer != c.answer || ok != c.ok {
			t.Errorf("%q: auth %q answer %q ok %v, want %q %q %v", c.purpose, auth, answer, ok, c.auth, c.answer, c.ok)
		}
		if got := Allows(c.purpose, EventNotNow); got != c.notNow {
			t.Errorf("%q: Allows(not_now) = %v, want %v", c.purpose, got, c.notNow)
		}
		if c.ok && (!Allows(c.purpose, EventConnect) || !Allows(c.purpose, EventDecline)) {
			t.Errorf("%q: connect and decline must be allowed", c.purpose)
		}
		if p, ok := ParsePurpose(string(c.purpose)); ok != c.ok || (ok && p == "") {
			t.Errorf("ParsePurpose(%q) = %q %v", c.purpose, p, ok)
		}
	}
}

// fixtureRedeemHash is sdk/contract/fixtures/setup/connect-create.json's
// redeem_hash.
const fixtureRedeemHash = "4gCLlovTgfGzwK4urGu0ushPtJ7SF1a3E6QVBfFb1Ks"

// validSDKCreate is the contract fixture's create body, which passes every
// rule.
func validSDKCreate() CreateRequest {
	return CreateRequest{
		Purpose:       "sdk_key",
		Client:        "superbased-sdk-python",
		ClientVersion: "0.3.0",
		ProjectName:   "support-bot",
		MachineName:   "studio-mac",
		OS:            "darwin",
		Arch:          "arm64",
		RedeemHash:    fixtureRedeemHash,
	}
}

func TestValidateCreateSDKKey(t *testing.T) {
	t.Parallel()
	got, err := ValidateCreate(validSDKCreate())
	if err != nil {
		t.Fatalf("valid SDK create: %v", err)
	}
	if got.Purpose != PurposeSDKKey || got.Client != "superbased-sdk-python" || got.ClientVersion != "0.3.0" ||
		got.ProjectName != "support-bot" || got.MachineName != "studio-mac" || got.OS != "darwin" || got.Arch != "arm64" ||
		got.RedeemHash != fixtureRedeemHash || got.PublicKey != nil || got.ObserverVersion != "" {
		t.Fatalf("cleaned = %+v", got)
	}
	ts := validSDKCreate()
	ts.Client, ts.OS = "superbased-sdk-typescript", "win32"
	if _, err := ValidateCreate(ts); err != nil {
		t.Fatalf("typescript on win32: %v", err)
	}

	cases := []struct {
		name string
		edit func(*CreateRequest)
		code string
	}{
		{"unknown purpose", func(r *CreateRequest) { r.Purpose = "token" }, "invalid_purpose"},
		{"device key", func(r *CreateRequest) { r.DevicePublicKey = "abc" }, "bad_request"},
		{"observer version", func(r *CreateRequest) { r.ObserverVersion = "1.0" }, "bad_request"},
		{"no client", func(r *CreateRequest) { r.Client = "" }, "invalid_client"},
		{"other client", func(r *CreateRequest) { r.Client = "superbased-sdk-go" }, "invalid_client"},
		{"no client version", func(r *CreateRequest) { r.ClientVersion = "" }, "invalid_client_version"},
		{"client version with space", func(r *CreateRequest) { r.ClientVersion = "0.3 beta" }, "invalid_client_version"},
		{"no project", func(r *CreateRequest) { r.ProjectName = "" }, "invalid_project_name"},
		{"upper-case project", func(r *CreateRequest) { r.ProjectName = "Support-Bot" }, "invalid_project_name"},
		{"long project", func(r *CreateRequest) { r.ProjectName = strings.Repeat("p", 65) }, "invalid_project_name"},
		{"blank machine", func(r *CreateRequest) { r.MachineName = "" }, "invalid_machine_name"},
		{"bad os", func(r *CreateRequest) { r.OS = "Darwin" }, "invalid_os"},
		{"no arch", func(r *CreateRequest) { r.Arch = "" }, "invalid_arch"},
		{"personal hint", func(r *CreateRequest) { r.TargetHint = "u-abcdefgh" }, "invalid_target_hint"},
		{"no redeem hash", func(r *CreateRequest) { r.RedeemHash = "" }, "invalid_redeem_hash"},
		{"hex redeem hash", func(r *CreateRequest) { r.RedeemHash = strings.Repeat("ab", 32) }, "invalid_redeem_hash"},
		{"padded redeem hash", func(r *CreateRequest) { r.RedeemHash = fixtureRedeemHash + "=" }, "invalid_redeem_hash"},
		{"loose last character", func(r *CreateRequest) { r.RedeemHash = fixtureRedeemHash[:42] + "t" }, "invalid_redeem_hash"},
	}
	for _, c := range cases {
		req := validSDKCreate()
		c.edit(&req)
		_, err := ValidateCreate(req)
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Code != c.code {
			t.Errorf("%s: err %v, want %s", c.name, err, c.code)
		}
	}
}

func TestValidateCreateMachineRefusesSDKFields(t *testing.T) {
	t.Parallel()
	base := validCreate()
	if got, err := ValidateCreate(base); err != nil || got.Purpose != PurposeMachine {
		t.Fatalf("machine create: %+v %v (no purpose is a machine)", got, err)
	}
	cases := []struct {
		name string
		edit func(*CreateRequest)
	}{
		{"client", func(r *CreateRequest) { r.Client = "superbased-sdk-python" }},
		{"client version", func(r *CreateRequest) { r.ClientVersion = "0.3.0" }},
		{"project", func(r *CreateRequest) { r.ProjectName = "x" }},
		{"redeem hash", func(r *CreateRequest) { r.RedeemHash = fixtureRedeemHash }},
	}
	for _, c := range cases {
		req := base
		c.edit(&req)
		_, err := ValidateCreate(req)
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Code != "bad_request" {
			t.Errorf("%s: err %v, want bad_request (a body mixing the two purposes)", c.name, err)
		}
	}
	explicit := base
	explicit.Purpose = "machine"
	if got, err := ValidateCreate(explicit); err != nil || got.Purpose != PurposeMachine {
		t.Fatalf("explicit machine: %+v %v", got, err)
	}
}

func TestDeviceCode(t *testing.T) {
	t.Parallel()
	code, hash, err := NewDeviceCode(bytes.NewReader(bytes.Repeat([]byte{7}, DeviceCodeBytes)))
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 43 || strings.ContainsAny(code, "+/=") {
		t.Fatalf("code %q is not 32 bytes of base64url", code)
	}
	sum := sha256.Sum256([]byte(code))
	if hash != hex.EncodeToString(sum[:]) || hash == code {
		t.Fatalf("hash %q is not the code's SHA-256", hash)
	}
	if _, _, err := NewDeviceCode(bytes.NewReader(make([]byte, 5))); err == nil {
		t.Fatal("a short random source minted a code")
	}
	cases := []struct {
		name            string
		stored, present string
		want            bool
	}{
		{"match", hash, code, true},
		{"other code", hash, code[:42] + "A", false},
		{"empty presented", hash, "", false},
		{"empty stored", "", code, false},
		{"oversized", hash, strings.Repeat("a", 129), false},
		{"the hash itself", hash, hash, false},
	}
	for _, c := range cases {
		if got := DeviceCodeMatches(c.stored, c.present); got != c.want {
			t.Errorf("%s: DeviceCodeMatches = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestBearerToken(t *testing.T) {
	t.Parallel()
	cases := []struct{ header, want string }{
		{"Bearer abc", "abc"},
		{"bearer  abc ", "abc"},
		{"Basic abc", ""},
		{"Bearer", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := BearerToken(c.header); got != c.want {
			t.Errorf("BearerToken(%q) = %q, want %q", c.header, got, c.want)
		}
	}
}

func TestKeyGrantDecision(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		f    KeyGrantFacts
		want KeyGrantPoll
	}{
		{"pending", KeyGrantFacts{Status: StatusPending, TargetReady: true, Now: at}, KeyGrantNone},
		{"declined", KeyGrantFacts{Status: StatusDeclined, Now: at}, KeyGrantNone},
		{"expired", KeyGrantFacts{Status: StatusExpired, Now: at}, KeyGrantNone},
		{"too many", KeyGrantFacts{Status: StatusApproved, Deliveries: 3, ApprovedAt: at, TargetReady: true, Now: at.Add(time.Minute)}, KeyGrantExhausted},
		{"too late, delivered once", KeyGrantFacts{Status: StatusApproved, Deliveries: 1, ApprovedAt: at, TargetReady: true, Now: at.Add(DeliveryWindow + time.Second)}, KeyGrantExhausted},
		{"too late, never delivered", KeyGrantFacts{Status: StatusApproved, ApprovedAt: at, TargetReady: true, Now: at.Add(DeliveryWindow + time.Second)}, KeyGrantWindowClosed},
		{"too late, never ready", KeyGrantFacts{Status: StatusApproved, ApprovedAt: at, Now: at.Add(DeliveryWindow + time.Second)}, KeyGrantWindowClosed},
		{"not ready", KeyGrantFacts{Status: StatusApproved, ApprovedAt: at, Now: at.Add(time.Minute)}, KeyGrantNotReady},
		{"first", KeyGrantFacts{Status: StatusApproved, ApprovedAt: at, TargetReady: true, Now: at.Add(time.Second)}, KeyGrantDeliver},
		{"third", KeyGrantFacts{Status: StatusApproved, Deliveries: 2, ApprovedAt: at, TargetReady: true, Now: at.Add(DeliveryWindow)}, KeyGrantDeliver},
	}
	for _, c := range cases {
		if got := KeyGrantDecision(c.f); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestSDKKeyDisclosure(t *testing.T) {
	t.Parallel()
	p, ok := SDKKeyDisclosure(KindPersonal, "ignored")
	if !ok || p.Level != ShareSummary || p.Version != SDKKeyDisclosureVersion || len(p.SHA256) != 64 {
		t.Fatalf("personal = %+v", p)
	}
	team, ok := SDKKeyDisclosure(KindTeam, "Acme‮")
	if !ok || team.Level != ShareFull || !strings.Contains(team.Text, "Acme's admins can read") || strings.Contains(team.Text, "‮") {
		t.Fatalf("team = %+v", team)
	}
	for _, d := range []DisclosureText{p, team} {
		for _, want := range []string{
			"send traces, logs and metrics", "ask admission", "prompts and trace costs", "write scores",
			SDKKeyLine, "only its user account can read", "expires in 90 days",
			"run setup with --forget on that computer", "Approve only a request you started on your own computer",
		} {
			if !strings.Contains(d.Text, want) {
				t.Errorf("%s disclosure lacks %q: %s", d.Level, want, d.Text)
			}
		}
		// No member-facing list of SDK keys exists: the text never sends a
		// member to one.
		if strings.Contains(d.Text, "under your SDK keys") {
			t.Errorf("%s disclosure names a list of the member's SDK keys: %s", d.Level, d.Text)
		}
		// The hosted AI gateway ships dark: the page never names it.
		if strings.Contains(strings.ToLower(d.Text+d.Title), "gateway") {
			t.Errorf("%s disclosure names a gateway: %s", d.Level, d.Text)
		}
		sum := sha256.Sum256([]byte(SDKKeyDisclosureVersion + "\n" + d.Text))
		if d.SHA256 != hex.EncodeToString(sum[:]) {
			t.Errorf("%s digest does not cover version and text", d.Level)
		}
	}
	// How to end the key sooner: the personal dashboard's owner is its admin
	// and revokes it on Machine identities; a team member asks an admin.
	if !strings.Contains(p.Text, "or revoke it on the dashboard's Machine identities page.") {
		t.Errorf("personal disclosure does not name Machine identities: %s", p.Text)
	}
	if !strings.Contains(team.Text, "or ask an admin of Acme to revoke it.") || strings.Contains(team.Text, "Machine identities") {
		t.Errorf("team disclosure does not send the member to an admin: %s", team.Text)
	}
	if _, ok := SDKKeyDisclosure("org", "x"); ok {
		t.Fatal("an unknown kind rendered")
	}
	// The purpose table dispatches: a machine keeps its texts, an SDK key
	// gets these, and the two never share a version.
	m, _ := DisclosureFor(PurposeMachine, KindTeam, "Acme")
	s, _ := DisclosureFor(PurposeSDKKey, KindTeam, "Acme")
	if m.Version != DisclosureVersion || s.Version != SDKKeyDisclosureVersion || m.SHA256 == s.SHA256 {
		t.Fatalf("DisclosureFor machine %+v sdk %+v", m, s)
	}
	if _, ok := DisclosureFor("other", KindTeam, "Acme"); ok {
		t.Fatal("an unknown purpose rendered")
	}
}
