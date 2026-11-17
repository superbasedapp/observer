package connectflow

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestTransition(t *testing.T) {
	t.Parallel()
	cases := []struct {
		from       Status
		ev         Event
		to         Status
		withTarget bool
		ok         bool
	}{
		{StatusPending, EventConnect, StatusApproved, true, true},
		{StatusPending, EventNotNow, StatusApproved, false, true},
		{StatusPending, EventDecline, StatusDeclined, false, true},
		{StatusApproved, EventConnect, StatusApproved, false, false},
		{StatusApproved, EventDecline, StatusApproved, false, false},
		{StatusDeclined, EventConnect, StatusDeclined, false, false},
		{StatusExpired, EventConnect, StatusExpired, false, false},
		{StatusExpired, EventNotNow, StatusExpired, false, false},
		{StatusPending, Event("other"), StatusPending, false, false},
	}
	for _, c := range cases {
		to, wt, ok := Transition(c.from, c.ev)
		if to != c.to || wt != c.withTarget || ok != c.ok {
			t.Errorf("Transition(%s, %s) = %s %v %v, want %s %v %v", c.from, c.ev, to, wt, ok, c.to, c.withTarget, c.ok)
		}
	}
}

func TestEffectiveStatus(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		stored Status
		exp    time.Time
		want   Status
	}{
		{StatusPending, now.Add(time.Second), StatusPending},
		{StatusPending, now, StatusExpired},
		{StatusPending, now.Add(-time.Minute), StatusExpired},
		{StatusApproved, now.Add(-time.Hour), StatusApproved},
		{StatusDeclined, now.Add(-time.Hour), StatusDeclined},
	}
	for _, c := range cases {
		if got := EffectiveStatus(c.stored, c.exp, now); got != c.want {
			t.Errorf("EffectiveStatus(%s, %s) = %s, want %s", c.stored, c.exp, got, c.want)
		}
	}
}

func TestDeliveryDecision(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		f    DeliveryFacts
		want Delivery
	}{
		{"pending", DeliveryFacts{Status: StatusPending, Now: at}, DeliverNone},
		{"declined", DeliveryFacts{Status: StatusDeclined, Now: at}, DeliverNone},
		{"first", DeliveryFacts{Status: StatusApproved, ApprovedAt: at, Now: at.Add(time.Second)}, DeliverSignIn},
		{"third", DeliveryFacts{Status: StatusApproved, Deliveries: 2, ApprovedAt: at, Now: at.Add(time.Minute)}, DeliverSignIn},
		{"too many", DeliveryFacts{Status: StatusApproved, Deliveries: 3, ApprovedAt: at, Now: at.Add(time.Minute)}, DeliverExhausted},
		{"edge of window", DeliveryFacts{Status: StatusApproved, ApprovedAt: at, Now: at.Add(DeliveryWindow)}, DeliverSignIn},
		{"too late", DeliveryFacts{Status: StatusApproved, ApprovedAt: at, Now: at.Add(DeliveryWindow + time.Second)}, DeliverExhausted},
	}
	for _, c := range cases {
		if got := DeliveryDecision(c.f); got != c.want {
			t.Errorf("%s: DeliveryDecision = %s, want %s", c.name, got, c.want)
		}
	}
}

var codeShape = regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{4}-[0-9]{4}$`)

func TestNewUserCode(t *testing.T) {
	t.Parallel()
	for i := 0; i < 200; i++ {
		c, err := NewUserCode(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if !codeShape.MatchString(c) {
			t.Fatalf("code %q has the wrong shape", c)
		}
	}
	// Rejection sampling skips bytes past the alphabet's last whole cycle.
	src := bytes.NewReader([]byte{255, 0, 1, 2, 3, 255, 0, 1, 2, 3})
	c, err := NewUserCode(src)
	if err != nil || c != "BCDF-0123" {
		t.Fatalf("NewUserCode(fixed) = %q, %v; want BCDF-0123", c, err)
	}
	if _, err := NewUserCode(bytes.NewReader([]byte{1, 2})); err == nil {
		t.Fatal("a short reader must fail")
	}
}

func TestNormalizeUserCode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"KTRW-4821", "KTRW-4821", true},
		{"ktrw4821", "KTRW-4821", true},
		{" kt rw - 48 21 ", "KTRW-4821", true},
		{"KTRW-482", "", false},
		{"KTRW-48211", "", false},
		{"KTOW-4821", "", false}, // O is not in the alphabet
		{"KTRW-48A1", "", false},
		{"", "", false},
		{"AEIO-1234", "", false},
	}
	for _, c := range cases {
		got, err := NormalizeUserCode(c.in)
		if c.ok != (err == nil) || got != c.want {
			t.Errorf("NormalizeUserCode(%q) = %q, %v", c.in, got, err)
		}
		if err != nil && !errors.Is(err, ErrUserCode) {
			t.Errorf("NormalizeUserCode(%q) error %v is not ErrUserCode", c.in, err)
		}
	}
}

func validCreate() CreateRequest {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return CreateRequest{
		DevicePublicKey: base64.RawURLEncoding.EncodeToString(pub),
		MachineName:     "studio-mac",
		OS:              "darwin",
		Arch:            "arm64",
		ObserverVersion: "1.40.0",
		TargetHint:      "",
	}
}

func TestValidateCreate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		edit  func(*CreateRequest)
		field string
	}{
		{"valid", func(*CreateRequest) {}, ""},
		{"valid with hint", func(r *CreateRequest) { r.TargetHint = " Acme " }, ""},
		{"bad key encoding", func(r *CreateRequest) { r.DevicePublicKey = "!!" }, "device_public_key"},
		{"short key", func(r *CreateRequest) { r.DevicePublicKey = base64.RawURLEncoding.EncodeToString([]byte("short")) }, "device_public_key"},
		{"empty name", func(r *CreateRequest) { r.MachineName = " ‎\t" }, "machine_name"},
		{"long name", func(r *CreateRequest) { r.MachineName = strings.Repeat("a", 65) }, "machine_name"},
		{"bad os", func(r *CreateRequest) { r.OS = "Darwin" }, "os"},
		{"empty arch", func(r *CreateRequest) { r.Arch = "" }, "arch"},
		{"bad version", func(r *CreateRequest) { r.ObserverVersion = "1.0 beta" }, "observer_version"},
		{"personal hint", func(r *CreateRequest) { r.TargetHint = "u-abcdefgh" }, "target_hint"},
		{"bad hint", func(r *CreateRequest) { r.TargetHint = "-acme" }, "target_hint"},
	}
	for _, c := range cases {
		in := validCreate()
		c.edit(&in)
		out, err := ValidateCreate(in)
		if c.field == "" {
			if err != nil {
				t.Errorf("%s: unexpected error %v", c.name, err)
			}
			if len(out.PublicKey) != ed25519.PublicKeySize {
				t.Errorf("%s: key not decoded", c.name)
			}
			continue
		}
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field != c.field || fe.Code != "invalid_"+c.field {
			t.Errorf("%s: error %v, want field %s", c.name, err, c.field)
		}
	}
	in := validCreate()
	in.TargetHint = " Acme "
	out, _ := ValidateCreate(in)
	if out.TargetHint != "acme" {
		t.Errorf("hint not normalized: %q", out.TargetHint)
	}
}

func TestCleanMachineName(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"studio-mac", "studio-mac"},
		{"  two   words \n", "two words"},
		{"evil‮gnp.exe", "evilgnp.exe"},
		{"zero​width", "zerowidth"},
		{"bell\x07", "bell"},
		{"Café ☕", "Café ☕"},
	}
	for _, c := range cases {
		if got := CleanMachineName(c.in); got != c.want {
			t.Errorf("CleanMachineName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNetworkPrefix(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"203.0.113.77", "203.0.113.0/24"},
		{"::ffff:203.0.113.77", "203.0.113.0/24"},
		{"2001:db8:1:2::5", "2001:db8:1::/48"},
		{"not an ip", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := NetworkPrefix(c.in); got != c.want {
			t.Errorf("NetworkPrefix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if !SameNetwork("203.0.113.0/24", "203.0.113.9") {
		t.Error("same /24 must be the same network")
	}
	if SameNetwork("203.0.113.0/24", "198.51.100.9") || SameNetwork("", "203.0.113.9") {
		t.Error("different or unknown networks must not match")
	}
}

func TestShareLevelAndDisclosure(t *testing.T) {
	t.Parallel()
	if l, ok := ShareLevelFor(KindPersonal); !ok || l != ShareSummary {
		t.Errorf("personal = %s %v", l, ok)
	}
	if l, ok := ShareLevelFor(KindTeam); !ok || l != ShareFull {
		t.Errorf("team = %s %v", l, ok)
	}
	if _, ok := ShareLevelFor("other"); ok {
		t.Error("unknown kind must not map")
	}
	sum, ok := Disclosure(ShareSummary, "ignored")
	if !ok || sum.Title != "Summary only" || !strings.Contains(sum.Text, "Never prompts") || sum.Version != DisclosureVersion {
		t.Errorf("summary disclosure = %+v", sum)
	}
	full, ok := Disclosure(ShareFull, "Acme")
	if !ok || full.Text != "Acme's admins can read full detail: prompts, responses and file paths." {
		t.Errorf("full disclosure = %+v", full)
	}
	other, _ := Disclosure(ShareFull, "Other")
	if other.SHA256 == full.SHA256 || len(full.SHA256) != 64 {
		t.Error("the digest must bind the rendered text")
	}
	if _, ok := Disclosure("none", "x"); ok {
		t.Error("unknown level must not render")
	}
	for _, d := range disclosureTexts {
		if strings.ContainsRune(d.template, '—') {
			t.Errorf("%s disclosure carries an em dash", d.level)
		}
	}
}
