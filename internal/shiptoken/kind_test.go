package shiptoken

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestKindTable(t *testing.T) {
	for _, c := range []struct {
		kind          Kind
		prefix, idPfx string
		def, min, max time.Duration
		rowCap, node  bool
		maxActive     int
	}{
		{KindCloudSession, "sbocs_", "cst_", 8 * time.Hour, 10 * time.Minute, 7 * 24 * time.Hour, true, true, 20},
		{KindTelemetry, "sbotel_", "otk_", 90 * 24 * time.Hour, 24 * time.Hour, 365 * 24 * time.Hour, false, false, 10},
	} {
		t.Run(string(c.kind), func(t *testing.T) {
			r, ok := RuleFor(c.kind)
			if !ok {
				t.Fatal("no row")
			}
			if r.Prefix != c.prefix || r.IDPrefix != c.idPfx || r.DefaultLifetime != c.def || r.MinLifetime != c.min ||
				r.MaxLifetime != c.max || r.LifetimeRowCap != c.rowCap || r.RequiresNode != c.node || r.MaxActive != c.maxActive {
				t.Fatalf("row = %+v", r)
			}
		})
	}
	if len(KindRules()) != 2 {
		t.Fatalf("kinds = %d, want 2", len(KindRules()))
	}
	if ValidKind("other") {
		t.Fatal("unknown kind valid")
	}
}

func TestKindPrefixesNeverCross(t *testing.T) {
	cs, err := GenerateKind(bytes.NewReader(bytes.Repeat([]byte{1}, 64)), KindCloudSession)
	if err != nil {
		t.Fatal(err)
	}
	tel, err := GenerateKind(bytes.NewReader(bytes.Repeat([]byte{2}, 64)), KindTelemetry)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		tok  string
		kind Kind
		ok   bool
	}{
		{"cloud token as cloud", cs.Token, KindCloudSession, true},
		{"telemetry token as telemetry", tel.Token, KindTelemetry, true},
		{"cloud token as telemetry", cs.Token, KindTelemetry, false},
		{"telemetry token as cloud", tel.Token, KindCloudSession, false},
		{"truncated telemetry", tel.Token[:len(tel.Token)-1], KindTelemetry, false},
		{"unknown kind", tel.Token, Kind("x"), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseKind(c.tok, c.kind)
			if (err == nil) != c.ok {
				t.Fatalf("ParseKind err = %v, want ok=%v", err, c.ok)
			}
			_, err = FromAuthorizationKind("bearer "+c.tok, c.kind)
			if (err == nil) != c.ok {
				t.Fatalf("FromAuthorizationKind err = %v, want ok=%v", err, c.ok)
			}
		})
	}
	// The legacy parser never accepts a telemetry token.
	if _, err := Parse(tel.Token); err == nil {
		t.Fatal("Parse accepted a telemetry token")
	}
	if !strings.HasPrefix(tel.ID, TelemetryIDPrefix) || !ValidIDKind(tel.ID, KindTelemetry) || ValidIDKind(tel.ID, KindCloudSession) || ValidID(tel.ID) {
		t.Fatalf("telemetry id %q shape wrong", tel.ID)
	}
	if !ValidIDKind(cs.ID, KindCloudSession) || ValidIDKind(cs.ID, KindTelemetry) {
		t.Fatalf("cloud id %q shape wrong", cs.ID)
	}
	if _, err := GenerateKind(bytes.NewReader(nil), "x"); err == nil {
		t.Fatal("unknown kind minted")
	}
}

func TestClampLifetimeKind(t *testing.T) {
	day := 24 * time.Hour
	for _, c := range []struct {
		name string
		kind Kind
		in   time.Duration
		want time.Duration
	}{
		{"telemetry unset", KindTelemetry, 0, 90 * day},
		{"telemetry below floor", KindTelemetry, time.Hour, day},
		{"telemetry above ceiling", KindTelemetry, 400 * day, 365 * day},
		{"telemetry in range", KindTelemetry, 30 * day, 30 * day},
		{"cloud above ceiling", KindCloudSession, 30 * day, 7 * day},
		{"unknown kind uses cloud bounds", Kind("x"), 30 * day, 7 * day},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := ClampLifetimeKind(c.kind, c.in); got != c.want {
				t.Fatalf("got %v want %v", got, c.want)
			}
		})
	}
}

func TestTelemetryPosture(t *testing.T) {
	for _, c := range []struct {
		name              string
		enrolled, managed bool
		want              string
	}{
		{"managed enrolment", true, true, PostureFullContent},
		{"managed by the member switch, no enrolment", false, true, PostureFullContent},
		{"individual enrolment", true, false, PostureMetadataOnly},
		{"no enrolment follows the org", false, false, TelemetryUnenrolledPosture},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := TelemetryPosture(c.enrolled, c.managed); got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestTelemetryRefusalCode(t *testing.T) {
	for status, want := range map[string]string{
		StatusActive: "", StatusExpired: CodeTelemetryExpired, StatusRevoked: CodeTelemetryRevoked, "?": CodeTelemetryInvalid,
	} {
		if got := TelemetryRefusalCode(status); got != want {
			t.Fatalf("%s: got %q want %q", status, got, want)
		}
	}
}
