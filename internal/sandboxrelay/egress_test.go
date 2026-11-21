package sandboxrelay

import (
	"errors"
	"strings"
	"testing"
)

// TestEgressRefusalReportRoundTrip is one row per payload rule.
func TestEgressRefusalReportRoundTrip(t *testing.T) {
	t.Parallel()
	ok := EgressRefusalReport{Host: "evil.example", Port: 443, Rule: "allow-list-miss", Key: "terminal.sandbox.egress_allow_hosts", AtMS: 1793400000000}
	b, err := EncodeEgressRefusalReport(ok)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeEgressRefusalReport(b)
	ok.V = EgressRefusalVersion
	if err != nil || got != ok {
		t.Fatalf("round trip %+v %v", got, err)
	}
	cases := []struct {
		name string
		raw  string
	}{
		{"unknown field", `{"v":1,"host":"h","port":1,"rule":"ssrf-floor","at_ms":1,"run_id":"x"}`},
		{"wrong version", `{"v":2,"host":"h","port":1,"rule":"ssrf-floor","at_ms":1}`},
		{"no host", `{"v":1,"host":"","port":1,"rule":"ssrf-floor","at_ms":1}`},
		{"host with a space", `{"v":1,"host":"a b","port":1,"rule":"ssrf-floor","at_ms":1}`},
		{"host with an escape", `{"v":1,"host":"a\u001b[2J","port":1,"rule":"ssrf-floor","at_ms":1}`},
		{"host too long", `{"v":1,"host":"` + strings.Repeat("a", 254) + `","port":1,"rule":"ssrf-floor","at_ms":1}`},
		{"port out of range", `{"v":1,"host":"h","port":70000,"rule":"ssrf-floor","at_ms":1}`},
		{"rule upper case", `{"v":1,"host":"h","port":1,"rule":"SSRF","at_ms":1}`},
		{"no rule", `{"v":1,"host":"h","port":1,"rule":"","at_ms":1}`},
		{"key with a space", `{"v":1,"host":"h","port":1,"rule":"ssrf-floor","key":"a b","at_ms":1}`},
		{"negative lost", `{"v":1,"host":"h","port":1,"rule":"ssrf-floor","at_ms":1,"lost":-1}`},
		{"lost over the bound", `{"v":1,"host":"h","port":1,"rule":"ssrf-floor","at_ms":1,"lost":1073741825}`},
		{"negative closed", `{"v":1,"host":"h","port":1,"rule":"ssrf-floor","at_ms":1,"closed":-1}`},
		{"negative time", `{"v":1,"host":"h","port":1,"rule":"ssrf-floor","at_ms":-1}`},
		{"trailing data", `{"v":1,"host":"h","port":1,"rule":"ssrf-floor","at_ms":1}{}`},
		{"over the cap", `{"v":1,"host":"h","port":1,"rule":"ssrf-floor","at_ms":1,"x":"` + strings.Repeat("a", MaxEgressRefusalReport) + `"}`},
	}
	for _, tc := range cases {
		if _, err := DecodeEgressRefusalReport([]byte(tc.raw)); !errors.Is(err, ErrHookSchema) {
			t.Errorf("%s: err %v, want ErrHookSchema", tc.name, err)
		}
	}
}

// TestEgressRefusalReportCarriesLinkLoss (F-012, audit finding N4-A4): the
// lost and closed counts round-trip, and a report without them encodes
// exactly as before the fields existed (they are omitted at zero).
func TestEgressRefusalReportCarriesLinkLoss(t *testing.T) {
	t.Parallel()
	rep := EgressRefusalReport{Host: "h", Port: 1, Rule: "ssrf-floor", AtMS: 1, Lost: 3, Closed: 7}
	b, err := EncodeEgressRefusalReport(rep)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeEgressRefusalReport(b)
	if err != nil || got.Lost != 3 || got.Closed != 7 {
		t.Fatalf("round trip %+v %v", got, err)
	}
	plain, err := EncodeEgressRefusalReport(EgressRefusalReport{Host: "h", Port: 1, Rule: "ssrf-floor", AtMS: 1})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"v":1,"host":"h","port":1,"rule":"ssrf-floor","at_ms":1}`; string(plain) != want {
		t.Fatalf("a report with no loss encodes %s, want %s", plain, want)
	}
}

// TestBoundEgressHost (audit N1-A2): a host over the bound is cut with the
// marker and then encodes; a host within it is unchanged.
func TestBoundEgressHost(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, host, want string
	}{
		{"within the bound", "evil.example", "evil.example"},
		{"at the bound", strings.Repeat("a", maxEgressHost), strings.Repeat("a", maxEgressHost)},
		{"over the bound", strings.Repeat("a", 300), strings.Repeat("a", maxEgressHost-len(EgressHostTruncated)) + EgressHostTruncated},
	}
	for _, tc := range cases {
		got := BoundEgressHost(tc.host)
		if got != tc.want {
			t.Errorf("%s: %q", tc.name, got)
		}
		if _, err := EncodeEgressRefusalReport(EgressRefusalReport{Host: got, Rule: "allow-list-miss", AtMS: 1}); err != nil {
			t.Errorf("%s: encode: %v", tc.name, err)
		}
	}
}

// TestEgressRefusalKindIsHelperOnly: the kind is in the vocabulary, a box
// may not send it, and it is never replayed.
func TestEgressRefusalKindIsHelperOnly(t *testing.T) {
	t.Parallel()
	if !KindEgressRefusal.Valid() || BoxKind(KindEgressRefusal) {
		t.Fatal("egress_refusal must be valid and helper-only")
	}
	payload, _ := EncodeEgressRefusalReport(EgressRefusalReport{Host: "h", Rule: "ssrf-floor"})
	msg, err := EncodeHookRequest(HookRequest{Kind: KindEgressRefusal, Args: []string{"claude-code"}, Stdin: payload})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeHookRequest(msg, RequestRules{}); err != nil {
		t.Fatalf("the link refused the helper's report: %v", err)
	}
	if _, err := DecodeHookRequest(msg, RequestRules{Kinds: BoxKind}); !errors.Is(err, ErrHookSchema) {
		t.Fatalf("a box channel accepted the report: %v", err)
	}
	replay, _ := EncodeHookRequest(HookRequest{Kind: KindEgressRefusal, Args: []string{"claude-code"}, Replay: true, Stdin: payload})
	if _, err := DecodeHookRequest(replay, RequestRules{}); !errors.Is(err, ErrHookSchema) {
		t.Fatalf("a replayed report was accepted: %v", err)
	}
}

// TestSafeEgressHost (audit finding FU5-R1): one row per host shape; every
// result passes the report's validation, so no refusal is unencodable.
func TestSafeEgressHost(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, host, want string
	}{
		{"plain name", "evil.example", "evil.example"},
		{"bracketed IPv6", "[::1]", "[::1]"},
		{"UTF-8 name", "\u00e9.example", "%C3%A9.example"},
		{"space", "a b", "a%20b"},
		{"control byte", "a\x1bb", "a%1Bb"},
		{"DEL", "a\x7fb", "a%7Fb"},
		{"empty", "", "-"},
	}
	for _, c := range cases {
		if got := SafeEgressHost(c.host); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	for _, h := range []string{"", "\u00e9.example", strings.Repeat("\u00e9", 300), strings.Repeat("a", 400), "\x00\x01 \x7f\xff"} {
		if _, err := EncodeEgressRefusalReport(EgressRefusalReport{Host: SafeEgressHost(h), Port: 443, Rule: "allow-list-miss", AtMS: 1}); err != nil {
			t.Errorf("SafeEgressHost(%q) does not encode: %v", h, err)
		}
	}
}
