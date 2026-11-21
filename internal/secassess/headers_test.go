package secassess

import (
	"regexp"
	"strings"
	"testing"
)

func TestCredentialHeaderName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"Authorization", true},
		{"Proxy-Authorization", true},
		{"Cookie", true},
		{"Set-Cookie", true},
		{"X-Api-Key", true},
		{"Api-Key", true},
		{"X-Access-Token", true},
		{"X-Session", true},
		{"X-Session-Id", true},
		{"X-Auth-Token", true},
		{"X-Csrf-Token", true},
		{"X-XSRF-TOKEN", true},
		{"X-Signature", true},
		{"X-Hub-Signature-256", true},
		{"X-Amz-Security-Token", true},
		{"X-OTP", true},
		{"Sec-WebSocket-Key", true},
		{"Idempotency-Key", true},
		{"X-Jwt-Assertion", true},
		{"X-Password-Reset", true},
		{"X-Hmac", true},
		{"Content-Type", false},
		{"Cache-Control", false},
		{"Content-Security-Policy", false},
		{"Location", false},
		{"Keep-Alive", false},
		{"Content-Disposition", false},
		{"X-Request-Id", false},
		{"X-Error-Code", false},
		{"WWW-Authenticate", false},
		{"Proxy-Authenticate", false},
		{"Access-Control-Allow-Credentials", false},
		{"", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CredentialHeaderName(c.name); got != c.want {
				t.Fatalf("CredentialHeaderName(%q) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}

func TestCredentialHeaderValue(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"Authorization", "Bearer opaquetokenvalue123456", "Bearer [REDACTED]"},
		{"authorization", "Basic dGVzdDp0ZXN0", "Basic [REDACTED]"},
		{"Authorization", "opaquetokenvalue", "[REDACTED]"},
		{"Authorization", "averyverylongschemeword abc", "[REDACTED]"},
		{"Proxy-Authorization", "Basic dGVzdDp0ZXN0", "Basic [REDACTED]"},
		{"Cookie", "a=1; b=two", "a=[REDACTED]; b=[REDACTED]"},
		{"Cookie", "novalue", "[REDACTED]"},
		{"Set-Cookie", "sid=abc123; Path=/; HttpOnly; SameSite=Lax", "sid=[REDACTED]; Path=/; HttpOnly; SameSite=Lax"},
		{"Set-Cookie", "sid=abc123", "sid=[REDACTED]"},
		{"Set-Cookie", "abc123; Path=/", "[REDACTED]; Path=/"},
		{"X-Access-Token", "opaquetokenvalue123456", "[REDACTED]"},
		{"X-Session", "mysessionvalue12345", "[REDACTED]"},
		{"Api-Key", "topsecretkeyvalue1", "[REDACTED]"},
		{"X-Api-Key", "", ""},
		{"X-Api-Key", "  ", ""},
	}
	for _, c := range cases {
		t.Run(c.name+" "+c.in, func(t *testing.T) {
			if got := credentialHeaderValue(c.name, c.in); got != c.want {
				t.Fatalf("credentialHeaderValue(%q, %q) = %q, want %q", c.name, c.in, got, c.want)
			}
		})
	}
}

// nameAwareRedactor is a redactor that, like the real one, only sees a secret
// when the line names it ("key: value") and not in a bare value.
func nameAwareRedactor(s string) string {
	return regexp.MustCompile(`(?i)(\bx-custom-info\s*[:=]\s*)\S+`).ReplaceAllString(s, "${1}[REDACTED]")
}

func TestStoredProbeHeaders(t *testing.T) {
	const clear = "opaquetokenvalue123456"
	rec := func(req, resp []ProbeHeader) ProbeRecord {
		return evRec(1, "", func(r *ProbeRecord) { r.ReqHeaders, r.RespHeaders = req, resp })
	}
	cases := []struct {
		name string
		in   ProbeRecord
		want map[string]string // header name -> stored value, over both lists
	}{
		{"credential names are hidden whatever the value looks like", rec(
			[]ProbeHeader{{N: "X-Access-Token", V: clear}, {N: "X-Session", V: "mysessionvalue12345"}, {N: "Api-Key", V: "topsecretkeyvalue1"}},
			[]ProbeHeader{{N: "X-Access-Token", V: clear}},
		), map[string]string{"X-Access-Token": "[REDACTED]", "X-Session": "[REDACTED]", "Api-Key": "[REDACTED]"}},
		{"a hand-written authorization keeps only its scheme", rec(
			[]ProbeHeader{{N: "Authorization", V: "Bearer " + clear}}, nil,
		), map[string]string{"Authorization": "Bearer [REDACTED]"}},
		{"set-cookie keeps its attributes", rec(
			nil, []ProbeHeader{{N: "Set-Cookie", V: "sid=" + clear + "; Path=/; HttpOnly"}},
		), map[string]string{"Set-Cookie": "sid=[REDACTED]; Path=/; HttpOnly"}},
		{"an ordinary header is redacted with its name in front", rec(
			[]ProbeHeader{{N: "X-Custom-Info", V: clear}, {N: "Content-Type", V: "application/json"}}, nil,
		), map[string]string{"X-Custom-Info": "[REDACTED]", "Content-Type": "application/json"}},
		{"the challenge header is shown", rec(
			nil, []ProbeHeader{{N: "WWW-Authenticate", V: `Basic realm="app"`}},
		), map[string]string{"WWW-Authenticate": `Basic realm="app"`}},
		{"an empty value stays empty", rec(
			[]ProbeHeader{{N: "X-Api-Key", V: ""}}, nil,
		), map[string]string{"X-Api-Key": ""}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := StoredProbe(c.in, nameAwareRedactor)
			seen := map[string]bool{}
			for _, h := range append(append([]ProbeHeader{}, got.ReqHeaders...), got.RespHeaders...) {
				want, ok := c.want[h.N]
				if !ok {
					continue
				}
				seen[h.N] = true
				if h.V != want {
					t.Errorf("%s = %q, want %q", h.N, h.V, want)
				}
				if strings.Contains(h.V, clear) {
					t.Errorf("%s still holds the clear value: %q", h.N, h.V)
				}
			}
			for n := range c.want {
				if !seen[n] {
					t.Errorf("header %s is missing from %+v", n, got)
				}
			}
		})
	}
	t.Run("the lists are never nil", func(t *testing.T) {
		got := StoredProbe(evRec(1, "", func(r *ProbeRecord) { r.ReqHeaders, r.RespHeaders = nil, nil }), nameAwareRedactor)
		if got.ReqHeaders == nil || got.RespHeaders == nil {
			t.Fatalf("lists %v / %v", got.ReqHeaders, got.RespHeaders)
		}
	})
	t.Run("the input is not modified", func(t *testing.T) {
		in := rec([]ProbeHeader{{N: "X-Session", V: "mysessionvalue12345"}}, nil)
		StoredProbe(in, nameAwareRedactor)
		if in.ReqHeaders[0].V != "mysessionvalue12345" {
			t.Fatalf("input changed: %+v", in.ReqHeaders)
		}
	})
}

func TestShownProbes(t *testing.T) {
	const clear = "opaquetokenvalue123456"
	in := []ProbeRecord{evRec(1, "", func(r *ProbeRecord) {
		r.ReqHeaders = []ProbeHeader{{N: "X-Access-Token", V: clear}, {N: "X-Custom-Info", V: clear}}
		r.Method = "FETCH"
	})}
	t.Run("a hand-edited stored copy cannot show a credential header", func(t *testing.T) {
		out, _ := ShownProbes(in, nameAwareRedactor)
		for _, h := range out[0].ReqHeaders {
			if h.V != "[REDACTED]" {
				t.Errorf("%s = %q", h.N, h.V)
			}
		}
		if in[0].ReqHeaders[0].V != clear {
			t.Errorf("the input was changed: %+v", in[0].ReqHeaders)
		}
	})
	t.Run("hiding off shows the stored copy as it is", func(t *testing.T) {
		out, hidden := ShownProbes(in, nil)
		if hidden != 0 || out[0].ReqHeaders[0].V != clear {
			t.Fatalf("hidden %d, headers %+v", hidden, out[0].ReqHeaders)
		}
	})
	t.Run("a method that is not one the helper sends is redacted like any text", func(t *testing.T) {
		out, _ := ShownProbes([]ProbeRecord{evRec(1, "", func(r *ProbeRecord) { r.Method = "sk-live-FAKE0123456789abcdef" })}, rxRedactor)
		if strings.Contains(out[0].Method, "FAKE0123") {
			t.Fatalf("method %q", out[0].Method)
		}
	})
}

// TestProbeRecordMethodAndAccount: a log line holds a method the helper sends
// or a bad_method refusal, and an account label of the shape --account takes.
func TestProbeRecordMethodAndAccount(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*ProbeRecord)
		ok   bool
	}{
		{"a plain GET", func(r *ProbeRecord) {}, true},
		{"every method the helper sends", func(r *ProbeRecord) { r.Method = "OPTIONS" }, true},
		{"a method the helper does not send, sent", func(r *ProbeRecord) { r.Method = "FETCH" }, false},
		{"a secret as a method, sent", func(r *ProbeRecord) { r.Method = "0123456789abcdef" }, false},
		{"an empty method", func(r *ProbeRecord) { r.Method = "" }, false},
		{"a bad_method refusal keeps what was asked for", func(r *ProbeRecord) {
			r.Method, r.Sent, r.Refused, r.Status, r.Cost = "FETCH", false, "bad_method", 0, 0
		}, true},
		{"a label", func(r *ProbeRecord) { r.Account = "alice.test-2_x" }, true},
		{"a label with a space", func(r *ProbeRecord) { r.Account = "alice smith" }, false},
		{"a label of 41 characters", func(r *ProbeRecord) { r.Account = strings.Repeat("a", 41) }, false},
		{"a label that is a secret shape", func(r *ProbeRecord) { r.Account = "sk-live-FAKE0123456789abcdef!" }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := ParseProbeLog(evLog(t, evRec(1, "a", c.mut)))
			if got := l.Problem == ""; got != c.ok {
				t.Fatalf("problem %q, want ok=%v", l.Problem, c.ok)
			}
		})
	}
}
