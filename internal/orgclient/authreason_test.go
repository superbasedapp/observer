package orgclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// clientWithLogBuffer returns a bare Client whose logger writes into a buffer.
// reportAuthFailure touches no other field, so this stays a unit test — the
// point is the diagnosis, not the push machinery around it.
func clientWithLogBuffer() (*Client, *bytes.Buffer) {
	var buf bytes.Buffer
	return &Client{
		logger: slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}, &buf
}

func TestParseAuthFailure(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantReason string
		wantFP     string
	}{
		{
			name:       "current server carries the discriminator",
			body:       `{"error":"unauthorized","message":"invalid per-push signature","reason":"binding_conflict","bound_key_fingerprint":"aabbccdd11223344"}`,
			wantReason: orgcontract.AuthReasonBindingConflict,
			wantFP:     "aabbccdd11223344",
		},
		{
			// The v1.8-class server. Must degrade to "the server did not say",
			// never to an error — this is the compat direction.
			name: "older server omits the fields",
			body: `{"error":"unauthorized","message":"invalid per-push signature"}`,
		},
		{
			name: "not JSON at all (an intermediate proxy's error page)",
			body: `<html>502</html>`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseAuthFailure([]byte(tc.body))
			if got.Reason != tc.wantReason || got.BoundKeyFingerprint != tc.wantFP {
				t.Errorf("parseAuthFailure = %+v, want reason=%q fp=%q", got, tc.wantReason, tc.wantFP)
			}
		})
	}
}

func TestReportAuthFailureNamesTheCause(t *testing.T) {
	_, localPriv, _ := ed25519.GenerateKey(rand.Reader)
	localFP := orgcontract.AgentKeyFingerprint(localPriv.Public().(ed25519.PublicKey))
	const otherFP = "ffffffffffffffff"

	tests := []struct {
		name string
		body string
		// wantLog are substrings the log line must carry.
		wantLog []string
		// wantMsg is the prefix of the RECORDED push message (what
		// `observer org status` shows).
		wantMsg string
	}{
		{
			name:    "server names the binding conflict",
			body:    `{"error":"unauthorized","message":"invalid per-push signature","reason":"binding_conflict","bound_key_fingerprint":"` + otherFP + `"}`,
			wantLog: []string{"reason=binding_conflict", "server_bound_key_fingerprint=" + otherFP, "local_key_fingerprint=" + localFP, "another machine enrolled"},
			wantMsg: "binding_conflict: ",
		},
		{
			// The upgrade path: the server could only prove "did not verify",
			// but the fingerprints differ, so the agent proves the collision
			// itself. This is what lets a current node diagnose a stranding
			// against a server too old to name it.
			name:    "agent upgrades signature_mismatch to binding_conflict from the fingerprints",
			body:    `{"error":"unauthorized","message":"invalid per-push signature","reason":"signature_mismatch","bound_key_fingerprint":"` + otherFP + `"}`,
			wantLog: []string{"reason=binding_conflict"},
			wantMsg: "binding_conflict: ",
		},
		{
			// Fingerprints AGREE: the key is right and the signature still
			// failed. Must NOT be reported as a collision.
			name:    "matching fingerprints stay signature_mismatch",
			body:    `{"error":"unauthorized","message":"invalid per-push signature","reason":"signature_mismatch","bound_key_fingerprint":"` + localFP + `"}`,
			wantLog: []string{"reason=signature_mismatch"},
			wantMsg: "signature_mismatch: ",
		},
		{
			name:    "unknown key",
			body:    `{"error":"unauthorized","message":"invalid per-push signature","reason":"unknown_key"}`,
			wantLog: []string{"reason=unknown_key", "re-enrol this node"},
			wantMsg: "unknown_key: ",
		},
		{
			name:    "clock skew names the clock, not the credential",
			body:    `{"error":"unauthorized","message":"timestamp outside allowed skew","reason":"timestamp_skew"}`,
			wantLog: []string{"reason=timestamp_skew", "sync time"},
			wantMsg: "timestamp_skew: ",
		},
		{
			// Compat: an older server says nothing extra. The message recorded
			// must stay exactly what it was before this change, so no existing
			// operator-facing string regresses.
			name:    "older server: no reason, message unchanged",
			body:    `{"error":"unauthorized","message":"invalid per-push signature"}`,
			wantLog: []string{"org push rejected"},
			wantMsg: "unauthorized: invalid per-push signature",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, buf := clientWithLogBuffer()
			msg := c.reportAuthFailure([]byte(tc.body), http.StatusUnauthorized, localFP, "https://org.example")
			if !strings.HasPrefix(msg, tc.wantMsg) {
				t.Errorf("recorded message = %q, want prefix %q", msg, tc.wantMsg)
			}
			line := buf.String()
			for _, want := range tc.wantLog {
				if !strings.Contains(line, want) {
					t.Errorf("log missing %q:\n%s", want, line)
				}
			}
		})
	}
}

// TestReportAuthFailureNoUpgradeWithoutServerFingerprint pins that the local
// upgrade needs BOTH fingerprints. A server that reports none must not be
// second-guessed into a collision diagnosis the agent cannot actually prove.
func TestReportAuthFailureNoUpgradeWithoutServerFingerprint(t *testing.T) {
	c, buf := clientWithLogBuffer()
	msg := c.reportAuthFailure(
		[]byte(`{"error":"unauthorized","message":"invalid per-push signature","reason":"signature_mismatch"}`),
		http.StatusUnauthorized, "aaaaaaaaaaaaaaaa", "https://org.example",
	)
	if strings.Contains(msg, orgcontract.AuthReasonBindingConflict) ||
		strings.Contains(buf.String(), "reason=binding_conflict") {
		t.Errorf("upgraded to binding_conflict with no server fingerprint to compare against:\nmsg=%q\n%s", msg, buf.String())
	}
}

func TestAgentKeyFingerprintEditor(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://org.example/api/agent/push", nil)
	if err := agentKeyFingerprintEditor("abcd1234abcd1234")(req.Context(), req); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get(orgcontract.HeaderAgentKeyFingerprint); got != "abcd1234abcd1234" {
		t.Errorf("header = %q, want the fingerprint", got)
	}

	// An empty fingerprint must set NO header at all, so a node that cannot
	// compute one sends the same request shape it always did.
	req2, _ := http.NewRequest(http.MethodPost, "https://org.example/api/agent/push", nil)
	if err := agentKeyFingerprintEditor("")(req2.Context(), req2); err != nil {
		t.Fatal(err)
	}
	if _, ok := req2.Header[http.CanonicalHeaderKey(orgcontract.HeaderAgentKeyFingerprint)]; ok {
		t.Error("empty fingerprint still set the header")
	}
}
