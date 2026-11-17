package scrub

import (
	"reflect"
	"strings"
	"testing"
)

// storageParitySamples holds one synthetic (obviously fake) value per
// SECRET-class typed detector whose shape the STORAGE table must also
// redact. Values are assembled from pieces so no literal in this file is
// itself a credential-shaped string a repository secret scanner trips on.
var storageParitySamples = map[string]string{
	"github_pat":        "ghp_" + strings.Repeat("Ab1", 8),
	"github_pat_fine":   "github_pat_11" + strings.Repeat("AbC1_", 6),
	"gcp_api_key":       "AIza" + strings.Repeat("x", 35),
	"slack_token":       "xoxb-" + "1234567890-abcdefghij",
	"aws_access_key":    "AKIA" + "ABCDEFGHIJKLMNOP",
	"api_key_prefixed":  "sk-" + strings.Repeat("q", 24),
	"api_key_named":     "api_key" + strings.Repeat("Z", 24),
	"bearer_token":      "Bearer " + "abcdefgh" + strings.Repeat("9", 8),
	"jwt":               "eyJ" + strings.Repeat("h", 12) + ".eyJ" + strings.Repeat("p", 12) + "." + strings.Repeat("s", 12),
	"private_key_block": "-----BEGIN " + "RSA PRIVATE KEY-----\n" + strings.Repeat("QUJD", 16) + "\n-----END " + "RSA PRIVATE KEY-----",
}

// storageParityExempt names every SECRET-class typed detector the storage
// table deliberately does NOT redact by shape, with the reason. A new
// secret row in detect.go must land in one of the two maps — the meta-test
// below fails otherwise, so the gap that let a fine-grained PAT reach the
// org wire (ledger PGC-1) cannot reopen silently.
var storageParityExempt = map[string]string{
	"json_secret_value":          "context row; covered by the storage JSON-key rows",
	"env_secret_value":           "context row; covered by the storage env-key JSON row",
	"secret_assignment":          "context row; covered by the storage key=value row",
	"api_key_assignment":         "context row; covered by the storage api_key: row",
	"export_secret":              "context row; covered by the storage export row",
	"connection_string_password": "context row; covered by the storage user:pass@host row",
	"aws_secret_key":             "context row; partially covered by the storage env/export rows",
	"entropy":                    "heuristic, never a storage redaction",
}

// TestStorageScrubCoversFixedPrefixSecretShapes pins, per sampled
// detector, that the storage table removes the value AND writes that
// detector's typed marker (audit P4): the post-hoc prompt guard reads the
// typed marker as a certain finding, so a stored prompt on a tool with no
// pre-send seam is flagged, not just redacted.
func TestStorageScrubCoversFixedPrefixSecretShapes(t *testing.T) {
	s := New()
	for typ, val := range storageParitySamples {
		t.Run(typ, func(t *testing.T) {
			if got := DetectSecrets("value " + val + " end"); len(got) == 0 || got[0].Type != typ {
				t.Fatalf("sample for %s is not detected as %s by the typed table: %+v", typ, typ, got)
			}
			out := s.String("here is my key " + val + " please use it")
			if strings.Contains(out, val) {
				t.Fatalf("storage scrub left the %s value in place: %q", typ, out)
			}
			if got := TypedRedactedMarkers(out); !reflect.DeepEqual(got, []string{typ}) {
				t.Fatalf("storage scrub of %s wrote markers %v in %q, want [%s]", typ, got, out, typ)
			}
			if again := s.String(out); again != out {
				t.Fatalf("storage scrub is not idempotent over its own %s marker: %q -> %q", typ, out, again)
			}
		})
	}
}

func TestStorageParityTableCoversEverySecretDetector(t *testing.T) {
	for _, name := range DetectorNames() {
		class, _ := DetectorClass(name)
		if class != ClassSecret {
			continue
		}
		_, sampled := storageParitySamples[name]
		_, exempt := storageParityExempt[name]
		if sampled == exempt {
			t.Errorf("secret detector %q must be in exactly one of storageParitySamples / storageParityExempt (sampled=%v exempt=%v)", name, sampled, exempt)
		}
	}
}

// TestStorageScrubContextAndProseStayBare pins the other half of P4: rows
// whose certainty comes from a key word, and prose the Bearer row also
// matches below the typed detector's 8-char floor, keep the bare marker,
// so they never become a capture-lane finding.
func TestStorageScrubContextAndProseStayBare(t *testing.T) {
	s := New()
	cases := []struct {
		name, in, wantGone string
	}{
		{"assignment consumes a typed value", "token: " + storageParitySamples["github_pat_fine"], "github_pat_11"},
		{"classic PAT assignment", "token: " + storageParitySamples["github_pat"], "ghp_"},
		{"short bearer value", "use Bearer abc123 here", "abc123"},
		{"json key", `{"password": "hunter2hunter2"}`, "hunter2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := s.String(tc.in)
			if strings.Contains(out, tc.wantGone) {
				t.Fatalf("value not redacted: %q", out)
			}
			if !strings.Contains(out, Redacted) {
				t.Fatalf("want a bare %s in %q", Redacted, out)
			}
			if got := TypedRedactedMarkers(out); got != nil {
				t.Fatalf("context/prose redaction must stay bare, got typed %v in %q", got, out)
			}
		})
	}
}

func TestTypedRedactedMarkers(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"none", "nothing here [REDACTED] at all", nil},
		{"one", "a [REDACTED:github_pat_fine] b", []string{"github_pat_fine"}},
		{"two in order", "[REDACTED:slack_token] x [REDACTED:gcp_api_key]", []string{"slack_token", "gcp_api_key"}},
		{"unknown id skipped", "[REDACTED:not_a_detector]", nil},
		{"pii id skipped", "[REDACTED:credit_card]", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := TypedRedactedMarkers(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("TypedRedactedMarkers(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestStoragePEMRowIsStrict pins the P5 PEM row's precision: key material
// (also a truncated paste, an encrypted key's headers, and a JSON-escaped
// block) is removed, while code that only names the header is untouched.
func TestStoragePEMRowIsStrict(t *testing.T) {
	s := New()
	header := "-----BEGIN " + "RSA PRIVATE KEY-----"
	footer := "-----END " + "RSA PRIVATE KEY-----"
	body := strings.Repeat("QUJD", 16)
	cases := []struct {
		name, in   string
		wantMarker bool
		mustDrop   string
	}{
		{"full block", "key:\n" + header + "\n" + body + "\n" + footer + "\nthanks", true, body},
		{"truncated paste", "here " + header + "\n" + body, true, body},
		{"encrypted key headers", header + "\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0A1B\n\n" + body + "\n" + footer, true, body},
		{"json-escaped block", `{"text":"` + header + `\n` + body + `\n` + footer + `"}`, true, body},
		{"code naming the header", `if strings.HasPrefix(s, "` + header + `") {`, false, ""},
		{"prose naming the header", "detect lines starting with " + header + " and warn", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := s.String(tc.in)
			has := strings.Contains(out, TypedRedactedMarker("private_key_block"))
			if has != tc.wantMarker {
				t.Fatalf("marker present = %v, want %v: %q", has, tc.wantMarker, out)
			}
			if tc.mustDrop != "" && strings.Contains(out, tc.mustDrop) {
				t.Fatalf("key material survived: %q", out)
			}
			if !tc.wantMarker && out != tc.in {
				t.Fatalf("code/prose was rewritten: %q -> %q", tc.in, out)
			}
		})
	}
}
