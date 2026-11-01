package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/regularfile"
)

// TestReadOAuthAccessTokenThroughRegularfile pins FU-172's code half: the
// credentials file is read as one capped regular file. A synthetic token is
// returned, a missing file is "", and an over-cap file is refused without
// any of its bytes in the error. Synthetic values only: no real credential.
func TestReadOAuthAccessTokenThroughRegularfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".credentials.json")
	if tok, stale, err := readOAuthAccessToken(path); tok != "" || stale || err != nil {
		t.Fatalf("missing file = %q, %v, %v; want empty, no error", tok, stale, err)
	}
	if err := os.WriteFile(path, []byte(`{"claudeAiOauth":{"accessToken":"synthetic-token-for-test"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if tok, stale, err := readOAuthAccessToken(path); tok != "synthetic-token-for-test" || stale || err != nil {
		t.Fatalf("synthetic file = %q, %v, %v", tok, stale, err)
	}
	marker := "synthetic-oversize-marker"
	big := `{"claudeAiOauth":{"accessToken":"` + marker + strings.Repeat("x", int(claudeCredentialsMaxBytes)) + `"}}`
	if err := os.WriteFile(path, []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	tok, _, err := readOAuthAccessToken(path)
	if tok != "" || !errors.Is(err, regularfile.ErrTooLarge) {
		t.Fatalf("over-cap file = %q, %v; want the too-large refusal", tok, err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Errorf("the refusal carries the file's bytes: %v", err)
	}
}
