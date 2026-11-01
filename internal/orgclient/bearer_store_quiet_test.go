package orgclient

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/zalando/go-keyring"
)

// TestOpenBearerStoreQuietNeitherWarnsNorArms pins T-735 (D-547): a node
// that is not enrolled opens the bearer store without the keychain-downgrade
// WARN and without recording its notice, so the first real enrolment still
// warns. Since WINNODE2 (16c) the "already warned" record is a notice marker
// outside the credential store, never a file under org-bearer/.
func TestOpenBearerStoreQuietNeitherWarnsNorArms(t *testing.T) {
	keyring.MockInitWithError(errors.New("no secret service"))
	dir := t.TempDir()
	sentinel := noticePath(dir, bearerNoticeKey("sbo-test"))

	bs := OpenBearerStoreQuiet("sbo-test", dir)
	if bs.Backend() != "file" {
		t.Fatalf("backend = %q, want file", bs.Backend())
	}
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatal("the quiet open armed the sentinel")
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	OpenBearerStore("sbo-test", dir, logger)
	if !bytes.Contains(logs.Bytes(), []byte("OS keychain unavailable")) {
		t.Fatalf("the first loud open after a quiet one did not warn:\n%s", logs.String())
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("the loud open did not record its notice: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "org-bearer")); err == nil {
		t.Fatal("opening the store created the credential store directory")
	}
}
