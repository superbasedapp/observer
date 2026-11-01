package modal

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	modalsdk "github.com/modal-labs/modal-client/go"
	pb "github.com/modal-labs/modal-client/go/proto/modal_proto"
)

// TestNoProfileFile (orchestrator ruling F7 at the SBX-P7 merge): the Modal
// SDK never reads its profile file. With a malformed file at
// MODAL_CONFIG_PATH the SDK fails to parse it unless the client passes the
// empty profile set, and with it the client builds (the credential goes in
// explicitly). The control plane is a stub, so nothing is dialled.
func TestNoProfileFile(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "modal.toml")
	if err := os.WriteFile(bad, []byte("this is [not toml"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MODAL_CONFIG_PATH", bad)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("MODAL_SERVER_URL", "")
	t.Setenv("MODAL_PROFILE", "")
	stub := struct{ pb.ModalClientClient }{}
	params := func() *modalsdk.ClientParams {
		return &modalsdk.ClientParams{TokenID: "ak-FAKE", TokenSecret: "as-FAKE", Logger: slog.New(slog.DiscardHandler), ControlPlaneClient: stub}
	}
	if _, err := modalsdk.NewClientWithOptions(params()); err == nil || !strings.Contains(err.Error(), "config") {
		t.Fatalf("control case: the SDK did not read the malformed profile file (%v), so this test proves nothing", err)
	}
	p := params()
	if err := noProfileFile(p); err != nil {
		t.Fatal(err)
	}
	if p.Config == nil {
		t.Fatal("noProfileFile left Config unset")
	}
	if _, err := modalsdk.NewClientWithOptions(p); err != nil {
		t.Fatalf("the SDK read the profile file despite the empty profile set: %v", err)
	}
}
