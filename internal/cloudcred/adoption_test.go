package cloudcred

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	keyring "github.com/zalando/go-keyring"
)

func TestLegacyAdoptionAcrossProcesses(t *testing.T) {
	if !fileFallbackSecure() {
		t.Skip("legacy adoption requires a verified private coordination directory")
	}
	if host := os.Getenv("SBO_CLOUD_ADOPTION_CHILD"); host != "" {
		s := &fileStore{dir: os.Getenv("SBO_CLOUD_ADOPTION_DIR"), host: host}
		_, apiErr := s.LoadAPIToken()
		_, refreshErr := s.LoadWorkOSRefresh()
		switch {
		case apiErr == nil && refreshErr == nil:
			t.Log("bundle claimed")
		case errors.Is(apiErr, ErrNotFound) && errors.Is(refreshErr, ErrNotFound):
			t.Log("bundle absent")
		default:
			t.Fatalf("split or failed adoption: API=%v, refresh=%v", apiErr, refreshErr)
		}
		return
	}
	dir := filepath.Join(t.TempDir(), "credentials")
	legacy := &fileStore{dir: dir}
	if err := legacy.SaveAPIToken("fixture-api"); err != nil {
		t.Fatal(err)
	}
	if err := legacy.SaveWorkOSRefresh("fixture-refresh"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	commands := make([]*exec.Cmd, 0, 2)
	for _, host := range []string{"a.example", "b.example"} {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLegacyAdoptionAcrossProcesses$", "-test.v")
		cmd.Env = append(os.Environ(), "SBO_CLOUD_ADOPTION_CHILD="+host, "SBO_CLOUD_ADOPTION_DIR="+dir)
		commands = append(commands, cmd)
	}
	type result struct {
		output []byte
		err    error
	}
	results := make(chan result, 2)
	for _, cmd := range commands {
		go func(cmd *exec.Cmd) { out, err := cmd.CombinedOutput(); results <- result{out, err} }(cmd)
	}
	claimed := 0
	for range commands {
		r := <-results
		if r.err != nil {
			t.Fatalf("child: %v\n%s", r.err, r.output)
		}
		if strings.Contains(string(r.output), "bundle claimed") {
			claimed++
		}
	}
	if claimed != 1 {
		t.Fatalf("%d hosts claimed the legacy bundle, want one", claimed)
	}
}

func TestKeychainLegacyAdoptionClaimsWholeBundle(t *testing.T) {
	if !fileFallbackSecure() {
		t.Skip("legacy adoption unavailable on this platform")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	keyring.MockInit()
	t.Cleanup(func() { keyring.MockInitWithError(errors.New("test keychain unavailable")) })
	for _, rec := range []string{recAPIToken, recWorkOSRefresh} {
		if err := keyring.Set(ServiceName, rec, "fixture"); err != nil {
			t.Fatal(err)
		}
	}
	a := &keychainStore{host: "a.example"}
	b := &keychainStore{host: "b.example"}
	if _, err := a.LoadAPIToken(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.LoadWorkOSRefresh(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second host adopted half the bundle: %v", err)
	}
	if _, err := a.LoadWorkOSRefresh(); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyAdoptionClaimSurvivesInterruptedCopy(t *testing.T) {
	if !fileFallbackSecure() {
		t.Skip("legacy adoption unavailable on this platform")
	}
	s := newFileStore(t)
	if err := s.SaveAPIToken("fixture-api"); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveWorkOSRefresh("fixture-refresh"); err != nil {
		t.Fatal(err)
	}
	get := func(rec string) (string, error) { b, err := s.read(rec); return string(b), err }
	set := func(rec, value string) error { return s.write(rec, []byte(value)) }
	remove := func(rec string) error { return os.Remove(s.path(rec)) }
	err := adoptLegacyBundle(s.dir, "a.example", get, func(rec, value string) error {
		if rec == recordName(recWorkOSRefresh, "a.example") {
			return errors.New("interrupted copy")
		}
		return set(rec, value)
	}, remove)
	if err == nil {
		t.Fatal("expected interrupted copy")
	}
	if err := adoptLegacyBundle(s.dir, "b.example", get, set, remove); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other host stole remaining record after interruption: %v", err)
	}
	if err := adoptLegacyBundle(s.dir, "a.example", get, set, remove); err != nil {
		t.Fatal(err)
	}
	if _, err := get(recordName(recWorkOSRefresh, "a.example")); err != nil {
		t.Fatal(err)
	}
}
