package proxyroute

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// TestRegisterClineRefusesAStateThatMoved (audit finding 3, lane
// w4-homes-b): Cline rewrites globalState.json whenever it saves its state.
// When the file changes between the route writer's read and its rename, the
// writer must not rename its edit of the older bytes over Cline's save. It
// re-reads and retries once; a file that keeps moving is refused with the
// file left exactly as Cline wrote it. Red on the old writer, which renamed
// without a re-check and dropped Cline's change.
func TestRegisterClineRefusesAStateThatMoved(t *testing.T) {
	for _, tc := range []struct {
		name string
		// saves is how many renames Cline races (each one rewrites the file).
		saves     int
		wantAdded bool
	}{
		{"one save in the window: retried on the new bytes", 1, true},
		{"Cline keeps saving: refused, the file is Cline's", 2, false},
		{"no save: written", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clineHermetic(t)
			home := t.TempDir()
			path := clineStatePath(home)
			seedClineState(t, path, clineState(",\n  \"actModeApiProvider\": \"openai\""))
			saved := 0
			var last string
			prev := clineBeforeRename
			clineBeforeRename = func(p string) {
				if p != path || saved >= tc.saves {
					return
				}
				saved++
				last = clineState(",\n  \"actModeApiProvider\": \"openai\",\n  \"clineSave\": " + strings.Repeat("1", saved))
				if err := os.WriteFile(p, []byte(last), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { clineBeforeRename = prev })

			r, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home})
			if err != nil {
				t.Fatal(err)
			}
			res := r.RegisterCline()
			got, _ := os.ReadFile(path)
			if tc.wantAdded {
				if res.Error != nil || !res.Added {
					t.Fatalf("result = %+v, want Added", res)
				}
				if !strings.Contains(string(got), "openAiBaseUrl") {
					t.Errorf("route member missing:\n%s", got)
				}
				if tc.saves > 0 && !strings.Contains(string(got), "clineSave") {
					t.Errorf("Cline's save was dropped:\n%s", got)
				}
				return
			}
			if !errors.Is(res.Error, errClineStateMoved) || res.Added {
				t.Fatalf("result = %+v, want the moved-state refusal", res)
			}
			if string(got) != last {
				t.Errorf("the file is not Cline's last save:\n%s", got)
			}
			if strings.Contains(res.Error.Error(), clineFakeKey) {
				t.Errorf("the error quotes the file: %v", res.Error)
			}
		})
	}
}

// TestRegisterClineRefusesARelativeDataDir (FU-31): Cline reads a relative
// CLINE_DATA_DIR against its own working directory, so the writer names no
// file and never routes the default globalState.json instead. Red before
// the relocation walk stopped at a relative value (it fell through to the
// default file).
func TestRegisterClineRefusesARelativeDataDir(t *testing.T) {
	home := t.TempDir()
	path := clineStatePath(home)
	body := clineState(",\n  \"actModeApiProvider\": \"openai\"")
	seedClineState(t, path, body)
	r, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home, Getenv: func(k string) string {
		if k == "CLINE_DATA_DIR" {
			return "rel-data"
		}
		return ""
	}})
	if err != nil {
		t.Fatal(err)
	}
	res := r.RegisterCline()
	if res.Error == nil || res.Added || !strings.Contains(res.Error.Error(), "CLINE_DATA_DIR") {
		t.Fatalf("result = %+v, want a refusal naming CLINE_DATA_DIR", res)
	}
	if got, _ := os.ReadFile(path); string(got) != body {
		t.Errorf("the default globalState.json was edited:\n%s", got)
	}
}
