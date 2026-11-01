package hook

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/regularfile"
)

// TestReadSettingsFileErrorWording pins the wording per error class of the
// bounded read: a file that changed under the read, a permission refusal
// and any other I/O error each get their own composed (safe) message, and a
// missing file keeps os.ErrNotExist.
func TestReadSettingsFileErrorWording(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"swapped to a FIFO", fmt.Errorf("x is %w", regularfile.ErrNotRegular), "changed while it was read"},
		{"grew past the cap", fmt.Errorf("x is %w", regularfile.ErrTooLarge), "changed while it was read"},
		{"permission denied", &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}, "unreadable (permission denied)"},
		{"I/O error", &fs.PathError{Op: "read", Path: path, Err: errors.New("input/output error")}, "unreadable (an I/O error while reading it)"},
		{"vanished", &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prev := settingsFileRead
			settingsFileRead = func(string, int64) ([]byte, error) { return nil, c.err }
			t.Cleanup(func() { settingsFileRead = prev })
			_, err := readSettingsFile(path)
			if c.want == "" {
				if !os.IsNotExist(err) {
					t.Errorf("err = %v, want not-exist", err)
				}
				return
			}
			var safe *safeMsgError
			if !errors.As(err, &safe) || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v (%T), want a safe message containing %q", err, err, c.want)
			}
		})
	}
}
