package diag

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/vscodehost"
	"github.com/marmutapp/superbased-observer/internal/regularfile"
)

// vscodeObsoleteMaxBytes caps the read of an extensions dir's .obsolete
// file (a small JSON map of uninstalled extension folders).
const vscodeObsoleteMaxBytes int64 = 1 << 20

// installedVSCodeExtensions is the read-only detector behind the doctor's
// "installed here" surface lines (FU-152): the lowercase ids of the
// extensions installed in every VS Code-family product's per-user extensions
// directory under h (vscodehost.ExtensionsDirs), each mapped to the first
// product host that has it. Only directory NAMES are read, plus the
// .obsolete file VS Code keeps of folders it uninstalled but has not
// deleted yet (through regularfile.Read, capped), so an uninstalled
// extension is not reported. Nothing is written; a missing or unreadable
// directory contributes nothing. getenv is the doctor's (VSCODE_EXTENSIONS,
// FU-170; nil or a pinned home reads none).
func installedVSCodeExtensions(h crossmount.HomeRoot, getenv func(string) string) map[string]string {
	out := map[string]string{}
	for _, ref := range vscodehost.ExtensionsDirs(h, getenv) {
		entries, err := os.ReadDir(ref.Path)
		if err != nil {
			continue
		}
		obsolete := map[string]bool{}
		if raw, err := regularfile.Read(filepath.Join(ref.Path, ".obsolete"), vscodeObsoleteMaxBytes); err == nil {
			_ = json.Unmarshal(raw, &obsolete)
		}
		for _, e := range entries {
			if !e.IsDir() || obsolete[e.Name()] {
				continue
			}
			id, ok := vscodehost.ExtensionIDFromDir(e.Name())
			if !ok {
				continue
			}
			if _, seen := out[id]; !seen {
				out[id] = ref.Product.Host
			}
		}
	}
	return out
}
