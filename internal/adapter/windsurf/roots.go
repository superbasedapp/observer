package windsurf

import (
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/vscodehost"
)

// allHomesFunc is the test seam over crossmount.AllHomes — tests override
// it to compose roots against fake homes without depending on the host's
// filesystem layout. Same shape as kirocli.allHomesFunc / clinecli.allHomesFunc.
var allHomesFunc = crossmount.AllHomes

// productDirName is the vscodehost product directory this adapter claims.
// Windsurf is a VS Code fork, so it appears in vscodehost.Products() with
// Dir "Windsurf" / Host "windsurf"; the table is filtered by Dir rather than
// re-deriving the per-OS user-data ladder here.
const productDirName = "Windsurf"

// cascadeChannelDirs are the `.codeium` child directories Windsurf composes
// per release channel. Bundle-grounded verbatim from
// WindsurfExtensionMetadata.codeiumDirPathSegments (extension.js of Windsurf
// 2.3.15, read read-only 2026-09-03):
//
//	[".codeium", isWindsurfInsiders() ? "windsurf-insiders"
//	           : isWindsurfNext()     ? "windsurf-next" : "windsurf"]
//
// The vendor docs only ever name the stable one; the other two come from
// that ternary, so an operator on an Insiders/Next build is covered without
// a second discovery pass.
var cascadeChannelDirs = []string{"windsurf", "windsurf-insiders", "windsurf-next"}

// cascadeLeafDir is the conversation-history directory under the channel
// dir. MEDIUM confidence — vendor docs + community only; the segment does
// not appear as a path literal anywhere in the extension bundle. See doc.go.
const cascadeLeafDir = "cascade"

// stateDBFileName is Windsurf's VS Code state database, watched as a FILE
// root (never its globalStorage parent). See doc.go, "Watch-root shape".
const stateDBFileName = "state.vscdb"

// defaultRoots returns this adapter's watch roots for every cross-mount
// resolved home:
//
//	<home>/.codeium/{windsurf,windsurf-insiders,windsurf-next}/cascade  (dir)
//	<...>/Windsurf/User/globalStorage/state.vscdb                      (file)
//
// The second is resolved through internal/platform/vscodehost so the per-OS
// user-data ladder (%APPDATA% / Library/Application Support / .config) stays
// owned by one package; only the Windsurf product row is used, so a sibling
// fork's state database is never claimed here.
//
// Non-existent roots are KEPT: adapters return their canonical paths
// regardless of installed state (adapter.Adapter's contract), and on this
// arc's development box none of them exists at all.
//
// Results are deduplicated and filepath.Clean-ed; order is homes-first, then
// the per-home order above.
func defaultRoots() []string {
	var roots []string
	seen := map[string]struct{}{}
	add := func(p string) {
		if strings.TrimSpace(p) == "" {
			return
		}
		p = filepath.Clean(p)
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		roots = append(roots, p)
	}

	for _, h := range allHomesFunc() {
		if h.Path == "" {
			continue
		}
		for _, channel := range cascadeChannelDirs {
			add(filepath.Join(h.Path, ".codeium", channel, cascadeLeafDir))
		}
		for _, p := range vscodehost.Products() {
			if p.Dir != productDirName {
				continue
			}
			dir := vscodehost.UserDir(h, p)
			if dir == "" {
				continue
			}
			add(filepath.Join(dir, "globalStorage", stateDBFileName))
		}
	}
	return roots
}
