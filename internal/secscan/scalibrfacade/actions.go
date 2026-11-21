//go:build !sbo_omit_security_scan_scalibr

package scalibrfacade

import (
	"context"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	"github.com/marmutapp/superbased-observer/internal/secciwf"
)

// actions.go is the facade's GitHub Actions extractor (rule S-779 on the
// node): the remote actions and reusable workflows a project's workflows
// use become packages of OSV's "GitHub Actions" ecosystem (owner/name,
// lowercased, at the version the workflow pins). The listing itself is
// internal/secciwf.ActionRefs, the one owner of reading uses: lines; this
// file only walks the workflow files SCALIBR's walker visits and turns each
// reference into one inventory row. SCALIBR's own githubactions extractor is
// not linked.
//
// What each reference becomes (the gap model of docs/dependency-scanning.md,
// "Scanned is not clean"):
//
//   - a tag (`@v45.0.0`): matched as written;
//   - a tag with fewer than three numeric components (`@v4`, `@v4.1`), which
//     its owner moves to each release: matched as its lowest member, marked
//     MovingTag (the finding says the version that runs may differ);
//   - a commit SHA with the conventional version comment
//     (`@<sha> # v4.1.0`): matched at the comment's version, marked
//     VersionFromComment (nothing checks the comment against the commit);
//   - a commit SHA with no comment: PinnedBySHA, a gap of its file (Observer
//     resolves no SHA: that would need api.github.com, a new egress lane);
//   - a branch or any other name (`@main`): NotAVersion, a gap of its file;
//   - a workflow over secciwf.MaxWorkflowBytes or one that does not parse:
//     the extractor fails on that file, which is a gap, never "uses no
//     action".

// actionsExtractorName is the extractor's plugin name.
const actionsExtractorName = "observer/githubactions"

// actionsExtractor is the facade's own filesystem extractor beside
// SCALIBR's, for workflow files.
type actionsExtractor struct{}

func newActionsExtractor(*cpb.PluginConfig) (filesystem.Extractor, error) {
	return actionsExtractor{}, nil
}

func (actionsExtractor) Name() string                       { return actionsExtractorName }
func (actionsExtractor) Version() int                       { return 0 }
func (actionsExtractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired claims a .yml or .yaml file directly inside a
// .github/workflows directory, at the root or nested (a monorepo's
// sub-project), never under node_modules (published package contents).
func (actionsExtractor) FileRequired(api filesystem.FileAPI) bool {
	return isWorkflowFile(filepath.ToSlash(api.Path()))
}

// isWorkflowFile reports a workflow file path (slash-separated, relative to
// the scan root), compared case-insensitively as GitHub does.
func isWorkflowFile(rel string) bool {
	rel = strings.ToLower(rel)
	if strings.Contains("/"+rel, "/node_modules/") {
		return false
	}
	dir, file := path.Split(rel)
	if dir != ".github/workflows/" && !strings.HasSuffix(dir, "/.github/workflows/") {
		return false
	}
	return strings.HasSuffix(file, ".yml") || strings.HasSuffix(file, ".yaml")
}

// errWorkflowStatus is the extraction failure of a workflow secciwf could
// not read whole (over its cap, or not YAML); SCALIBR records it against the
// file, so the file is a gap.
type errWorkflowStatus struct{ status secciwf.Status }

func (e errWorkflowStatus) Error() string {
	return fmt.Sprintf("workflow not read: %s", e.status)
}

// Extract lists one workflow's references, one package per distinct
// (owner/name, ref) at its first line.
func (actionsExtractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	body, err := io.ReadAll(io.LimitReader(input.Reader, secciwf.MaxWorkflowBytes+1))
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("read workflow: %w", err)
	}
	refs, status := secciwf.ActionRefs(body)
	if status != secciwf.StatusComplete {
		return inventory.Inventory{}, errWorkflowStatus{status: status}
	}
	rel := filepath.ToSlash(input.Path)
	var inv inventory.Inventory
	seen := map[string]bool{}
	for _, r := range refs {
		key := r.Repo + "@" + r.Ref
		if seen[key] {
			continue
		}
		seen[key] = true
		version, meta := classifyActionRef(r)
		inv.Packages = append(inv.Packages, &extractor.Package{
			Name: r.Repo, Version: version, PURLType: purl.TypeGithub,
			Location: extractor.LocationFromPathAndLine(rel, r.Line),
			Metadata: meta,
		})
	}
	return inv, nil
}

// actionMetadata carries how a reference's version was known to the row
// (plainPackage).
type actionMetadata struct {
	PinnedBySHA, NotAVersion, MovingTag, FromComment bool
}

// IsProtoable marks actionMetadata as package metadata. It never leaves the
// facade (no SCALIBR result is serialized).
func (*actionMetadata) IsProtoable() {}

// versionRef is a version-shaped ref: an optional v, dot-separated numeric
// components, and an optional pre-release or build suffix.
var versionRef = regexp.MustCompile(`^[vV]?([0-9]{1,9}(?:\.[0-9]{1,9}){0,5})([-+._A-Za-z][0-9A-Za-z.+_-]{0,63})?$`)

// classifyActionRef is the table above: the version a reference is matched
// at, and how it was known.
func classifyActionRef(r secciwf.ActionRef) (string, *actionMetadata) {
	meta := &actionMetadata{}
	if r.VersionSource == secciwf.VersionUnknown {
		meta.PinnedBySHA = true
		return "", meta
	}
	meta.FromComment = r.VersionSource == secciwf.VersionFromComment
	m := versionRef.FindStringSubmatch(r.Version)
	if m == nil {
		meta.NotAVersion = true
		return r.Version, meta
	}
	if strings.Count(m[1], ".")+1 < 3 {
		meta.MovingTag = true
	}
	return r.Version, meta
}
