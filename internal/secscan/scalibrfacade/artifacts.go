//go:build !sbo_omit_security_scan_scalibr

package scalibrfacade

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gobinary"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/archive"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargoauditable"

	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

// artifacts.go is the facade's part of the artifact extractors (OS and CI
// vulnerability scanning plan section 14.6, M3L-2 item 4): four SCALIBR
// v0.5.3 extractors that read packages out of build artifacts, in the same
// scan child, under security.scan.scalibr:
//
//   - language/golang/gobinary: an executable's Go build info (the
//     toolchain version included, repaired to the "stdlib" name the Go
//     advisories use: repairArtifactPackages);
//   - language/java/archive: .jar, .war, .ear and the other Java archives
//     (pom.properties, else MANIFEST.MF and the file name; nested archives
//     to depth 16), with JAR hashing off (the SHA-1 is never used) and the
//     bytes opened capped at depscan.MaxArtifactBytes;
//   - language/python/wheelegg: .whl, .egg, *.dist-info/METADATA and
//     *.egg-info/PKG-INFO;
//   - language/rust/cargoauditable: the dependency list cargo auditable
//     embeds in a Rust binary (github.com/rust-secure-code/go-rustaudit).
//
// None of them makes a request or links a container module. The two
// executable readers never see a file by their own rule (mode bits and
// extensions, which Windows does not carry): artifactGate hands them only a
// regular file under an artifact directory (depscan.ArtifactDirs: the
// ruled defaults plus the ones the developer named) whose first bytes are
// an executable header (depscan.ExecutableFormat). Every artifact file is
// held to the per-file cap; a larger one is not read and is reported
// (Inventory.TooLarge), which the child turns into a gap.

// artifactMode is how a table row reads build artifacts.
type artifactMode int

const (
	// notArtifact: a lockfile or manifest row.
	notArtifact artifactMode = iota
	// artifactByName: the extractor's own file rule (an archive, a wheel's
	// metadata), then the size cap.
	artifactByName
	// artifactExecutable: an executable under an artifact directory,
	// detected by header, then the size cap.
	artifactExecutable
)

// newJavaArchive is the Java archive extractor with JAR hashing off and the
// bytes opened recursively capped at the artifact cap.
func newJavaArchive(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	hash := false
	c := &cpb.PluginConfig{PluginSpecific: []*cpb.PluginSpecificConfig{{Config: &cpb.PluginSpecificConfig_JavaArchive{JavaArchive: &cpb.JavaArchiveConfig{
		MaxOpenedBytes: depscan.MaxArtifactBytes,
		HashJars:       &hash,
	}}}}}
	if cfg != nil {
		c.MaxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}
	return archive.New(c)
}

// artifactGate is one extraction pass's artifact rule: the root, the
// artifact folders turned on, the candidate folders left off, the cap, a
// header cache shared by the executable readers, and the files over the
// cap.
type artifactGate struct {
	root   string
	dirs   []string
	off    []string
	maxLen int64

	mu       sync.Mutex
	exe      map[string]bool
	tooLarge map[ArtifactSkip]bool
}

func newArtifactGate(root string, dirs, off []string, maxLen int64) *artifactGate {
	if maxLen <= 0 {
		maxLen = depscan.MaxArtifactBytes
	}
	return &artifactGate{root: root, dirs: depscan.ArtifactDirs(dirs), off: depscan.ArtifactDirs(off), maxLen: maxLen, exe: map[string]bool{}, tooLarge: map[ArtifactSkip]bool{}}
}

// leftOff reports a file under a candidate folder that is not turned on
// (and not under one that is): nothing under it is read.
func (g *artifactGate) leftOff(rel string) bool {
	return depscan.UnderArtifactDir(rel, g.off) && !depscan.UnderArtifactDir(rel, g.dirs)
}

// isExecutable reads a file's first bytes once per pass.
func (g *artifactGate) isExecutable(rel string) bool {
	g.mu.Lock()
	v, ok := g.exe[rel]
	g.mu.Unlock()
	if ok {
		return v
	}
	v = false
	if f, err := os.Open(filepath.Join(g.root, filepath.FromSlash(rel))); err == nil { //nolint:gosec // G304: a file of the project the developer scans, under its root
		head := make([]byte, depscan.ExecutableHeaderBytes)
		n, _ := io.ReadFull(f, head)
		_ = f.Close()
		v = depscan.ExecutableFormat(head[:n]) != ""
	}
	g.mu.Lock()
	g.exe[rel] = v
	g.mu.Unlock()
	return v
}

// fits reports whether a file is within the cap, recording it when not.
func (g *artifactGate) fits(rel, eco string, size int64) bool {
	if size <= g.maxLen {
		return true
	}
	g.mu.Lock()
	g.tooLarge[ArtifactSkip{Ecosystem: eco, Path: rel}] = true
	g.mu.Unlock()
	return false
}

// skipped returns the files over the cap, sorted.
func (g *artifactGate) skipped() []ArtifactSkip {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]ArtifactSkip, 0, len(g.tooLarge))
	for s := range g.tooLarge {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Ecosystem < out[j].Ecosystem
	})
	return out
}

// gatedExtractor is a SCALIBR artifact extractor behind the gate; every
// other method is the extractor's own.
type gatedExtractor struct {
	filesystem.Extractor
	gate *artifactGate
	mode artifactMode
	eco  string
}

// FileRequired is the gate's rule (artifactMode).
func (x *gatedExtractor) FileRequired(api filesystem.FileAPI) bool {
	rel := filepath.ToSlash(api.Path())
	switch x.mode {
	case artifactExecutable:
		if !depscan.UnderArtifactDir(rel, x.gate.dirs) {
			return false
		}
		fi, err := api.Stat()
		if err != nil || !fi.Mode().IsRegular() || fi.Size() < depscan.ExecutableHeaderBytes || !x.gate.isExecutable(rel) {
			return false
		}
		// An executable of unknown language: the gap names no ecosystem.
		return x.gate.fits(rel, "", fi.Size())
	case artifactByName:
		if x.gate.leftOff(rel) || !x.Extractor.FileRequired(api) {
			return false
		}
		fi, err := api.Stat()
		if err != nil {
			return false
		}
		return x.gate.fits(rel, x.eco, fi.Size())
	}
	return x.Extractor.FileRequired(api)
}

// artifactExtractorNames are the SCALIBR names of the four artifact
// extractors: a package one of them emitted is marked Artifact.
var artifactExtractorNames = map[string]bool{
	gobinary.Name: true, archive.Name: true, wheelegg.Name: true, cargoauditable.Name: true,
}

// repairArtifactPackages gives a Go binary's toolchain row the identity the
// Go advisories use for the standard library it embeds: the name "stdlib"
// ("go" -> "stdlib"; never twice, so an upstream rename makes it a no-op)
// at the Go release its build info names, normalized (depscan.
// NormalizeGoVersion: go1.22 is 1.22.0, an experiment or vendor suffix is
// cut). A version that is not a release (a development build, an
// unparseable string) is emptied and reported in the returned set, so the
// driver leaves the binary's standard library unmatched and says so (a
// gap), never clean. The "toolchain" advisory identity is never created
// here: it is the go command, not an embedded library (operator ruling
// 2026-11-05, item 4 Go stdlib (c)). Version ordering stays SCALIBR's.
func repairArtifactPackages(pkgs []*extractor.Package) map[*extractor.Package]bool {
	unknown := map[*extractor.Package]bool{}
	for _, p := range pkgs {
		if p == nil || len(p.Plugins) == 0 || p.Plugins[0] != gobinary.Name {
			continue
		}
		if p.Name != "go" && p.Name != "stdlib" {
			continue
		}
		p.Name = "stdlib"
		if v := depscan.NormalizeGoVersion(p.Version); v != "" {
			p.Version = v
		} else {
			p.Version = ""
			unknown[p] = true
		}
	}
	return unknown
}
