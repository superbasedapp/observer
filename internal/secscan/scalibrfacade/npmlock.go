//go:build !sbo_omit_security_scan_scalibr

package scalibrfacade

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem"
	jsmeta "github.com/google/osv-scalibr/extractor/filesystem/language/javascript/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/inventory"
)

// npmlock.go closes the npm LOCAL false negative (JSP-9b section 5): npm
// writes hoisted workspace dependencies into package-lock.json with no
// "resolved" field, SCALIBR's DeterminePackageSource then classifies them
// LOCAL, and osvlocal skips every LOCAL npm package, so a vulnerable
// registry package goes unreported (@babel/core 7.29.0, esbuild 0.21.5 and
// vite 5.4.21 in this repository's root lockfile, all matched by
// osv-scanner).
//
// The rule is an extraction rule, not version logic: an entry of the
// lockfile's "packages" map whose key lies under node_modules/, whose
// "resolved" is empty, that is not a link, and whose version is not a
// file: reference is a registry package. A LOCAL package is passed on as
// a registry one only when every lockfile entry with its name and version
// fits the rule; a workspace member (its key has no node_modules segment)
// and a real file: or link dependency stay LOCAL. The rule is reported
// upstream (docs/dependency-scanning.md).

// restoredMetadata marks a package the rule passed on. It embeds SCALIBR's
// own metadata, so the matcher's PackageSource and DepGroups still work.
type restoredMetadata struct {
	*jsmeta.JavascriptPackageMetadata
}

// PackageSource reports the registry source the rule restored.
func (m *restoredMetadata) PackageSource() jsmeta.NPMPackageSource {
	return jsmeta.PublicRegistry
}

// uncheckedMetadata marks a LOCAL entry of a lockfile the rule could not
// read (over maxNPMLockBytes). It keeps SCALIBR's own metadata, so the
// package stays LOCAL for the matcher.
type uncheckedMetadata struct {
	*jsmeta.JavascriptPackageMetadata
}

// npmLockExtractor wraps SCALIBR's package-lock.json extractor with the
// rule above.
type npmLockExtractor struct {
	filesystem.Extractor
}

func newNPMLock(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	inner, err := packagelockjson.New(cfg)
	if err != nil {
		return nil, err
	}
	return npmLockExtractor{Extractor: inner}, nil
}

// maxNPMLockBytes bounds the copy the rule reads (a lockfile larger than
// this is extracted as SCALIBR reads it, without the rule, and its LOCAL
// entries are marked unchecked). A variable so a test can lower it.
var maxNPMLockBytes = 64 << 20

// Extract reads the lockfile once, hands SCALIBR a copy and applies the
// rule to what it extracted.
func (e npmLockExtractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	b, err := io.ReadAll(io.LimitReader(input.Reader, int64(maxNPMLockBytes)+1))
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not read: %w", err)
	}
	if len(b) > maxNPMLockBytes {
		in := *input
		in.Reader = io.MultiReader(bytes.NewReader(b), input.Reader)
		inv, err := e.Extractor.Extract(ctx, &in)
		if err != nil {
			return inv, err
		}
		// The rule could not read this lockfile: its LOCAL entries may be
		// hoisted registry packages, so they are marked unchecked and the
		// run is partial (depscan's local_unchecked drop), never clean.
		for _, p := range inv.Packages {
			if m, ok := p.Metadata.(*jsmeta.JavascriptPackageMetadata); ok && m.Source == jsmeta.Local {
				p.Metadata = &uncheckedMetadata{JavascriptPackageMetadata: m}
			}
		}
		return inv, nil
	}
	in := *input
	in.Reader = bytes.NewReader(b)
	inv, err := e.Extractor.Extract(ctx, &in)
	if err != nil {
		return inv, err
	}
	registry := RegistryEntries(b)
	for _, p := range inv.Packages {
		m, ok := p.Metadata.(*jsmeta.JavascriptPackageMetadata)
		if !ok || m.Source != jsmeta.Local {
			continue
		}
		if registry[p.Name+"@"+p.Version] {
			p.Metadata = &restoredMetadata{JavascriptPackageMetadata: m}
		}
	}
	return inv, nil
}

// lockEntry is the part of a "packages" entry the rule reads.
type lockEntry struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Resolved string `json:"resolved"`
	Link     bool   `json:"link"`
}

// RegistryEntries returns the name@version keys of a package-lock.json
// (lockfile version 2 or 3, the "packages" map) that the rule treats as
// registry packages: every entry with that name and version lies under
// node_modules/, has an empty "resolved", is not a link and has no file:
// version. Exported for the fixture test.
func RegistryEntries(lock []byte) map[string]bool {
	var lf struct {
		Packages map[string]lockEntry `json:"packages"`
	}
	if err := json.Unmarshal(lock, &lf); err != nil {
		return nil
	}
	fits := map[string]bool{}
	broken := map[string]bool{}
	for key, ent := range lf.Packages {
		if key == "" || ent.Version == "" {
			continue
		}
		name := ent.Name
		if name == "" {
			name = npmNameFromKey(key)
		}
		id := name + "@" + ent.Version
		ok := strings.Contains("/"+key, "/node_modules/") &&
			ent.Resolved == "" && !ent.Link && !strings.HasPrefix(ent.Version, "file:")
		if ok {
			fits[id] = true
		} else {
			broken[id] = true
		}
	}
	out := map[string]bool{}
	for id := range fits {
		if !broken[id] {
			out[id] = true
		}
	}
	return out
}

// npmNameFromKey is the package name of a lockfile key: the part after the
// last node_modules/, scoped names kept whole.
func npmNameFromKey(key string) string {
	if i := strings.LastIndex(key, "node_modules/"); i >= 0 {
		return key[i+len("node_modules/"):]
	}
	return key
}
