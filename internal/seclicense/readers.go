package seclicense

import (
	"bytes"
	"encoding/json"
	"path"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// MaxFileBytes is the most bytes a reader accepts; a larger file yields no
// entries.
const MaxFileBytes = 8 << 20

// MaxRaw is the most bytes of the declared licence text an Entry keeps.
const MaxRaw = 256

// The ecosystems the readers emit (the osv.dev spellings the inventory
// uses).
const (
	EcosystemNPM       = "npm"
	EcosystemPackagist = "Packagist"
	EcosystemPyPI      = "PyPI"
	EcosystemCrates    = "crates.io"
)

// Entry is one dependency's declared licence.
type Entry struct {
	Ecosystem string
	Name      string
	Version   string
	// License is the normalized SPDX id or expression ("" when none is
	// declared).
	License string
	// Raw is the declared value as written, capped at MaxRaw bytes. It
	// never enters a finding.
	Raw string
	// Confidence is high for a declared field and medium for a value
	// derived from a free-text field or a classifier.
	Confidence policy.FindingConfidence
	// Path is the project-relative dependency file the entry came from.
	Path string
}

// Reader reads one dependency file's bytes into entries. Malformed input
// yields nil.
type Reader func(relPath string, data []byte) []Entry

// readerRow is one row of the reader table: a file pattern and its reader.
type readerRow struct {
	Name  string
	Match func(parts []string) bool
	Read  Reader
}

// readerTable is the reader table, walked top-down; the first matching
// row reads the file.
var readerTable = []readerRow{
	{Name: "package-lock.json", Match: matchBase("package-lock.json", "npm-shrinkwrap.json"), Read: readPackageLock},
	{Name: "node_modules package.json", Match: matchNodeModulesManifest, Read: readPackageJSON},
	{Name: "composer.lock", Match: matchBase("composer.lock"), Read: readComposerLock},
	{Name: "dist-info METADATA", Match: matchDistInfo, Read: readDistInfoMetadata},
	{Name: "vendored Cargo.toml", Match: matchVendoredCargo, Read: readVendoredCargo},
}

// splitPath splits a project-relative path on either separator.
func splitPath(relPath string) []string {
	p := strings.ReplaceAll(relPath, "\\", "/")
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s != "" && s != "." {
			out = append(out, s)
		}
	}
	return out
}

func matchBase(names ...string) func([]string) bool {
	return func(parts []string) bool {
		if len(parts) == 0 {
			return false
		}
		base := parts[len(parts)-1]
		for _, n := range names {
			if base == n {
				return true
			}
		}
		return false
	}
}

// matchNodeModulesManifest matches node_modules/<name>/package.json and
// node_modules/@scope/<name>/package.json, at any depth.
func matchNodeModulesManifest(parts []string) bool {
	n := len(parts)
	if n < 3 || parts[n-1] != "package.json" {
		return false
	}
	if parts[n-3] == "node_modules" && !strings.HasPrefix(parts[n-2], "@") {
		return true
	}
	return n >= 4 && parts[n-4] == "node_modules" && strings.HasPrefix(parts[n-3], "@")
}

// matchDistInfo matches <pkg>.dist-info/METADATA.
func matchDistInfo(parts []string) bool {
	n := len(parts)
	return n >= 2 && parts[n-1] == "METADATA" && strings.HasSuffix(parts[n-2], ".dist-info")
}

// matchVendoredCargo matches vendor/<crate>/Cargo.toml.
func matchVendoredCargo(parts []string) bool {
	n := len(parts)
	return n >= 3 && parts[n-1] == "Cargo.toml" && parts[n-3] == "vendor"
}

// ReaderFor returns the reader for a project-relative dependency file
// path, from the first matching reader table row.
func ReaderFor(relPath string) (Reader, bool) {
	parts := splitPath(relPath)
	for _, r := range readerTable {
		if r.Match(parts) {
			return r.Read, true
		}
	}
	return nil, false
}

// Read reads relPath's bytes with its reader; nil when no reader matches
// or the file is too large or malformed.
func Read(relPath string, data []byte) []Entry {
	r, ok := ReaderFor(relPath)
	if !ok {
		return nil
	}
	return r(relPath, data)
}

// clipRaw caps a declared value for Entry.Raw.
func clipRaw(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= MaxRaw {
		return s
	}
	cut := MaxRaw
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut]
}

// joinOr normalizes each declared licence and joins them with OR, wrapping
// a compound one in parentheses. Empty parts are dropped.
func joinOr(raw []string) string {
	var parts []string
	for _, r := range raw {
		n := Normalize(r)
		if n == "" {
			continue
		}
		if len(raw) > 1 && hasOperator(n) {
			n = "(" + n + ")"
		}
		parts = append(parts, n)
	}
	return strings.Join(parts, " OR ")
}

// jsonLicense decodes npm's license field: a string, an object {type}, or
// (legacy) an array of strings or objects (OR). It returns the declared
// strings.
func jsonLicense(raw json.RawMessage) []string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []string{s}
	}
	var obj struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &obj) == nil && raw[0] == '{' {
		if obj.Type == "" {
			return nil
		}
		return []string{obj.Type}
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil {
		var out []string
		for _, a := range arr {
			out = append(out, jsonLicense(a)...)
		}
		return out
	}
	return nil
}

// npmEntry builds an npm entry from the declared license values.
func npmEntry(relPath, name, version string, declared []string) Entry {
	return Entry{
		Ecosystem:  EcosystemNPM,
		Name:       name,
		Version:    version,
		License:    joinOr(declared),
		Raw:        clipRaw(strings.Join(declared, " OR ")),
		Confidence: policy.FindingConfidenceHigh,
		Path:       relPath,
	}
}

// readPackageLock reads package-lock.json v2/v3's packages map: every
// node_modules key (nested ones too), the root "" and links skipped.
func readPackageLock(relPath string, data []byte) []Entry {
	if len(data) > MaxFileBytes {
		return nil
	}
	var doc struct {
		Packages map[string]struct {
			Name     string          `json:"name"`
			Version  string          `json:"version"`
			License  json.RawMessage `json:"license"`
			Licenses json.RawMessage `json:"licenses"`
			Link     bool            `json:"link"`
		} `json:"packages"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	keys := make([]string, 0, len(doc.Packages))
	for k := range doc.Packages {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []Entry
	for _, k := range keys {
		p := doc.Packages[k]
		i := strings.LastIndex(k, "node_modules/")
		if k == "" || p.Link || i < 0 {
			continue
		}
		name := k[i+len("node_modules/"):]
		if p.Name != "" {
			name = p.Name
		}
		if name == "" {
			continue
		}
		declared := jsonLicense(p.License)
		if len(declared) == 0 {
			declared = jsonLicense(p.Licenses)
		}
		out = append(out, npmEntry(relPath, name, p.Version, declared))
	}
	return out
}

// readPackageJSON reads an installed package's package.json: license (a
// string or an object), else the legacy licenses array.
func readPackageJSON(relPath string, data []byte) []Entry {
	if len(data) > MaxFileBytes {
		return nil
	}
	var doc struct {
		Name     string          `json:"name"`
		Version  string          `json:"version"`
		License  json.RawMessage `json:"license"`
		Licenses json.RawMessage `json:"licenses"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	name := doc.Name
	if name == "" {
		parts := splitPath(relPath)
		n := len(parts)
		if n >= 4 && strings.HasPrefix(parts[n-3], "@") {
			name = parts[n-3] + "/" + parts[n-2]
		} else if n >= 2 {
			name = parts[n-2]
		}
	}
	if name == "" {
		return nil
	}
	declared := jsonLicense(doc.License)
	if len(declared) == 0 {
		declared = jsonLicense(doc.Licenses)
	}
	return []Entry{npmEntry(relPath, name, doc.Version, declared)}
}

// readComposerLock reads composer.lock's packages and packages-dev; a
// license array is a choice (OR).
func readComposerLock(relPath string, data []byte) []Entry {
	if len(data) > MaxFileBytes {
		return nil
	}
	type pkg struct {
		Name    string   `json:"name"`
		Version string   `json:"version"`
		License []string `json:"license"`
	}
	var doc struct {
		Packages    []pkg `json:"packages"`
		PackagesDev []pkg `json:"packages-dev"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	var out []Entry
	for _, p := range append(doc.Packages, doc.PackagesDev...) {
		if p.Name == "" {
			continue
		}
		out = append(out, Entry{
			Ecosystem:  EcosystemPackagist,
			Name:       p.Name,
			Version:    p.Version,
			License:    joinOr(p.License),
			Raw:        clipRaw(strings.Join(p.License, " OR ")),
			Confidence: policy.FindingConfidenceHigh,
			Path:       relPath,
		})
	}
	return out
}

// maxShortLicense is the longest METADATA License value read as a name;
// a longer one is the licence text itself.
const maxShortLicense = 64

// classifierTable maps a Trove licence classifier (the text after
// "License :: ") to its SPDX id. An ambiguous one ("OSI Approved :: BSD
// License") maps to a name that classifies unknown.
var classifierTable = []struct{ Classifier, ID string }{
	{"OSI Approved :: MIT License", "MIT"},
	{"OSI Approved :: MIT No Attribution License (MIT-0)", "MIT-0"},
	{"OSI Approved :: Apache Software License", "Apache-2.0"},
	{"OSI Approved :: BSD License", "BSD"},
	{"OSI Approved :: ISC License (ISCL)", "ISC"},
	{"OSI Approved :: Zero-Clause BSD (0BSD)", "0BSD"},
	{"OSI Approved :: zlib/libpng License", "Zlib"},
	{"OSI Approved :: The Unlicense (Unlicense)", "Unlicense"},
	{"OSI Approved :: Python Software Foundation License", "PSF-2.0"},
	{"OSI Approved :: Boost Software License 1.0 (BSL-1.0)", "BSL-1.0"},
	{"OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)", "MPL-2.0"},
	{"OSI Approved :: Eclipse Public License 1.0 (EPL-1.0)", "EPL-1.0"},
	{"OSI Approved :: Eclipse Public License 2.0 (EPL-2.0)", "EPL-2.0"},
	{"OSI Approved :: GNU General Public License v2 (GPLv2)", "GPL-2.0-only"},
	{"OSI Approved :: GNU General Public License v2 or later (GPLv2+)", "GPL-2.0-or-later"},
	{"OSI Approved :: GNU General Public License v3 (GPLv3)", "GPL-3.0-only"},
	{"OSI Approved :: GNU General Public License v3 or later (GPLv3+)", "GPL-3.0-or-later"},
	{"OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)", "LGPL-2.0-only"},
	{"OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)", "LGPL-2.0-or-later"},
	{"OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)", "LGPL-3.0-only"},
	{"OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)", "LGPL-3.0-or-later"},
	{"OSI Approved :: GNU Library or Lesser General Public License (LGPL)", "LGPL"},
	{"OSI Approved :: GNU Affero General Public License v3", "AGPL-3.0-only"},
	{"OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)", "AGPL-3.0-or-later"},
	{"CC0 1.0 Universal (CC0 1.0) Public Domain Dedication", "CC0-1.0"},
	{"Other/Proprietary License", ProprietaryID},
}

// classifierID maps one "License :: ..." classifier to its id.
func classifierID(c string) (string, bool) {
	c = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(c), "License ::"))
	for _, r := range classifierTable {
		if strings.EqualFold(r.Classifier, c) {
			return r.ID, true
		}
	}
	return "", false
}

// rfc822Headers parses the header block of a METADATA file (up to the
// first blank line). A continuation line (leading white space) marks its
// header as multi-line in multi.
func rfc822Headers(data []byte) (hdr map[string][]string, multi map[string]bool) {
	hdr = map[string][]string{}
	multi = map[string]bool{}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	last := ""
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			if last != "" {
				multi[last] = true
			}
			continue
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			last = ""
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:i]))
		hdr[key] = append(hdr[key], strings.TrimSpace(line[i+1:]))
		last = key
	}
	return hdr, multi
}

// readDistInfoMetadata reads a Python *.dist-info/METADATA: License-
// Expression (high), else a short License value that is not "UNKNOWN"
// (medium), else the licence classifiers joined with OR (medium).
func readDistInfoMetadata(relPath string, data []byte) []Entry {
	if len(data) > MaxFileBytes {
		return nil
	}
	hdr, multi := rfc822Headers(data)
	first := func(k string) string {
		if v := hdr[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	name := first("name")
	if name == "" {
		return nil
	}
	e := Entry{Ecosystem: EcosystemPyPI, Name: name, Version: first("version"), Path: relPath, Confidence: policy.FindingConfidenceMedium}
	if expr := first("license-expression"); expr != "" {
		e.License, e.Raw, e.Confidence = Normalize(expr), clipRaw(expr), policy.FindingConfidenceHigh
		return []Entry{e}
	}
	if lic := first("license"); lic != "" && !multi["license"] && len(lic) <= maxShortLicense && !strings.EqualFold(lic, "UNKNOWN") {
		e.License, e.Raw = Normalize(lic), clipRaw(lic)
		return []Entry{e}
	}
	var ids, raws []string
	for _, c := range hdr["classifier"] {
		if !strings.HasPrefix(strings.TrimSpace(c), "License ::") {
			continue
		}
		raws = append(raws, c)
		if id, ok := classifierID(c); ok {
			ids = append(ids, id)
		}
	}
	e.License = joinOr(ids)
	e.Raw = clipRaw(strings.Join(raws, "; "))
	return []Entry{e}
}

// readVendoredCargo reads a vendored crate's Cargo.toml [package] table.
// A workspace-inherited field (a table, not a string) reads as empty.
func readVendoredCargo(relPath string, data []byte) []Entry {
	if len(data) > MaxFileBytes {
		return nil
	}
	var doc map[string]any
	if _, err := toml.Decode(string(data), &doc); err != nil {
		return nil
	}
	pkg, _ := doc["package"].(map[string]any)
	if pkg == nil {
		return nil
	}
	str := func(k string) string {
		s, _ := pkg[k].(string)
		return s
	}
	name := str("name")
	if name == "" {
		name = path.Base(path.Dir(strings.ReplaceAll(relPath, "\\", "/")))
	}
	if name == "" || name == "." || name == "/" {
		return nil
	}
	lic := str("license")
	return []Entry{{
		Ecosystem:  EcosystemCrates,
		Name:       name,
		Version:    str("version"),
		License:    Normalize(lic),
		Raw:        clipRaw(lic),
		Confidence: policy.FindingConfidenceHigh,
		Path:       relPath,
	}}
}
