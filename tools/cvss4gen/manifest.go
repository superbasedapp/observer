package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// manifest is the parsed UPSTREAM file: which upstream commit the vendored
// files are, and the sha256 each file must have. The generator refuses to
// run on a file whose bytes do not match, so a hand-edited or half-updated
// copy cannot feed the tables.
type manifest struct {
	Repo       string
	Branch     string
	Commit     string
	CommitDate string
	License    string
	Files      []manifestFile // in manifest order
}

type manifestFile struct {
	Name   string
	SHA256 string
}

// requiredFiles are the upstream files the generator reads, in the order the
// header and the manifest list them.
var requiredFiles = []string{
	"LICENSE",
	"cvss_lookup.js",
	"max_composed.js",
	"max_severity.js",
	"cvss_config.js",
	"cvss_score.js",
}

func readManifest(dir string) (*manifest, error) {
	path := filepath.Join(dir, "UPSTREAM")
	f, err := os.Open(path) //nolint:gosec // G304: a path under the repository's own tools directory
	if err != nil {
		return nil, fmt.Errorf("cvss4gen.readManifest: %w", err)
	}
	defer func() { _ = f.Close() }()

	m := &manifest{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		switch fields[0] {
		case "repo", "branch", "commit", "commit-date", "license":
			if len(fields) != 2 {
				return nil, fmt.Errorf("cvss4gen.readManifest: %q wants one value", fields[0])
			}
			switch fields[0] {
			case "repo":
				m.Repo = fields[1]
			case "branch":
				m.Branch = fields[1]
			case "commit":
				m.Commit = fields[1]
			case "commit-date":
				m.CommitDate = fields[1]
			case "license":
				m.License = fields[1]
			}
		case "file":
			if len(fields) != 3 {
				return nil, fmt.Errorf("cvss4gen.readManifest: file line wants a name and a sha256: %q", line)
			}
			m.Files = append(m.Files, manifestFile{Name: fields[1], SHA256: fields[2]})
		default:
			return nil, fmt.Errorf("cvss4gen.readManifest: unknown key %q", fields[0])
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("cvss4gen.readManifest: %w", err)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *manifest) validate() error {
	if m.Repo == "" || m.Branch == "" || m.CommitDate == "" || m.License == "" {
		return fmt.Errorf("cvss4gen.manifest: repo, branch, commit-date and license are all required")
	}
	if len(m.Commit) != 40 || strings.Trim(m.Commit, "0123456789abcdef") != "" {
		return fmt.Errorf("cvss4gen.manifest: commit %q is not a full 40-hex sha", m.Commit)
	}
	if len(m.Files) != len(requiredFiles) {
		return fmt.Errorf("cvss4gen.manifest: want %d file lines, found %d", len(requiredFiles), len(m.Files))
	}
	for i, want := range requiredFiles {
		got := m.Files[i]
		if got.Name != want {
			return fmt.Errorf("cvss4gen.manifest: file line %d is %q, want %q", i+1, got.Name, want)
		}
		if len(got.SHA256) != 64 || strings.Trim(got.SHA256, "0123456789abcdef") != "" {
			return fmt.Errorf("cvss4gen.manifest: %s has a malformed sha256", got.Name)
		}
	}
	return nil
}

// loadUpstream reads every required file, checks it against the manifest and
// returns the contents by name.
func loadUpstream(dir string, m *manifest) (map[string]string, error) {
	out := make(map[string]string, len(m.Files))
	for _, f := range m.Files {
		b, err := os.ReadFile(filepath.Join(dir, f.Name)) //nolint:gosec // G304: a fixed file name under the vendored upstream directory
		if err != nil {
			return nil, fmt.Errorf("cvss4gen.loadUpstream: %w", err)
		}
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != f.SHA256 {
			return nil, fmt.Errorf("cvss4gen.loadUpstream: %s has sha256 %s, UPSTREAM pins %s (the vendored copy changed; refresh it with fetch.sh and update UPSTREAM together)", f.Name, got, f.SHA256)
		}
		out[f.Name] = string(b)
	}
	return out, nil
}
