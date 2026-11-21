package secreachgovuln

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

// ErrNotCompiled is what Run answers in a build without x/vuln
// (sbo_omit_security_reach_go or sbo_omit_security).
var ErrNotCompiled = errors.New("secreachgovuln: golang.org/x/vuln is not compiled into this build")

// ErrNotLocal is what Run answers for a database that is not a local
// directory.
var ErrNotLocal = errors.New("secreachgovuln: the database must be a local directory")

// Version is the linked golang.org/x/vuln release (go.mod), for the run's
// engine label.
const Version = "1.7.0"

// DBURL is the file:// URL of a local database directory (absolute), in the
// form govulncheck's -db flag takes on every OS ("file:///C:/..." on
// Windows).
func DBURL(dir string) (string, error) {
	if dir == "" || !filepath.IsAbs(dir) {
		return "", ErrNotLocal
	}
	p := filepath.ToSlash(dir)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return (&url.URL{Scheme: "file", Path: p}).String(), nil
}

// Args are govulncheck's arguments for one binary: binary mode, JSON, the
// symbol scan level and the local database. Pinned by a test: no source
// mode, no -test, no network database.
func Args(dbURL, binary string) ([]string, error) {
	u, err := url.Parse(dbURL)
	if err != nil || u.Scheme != "file" || u.Host != "" {
		return nil, fmt.Errorf("%w: %q", ErrNotLocal, dbURL)
	}
	if binary == "" || !filepath.IsAbs(binary) {
		return nil, errors.New("secreachgovuln: the binary must be an absolute path")
	}
	return []string{"-mode", "binary", "-format", "json", "-scan", "symbol", "-db", dbURL, binary}, nil
}
