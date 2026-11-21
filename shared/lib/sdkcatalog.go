package sdkcatalog

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

//go:embed sdkCatalog.json
var catalogJSON []byte

// SDK is one catalog row. Install is the line to show now: InstallPublished
// once Published, else InstallCheckout (the same rule as sdkCatalog.ts).
type SDK struct {
	ID               string   `json:"id"`
	Label            string   `json:"label"`
	Package          string   `json:"package"`
	Registry         string   `json:"registry"`
	Docs             string   `json:"docs"`
	Published        bool     `json:"published"`
	Release          string   `json:"release"`
	InstallCheckout  string   `json:"install_checkout"`
	InstallPublished string   `json:"install_published"`
	Snippet          []string `json:"snippet"`
}

// Install is the install line to show now.
func (s SDK) Install() string {
	if s.Published {
		return s.InstallPublished
	}
	return s.InstallCheckout
}

// Parse validates a catalog document with the rules sdkCatalog.ts applies:
// at least one row; every row has an id (lowercase, unique), a label, a
// package, a docs path starting with "/", both install lines, a release of
// "sdk-release" or "none", and a non-empty snippet.
func Parse(b []byte) ([]SDK, error) {
	var doc struct {
		SDKs []SDK `json:"sdks"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("sdkcatalog.Parse: %w", err)
	}
	if len(doc.SDKs) == 0 {
		return nil, errors.New("sdkcatalog.Parse: no sdks")
	}
	seen := map[string]bool{}
	for i, s := range doc.SDKs {
		switch {
		case s.ID == "" || s.ID != strings.ToLower(s.ID):
			return nil, fmt.Errorf("sdkcatalog.Parse: row %d: id %q must be lowercase and set", i, s.ID)
		case seen[s.ID]:
			return nil, fmt.Errorf("sdkcatalog.Parse: row %d: id %q repeats", i, s.ID)
		case s.Label == "" || s.Package == "":
			return nil, fmt.Errorf("sdkcatalog.Parse: %s: label and package are required", s.ID)
		case !strings.HasPrefix(s.Docs, "/"):
			return nil, fmt.Errorf("sdkcatalog.Parse: %s: docs must be a site path", s.ID)
		case s.InstallCheckout == "" || s.InstallPublished == "":
			return nil, fmt.Errorf("sdkcatalog.Parse: %s: both install lines are required", s.ID)
		case s.Release != "sdk-release" && s.Release != "none":
			return nil, fmt.Errorf("sdkcatalog.Parse: %s: release %q is not sdk-release or none", s.ID, s.Release)
		case len(s.Snippet) == 0:
			return nil, fmt.Errorf("sdkcatalog.Parse: %s: snippet is empty", s.ID)
		}
		seen[s.ID] = true
	}
	return doc.SDKs, nil
}

// All returns the embedded catalog's rows in catalog order. The embedded
// file is checked by this package's tests, so an error here means a broken
// build; callers print nothing rather than fail.
func All() ([]SDK, error) { return Parse(catalogJSON) }
