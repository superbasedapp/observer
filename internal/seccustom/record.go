package seccustom

import (
	"errors"
	"strings"
	"time"
)

// ComponentID is the catalog row that owns every custom driver run.
const ComponentID = "security.scan.custom"

// DriverPrefix prefixes a custom driver's id on its findings and scan runs,
// so a custom driver's findings can only ever close its own (section 8.6).
const DriverPrefix = "custom:"

// Record is one accepted driver as the store keeps it: the manifest as
// confirmed, its digests, the pin label and the self-test state. It lives
// only in the global config directory the dashboard writes
// (~/.observer/security/custom/), never in a project or the environment.
type Record struct {
	ID       string   `json:"id"`
	Manifest Manifest `json:"manifest"`
	// ManifestSHA256 is Manifest.Digest() at accept; FileSHA256 the digest
	// of the file shown in full (empty for a template).
	ManifestSHA256 string    `json:"manifest_sha256"`
	FileSHA256     string    `json:"file_sha256,omitempty"`
	Pin            PinScope  `json:"pin"`
	AcceptedAt     time.Time `json:"accepted_at"`
	// AcceptedVia is "dashboard" or "cli".
	AcceptedVia string `json:"accepted_via"`
	// OrgApproved marks a manifest from the org's pre-approved catalog.
	OrgApproved bool `json:"org_approved,omitempty"`
	// ExecNote carries a check that could not be made here (Windows ACLs).
	ExecNote string        `json:"exec_note,omitempty"`
	SelfTest SelfTestState `json:"self_test"`
}

// Driver is the driver id findings and scan runs carry.
func (r Record) Driver() string { return DriverPrefix + r.ID }

// SelfTestState is the last self-test: what it ran against and whether it
// passed. A run is clean only while this matches the current digests and
// versions (Current).
type SelfTestState struct {
	Ran          bool              `json:"ran"`
	Passed       bool              `json:"passed"`
	At           time.Time         `json:"at,omitempty"`
	BinaryDigest string            `json:"binary_digest,omitempty"`
	Companions   map[string]string `json:"companions,omitempty"`
	Versions     map[string]string `json:"versions,omitempty"`
	// Missing are the expected rules the self-test did not see.
	Missing []string `json:"missing,omitempty"`
	// Detail is one plain sentence on a failure.
	Detail string `json:"detail,omitempty"`
}

// Current reports whether the self-test passed for exactly these digests
// and companion versions (section 8.6: re-run whenever a driver or
// companion digest or version changes).
func (s SelfTestState) Current(binary string, companions, versions map[string]string) bool {
	if !s.Ran || !s.Passed || s.BinaryDigest == "" || s.BinaryDigest != binary {
		return false
	}
	return sameMap(s.Companions, companions) && sameMap(s.Versions, versions)
}

func sameMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// DriverID turns a manifest name into a driver id: lower case, letters,
// digits and dashes only, at most 32 bytes.
func DriverID(name string) (string, error) {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
		if b.Len() >= 32 {
			break
		}
	}
	id := strings.Trim(b.String(), "-")
	if id == "" {
		return "", errors.New("the name gives no usable driver id (letters or digits are needed)")
	}
	return id, nil
}

// ValidID reports whether id is a driver id DriverID could produce.
func ValidID(id string) bool {
	if id == "" || len(id) > 32 || id[0] == '-' || id[len(id)-1] == '-' {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}
