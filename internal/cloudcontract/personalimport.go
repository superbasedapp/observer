package cloudcontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// personalimport.go is the E3 hand-off format (managed SaaS plan 06 section
// 9.4; plan 07 M9.3; docs/plans/managed-saas/individuals/inventory.md
// D-IND-4, D-IND-5): the personal plane's enrichment results for one account,
// written by the control plane (`observer-cloud migrate-personal run`) and
// read on the tenant host (`observer-org tenant import-intel`). The control
// plane holds no credential to tenant data, so the copy crosses the boundary
// as a file the operator carries, and both sides check the same digest.
//
// A bundle is two files in one directory:
//
//	manifest.json   PersonalImportManifest
//	results.ndjson  one PersonalImportRecord per line, the exact bytes the
//	                manifest's RecordsSHA256 names
//
// The format is pure (no I/O): EncodePersonalImportRecords produces the
// bytes and their digest, VerifyPersonalImport checks bytes against a
// manifest and decodes them.

// PersonalImportFormat is the manifest's format tag.
const PersonalImportFormat = "sbo-personal-import-v1"

// PersonalImportRefPrefix starts every record's import reference: the
// personal plane's result id under a fixed namespace, the tenant's
// idempotency key (org_intel_results.import_ref).
const PersonalImportRefPrefix = "personal:"

// PersonalImportSessionPrefix starts the session id an imported result is
// stored under on the tenant: the personal plane only ever saw the node's
// random cloud session pseudonym, never a node session id, so the stored id
// is namespaced and can never collide with a pushed session.
const PersonalImportSessionPrefix = "personal:"

// MaxPersonalImportRecords bounds one bundle.
const MaxPersonalImportRecords = 100000

// PersonalImportManifest describes one account's bundle.
type PersonalImportManifest struct {
	Format string `json:"format"`
	// AccountID is the personal-plane account (cloud accounts.account_id).
	AccountID string `json:"account_id"`
	// OrgID is the account's personal org (cloud orgs.org_id, the tenant's
	// org id).
	OrgID string `json:"org_id"`
	// OrgSlug is the personal org's slug (u-<8 base32>).
	OrgSlug string `json:"org_slug"`
	// OwnerSubject is the WorkOS subject the tenant's owner member is bound
	// to; the tenant resolves the owner member from it.
	OwnerSubject string `json:"owner_subject"`
	// RecordCount is the number of lines in results.ndjson.
	RecordCount int `json:"record_count"`
	// RecordsSHA256 is the lowercase hex SHA-256 of results.ndjson's bytes.
	RecordsSHA256 string `json:"records_sha256"`
	// CreatedAt is when the bundle was written (RFC 3339, UTC).
	CreatedAt string `json:"created_at"`
}

// PersonalImportRecord is one enrichment result to import.
type PersonalImportRecord struct {
	// ImportRef is PersonalImportRefPrefix + the personal plane's result id.
	ImportRef string `json:"import_ref"`
	// CloudSessionID is the node-minted pseudonym the result describes.
	CloudSessionID string `json:"cloud_session_id"`
	// CreatedAt is when the personal plane stored the result (RFC 3339).
	CreatedAt string `json:"created_at"`
	// Corrected is true when Result already carries the user's latest
	// correction (the personal plane's revision history is not carried).
	Corrected bool `json:"corrected"`
	// Result is the effective result.
	Result Result `json:"result"`
}

// TenantSessionID is the session id the record is stored under on the tenant.
func (r PersonalImportRecord) TenantSessionID() string {
	return PersonalImportSessionPrefix + r.CloudSessionID
}

// Validate checks one record: the reference namespace, a bounded pseudonym,
// a parseable time and a result that normalizes.
func (r PersonalImportRecord) Validate() error {
	ref, ok := strings.CutPrefix(r.ImportRef, PersonalImportRefPrefix)
	if !ok || strings.TrimSpace(ref) == "" || len(r.ImportRef) > 200 {
		return fmt.Errorf("cloudcontract.PersonalImportRecord: import_ref must be %q plus an id", PersonalImportRefPrefix)
	}
	if strings.TrimSpace(r.CloudSessionID) == "" || len(r.CloudSessionID) > MaxCloudIDBytes {
		return fmt.Errorf("cloudcontract.PersonalImportRecord: cloud_session_id must be 1 to %d bytes", MaxCloudIDBytes)
	}
	if _, err := time.Parse(time.RFC3339, r.CreatedAt); err != nil {
		return fmt.Errorf("cloudcontract.PersonalImportRecord: created_at: %w", err)
	}
	if _, err := r.Result.Normalize(); err != nil {
		return fmt.Errorf("cloudcontract.PersonalImportRecord: result: %w", err)
	}
	return nil
}

// Validate checks the manifest's own shape.
func (m PersonalImportManifest) Validate() error {
	switch {
	case m.Format != PersonalImportFormat:
		return fmt.Errorf("cloudcontract.PersonalImportManifest: format %q, want %q", m.Format, PersonalImportFormat)
	case strings.TrimSpace(m.AccountID) == "", strings.TrimSpace(m.OrgID) == "", strings.TrimSpace(m.OwnerSubject) == "":
		return fmt.Errorf("cloudcontract.PersonalImportManifest: account_id, org_id and owner_subject are required")
	case !strings.HasPrefix(m.OrgSlug, "u-"):
		return fmt.Errorf("cloudcontract.PersonalImportManifest: org_slug %q is not a personal slug", m.OrgSlug)
	case m.RecordCount < 0 || m.RecordCount > MaxPersonalImportRecords:
		return fmt.Errorf("cloudcontract.PersonalImportManifest: record_count %d out of range", m.RecordCount)
	case len(m.RecordsSHA256) != sha256.Size*2:
		return fmt.Errorf("cloudcontract.PersonalImportManifest: records_sha256 must be %d hex characters", sha256.Size*2)
	}
	if _, err := hex.DecodeString(m.RecordsSHA256); err != nil {
		return fmt.Errorf("cloudcontract.PersonalImportManifest: records_sha256: %w", err)
	}
	if _, err := time.Parse(time.RFC3339, m.CreatedAt); err != nil {
		return fmt.Errorf("cloudcontract.PersonalImportManifest: created_at: %w", err)
	}
	return nil
}

// EncodePersonalImportRecords validates every record, refuses a repeated
// import reference, and returns the results.ndjson bytes (one compact JSON
// object per line, each ending in a newline) with their lowercase hex
// SHA-256.
func EncodePersonalImportRecords(records []PersonalImportRecord) ([]byte, string, error) {
	if len(records) > MaxPersonalImportRecords {
		return nil, "", fmt.Errorf("cloudcontract.EncodePersonalImportRecords: %d records exceeds %d", len(records), MaxPersonalImportRecords)
	}
	seen := make(map[string]bool, len(records))
	var buf bytes.Buffer
	for i, r := range records {
		if err := r.Validate(); err != nil {
			return nil, "", fmt.Errorf("record %d: %w", i, err)
		}
		if seen[r.ImportRef] {
			return nil, "", fmt.Errorf("record %d: import_ref %q repeated", i, r.ImportRef)
		}
		seen[r.ImportRef] = true
		line, err := json.Marshal(r)
		if err != nil {
			return nil, "", fmt.Errorf("record %d: %w", i, err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:]), nil
}

// VerifyPersonalImport checks records (results.ndjson's bytes) against m:
// the manifest's shape, the digest, the line count, every record's shape and
// no repeated import reference. It returns the decoded records.
func VerifyPersonalImport(m PersonalImportManifest, records []byte) ([]PersonalImportRecord, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(records)
	if got := hex.EncodeToString(sum[:]); got != strings.ToLower(m.RecordsSHA256) {
		return nil, fmt.Errorf("cloudcontract.VerifyPersonalImport: records digest %s does not match the manifest's %s", got, m.RecordsSHA256)
	}
	var out []PersonalImportRecord
	seen := map[string]bool{}
	if len(records) > 0 {
		if records[len(records)-1] != '\n' {
			return nil, fmt.Errorf("cloudcontract.VerifyPersonalImport: the records file must end with a newline")
		}
		for i, line := range bytes.Split(records[:len(records)-1], []byte{'\n'}) {
			var r PersonalImportRecord
			dec := json.NewDecoder(bytes.NewReader(line))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&r); err != nil {
				return nil, fmt.Errorf("cloudcontract.VerifyPersonalImport: line %d: %w", i+1, err)
			}
			if err := r.Validate(); err != nil {
				return nil, fmt.Errorf("cloudcontract.VerifyPersonalImport: line %d: %w", i+1, err)
			}
			if seen[r.ImportRef] {
				return nil, fmt.Errorf("cloudcontract.VerifyPersonalImport: line %d: import_ref %q repeated", i+1, r.ImportRef)
			}
			seen[r.ImportRef] = true
			out = append(out, r)
		}
	}
	if len(out) != m.RecordCount {
		return nil, fmt.Errorf("cloudcontract.VerifyPersonalImport: %d records, the manifest says %d", len(out), m.RecordCount)
	}
	return out, nil
}

// PersonalImportReceipt is what the tenant writes after an import, read back
// by `observer-cloud migrate-personal verify`: the counts the two sides
// compare.
type PersonalImportReceipt struct {
	Format        string `json:"format"`
	OrgID         string `json:"org_id"`
	RecordsSHA256 string `json:"records_sha256"`
	// RecordCount is the manifest's count.
	RecordCount int `json:"record_count"`
	// Inserted is the number of records this run wrote.
	Inserted int `json:"inserted"`
	// AlreadyPresent is the number found already imported (a rerun).
	AlreadyPresent int `json:"already_present"`
	// Present is the number of the bundle's import references present on the
	// tenant after the run (Inserted + AlreadyPresent when nothing failed).
	Present    int    `json:"present"`
	ImportedAt string `json:"imported_at"`
}

// Complete reports whether the receipt proves every record is on the tenant.
func (r PersonalImportReceipt) Complete(m PersonalImportManifest) bool {
	return r.Format == PersonalImportFormat && r.OrgID == m.OrgID &&
		strings.EqualFold(r.RecordsSHA256, m.RecordsSHA256) &&
		r.RecordCount == m.RecordCount && r.Present == m.RecordCount
}
