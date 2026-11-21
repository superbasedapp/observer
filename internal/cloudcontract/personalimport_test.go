package cloudcontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func importRecord(id string) PersonalImportRecord {
	return PersonalImportRecord{
		ImportRef:      PersonalImportRefPrefix + id,
		CloudSessionID: "cs-" + id,
		CreatedAt:      "2026-10-01T10:00:00Z",
		Result: Result{
			Title:         "Fix the parser",
			TaxonomyTags:  []string{},
			SuggestedTags: []string{},
			Description:   "Fixed a bug.",
			Confidence:    ConfidenceMedium,
			EvidenceRefs:  []string{},
			Limitations:   []string{},
			SchemaVersion: ResultSchemaVersion,
		},
	}
}

func importManifest(records []byte, digest string, n int) PersonalImportManifest {
	return PersonalImportManifest{
		Format: PersonalImportFormat, AccountID: "acct", OrgID: "org-1", OrgSlug: "u-abcd2345",
		OwnerSubject: "user_01", RecordCount: n, RecordsSHA256: digest, CreatedAt: "2026-11-16T00:00:00Z",
	}
}

func TestPersonalImportRoundTrip(t *testing.T) {
	recs := []PersonalImportRecord{importRecord("a"), importRecord("b")}
	b, digest, err := EncodePersonalImportRecords(recs)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := VerifyPersonalImport(importManifest(b, digest, 2), b)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(got) != 2 || got[1].ImportRef != "personal:b" || got[0].TenantSessionID() != "personal:cs-a" {
		t.Fatalf("decoded %+v", got)
	}
	// Encoding is deterministic.
	b2, d2, _ := EncodePersonalImportRecords(recs)
	if !bytes.Equal(b, b2) || d2 != digest {
		t.Fatal("encoding is not deterministic")
	}
	// An empty bundle is valid.
	eb, ed, err := EncodePersonalImportRecords(nil)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := VerifyPersonalImport(importManifest(eb, ed, 0), eb); err != nil || len(out) != 0 {
		t.Fatalf("empty bundle: %v %v", out, err)
	}
}

func TestPersonalImportRefusals(t *testing.T) {
	good := []PersonalImportRecord{importRecord("a"), importRecord("b")}
	b, digest, _ := EncodePersonalImportRecords(good)
	bad := func(mut func(*PersonalImportRecord)) PersonalImportRecord {
		r := importRecord("x")
		mut(&r)
		return r
	}
	encodeCases := []struct {
		name string
		recs []PersonalImportRecord
	}{
		{"repeated ref", []PersonalImportRecord{importRecord("a"), importRecord("a")}},
		{"ref without prefix", []PersonalImportRecord{bad(func(r *PersonalImportRecord) { r.ImportRef = "x" })}},
		{"empty pseudonym", []PersonalImportRecord{bad(func(r *PersonalImportRecord) { r.CloudSessionID = "" })}},
		{"long pseudonym", []PersonalImportRecord{bad(func(r *PersonalImportRecord) { r.CloudSessionID = strings.Repeat("a", MaxCloudIDBytes+1) })}},
		{"bad time", []PersonalImportRecord{bad(func(r *PersonalImportRecord) { r.CreatedAt = "yesterday" })}},
		{"bad confidence", []PersonalImportRecord{bad(func(r *PersonalImportRecord) { r.Result.Confidence = "certain" })}},
	}
	for _, c := range encodeCases {
		if _, _, err := EncodePersonalImportRecords(c.recs); err == nil {
			t.Errorf("%s: encode accepted", c.name)
		}
	}
	verifyCases := []struct {
		name string
		m    PersonalImportManifest
		b    []byte
	}{
		{"digest mismatch", importManifest(b, strings.Repeat("0", 64), 2), b},
		{"count mismatch", importManifest(b, digest, 3), b},
		{"wrong format", func() PersonalImportManifest { m := importManifest(b, digest, 2); m.Format = "v0"; return m }(), b},
		{"team slug", func() PersonalImportManifest { m := importManifest(b, digest, 2); m.OrgSlug = "acme"; return m }(), b},
		{"no owner", func() PersonalImportManifest { m := importManifest(b, digest, 2); m.OwnerSubject = ""; return m }(), b},
		{"truncated", importManifest(b[:len(b)-1], digestOf(b[:len(b)-1]), 2), b[:len(b)-1]},
		{"unknown field", importManifest([]byte("{\"zz\":1}\n"), digestOf([]byte("{\"zz\":1}\n")), 1), []byte("{\"zz\":1}\n")},
	}
	for _, c := range verifyCases {
		if _, err := VerifyPersonalImport(c.m, c.b); err == nil {
			t.Errorf("%s: verify accepted", c.name)
		}
	}
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestPersonalImportReceiptComplete(t *testing.T) {
	m := importManifest(nil, strings.Repeat("a", 64), 3)
	cases := []struct {
		name string
		r    PersonalImportReceipt
		want bool
	}{
		{"complete", PersonalImportReceipt{Format: PersonalImportFormat, OrgID: "org-1", RecordsSHA256: strings.Repeat("A", 64), RecordCount: 3, Present: 3}, true},
		{"short", PersonalImportReceipt{Format: PersonalImportFormat, OrgID: "org-1", RecordsSHA256: strings.Repeat("a", 64), RecordCount: 3, Present: 2}, false},
		{"other org", PersonalImportReceipt{Format: PersonalImportFormat, OrgID: "org-2", RecordsSHA256: strings.Repeat("a", 64), RecordCount: 3, Present: 3}, false},
		{"other bundle", PersonalImportReceipt{Format: PersonalImportFormat, OrgID: "org-1", RecordsSHA256: strings.Repeat("b", 64), RecordCount: 3, Present: 3}, false},
	}
	for _, c := range cases {
		if got := c.r.Complete(m); got != c.want {
			t.Errorf("%s: Complete = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestDeviceOrgValidate(t *testing.T) {
	ok := DeviceOrg{OrgID: "o", Slug: "u-abcd2345", DisplayName: "Personal", Kind: DeviceOrgPersonal, Status: DeviceOrgActive, Tenancy: "individual", ServerURL: "https://u-abcd2345.superbased.app"}
	cases := []struct {
		name string
		mut  func(*DeviceOrg)
		ok   bool
	}{
		{"personal active", func(*DeviceOrg) {}, true},
		{"no url while provisioning", func(o *DeviceOrg) { o.Status = DeviceOrgProvisioning; o.ServerURL = ""; o.Stage = "queued" }, true},
		{"team managed", func(o *DeviceOrg) {
			o.Kind = DeviceOrgTeam
			o.Slug = "acme"
			o.Tenancy = "managed"
			o.ServerURL = "https://acme.superbased.app"
		}, true},
		{"personal managed", func(o *DeviceOrg) { o.Tenancy = "managed" }, false},
		{"unknown kind", func(o *DeviceOrg) { o.Kind = "group" }, false},
		{"unknown status", func(o *DeviceOrg) { o.Status = "live" }, false},
		{"http url", func(o *DeviceOrg) { o.ServerURL = "http://u-abcd2345.superbased.app" }, false},
		{"other slug host", func(o *DeviceOrg) { o.ServerURL = "https://evil.superbased.app" }, false},
		{"bare host", func(o *DeviceOrg) { o.ServerURL = "https://u-abcd2345" }, false},
		{"no id", func(o *DeviceOrg) { o.OrgID = "" }, false},
	}
	for _, c := range cases {
		o := ok
		c.mut(&o)
		if err := o.Validate(); (err == nil) != c.ok {
			t.Errorf("%s: Validate = %v, want ok=%v", c.name, err, c.ok)
		}
	}
	team := ok
	team.Kind, team.Slug, team.Tenancy, team.ServerURL = DeviceOrgTeam, "acme", "managed", ""
	if err := (EnsurePersonalOrgResponse{Org: team}).Validate(); err == nil {
		t.Error("ensure answered a team org and was accepted")
	}
	if err := (EnsurePersonalOrgResponse{Org: ok, Created: true}).Validate(); err != nil {
		t.Errorf("ensure personal: %v", err)
	}
	if !DeviceOrgActive.Attachable() || DeviceOrgProvisioning.Attachable() {
		t.Error("Attachable: only active attaches")
	}
}
