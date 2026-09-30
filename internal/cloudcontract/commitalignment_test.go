package cloudcontract

import (
	"bytes"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dataauthority"
)

// validCommitAlignmentEvidence returns a fully-populated, schema-valid
// CommitAlignmentEvidence for tests.
func validCommitAlignmentEvidence() CommitAlignmentEvidence {
	return CommitAlignmentEvidence{
		SchemaVersion:  CommitAlignmentEvidenceSchema,
		CloudProjectID: "cp-4b7e88",
		CloudSessionID: "cs-9f2a1c",
		PromptExcerpt:  "Add a retry with backoff to the upload path.",
		CommitSubject:  "fix(cloud): retry upload with backoff",
		CommitFiles: []CommitAlignmentFile{
			{PathHash: "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9", Added: 12, Deleted: 3},
		},
		EditHunks: []CommitAlignmentHunk{
			{PathHash: "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9", Excerpt: "+ retry with backoff"},
		},
		LinkStatus:         "committed",
		WindowDays:         14,
		DisclosurePurposes: []Purpose{PurposeExtendedEvidence},
		ScrubberVersion:    "scrub-v1",
		Authority: dataauthority.Classification{
			Authority: dataauthority.AuthorityPersonal,
			Version:   dataauthority.Version,
		},
	}
}

func TestCommitAlignmentEvidenceValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*CommitAlignmentEvidence)
		wantErr bool
	}{
		{"valid", func(*CommitAlignmentEvidence) {}, false},
		{"bad schema", func(e *CommitAlignmentEvidence) { e.SchemaVersion = "x" }, true},
		{"empty project id", func(e *CommitAlignmentEvidence) { e.CloudProjectID = "" }, true},
		{"empty session id", func(e *CommitAlignmentEvidence) { e.CloudSessionID = "" }, true},
		{"prompt excerpt too long", func(e *CommitAlignmentEvidence) {
			e.PromptExcerpt = strings.Repeat("x", MaxExcerptBytes+1)
		}, true},
		{"commit subject too long", func(e *CommitAlignmentEvidence) {
			e.CommitSubject = strings.Repeat("x", MaxCommitAlignmentSubjectBytes+1)
		}, true},
		{"too many commit files", func(e *CommitAlignmentEvidence) {
			files := make([]CommitAlignmentFile, MaxCommitAlignmentFiles+1)
			for i := range files {
				files[i] = CommitAlignmentFile{PathHash: "h"}
			}
			e.CommitFiles = files
		}, true},
		{"commit file missing path hash", func(e *CommitAlignmentEvidence) {
			e.CommitFiles = []CommitAlignmentFile{{PathHash: ""}}
		}, true},
		{"commit file negative added", func(e *CommitAlignmentEvidence) {
			e.CommitFiles = []CommitAlignmentFile{{PathHash: "h", Added: -1}}
		}, true},
		{"too many edit hunks", func(e *CommitAlignmentEvidence) {
			hunks := make([]CommitAlignmentHunk, MaxCommitAlignmentHunks+1)
			for i := range hunks {
				hunks[i] = CommitAlignmentHunk{PathHash: "h"}
			}
			e.EditHunks = hunks
		}, true},
		{"edit hunk excerpt too long", func(e *CommitAlignmentEvidence) {
			e.EditHunks = []CommitAlignmentHunk{{PathHash: "h", Excerpt: strings.Repeat("x", MaxCommitAlignmentHunkExcerptBytes+1)}}
		}, true},
		{"edit hunk missing path hash", func(e *CommitAlignmentEvidence) {
			e.EditHunks = []CommitAlignmentHunk{{PathHash: "", Excerpt: "x"}}
		}, true},
		{"unknown link status", func(e *CommitAlignmentEvidence) { e.LinkStatus = "bogus" }, true},
		{"negative window", func(e *CommitAlignmentEvidence) { e.WindowDays = -1 }, true},
		{"missing extended-evidence purpose", func(e *CommitAlignmentEvidence) {
			e.DisclosurePurposes = []Purpose{PurposeStructuralInsights}
		}, true},
		{"unknown purpose", func(e *CommitAlignmentEvidence) {
			e.DisclosurePurposes = []Purpose{PurposeExtendedEvidence, "bogus"}
		}, true},
		{"duplicate purpose", func(e *CommitAlignmentEvidence) {
			e.DisclosurePurposes = []Purpose{PurposeExtendedEvidence, PurposeExtendedEvidence}
		}, true},
		{"empty scrubber version", func(e *CommitAlignmentEvidence) { e.ScrubberVersion = "" }, true},
		{"unknown authority", func(e *CommitAlignmentEvidence) { e.Authority.Authority = "bogus" }, true},
		{"zero authority version", func(e *CommitAlignmentEvidence) { e.Authority.Version = 0 }, true},
		{"org authority is schema-valid", func(e *CommitAlignmentEvidence) {
			e.Authority.Authority = dataauthority.AuthorityOrg
		}, false},
		{"digest missing prefix", func(e *CommitAlignmentEvidence) { e.EvidenceContentDigest = "not-a-digest" }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := validCommitAlignmentEvidence()
			tt.mutate(&e)
			err := e.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCommitAlignmentEvidencePreimageOmitsDigestFields(t *testing.T) {
	e := validCommitAlignmentEvidence()
	e.EvidenceContentDigest = "sha256:should-not-appear"
	e.UploadDigest = "sha256:should-never-appear"
	pre, err := CommitAlignmentEvidencePreimage(e)
	if err != nil {
		t.Fatalf("CommitAlignmentEvidencePreimage: %v", err)
	}
	if bytes.Contains(pre, []byte("evidence_content_digest")) {
		t.Errorf("preimage contains evidence_content_digest field (self-referential)")
	}
	if bytes.Contains(pre, []byte("upload_digest")) {
		t.Errorf("preimage contains upload_digest field")
	}
	if bytes.Contains(pre, []byte("should-not-appear")) || bytes.Contains(pre, []byte("should-never-appear")) {
		t.Errorf("preimage leaked a preset digest value")
	}
}

func TestCommitAlignmentUploadBytesOmitUploadDigest(t *testing.T) {
	e := validCommitAlignmentEvidence()
	d, err := CommitAlignmentEvidenceContentDigest(e)
	if err != nil {
		t.Fatalf("CommitAlignmentEvidenceContentDigest: %v", err)
	}
	e.EvidenceContentDigest = d
	e.UploadDigest = "sha256:must-not-serialize"
	final, err := CommitAlignmentUploadBytes(e)
	if err != nil {
		t.Fatalf("CommitAlignmentUploadBytes: %v", err)
	}
	if !bytes.Contains(final, []byte("evidence_content_digest")) {
		t.Errorf("final bytes missing evidence_content_digest")
	}
	if bytes.Contains(final, []byte("upload_digest")) || bytes.Contains(final, []byte("must-not-serialize")) {
		t.Errorf("final bytes contain the upload digest (self-referential)")
	}
	ud := UploadDigest(final)
	if !strings.HasPrefix(ud, "sha256:") {
		t.Errorf("upload digest %q missing sha256: prefix", ud)
	}
}

func TestCommitAlignmentEvidenceDigestStability(t *testing.T) {
	a := validCommitAlignmentEvidence()
	b := validCommitAlignmentEvidence()
	da, err := CommitAlignmentEvidenceContentDigest(a)
	if err != nil {
		t.Fatalf("digest a: %v", err)
	}
	db, err := CommitAlignmentEvidenceContentDigest(b)
	if err != nil {
		t.Fatalf("digest b: %v", err)
	}
	if da != db {
		t.Errorf("structurally-equal evidence hashed differently: %q vs %q", da, db)
	}
	c := validCommitAlignmentEvidence()
	c.CommitSubject = "a different subject entirely"
	dc, err := CommitAlignmentEvidenceContentDigest(c)
	if err != nil {
		t.Fatalf("digest c: %v", err)
	}
	if dc == da {
		t.Errorf("changing commit_subject did not change the digest")
	}
}

func TestCommitAlignmentResultNormalize(t *testing.T) {
	valid := CommitAlignmentResult{
		Delivered:     []string{"the retry logic"},
		Missed:        []string{"the backoff cap"},
		Extra:         []string{"a log line"},
		Confidence:    0.75,
		Notes:         "mostly delivered",
		SchemaVersion: CommitAlignmentResultSchema,
	}
	if _, err := valid.Normalize(); err != nil {
		t.Fatalf("Normalize() valid input: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*CommitAlignmentResult)
		wantErr bool
	}{
		{"bad schema", func(r *CommitAlignmentResult) { r.SchemaVersion = "x" }, true},
		{"confidence too high", func(r *CommitAlignmentResult) { r.Confidence = 1.5 }, true},
		{"confidence negative", func(r *CommitAlignmentResult) { r.Confidence = -0.1 }, true},
		{"too many delivered items", func(r *CommitAlignmentResult) {
			items := make([]string, MaxCommitAlignmentResultItems+1)
			for i := range items {
				items[i] = "x"
			}
			r.Delivered = items
		}, true},
		{"notes too long", func(r *CommitAlignmentResult) {
			r.Notes = strings.Repeat("x", MaxCommitAlignmentNotesBytes+1)
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := valid
			tt.mutate(&r)
			_, err := r.Normalize()
			if (err != nil) != tt.wantErr {
				t.Errorf("Normalize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
