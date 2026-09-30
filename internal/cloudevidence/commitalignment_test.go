package cloudevidence

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/dataauthority"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// baseCommitAlignmentInput returns a minimal, valid commit-alignment input.
func baseCommitAlignmentInput() CommitAlignmentInput {
	return CommitAlignmentInput{
		CloudProjectID: "cp-def456",
		CloudSessionID: "cs-abc123",
		PromptExcerpt:  "Add a retry with backoff to the upload path.",
		CommitSubject:  "fix(cloud): retry upload with backoff",
		CommitFiles: []CommitAlignmentFileInput{
			{PathHash: "a1b2c3d4e5f6", Added: 12, Deleted: 3},
		},
		EditHunks: []CommitAlignmentHunkInput{
			{PathHash: "a1b2c3d4e5f6", Excerpt: "+ retry with backoff"},
		},
		LinkStatus:      "committed",
		WindowDays:      14,
		Authority:       personalAuthority(),
		GrantedPurposes: []cloudcontract.Purpose{cloudcontract.PurposeExtendedEvidence},
		Scrubber:        scrub.New(),
		ScrubberVersion: "scrub-v1",
	}
}

func TestBuildCommitAlignmentValid(t *testing.T) {
	ev, err := BuildCommitAlignment(baseCommitAlignmentInput())
	if err != nil {
		t.Fatalf("BuildCommitAlignment: %v", err)
	}
	if err := ev.Validate(); err != nil {
		t.Fatalf("built evidence failed Validate: %v", err)
	}
	if ev.SchemaVersion != cloudcontract.CommitAlignmentEvidenceSchema {
		t.Errorf("schema_version = %q, want %q", ev.SchemaVersion, cloudcontract.CommitAlignmentEvidenceSchema)
	}
	if len(ev.CommitFiles) != 1 || ev.CommitFiles[0].PathHash != "a1b2c3d4e5f6" {
		t.Errorf("commit files not carried through: %+v", ev.CommitFiles)
	}
	if len(ev.EditHunks) != 1 || ev.EditHunks[0].Excerpt != "+ retry with backoff" {
		t.Errorf("edit hunks not carried through: %+v", ev.EditHunks)
	}
}

func TestBuildCommitAlignmentRefusesIneligibleAuthority(t *testing.T) {
	for _, tc := range []struct {
		name string
		auth dataauthority.Classification
	}{
		{"org", dataauthority.Classification{Authority: dataauthority.AuthorityOrg, Version: dataauthority.Version}},
		{"unknown", dataauthority.Classification{Authority: "unknown", Version: dataauthority.Version}},
		{"zero", dataauthority.Classification{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := baseCommitAlignmentInput()
			in.Authority = tc.auth
			if _, err := BuildCommitAlignment(in); err == nil {
				t.Errorf("BuildCommitAlignment: want error for %s authority, got nil", tc.name)
			}
		})
	}
}

func TestBuildCommitAlignmentRequiresExtendedEvidencePurpose(t *testing.T) {
	for _, tc := range []struct {
		name     string
		purposes []cloudcontract.Purpose
	}{
		{"none granted", nil},
		{"wrong purpose only", []cloudcontract.Purpose{cloudcontract.PurposeStructuralInsights}},
		{"structural plus context, still missing", []cloudcontract.Purpose{
			cloudcontract.PurposeStructuralInsights, cloudcontract.PurposeContextEnrichment,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := baseCommitAlignmentInput()
			in.GrantedPurposes = tc.purposes
			if _, err := BuildCommitAlignment(in); err == nil {
				t.Errorf("BuildCommitAlignment: want error without PurposeExtendedEvidence granted, got nil")
			}
		})
	}

	// The converse: granting it (alongside others) succeeds.
	in := baseCommitAlignmentInput()
	in.GrantedPurposes = []cloudcontract.Purpose{cloudcontract.PurposeStructuralInsights, cloudcontract.PurposeExtendedEvidence}
	ev, err := BuildCommitAlignment(in)
	if err != nil {
		t.Fatalf("BuildCommitAlignment with extended-evidence granted: %v", err)
	}
	found := false
	for _, p := range ev.DisclosurePurposes {
		if p == cloudcontract.PurposeExtendedEvidence {
			found = true
		}
	}
	if !found {
		t.Errorf("disclosure_purposes %v missing %q", ev.DisclosurePurposes, cloudcontract.PurposeExtendedEvidence)
	}
}

func TestBuildCommitAlignmentRejectsPathLikeCloudIDs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*CommitAlignmentInput)
	}{
		{"session id looks like a path", func(in *CommitAlignmentInput) { in.CloudSessionID = "/home/dev/project" }},
		{"project id looks like a PK", func(in *CommitAlignmentInput) { in.CloudProjectID = "123456" }},
		{"session id empty", func(in *CommitAlignmentInput) { in.CloudSessionID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := baseCommitAlignmentInput()
			tc.mutate(&in)
			if _, err := BuildCommitAlignment(in); err == nil {
				t.Errorf("BuildCommitAlignment: want error for %s, got nil", tc.name)
			}
		})
	}
}

func TestBuildCommitAlignmentScrubsExcerpts(t *testing.T) {
	in := baseCommitAlignmentInput()
	const secret = "sk-live-abcdefghijklmnopqrstuvwxyz012345"
	in.PromptExcerpt = "here is my key " + secret
	in.CommitSubject = "commit with key " + secret
	in.EditHunks = []CommitAlignmentHunkInput{{PathHash: "h1", Excerpt: "+ key = " + secret}}

	ev, err := BuildCommitAlignment(in)
	if err != nil {
		t.Fatalf("BuildCommitAlignment: %v", err)
	}
	if strings.Contains(ev.PromptExcerpt, secret) {
		t.Errorf("prompt excerpt leaked the secret: %q", ev.PromptExcerpt)
	}
	if strings.Contains(ev.CommitSubject, secret) {
		t.Errorf("commit subject leaked the secret: %q", ev.CommitSubject)
	}
	for _, h := range ev.EditHunks {
		if strings.Contains(h.Excerpt, secret) {
			t.Errorf("edit hunk leaked the secret: %q", h.Excerpt)
		}
	}
}

func TestBuildCommitAlignmentBoundsCollections(t *testing.T) {
	in := baseCommitAlignmentInput()
	files := make([]CommitAlignmentFileInput, cloudcontract.MaxCommitAlignmentFiles+50)
	for i := range files {
		files[i] = CommitAlignmentFileInput{PathHash: "h", Added: 1}
	}
	in.CommitFiles = files

	hunks := make([]CommitAlignmentHunkInput, cloudcontract.MaxCommitAlignmentHunks+10)
	for i := range hunks {
		hunks[i] = CommitAlignmentHunkInput{PathHash: "h", Excerpt: "x"}
	}
	in.EditHunks = hunks

	ev, err := BuildCommitAlignment(in)
	if err != nil {
		t.Fatalf("BuildCommitAlignment: %v", err)
	}
	if len(ev.CommitFiles) != cloudcontract.MaxCommitAlignmentFiles {
		t.Errorf("commit_files = %d, want capped at %d", len(ev.CommitFiles), cloudcontract.MaxCommitAlignmentFiles)
	}
	if len(ev.EditHunks) != cloudcontract.MaxCommitAlignmentHunks {
		t.Errorf("edit_hunks = %d, want capped at %d", len(ev.EditHunks), cloudcontract.MaxCommitAlignmentHunks)
	}
}

func TestBuildCommitAlignmentRequiresScrubberAndVersion(t *testing.T) {
	t.Run("nil scrubber", func(t *testing.T) {
		in := baseCommitAlignmentInput()
		in.Scrubber = nil
		if _, err := BuildCommitAlignment(in); err == nil {
			t.Errorf("want error for nil scrubber, got nil")
		}
	})
	t.Run("empty scrubber version", func(t *testing.T) {
		in := baseCommitAlignmentInput()
		in.ScrubberVersion = ""
		if _, err := BuildCommitAlignment(in); err == nil {
			t.Errorf("want error for empty scrubber version, got nil")
		}
	})
}

func TestSerializeCommitAlignmentDigestsAndStability(t *testing.T) {
	ev, err := BuildCommitAlignment(baseCommitAlignmentInput())
	if err != nil {
		t.Fatalf("BuildCommitAlignment: %v", err)
	}

	bytes1, digests1, err := SerializeCommitAlignment(&ev)
	if err != nil {
		t.Fatalf("SerializeCommitAlignment: %v", err)
	}
	if !strings.HasPrefix(digests1.EvidenceContent, "sha256:") {
		t.Errorf("evidence-content digest missing sha256: prefix: %q", digests1.EvidenceContent)
	}
	if !strings.HasPrefix(digests1.Upload, "sha256:") {
		t.Errorf("upload digest missing sha256: prefix: %q", digests1.Upload)
	}
	if digests1.EvidenceContent == digests1.Upload {
		t.Errorf("evidence-content and upload digests must differ (distinct preimages)")
	}

	// preview == upload: rebuilding the identical evidence yields byte-
	// identical bytes and equal digests.
	ev2, err := BuildCommitAlignment(baseCommitAlignmentInput())
	if err != nil {
		t.Fatalf("BuildCommitAlignment (rebuild): %v", err)
	}
	bytes2, digests2, err := SerializeCommitAlignment(&ev2)
	if err != nil {
		t.Fatalf("SerializeCommitAlignment (rebuild): %v", err)
	}
	if string(bytes1) != string(bytes2) {
		t.Errorf("rebuild produced different bytes — not deterministic")
	}
	if digests1 != digests2 {
		t.Errorf("rebuild produced different digests: %+v vs %+v", digests1, digests2)
	}

	// Changing the evidence changes the digest.
	in3 := baseCommitAlignmentInput()
	in3.LinkStatus = "partial"
	ev3, err := BuildCommitAlignment(in3)
	if err != nil {
		t.Fatalf("BuildCommitAlignment (changed): %v", err)
	}
	_, digests3, err := SerializeCommitAlignment(&ev3)
	if err != nil {
		t.Fatalf("SerializeCommitAlignment (changed): %v", err)
	}
	if digests3.EvidenceContent == digests1.EvidenceContent {
		t.Errorf("changing link_status did not change the evidence-content digest")
	}
}

func TestSerializeCommitAlignmentNilEvidence(t *testing.T) {
	if _, _, err := SerializeCommitAlignment(nil); err == nil {
		t.Errorf("SerializeCommitAlignment(nil): want error, got nil")
	}
}
