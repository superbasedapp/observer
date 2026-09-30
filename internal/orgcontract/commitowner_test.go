package orgcontract

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// TestCommitOwnershipRowRoundTrip pins the JSON round trip of the commit
// ownership wire row, and that no author or path field exists on it at all.
func TestCommitOwnershipRowRoundTrip(t *testing.T) {
	in := CommitOwnershipRow{
		OrgID: "org-1", UserEmail: "dev@acme.example",
		ProjectRootHash: "h", CommitSHA: "abc", CommittedAt: "2026-09-28T10:00:00Z",
		Reachable: true, FilesCount: 2, Added: 5, Deleted: 1,
		AIFiles: 1, AICodeLines: 4, AICommentLines: 1,
		OwnerSessionID: "s1", OwnerReason: "sole_contributor", ShareBasis: "code_lines",
		Contributors: []CommitContributorRow{{SessionID: "s1", Share: 1, CodeLines: 4, CommentLines: 1, Files: 1, Prompts: 2}},
		Subject:      "feat: x", RuleVersion: 1,
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out CommitOwnershipRow
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip:\n in  %+v\n out %+v", in, out)
	}
	for _, ty := range []reflect.Type{reflect.TypeOf(CommitOwnershipRow{}), reflect.TypeOf(CommitContributorRow{})} {
		for i := 0; i < ty.NumField(); i++ {
			name := strings.ToLower(ty.Field(i).Name + " " + ty.Field(i).Tag.Get("json"))
			if strings.Contains(name, "author") || strings.Contains(name, "path") {
				t.Errorf("%s.%s: the commit ownership wire must carry no author identity and no path (COMMIT-2/COMMIT-3)", ty.Name(), ty.Field(i).Name)
			}
		}
	}
}

// TestCommitOwnershipWireCompatBothDirections pins the compat invariant: an
// older agent's envelope decodes to a nil slice, an agent with nothing to send
// adds no key (an older server sees the prior shape), and an unknown future
// row field does not break today's decoder.
func TestCommitOwnershipWireCompatBothDirections(t *testing.T) {
	var env PushEnvelope
	if err := json.Unmarshal([]byte(`{"agent_version":"1.30.0","cursor_from":1,"cursor_to":2}`), &env); err != nil {
		t.Fatal(err)
	}
	if env.CommitOwnership != nil {
		t.Fatalf("older-agent envelope decoded commit_ownership as %v, want nil", env.CommitOwnership)
	}
	empty, err := json.Marshal(PushEnvelope{AgentVersion: "1.36.0", CursorFrom: 1, CursorTo: 2})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(empty, []byte(`"commit_ownership"`)) {
		t.Error("an envelope with no commit ownership rows carries the key; it must be omitempty")
	}
	var future PushEnvelope
	if err := json.Unmarshal([]byte(`{"commit_ownership":[{"project_root_hash":"h","commit_sha":"abc","committed_at":"2026-09-28T10:00:00Z","reachable":true,"owner_reason":"sole_contributor","rule_version":2,"some_future_field":1}]}`), &future); err != nil {
		t.Fatal(err)
	}
	if len(future.CommitOwnership) != 1 || future.CommitOwnership[0].RuleVersion != 2 {
		t.Fatalf("newer-agent row decoded to %+v", future.CommitOwnership)
	}
	// A metadata-posture row carries no subject key at all.
	row, err := json.Marshal(CommitOwnershipRow{CommitSHA: "abc", Reachable: true})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(row, []byte(`"subject"`)) || bytes.Contains(row, []byte(`"owner_session_id"`)) {
		t.Errorf("an empty subject/owner must be omitted, got %s", row)
	}
}
