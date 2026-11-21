package sandboxopenshell

import (
	"strings"
	"testing"
)

// testEngineID is a Docker 28 shaped engine ID.
const testEngineID = "ABCD:EFGH:IJKL:MNOP:QRST:UVWX:YZ23:4567:ABCD:EFGH:IJKL:MNOP"

// TestParseEngineID: one case per answer shape of `docker info --format
// '{{json .ID}}'`.
func TestParseEngineID(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, out, want string
		ok              bool
	}{
		{"docker 28", `"` + testEngineID + `"` + "\n", testEngineID, true},
		{"docker 29 uuid", `"5b1e3f0a-6c0d-4a8e-9f1a-2b3c4d5e6f70"`, "5b1e3f0a-6c0d-4a8e-9f1a-2b3c4d5e6f70", true},
		{"empty", `""`, "", false},
		{"not json", "ABCD", "", false},
		{"a quote inside", `"AB\"CD:EFGH:IJKL"`, "", false},
		{"a space inside", `"ABCD EFGH IJKL"`, "", false},
	} {
		got, ok := ParseEngineID(tc.out)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: got %q %v", tc.name, got, ok)
		}
	}
}

// TestEngineVerdict: one case per row of the engine table, plus the first
// use and the same engine through another socket spelling (the ID is the
// engine's, so a symlink answers the same one).
func TestEngineVerdict(t *testing.T) {
	t.Parallel()
	other := "5b1e3f0a-6c0d-4a8e-9f1a-2b3c4d5e6f70"
	for _, tc := range []struct {
		name    string
		f       EngineFacts
		verdict string
		says    string
		record  bool
	}{
		{"E1 id not read", EngineFacts{Detail: "Cannot connect to the Docker daemon", Record: EngineRecordRead, Recorded: testEngineID}, VerdictEngineUnread, `("Cannot connect to the Docker daemon")`, false},
		{"E2 record unreadable", EngineFacts{ID: testEngineID, Record: EngineRecordUnreadable, RecordPath: "/s/engine-id.json"}, VerdictEngineRecordUnreadable, `remove it`, false},
		{"E4 changed", EngineFacts{ID: other, Record: EngineRecordRead, Recorded: testEngineID, RecordPath: "/s/engine-id.json"}, VerdictEngineChanged, `remove "/s/engine-id.json"`, false},
		{"first use", EngineFacts{ID: testEngineID, Record: EngineRecordAbsent}, "", "", true},
		{"the same engine (any socket spelling)", EngineFacts{ID: testEngineID, Record: EngineRecordRead, Recorded: testEngineID}, "", "", false},
	} {
		v, r := EngineVerdict(tc.f)
		if v != tc.verdict || !strings.Contains(r, tc.says) || EngineShouldRecord(tc.f) != tc.record {
			t.Errorf("%s: got %q %q record=%v", tc.name, v, r, EngineShouldRecord(tc.f))
		}
	}
}

// TestParseEngineRecord accepts only a record with a well-formed ID.
func TestParseEngineRecord(t *testing.T) {
	t.Parallel()
	if r, ok := ParseEngineRecord([]byte(`{"engine_id":"` + testEngineID + `","first_seen":1}`)); !ok || r.EngineID != testEngineID || r.FirstSeen != 1 {
		t.Fatalf("got %+v %v", r, ok)
	}
	for _, bad := range []string{"", "{", `{"engine_id":""}`, `{"engine_id":"a b c d e f"}`} {
		if _, ok := ParseEngineRecord([]byte(bad)); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}
