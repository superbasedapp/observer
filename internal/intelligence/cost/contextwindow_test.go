package cost

import "testing"

func TestParseSnapshotContextWindows(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want map[string]int64
	}{
		{"empty document", ``, map[string]int64{}},
		{"undecodable", `{`, map[string]int64{}},
		{"wrong schema version", `{"schema_version":99,"rows":[{"model":"m","context_window_tokens":5}]}`, map[string]int64{}},
		{"row without window is unknown", `{"schema_version":1,"rows":[{"model":"m","input_per_mtok":1}]}`, map[string]int64{}},
		{"non-positive window is unknown", `{"schema_version":1,"rows":[{"model":"m","context_window_tokens":0}]}`, map[string]int64{}},
		{"stated window, key normalized", `{"schema_version":1,"rows":[{"model":" Claude-X ","context_window_tokens":200000}]}`, map[string]int64{"claude-x": 200000}},
		{"latest dated row wins", `{"schema_version":1,"rows":[
			{"model":"m","effective_from":"2026-09-01T00:00:00Z","context_window_tokens":1000000},
			{"model":"m","effective_from":"2026-01-01T00:00:00Z","context_window_tokens":200000}]}`, map[string]int64{"m": 1000000}},
		{"a later row without a window keeps the stated one", `{"schema_version":1,"rows":[
			{"model":"m","effective_from":"2026-01-01T00:00:00Z","context_window_tokens":200000},
			{"model":"m","effective_from":"2026-09-01T00:00:00Z"}]}`, map[string]int64{"m": 200000}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseSnapshotContextWindows([]byte(tc.doc))
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestSnapshotContextWindowsReturnsCopy(t *testing.T) {
	a := SnapshotContextWindows()
	a["mutated-by-test"] = 1
	if _, ok := SnapshotContextWindows()["mutated-by-test"]; ok {
		t.Fatal("SnapshotContextWindows must return a fresh copy")
	}
}
