package commitlog

import (
	"reflect"
	"strings"
	"testing"
)

// TestArgs pins the exact argv Args builds for each since/max
// combination — ParseLog's logFormat and this argv must never drift
// apart (doc.go), so any edit to one that isn't mirrored here should
// fail loudly.
func TestArgs(t *testing.T) {
	base := []string{"log", "HEAD", "--no-renames", "--no-color", "--date-order"}
	tail := []string{"--numstat", "--format=tformat:" + logFormat, "--"}

	tests := []struct {
		name  string
		since string
		max   int
		want  []string
	}{
		{
			name: "no since, no max (full history, e.g. backfill)",
			want: append(append([]string{}, base...), tail...),
		},
		{
			name: "max only",
			max:  500,
			want: append(append(append([]string{}, base...), "-n", "500"), tail...),
		},
		{
			name:  "since only",
			since: "2026-09-01T00:00:00Z",
			want:  append(append([]string{}, base...), append([]string{"--since=2026-09-01T00:00:00Z"}, tail...)...),
		},
		{
			name:  "since and max together",
			since: "2026-09-01T00:00:00Z",
			max:   500,
			want: append(append(append([]string{}, base...), "-n", "500", "--since=2026-09-01T00:00:00Z"),
				tail...),
		},
		{
			name: "max <= 0 is treated as unbounded",
			max:  0,
			want: append(append([]string{}, base...), tail...),
		},
		{
			name: "negative max is also treated as unbounded",
			max:  -1,
			want: append(append([]string{}, base...), tail...),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Args(tt.since, tt.max)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Args(%q, %d) =\n  %v\nwant\n  %v", tt.since, tt.max, got, tt.want)
			}
		})
	}
}

func TestPageArgsSkip(t *testing.T) {
	got := PageArgs("", 500, 1000, "")
	var hasSkip, hasN bool
	for _, a := range got {
		if a == "--skip=1000" {
			hasSkip = true
		}
		if a == "500" {
			hasN = true
		}
	}
	if !hasSkip || !hasN {
		t.Errorf("PageArgs(\"\", 500, 1000) = %v, want -n 500 and --skip=1000", got)
	}
	if strings.Join(PageArgs("2026-01-01T00:00:00Z", 10, 0, ""), " ") != strings.Join(Args("2026-01-01T00:00:00Z", 10), " ") {
		t.Errorf("PageArgs with skip 0 must equal Args")
	}
	if got[len(got)-1] != "--" {
		t.Errorf("argv must end with the pathspec separator, got %v", got)
	}
	sub := PageArgs("", 500, 0, "web/")
	if sub[len(sub)-2] != "--" || sub[len(sub)-1] != "web/" {
		t.Errorf("a subtree pathspec must follow the -- separator, got %v", sub)
	}
}
