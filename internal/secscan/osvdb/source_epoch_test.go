package osvdb

import (
	"context"
	"strings"
	"testing"
	"time"
)

// sourcedRemote is fakeRemote naming its source.
type sourcedRemote struct {
	*fakeRemote
	src string
}

func (s sourcedRemote) OSVSource() string { return s.src }

// TestEpochRecordsItsSource: a base from a SourcedRemote records the source
// in the epoch (and its string, which findings and scan runs carry); a base
// from the bucket's remote keeps the epoch string it always had.
func TestEpochRecordsItsSource(t *testing.T) {
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	s := Open(t.TempDir())
	feed := sourcedRemote{&fakeRemote{body: map[string][]byte{"npm": zipOf(t, "a.json", "{}")}}, SourceFeed}
	if _, err := s.Refresh(context.Background(), feed, []string{"npm"}, now); err != nil {
		t.Fatal(err)
	}
	inst, _ := s.Installed()
	if !strings.HasSuffix(inst["npm"], " source=feed") {
		t.Fatalf("feed epoch %q", inst["npm"])
	}
	bucket := &fakeRemote{body: map[string][]byte{"npm": zipOf(t, "b.json", "{}")}}
	if _, err := s.Refresh(context.Background(), bucket, []string{"npm"}, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	inst, _ = s.Installed()
	if strings.Contains(inst["npm"], "source=") {
		t.Fatalf("a bucket epoch must not name a source: %q", inst["npm"])
	}
}
