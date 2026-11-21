package models

import "testing"

func TestKnownExecutionLocation(t *testing.T) {
	cases := []struct {
		loc  string
		want bool
	}{
		{ExecutionLocal, true},
		{ExecutionVendorCloud, true},
		{ExecutionCustomerWorker, true},
		{"", false},
		{"cloud", false},
		{"Local", false},
		{"vendor-cloud", false},
		{SurfaceWeb, false},
	}
	for _, c := range cases {
		if got := KnownExecutionLocation(c.loc); got != c.want {
			t.Errorf("KnownExecutionLocation(%q) = %v, want %v", c.loc, got, c.want)
		}
	}
}

func TestExecutionLocationsIsACopy(t *testing.T) {
	got := ExecutionLocations()
	if len(got) != 3 {
		t.Fatalf("ExecutionLocations() = %v, want the three kinds", got)
	}
	got[0] = "tampered"
	if !KnownExecutionLocation(ExecutionLocal) {
		t.Fatal("mutating the returned slice changed the vocabulary")
	}
	for _, k := range ExecutionLocations() {
		if !KnownExecutionLocation(k) {
			t.Errorf("ExecutionLocations() lists %q, which KnownExecutionLocation rejects", k)
		}
	}
}

func TestCloudUsageVocabularies(t *testing.T) {
	cases := []struct {
		name  string
		vocab func() []string
		known func(string) bool
		size  int
	}{
		{"usage sources", UsageSources, KnownUsageSource, 4},
		{"usage value types", UsageValueTypes, KnownUsageValueType, 5},
		{"usage monetary statuses", UsageMonetaryStatuses, KnownUsageMonetaryStatus, 5},
		{"sync streams", SyncStreams, KnownSyncStream, 4},
	}
	for _, c := range cases {
		got := c.vocab()
		if len(got) != c.size {
			t.Errorf("%s: %d members %v, want %d", c.name, len(got), got, c.size)
		}
		for _, v := range got {
			if !c.known(v) {
				t.Errorf("%s: lists %q but rejects it", c.name, v)
			}
		}
		if c.known("") || c.known("unknown-token") {
			t.Errorf("%s: accepts an empty or unknown value", c.name)
		}
		got[0] = "tampered"
		if c.known("tampered") {
			t.Errorf("%s: mutating the returned slice changed the vocabulary", c.name)
		}
	}
}

func TestSyntheticCloudProjectRoot(t *testing.T) {
	if got := SyntheticCloudProjectRoot("github.com/org/repo"); got != "cloud:github.com/org/repo" {
		t.Fatalf("SyntheticCloudProjectRoot = %q", got)
	}
	cases := []struct {
		root string
		want bool
	}{
		{"cloud:github.com/org/repo", true},
		{"cloud:", false},
		{"/home/dev/repo", false},
		{"[cursor]", false},
		{"cloudy/repo", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsSyntheticCloudProjectRoot(c.root); got != c.want {
			t.Errorf("IsSyntheticCloudProjectRoot(%q) = %v, want %v", c.root, got, c.want)
		}
	}
}
