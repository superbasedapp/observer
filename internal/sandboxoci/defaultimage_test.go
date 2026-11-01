package sandboxoci

import (
	"strings"
	"testing"
)

func TestPlanPruneRows(t *testing.T) {
	t.Parallel()
	dig := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	ours := map[string]string{ObserverImageLabel: "none"}
	cases := []struct {
		name    string
		img     PulledImage
		st      PulledImageState
		revoked bool
		want    PruneAction
		reason  string
	}{
		{"not revoked", PulledImage{Ref: "r1", Digest: dig("1"), ID: dig("a")}, PulledImageState{Present: true, ID: dig("a"), Labels: ours}, false, PruneKeep, ""},
		{"gone", PulledImage{Ref: "r2", Digest: dig("2")}, PulledImageState{}, true, PruneForget, ""},
		{"label gone", PulledImage{Ref: "r3", Digest: dig("3"), ID: dig("c")}, PulledImageState{Present: true, ID: dig("c")}, true, PruneRefuse, "no longer carries"},
		{"rebuilt under the name", PulledImage{Ref: "r4", Digest: dig("4"), ID: dig("d")}, PulledImageState{Present: true, ID: dig("e"), Labels: ours}, true, PruneRefuse, "not the"},
		{"in use", PulledImage{Ref: "r5", Digest: dig("5"), ID: dig("f")}, PulledImageState{Present: true, ID: dig("f"), Labels: ours, UsedBy: []string{"b2", "a1"}}, true, PruneRefuse, "container a1, b2"},
		{"remove", PulledImage{Ref: "r6", Digest: dig("6"), ID: dig("9")}, PulledImageState{Present: true, ID: dig("9"), Labels: ours}, true, PruneRemove, ""},
	}
	for _, c := range cases {
		rv := c.revoked
		got := PlanPrune([]PulledImage{c.img}, func(PulledImage) PulledImageState { return c.st }, func(string) bool { return rv })
		if len(got) != 1 || got[0].Action != c.want || !strings.Contains(got[0].Reason, c.reason) {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
	// Revoked by the image id alone.
	got := PlanPrune([]PulledImage{{Ref: "r7", Digest: dig("7"), ID: dig("8")}}, func(PulledImage) PulledImageState {
		return PulledImageState{Present: true, ID: dig("8"), Labels: ours}
	}, func(h string) bool { return h == strings.Repeat("8", 64) })
	if got[0].Action != PruneRemove {
		t.Fatalf("revoked by id: %+v", got)
	}
}

func TestRevokedCaches(t *testing.T) {
	t.Parallel()
	d := "sha256:" + strings.Repeat("1", 64)
	vols := []CacheVolumeFact{
		{Name: "observer-tool-b", Labels: CacheLabels("inst000000000001", d, "t", "1.0.0", "p")},
		{Name: "observer-tool-a", Labels: CacheLabels("inst000000000001", d, "t", "2.0.0", "p")},
		{Name: "observer-tool-c", Labels: CacheLabels("inst000000000002", d, "t", "1.0.0", "p")},
		{Name: "observer-tool-d", Labels: CacheLabels("inst000000000001", "sha256:"+strings.Repeat("2", 64), "t", "1.0.0", "p")},
	}
	got := RevokedCaches(vols, "inst000000000001", func(h string) bool { return h == strings.Repeat("1", 64) })
	if strings.Join(got, ",") != "observer-tool-a,observer-tool-b" {
		t.Fatalf("%v", got)
	}
}

func TestPullTracker(t *testing.T) {
	t.Parallel()
	var tr PullTracker
	var lines []string
	add := func(status, id string, total int64, e string) {
		if l := tr.Add(status, id, total, e); l != "" {
			lines = append(lines, l)
		}
	}
	add("Pulling fs layer", "abcdef0123456789", 0, "")
	add("Downloading", "abcdef0123456789", 2_500_000, "")
	add("Pull complete", "abcdef0123456789", 0, "")
	add("Pull complete", "abcdef0123456789", 0, "")
	add("Already exists", "ffff", 0, "")
	add("Digest: sha256:"+strings.Repeat("a", 64), "", 0, "")
	if strings.Join(lines, "|") != "layer abcdef012345: 2.5 MB|layer ffff: already exists" {
		t.Fatalf("lines %q", lines)
	}
	if tr.Bytes() != 2_500_000 || tr.Digest() != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("bytes %d digest %q", tr.Bytes(), tr.Digest())
	}
	if err := CheckPulledDigest("sha256:"+strings.Repeat("a", 64), tr.Digest()); err != nil {
		t.Fatal(err)
	}
	if err := CheckPulledDigest("sha256:"+strings.Repeat("b", 64), tr.Digest()); err == nil {
		t.Fatal("a mismatched digest passed")
	}
	if l := tr.Add("", "", 0, "manifest unknown"); !strings.Contains(l, "manifest unknown") {
		t.Fatalf("error line %q", l)
	}
	if HumanBytes(999) != "999 B" || HumanBytes(1_500_000_000) != "1.5 GB" {
		t.Fatal(HumanBytes(999), HumanBytes(1_500_000_000))
	}
}

// TestPullByteBoundAndAnnouncement (lane SBX-P3C audit finding 5): the
// bound is the declared size plus slack, or the default when undeclared,
// and the announcement names the source, the declared size and the bounds.
func TestPullByteBoundAndAnnouncement(t *testing.T) {
	if PullByteBound(0) != DefaultPullByteBound || PullByteBound(-1) != DefaultPullByteBound {
		t.Fatal("an undeclared size takes the default bound")
	}
	if got := PullByteBound(1_000_000_000); got != 1_000_000_000+100_000_000+8<<20 {
		t.Fatalf("bound %d", got)
	}
	a := PullAnnouncement("r@sha256:x", "1.0.0", "ghcr.io/r", 500_000_000, "10m0s")
	for _, want := range []string{"r@sha256:x", "from ghcr.io/r", "500.0 MB as the signed manifest declares", "10m0s"} {
		if !strings.Contains(a, want) {
			t.Fatalf("%q does not say %q", a, want)
		}
	}
	if !strings.Contains(PullAnnouncement("r", "1.0.0", "g", 0, "1m"), "size not declared") {
		t.Fatal("an undeclared size is not said")
	}
}
