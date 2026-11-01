//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/sandboximage"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
)

// p3cPullStream is a recorded Docker Engine pull stream (two layers, the
// digest line and the status line), with the digest given.
func p3cPullStream(digest string) string {
	return `{"status":"Pulling from example/observer-sandbox","id":"sha256:aaaa"}
{"status":"Pulling fs layer","progressDetail":{},"id":"1111aaaa2222"}
{"status":"Pulling fs layer","progressDetail":{},"id":"3333bbbb4444"}
{"status":"Downloading","progressDetail":{"current":1000000,"total":30000000},"progress":"[>  ]","id":"1111aaaa2222"}
{"status":"Downloading","progressDetail":{"current":5000000,"total":12000000},"progress":"[==> ]","id":"3333bbbb4444"}
{"status":"Download complete","progressDetail":{},"id":"1111aaaa2222"}
{"status":"Pull complete","progressDetail":{},"id":"1111aaaa2222"}
{"status":"Pull complete","progressDetail":{},"id":"3333bbbb4444"}
{"status":"Digest: ` + digest + `"}
{"status":"Status: Downloaded newer image for ghcr.io/example/observer-sandbox@` + digest + `"}
`
}

func p3cDefaultImageInspect(d sandboximage.Descriptor) map[string]any {
	return map[string]any{
		"Id": d.ConfigDigests["linux/amd64"], "RepoDigests": []string{d.Ref()}, "Os": "linux", "Architecture": "amd64",
		"Config": map[string]any{"Labels": map[string]string{sandboxoci.ObserverImageLabel: "none"}},
	}
}

// TestOCIPullDefaultByDigest: a signed manifest's image is pulled by its
// digest only, the size and source are said, the engine's copy is read back
// (id, platform) before use, and the pull is recorded.
func TestOCIPullDefaultByDigest(t *testing.T) {
	f := newP3CFake(t)
	store, tr, d := installTestImage(t)
	trust := ociResolveImage(config.TerminalSandboxOCIConfig{}, store, tr)
	f.pullStream = p3cPullStream(d.Digest)
	f.onPull[d.Ref()] = p3cDefaultImageInspect(d)
	c, err := ociEngineClient(f.sock, "1.52")
	if err != nil {
		t.Fatal(err)
	}
	obs := t.TempDir()
	var lines []string
	img, size, err := ociPullDefault(context.Background(), c, trust, obs, func(l string) { lines = append(lines, l) })
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.pulled, []string{d.Ref()}) {
		t.Fatalf("pulled %v, want only %s", f.pulled, d.Ref())
	}
	all := strings.Join(lines, "\n")
	for _, want := range []string{"from ghcr.io/example/observer-sandbox", "layer 1111aaaa2222: 30.0 MB", "layer 3333bbbb4444: 12.0 MB", "pulled " + d.Ref() + " (42.0 MB)", "linux/amd64"} {
		if !strings.Contains(all, want) {
			t.Fatalf("the pull did not say %q:\n%s", want, all)
		}
	}
	if size != 42_000_000 || img.ID != d.ConfigDigests["linux/amd64"] {
		t.Fatalf("size %d img %+v", size, img)
	}
	if got := ociPulledImages(obs); len(got) != 1 || got[0].Ref != d.Ref() {
		t.Fatalf("record %+v", got)
	}
}

// TestOCIPullDefaultRefuses: an unsigned manifest, an expired one without a
// present image, and no manifest at all are refused before any pull; a
// pull whose engine reports another digest, and a copy that fails its
// read-back, are refused and the image removed.
func TestOCIPullDefaultRefuses(t *testing.T) {
	store, tr, d := installTestImage(t)
	good := ociResolveImage(config.TerminalSandboxOCIConfig{}, store, tr)
	unsigned := ociResolveImage(config.TerminalSandboxOCIConfig{}, store, contentchan.Trust{VendorKeys: sandboxImageVendorKeys()})
	expired := good
	expired.stale = true
	before := []struct {
		name  string
		trust ociImageTrust
		want  string
	}{
		{"unsigned", unsigned, "artifact_unverified"},
		{"expired without last-known-good", expired, sandboximage.ReasonNeedsFresh},
		{"no manifest", ociImageTrust{}, "not published yet"},
	}
	for _, c := range before {
		f := newP3CFake(t)
		cl, _ := ociEngineClient(f.sock, "1.52")
		_, _, err := ociPullDefault(context.Background(), cl, c.trust, t.TempDir(), func(string) {})
		if err == nil || !strings.Contains(err.Error(), c.want) || len(f.pulled) != 0 {
			t.Fatalf("%s: err %v pulled %v", c.name, err, f.pulled)
		}
	}
	// Another digest reported.
	f := newP3CFake(t)
	f.pullStream = p3cPullStream("sha256:" + strings.Repeat("9", 64))
	f.onPull[d.Ref()] = p3cDefaultImageInspect(d)
	cl, _ := ociEngineClient(f.sock, "1.52")
	obs := t.TempDir()
	if _, _, err := ociPullDefault(context.Background(), cl, good, obs, func(string) {}); err == nil || !strings.Contains(err.Error(), "reported digest") {
		t.Fatalf("digest mismatch: %v", err)
	}
	if !slices.Contains(f.imageRemoved, d.Ref()) || len(ociPulledImages(obs)) != 0 {
		t.Fatalf("a mismatched pull was kept: removed %v record %v", f.imageRemoved, ociPulledImages(obs))
	}
	// A copy that reads back with another id.
	f = newP3CFake(t)
	f.pullStream = p3cPullStream(d.Digest)
	bad := p3cDefaultImageInspect(d)
	bad["Id"] = "sha256:" + strings.Repeat("d", 64)
	f.onPull[d.Ref()] = bad
	cl, _ = ociEngineClient(f.sock, "1.52")
	if _, _, err := ociPullDefault(context.Background(), cl, good, obs, func(string) {}); err == nil || !strings.Contains(err.Error(), "read-back") {
		t.Fatalf("tampered copy: %v", err)
	}
	if !slices.Contains(f.imageRemoved, d.Ref()) {
		t.Fatalf("a tampered pull was not removed: %v", f.imageRemoved)
	}
}

// TestOCIPruneRevokedImages: only an image Observer pulled, still carrying
// its label, revoked, and unused is removed; a user's image (never in the
// record) and an unlabelled one are left alone; an image in use is refused
// by name; the tool caches keyed by a revoked digest go too.
func TestOCIPruneRevokedImages(t *testing.T) {
	f := newP3CFake(t)
	cl, _ := ociEngineClient(f.sock, "1.52")
	obs := t.TempDir()
	inst := "inst000000000001"
	dig := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	ref := func(c string) string { return "ghcr.io/example/observer-sandbox@" + dig(c) }
	labelled := func(id string) map[string]any {
		return map[string]any{"Id": id, "Config": map[string]any{"Labels": map[string]string{sandboxoci.ObserverImageLabel: "none"}}}
	}
	recs := []sandboxoci.PulledImage{
		{Ref: ref("1"), Digest: dig("1"), ID: dig("a")}, // revoked, ours, unused
		{Ref: ref("2"), Digest: dig("2"), ID: dig("b")}, // revoked, label gone
		{Ref: ref("3"), Digest: dig("3"), ID: dig("c")}, // revoked, in use
		{Ref: ref("4"), Digest: dig("4"), ID: dig("e")}, // not revoked
		{Ref: ref("5"), Digest: dig("5"), ID: dig("f")}, // revoked by id, already gone
	}
	for _, r := range recs {
		if err := setOCIPulled(obs, r, true); err != nil {
			t.Fatal(err)
		}
	}
	f.images[ref("1")] = labelled(dig("a"))
	f.images[ref("2")] = map[string]any{"Id": dig("b"), "Config": map[string]any{"Labels": map[string]string{}}}
	f.images[ref("3")] = labelled(dig("c"))
	f.images[ref("4")] = labelled(dig("e"))
	f.images["docker.io/library/alpine@"+dig("7")] = labelled(dig("7")) // the user's own
	f.containers = []map[string]any{{"Id": "c9", "Image": ref("3"), "State": "running"}}
	cache := sandboxoci.CacheVolumeName(inst, dig("1"), "tool-a", "1.0.0")
	keep := sandboxoci.CacheVolumeName(inst, dig("4"), "tool-a", "1.0.0")
	f.volumes[cache] = map[string]any{"Labels": sandboxoci.CacheLabels(inst, dig("1"), "tool-a", "1.0.0", "p")}
	f.volumes[keep] = map[string]any{"Labels": sandboxoci.CacheLabels(inst, dig("4"), "tool-a", "1.0.0", "p")}
	revoked := map[string]bool{strings.Repeat("1", 64): true, strings.Repeat("2", 64): true, strings.Repeat("3", 64): true, strings.Repeat("f", 64): true, strings.Repeat("7", 64): true}
	res, err := ociPruneRevoked(context.Background(), cl, obs, inst, func(h string) bool { return revoked[h] })
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Removed, []string{ref("1")}) || !slices.Equal(f.imageRemoved, []string{ref("1")}) {
		t.Fatalf("removed %v (engine %v)", res.Removed, f.imageRemoved)
	}
	refused := strings.Join(res.Refused, "\n")
	if !strings.Contains(refused, ref("2")+" no longer carries Observer's image label") || !strings.Contains(refused, "still used by container c9") {
		t.Fatalf("refused %q", refused)
	}
	if !slices.Equal(res.Caches, []string{cache}) || !slices.Contains(f.volRemoved, cache) || slices.Contains(f.volRemoved, keep) {
		t.Fatalf("caches %v removed %v", res.Caches, f.volRemoved)
	}
	var left []string
	for _, r := range ociPulledImages(obs) {
		left = append(left, r.Ref)
	}
	if !slices.Equal(left, []string{ref("2"), ref("3"), ref("4")}) {
		t.Fatalf("the record keeps %v", left)
	}
	if _, ok := f.images["docker.io/library/alpine@"+dig("7")]; !ok || slices.Contains(f.imageRemoved, "docker.io/library/alpine@"+dig("7")) {
		t.Fatal("a user's image was touched")
	}
	// No manifest: nothing at all.
	if res, err := ociPruneRevoked(context.Background(), cl, obs, inst, nil); err != nil || len(res.Removed)+len(res.Refused)+len(res.Caches) != 0 {
		t.Fatalf("no manifest pruned %+v %v", res, err)
	}
}

// TestOCIPullDefaultSaysSizeFirstAndIsBounded is audit finding 5: the first
// line, said before the engine is asked for anything, names the source and
// the size the signed manifest declares; a pull whose layers pass the bound
// is stopped, its image removed, and nothing is recorded.
func TestOCIPullDefaultSaysSizeFirstAndIsBounded(t *testing.T) {
	f := newP3CFake(t)
	store, tr, d := installTestImage(t)
	trust := ociResolveImage(config.TerminalSandboxOCIConfig{}, store, tr)
	small := *trust.desc
	small.SizeBytes = 1_000_000
	trust.desc = &small
	f.pullStream = p3cPullStream(d.Digest)
	f.onPull[d.Ref()] = p3cDefaultImageInspect(d)
	c, err := ociEngineClient(f.sock, "1.52")
	if err != nil {
		t.Fatal(err)
	}
	obs := t.TempDir()
	var lines []string
	pulledAtFirstLine := -1
	_, _, err = ociPullDefault(context.Background(), c, trust, obs, func(l string) {
		if len(lines) == 0 {
			pulledAtFirstLine = len(f.pulled)
		}
		lines = append(lines, l)
	})
	if err == nil || !strings.Contains(err.Error(), "stopped") {
		t.Fatalf("an over-bound pull was not stopped: %v", err)
	}
	if pulledAtFirstLine != 0 || len(lines) == 0 || !strings.Contains(lines[0], "1.0 MB as the signed manifest declares") || !strings.Contains(lines[0], "from ghcr.io/example/observer-sandbox") {
		t.Fatalf("the size and source were not said before the download (pulls at first line %d): %q", pulledAtFirstLine, lines)
	}
	if got := ociPulledImages(obs); len(got) != 0 {
		t.Fatalf("a stopped pull was recorded: %+v", got)
	}
}
