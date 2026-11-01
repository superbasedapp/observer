package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
)

func TestGenDocsThenCheck(t *testing.T) {
	p := filepath.Join(t.TempDir(), "components.md")
	var out, errb bytes.Buffer
	if rc := run([]string{"check", "-o", p}, &out, &errb); rc == 0 {
		t.Fatal("check must fail when the file is missing")
	}
	if rc := run([]string{"gen-docs", "-o", p}, &out, &errb); rc != 0 {
		t.Fatalf("gen-docs rc=%d: %s", rc, errb.String())
	}
	if rc := run([]string{"check", "-o", p}, &out, &errb); rc != 0 {
		t.Fatalf("check after gen-docs rc=%d: %s", rc, errb.String())
	}
	if err := os.WriteFile(p, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rc := run([]string{"check", "-o", p}, &out, &errb); rc == 0 {
		t.Fatal("check must fail on a stale file")
	}
}

func TestTagsAndIDs(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := run([]string{"tags", "--distro", "full"}, &out, &errb); rc != 0 || strings.TrimSpace(out.String()) != "" {
		t.Fatalf("full has no omit tags, got rc=%d %q", rc, out.String())
	}
	out.Reset()
	if rc := run([]string{"tags", "--distro", "minimal"}, &out, &errb); rc != 0 {
		t.Fatal(errb.String())
	}
	if got := strings.TrimSpace(out.String()); got != strings.Join(components.DistroTags(components.DistroMinimal), ",") || !strings.Contains(got, "sbo_omit_codeintel") || !strings.Contains(got, "sbo_distro_minimal") {
		t.Fatalf("minimal tags = %q", got)
	}
	out.Reset()
	if rc := run([]string{"validate", "--distro", "managed"}, &out, &errb); rc != 0 {
		t.Fatalf("managed must validate: %s", errb.String())
	}
	if rc := run([]string{"tags", "--distro", "nope"}, &out, &errb); rc != 2 {
		t.Fatal("unknown distro must be a usage error")
	}
	if rc := run(nil, &out, &errb); rc != 2 {
		t.Fatal("no args must be a usage error")
	}
}

// TestDistrosListsEveryStampedDistro: the distros verb names every prebuilt
// distro whose build passes a tag set, so scripts/omit-tag-check.sh checks a
// new distro without a hand edit (TESTCI L3); full, the plain build, is not
// listed.
func TestDistrosListsEveryStampedDistro(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := run([]string{"distros"}, &out, &errb); rc != 0 {
		t.Fatalf("distros: rc=%d %s", rc, errb.String())
	}
	var want []string
	for _, d := range components.Distros() {
		if len(components.DistroTags(d)) != 0 {
			want = append(want, string(d))
		}
	}
	if got := strings.Fields(out.String()); strings.Join(got, ",") != strings.Join(want, ",") || len(got) == 0 {
		t.Fatalf("distros = %q, want %q", got, want)
	}
	if strings.Contains(out.String(), string(components.DistroFull)) {
		t.Fatalf("full has no tag set and must not be listed: %q", out.String())
	}
}

// TestImageTags (lane MP-ORG): the full image passes no tags; the core image
// passes the image marker and the omit tag of every L1-target module its
// column lists as out, including the six that compile out today.
func TestImageTags(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := run([]string{"tags", "--image", "full"}, &out, &errb); rc != 0 || strings.TrimSpace(out.String()) != "" {
		t.Fatalf("full image has no tags, got rc=%d %q", rc, out.String())
	}
	out.Reset()
	if rc := run([]string{"tags", "--image", "core"}, &out, &errb); rc != 0 {
		t.Fatal(errb.String())
	}
	got := strings.TrimSpace(out.String())
	for _, want := range []string{"sbo_image_core", "sbo_omit_org_saml", "sbo_omit_org_scim", "sbo_omit_org_log_kafka", "sbo_omit_org_opamp", "sbo_omit_org_sor_s3", "sbo_omit_org_sor_azblob"} {
		if !strings.Contains(","+got+",", ","+want+",") {
			t.Errorf("core image tags %q lack %s", got, want)
		}
	}
	if strings.Contains(got, "sbo_omit_org_oidc") || strings.Contains(got, "sbo_omit_org_core") {
		t.Errorf("core image must keep org.core and org.oidc: %q", got)
	}
	if rc := run([]string{"tags", "--image", "tiny"}, &out, &errb); rc != 2 {
		t.Fatal("unknown image must be a usage error")
	}
}
