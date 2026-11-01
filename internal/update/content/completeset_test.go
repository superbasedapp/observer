package content

import "testing"

// TestCheckCompleteSet: a complete-set kind whose every entry name has an
// entry for the platform passes; a missing name is partial_set; a kind that
// is not a complete set (the native files, whose entries are per-OS
// alternatives) is never refused here (WINFIX2 audit finding 8).
func TestCheckCompleteSet(t *testing.T) {
	e := func(name, os, arch string) Entry { return Entry{Name: name, OS: os, Arch: arch} }
	cases := []struct {
		name         string
		kind         Kind
		entries      []Entry
		goos, goarch string
		partial      bool
	}{
		{"whole rootfs", SandboxRootfs, []Entry{e("sbom", "", ""), e("vmlinuz", "linux", "amd64")}, "linux", "amd64", false},
		{"rootfs for arm64 only", SandboxRootfs, []Entry{e("sbom", "", ""), e("vmlinuz", "linux", "arm64")}, "linux", "amd64", true},
		{"guest for both arches", SandboxGuest, []Entry{e("observer-guest", "linux", "amd64"), e("observer-guest", "linux", "arm64")}, "linux", "arm64", false},
		{"guest missing this arch", SandboxGuest, []Entry{e("observer-guest", "linux", "arm64")}, "linux", "amd64", true},
		{"image descriptor and sbom", SandboxImage, []Entry{e("d", "", ""), e("s", "", "")}, "windows", "amd64", false},
		{"native files per OS", SandboxNative, []Entry{e("mxc_ffi.dll", "windows", "amd64"), e("mxc-exec-mac", "darwin", "arm64")}, "windows", "amd64", false},
	}
	for _, c := range cases {
		err := CheckCompleteSet(Manifest{Kind: c.kind, Entries: c.entries}, c.goos, c.goarch)
		if c.partial != (ReasonOf(err) == ContentReasonPartialSet) {
			t.Errorf("%s: %v, partial = %v", c.name, err, c.partial)
		}
	}
}
