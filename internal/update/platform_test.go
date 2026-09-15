package update

import "testing"

// TestNormalizePlatformSpellings pins the alias tables. The release
// pipeline names assets "linux-x64" / "win32-x64" while Go says
// "linux/amd64" / "windows/amd64"; a manifest may be authored either
// way and must still select the same artifact.
func TestNormalizePlatformSpellings(t *testing.T) {
	osCases := map[string]string{
		"linux": "linux", "Linux": "linux",
		"darwin": "darwin", "macos": "darwin", "osx": "darwin", "mac": "darwin",
		"windows": "windows", "win32": "windows", "WIN32": "windows", "win": "windows",
		"plan9": "plan9", // unknown stays visible, never folded onto a default
	}
	for in, want := range osCases {
		if got := NormalizeOS(in); got != want {
			t.Errorf("NormalizeOS(%q) = %q, want %q", in, got, want)
		}
	}
	archCases := map[string]string{
		"amd64": "amd64", "x64": "amd64", "x86_64": "amd64", "X64": "amd64",
		"arm64": "arm64", "aarch64": "arm64",
		"riscv64": "riscv64",
	}
	for in, want := range archCases {
		if got := NormalizeArch(in); got != want {
			t.Errorf("NormalizeArch(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestArchiveShapeHelpers pins the per-OS shapes the pipeline really
// emits, including the alias name the extractor skips.
func TestArchiveShapeHelpers(t *testing.T) {
	cases := []struct {
		goos                       string
		archive, binary, aliasName string
	}{
		{"linux", ArchiveTarGz, "observer", "superbased"},
		{"darwin", ArchiveTarGz, "observer", "superbased"},
		{"macos", ArchiveTarGz, "observer", "superbased"},
		{"windows", ArchiveZip, "observer.exe", "superbased.exe"},
		{"win32", ArchiveZip, "observer.exe", "superbased.exe"},
	}
	for _, tc := range cases {
		t.Run(tc.goos, func(t *testing.T) {
			if got := DefaultArchiveTypeFor(tc.goos); got != tc.archive {
				t.Errorf("DefaultArchiveTypeFor = %q, want %q", got, tc.archive)
			}
			if got := BinaryName(tc.goos); got != tc.binary {
				t.Errorf("BinaryName = %q, want %q", got, tc.binary)
			}
			if got := AliasName(tc.goos); got != tc.aliasName {
				t.Errorf("AliasName = %q, want %q", got, tc.aliasName)
			}
		})
	}
	if KnownArchiveType("7z") || KnownArchiveType("") {
		t.Error("KnownArchiveType accepted an unknown shape")
	}
	if !KnownArchiveType(ArchiveTarGz) || !KnownArchiveType(ArchiveZip) {
		t.Error("KnownArchiveType rejected a real shape")
	}
}

// TestSelectArtifact walks the selection rule, including the
// normalization that makes two spellings of one platform the same row.
func TestSelectArtifact(t *testing.T) {
	m := baseManifest()
	cases := []struct {
		goos, goarch string
		wantFile     string
		wantOK       bool
	}{
		{"linux", "amd64", "observer-v1.33.0-linux-x64.tar.gz", true},
		{"linux", "x64", "observer-v1.33.0-linux-x64.tar.gz", true},
		{"windows", "amd64", "observer-v1.33.0-win32-x64.zip", true},
		{"win32", "x64", "observer-v1.33.0-win32-x64.zip", true},
		{"darwin", "arm64", "", false},
		{"linux", "arm64", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.goos+"/"+tc.goarch, func(t *testing.T) {
			a, ok := SelectArtifact(m, KindAgent, tc.goos, tc.goarch)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && a.Filename != tc.wantFile {
				t.Fatalf("filename = %q, want %q", a.Filename, tc.wantFile)
			}
		})
	}
	if _, ok := SelectArtifact(m, "edge-collector", "linux", "amd64"); ok {
		t.Error("selection ignored the artifact kind")
	}
}

// TestCurrentPlatformIsNormalized guards the one place runtime values
// enter the package.
func TestCurrentPlatformIsNormalized(t *testing.T) {
	goos, goarch := CurrentPlatform()
	if goos != NormalizeOS(goos) || goarch != NormalizeArch(goarch) {
		t.Fatalf("CurrentPlatform() = %s/%s, which is not already normalized", goos, goarch)
	}
}

// TestArtifactKeyString keeps the error-message spelling stable.
func TestArtifactKeyString(t *testing.T) {
	if got := KeyOf(linuxArtifact()).String(); got != "agent/linux/amd64" {
		t.Fatalf("key = %q", got)
	}
}
