package update

import (
	"errors"
	"testing"
)

func TestParseArtifactName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                           string
		in                             string
		wantVer, wantOS, wantArch, ext string
		wantErr                        error
	}{
		{"linux tarball", "observer-v1.33.0-linux-x64.tar.gz", "v1.33.0", "linux", "amd64", "tar.gz", nil},
		{"linux arm tarball", "observer-v1.33.0-linux-arm64.tar.gz", "v1.33.0", "linux", "arm64", "tar.gz", nil},
		{"darwin arm tarball", "observer-v1.33.0-darwin-arm64.tar.gz", "v1.33.0", "darwin", "arm64", "tar.gz", nil},
		{"win32 zip normalizes to windows/amd64", "observer-v1.33.0-win32-x64.zip", "v1.33.0", "windows", "amd64", "zip", nil},
		// Pre-release tags: the suffix belongs to the VERSION, never to the
		// os. v1.34.0-rc.1 (importer copy) and v1.34.0-rc.2 (pipeline copy)
		// each failed a release on this before the rule had one owner.
		{"rc tarball", "observer-v1.34.0-rc.2-linux-x64.tar.gz", "v1.34.0-rc.2", "linux", "amd64", "tar.gz", nil},
		{"rc zip", "observer-v1.34.0-rc.2-win32-x64.zip", "v1.34.0-rc.2", "windows", "amd64", "zip", nil},
		{"alpha tarball", "observer-v0.5.0-alpha-darwin-arm64.tar.gz", "v0.5.0-alpha", "darwin", "arm64", "tar.gz", nil},
		// A zip for a POSIX target (or a tarball for windows) is the
		// "unpack it somehow" guess the extractor must never make, and a
		// directory scanner must not skip it as a foreign file.
		{"posix target in a zip is refused", "observer-v1.33.0-linux-x64.zip", "", "", "", "", ErrArchiveTypeMismatch},
		{"windows target in a tarball is refused", "observer-v1.33.0-win32-x64.tar.gz", "", "", "", "", ErrArchiveTypeMismatch},
		{"foreign binary name", "observer-org-v1.33.0-linux-x64.tar.gz", "", "", "", "", ErrUnrecognizedArtifact},
		{"org archive with an rc version", "observer-org-v1.34.0-rc.2-linux-x64.tar.gz", "", "", "", "", ErrUnrecognizedArtifact},
		{"no version", "observer-linux-x64.tar.gz", "", "", "", "", ErrUnrecognizedArtifact},
		{"sums file", "SHA256SUMS", "", "", "", "", ErrUnrecognizedArtifact},
		{"signature beside an archive", "observer-v1.33.0-linux-x64.tar.gz.sig", "", "", "", "", ErrUnrecognizedArtifact},
		{"traversal attempt", "../observer-v1.33.0-linux-x64.tar.gz", "", "", "", "", ErrUnrecognizedArtifact},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ver, goos, goarch, ext, err := ParseArtifactName(tc.in)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if !errors.Is(err, ErrUnrecognizedArtifact) {
					t.Fatalf("err = %v, want it to also be ErrUnrecognizedArtifact", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseArtifactName: %v", err)
			}
			if ver != tc.wantVer || goos != tc.wantOS || goarch != tc.wantArch || ext != tc.ext {
				t.Fatalf("got %s %s/%s/%s, want %s %s/%s/%s", ver, goos, goarch, ext, tc.wantVer, tc.wantOS, tc.wantArch, tc.ext)
			}
		})
	}
}
