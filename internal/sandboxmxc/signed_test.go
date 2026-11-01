package sandboxmxc

import (
	"strings"
	"testing"
)

// signedDescriptor is the descriptor vendorsign sandboxnative writes for
// the compiled x64 set.
func signedDescriptor(t *testing.T, mut func(*NativeFiles)) []byte {
	t.Helper()
	m := ManifestX64
	n := NativeFiles{
		Schema: NativeFilesSchema, OS: "windows", Arch: "amd64", Upstream: m.Upstream, Version: m.Version,
		PackageURL: m.PackageURL, PackageSHA256: m.PackageSHA256, MinVersion: m.Version, Signer: m.Signer,
		Authenticode: "valid mxc_ffi.dll=AB wxc-exec.exe=CD",
	}
	for _, f := range m.Files {
		n.Files = append(n.Files, NativeFile{Name: f.Name, PackagePath: f.PackagePath, SHA256: f.SHA256, Size: f.Size})
	}
	if mut != nil {
		mut(&n)
	}
	b, err := n.Encode()
	if err != nil && mut == nil {
		t.Fatal(err)
	}
	if err != nil {
		// A mutation that breaks validation is encoded raw, so the parse
		// row is what refuses it.
		b = []byte(`{"schema":"` + n.Schema + `"}`)
	}
	return b
}

func signedIn(t *testing.T) SignedInput {
	return SignedInput{
		Compiled: ManifestX64, HasCompiled: true, Arch: "amd64", Installed: true, Freshness: "fresh",
		Descriptor: signedDescriptor(t, nil),
	}
}

// TestResolveSignedRows is one case per row of the decision table.
func TestResolveSignedRows(t *testing.T) {
	cases := []struct {
		name   string
		mut    func(*SignedInput)
		ok     bool
		rule   string
		source string
		stale  bool
		reason string
	}{
		{"no compiled set", func(in *SignedInput) { in.HasCompiled, in.Compiled = false, Manifest{} }, true, "no_compiled_set", SignedSourceCompiled, false, ""},
		{"none installed", func(in *SignedInput) { in.Installed, in.Descriptor = false, nil }, true, "none_installed", SignedSourceCompiled, false, ""},
		{"load error", func(in *SignedInput) { in.LoadError = "vendor_signature" }, false, "load", "", false, "does not verify"},
		{"past the age floor", func(in *SignedInput) { in.Freshness = "unknown" }, false, "age", "", false, "age floor"},
		{"package revoked", func(in *SignedInput) { in.Revoked = []string{ManifestX64.PackageSHA256} }, false, "revoked", "", false, "revokes the MXC package"},
		{"file revoked", func(in *SignedInput) { in.Revoked = []string{strings.ToUpper(ManifestX64.Files[1].SHA256)} }, false, "revoked", "", false, "revokes wxc-exec.exe"},
		{"descriptor unreadable", func(in *SignedInput) { in.DescriptorError = "not_covered" }, false, "descriptor", "", false, "cannot be read"},
		{"descriptor malformed", func(in *SignedInput) {
			in.Descriptor = signedDescriptor(t, func(n *NativeFiles) { n.Authenticode = "not_checked" })
		}, false, "descriptor", "", false, "native files"},
		{"another arch", func(in *SignedInput) {
			in.Descriptor = signedDescriptor(t, func(n *NativeFiles) { n.Arch = "arm64" })
		}, false, "platform", "", false, "is for arm64"},
		{"a different hash", func(in *SignedInput) {
			in.Descriptor = signedDescriptor(t, func(n *NativeFiles) { n.Files[0].SHA256 = strings.Repeat("a", 64) })
		}, false, "floor", "", false, "compiled pins do not"},
		{"a newer version", func(in *SignedInput) {
			in.Descriptor = signedDescriptor(t, func(n *NativeFiles) { n.Version, n.MinVersion = "1.0.2", "1.0.2" })
		}, false, "floor", "", false, "agent release"},
		{"an extra file", func(in *SignedInput) {
			in.Descriptor = signedDescriptor(t, func(n *NativeFiles) {
				n.Files = append(n.Files, NativeFile{Name: "extra.dll", PackagePath: "package/x", SHA256: strings.Repeat("b", 64), Size: 1})
			})
		}, false, "floor", "", false, "3 files"},
		{"minimum raised", func(in *SignedInput) {
			in.Descriptor = signedDescriptor(t, func(n *NativeFiles) { n.MinVersion = "1.1.0" })
		}, false, "min_version", "", false, "below the signed minimum 1.1.0"},
		{"stale is last-known-good", func(in *SignedInput) { in.Freshness = "stale" }, true, "signed", SignedSourceSigned, true, ""},
		{"fresh", nil, true, "signed", SignedSourceSigned, false, ""},
	}
	rules := map[string]bool{}
	for _, tc := range cases {
		in := signedIn(t)
		if tc.mut != nil {
			tc.mut(&in)
		}
		r := ResolveSigned(in)
		rules[r.Rule] = true
		if r.OK != tc.ok || r.Rule != tc.rule || r.Source != tc.source || r.Stale != tc.stale {
			t.Errorf("%s: %+v", tc.name, r)
			continue
		}
		if !tc.ok {
			if r.Verdict.Code != VerdictArtifactUnverified || !strings.Contains(r.Verdict.Reason, tc.reason) {
				t.Errorf("%s: %+v, want reason %q", tc.name, r.Verdict, tc.reason)
			}
			continue
		}
		// The effective set is always the compiled pins.
		if len(r.Manifest.Files) != len(in.Compiled.Files) || (in.HasCompiled && r.Manifest.Files[0].SHA256 != ManifestX64.Files[0].SHA256) {
			t.Errorf("%s: the effective set is not the compiled pins: %+v", tc.name, r.Manifest)
		}
	}
	for _, id := range SignedRules() {
		if !rules[id] {
			t.Errorf("no case decides at row %s", id)
		}
	}
}

// TestNoneInstalledIsByteIdentical: with nothing installed the effective
// set is exactly ManifestFor's.
func TestNoneInstalledIsByteIdentical(t *testing.T) {
	m, ok := ManifestFor("amd64")
	r := ResolveSigned(SignedInput{Compiled: m, HasCompiled: ok, Arch: "amd64"})
	if !r.OK || r.Source != SignedSourceCompiled {
		t.Fatalf("%+v", r)
	}
	a, _ := NativeFilesFromManifest(m, "amd64", "valid x").Encode()
	b, _ := NativeFilesFromManifest(r.Manifest, "amd64", "valid x").Encode()
	if string(a) != string(b) || r.Manifest.PackageIntegrity != m.PackageIntegrity {
		t.Fatal("the effective set differs from the compiled pins")
	}
}

func TestVersionLess(t *testing.T) {
	for _, c := range []struct {
		a, b string
		less bool
	}{{"1.0.1", "1.0.2", true}, {"1.0.1", "1.0.1", false}, {"1.10.0", "1.9.9", false}, {"1.0", "1.0.1", true}, {"x", "1.0", false}} {
		if versionLess(c.a, c.b) != c.less {
			t.Errorf("versionLess(%s, %s) != %v", c.a, c.b, c.less)
		}
	}
}
