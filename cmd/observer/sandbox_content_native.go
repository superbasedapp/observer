//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// sandbox_content_native.go reads the signed sandbox.native_files kind for
// the Windows driver (sandbox plan 12.3, SBX-SUP-1, lane SBX-P3D): the
// installed manifest, re-verified by the content channel, reduced to plain
// facts for sandboxmxc.ResolveSigned, which keeps the compiled pins as the
// floor. Nothing installed is today's behaviour byte for byte. It is not
// Windows-only so the reading is tested everywhere; only the Windows helper
// (mxcManifest) acts on it.

// mxcSignedInput reads the installed kind from st.
func mxcSignedInput(st contentchan.Store, tr contentchan.Trust, compiled sandboxmxc.Manifest, hasCompiled bool, goarch string) sandboxmxc.SignedInput {
	in := sandboxmxc.SignedInput{Compiled: compiled, HasCompiled: hasCompiled, Arch: goarch}
	l, err := st.Load(content.SandboxNative, tr, 0)
	if errors.Is(err, contentchan.ErrNotInstalled) {
		return in
	}
	in.Installed = true
	if err != nil {
		in.LoadError = err.Error()
		return in
	}
	in.Freshness = string(l.Freshness)
	for _, r := range l.Manifest.Revoked {
		in.Revoked = append(in.Revoked, r.SHA256)
	}
	b, err := l.ReadArtifact(sandboxmxc.NativeFilesName)
	if err != nil {
		in.DescriptorError = err.Error()
		return in
	}
	in.Descriptor = b
	return in
}

// mxcEffectiveSet resolves the MXC file set for observerDir and goarch.
func mxcEffectiveSet(observerDir, goarch string) sandboxmxc.SignedResult {
	m, ok := sandboxmxc.ManifestFor(goarch)
	st := sandboxContentStore(observerDir)
	st.GOOS, st.GOARCH = "windows", goarch
	return sandboxmxc.ResolveSigned(mxcSignedInput(st, contentchan.Trust{VendorKeys: sandboxContentVendorKeys()}, m, ok, goarch))
}
