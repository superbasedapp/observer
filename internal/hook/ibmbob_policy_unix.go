//go:build unix

package hook

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

// ibmBobPolicyFile is Bob's Linux policy file; Bob reads it on Linux only
// (and on z/OS / IBM i, which Go does not target).
const ibmBobPolicyFile = "/etc/bob/policy.json"

// ibmBobManagedPrefsDir is where macOS MDM places a managed-preferences
// domain: the device-wide plist, then the per-user one under <user>/.
const ibmBobManagedPrefsDir = "/Library/Managed Preferences"

// ibmBobPlutil converts a plist to JSON, by absolute path so PATH cannot
// redirect it.
const ibmBobPlutil = "/usr/bin/plutil"

func readIBMBobPolicyOS() IBMBobPolicy {
	switch runtime.GOOS {
	case "linux":
		return readIBMBobPolicyFile(ibmBobPolicyFile, nil)
	case "darwin":
		for _, p := range ibmBobManagedPlistPaths() {
			if pol := readIBMBobPolicyFile(p, plistToJSON); pol.Found {
				return pol
			}
		}
	}
	return IBMBobPolicy{}
}

// ibmBobManagedPlistPaths are the macOS managed-preferences plists of the
// com.ibm.bob domain, device-wide first, then the current user's.
func ibmBobManagedPlistPaths() []string {
	paths := []string{filepath.Join(ibmBobManagedPrefsDir, "com.ibm.bob.plist")}
	if u, err := user.Current(); err == nil && u.Username != "" {
		paths = append(paths, filepath.Join(ibmBobManagedPrefsDir, u.Username, "com.ibm.bob.plist"))
	}
	return paths
}

// readIBMBobPolicyDomainsOS reads Bob's macOS preferences domains under home
// (FU-105): the managed plists by the root-ownership rule, the user's own
// domain as untrusted. Every other OS has no such domain.
//
// The user plist is read from disk. cfprefsd writes a `defaults write`
// through to it, but asynchronously, so a value written a moment ago may not
// be visible yet (lane report FU-105, residual).
func readIBMBobPolicyDomainsOS(home string, system bool) IBMBobPolicyDomains {
	if runtime.GOOS != "darwin" {
		return IBMBobPolicyDomains{}
	}
	var managed []string
	if system {
		managed = ibmBobManagedPlistPaths()
	}
	return ibmBobPolicyDomainsAt(home, managed, plistToJSON, ibmBobOwnerUntrusted)
}

// ibmBobOwnerUntrusted is the trust rule of an administrator policy file:
// root-owned and not writable by group or others.
func ibmBobOwnerUntrusted(path string, fi os.FileInfo) string {
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case fi.Mode().Perm()&0o022 != 0:
		return path + " is writable by group or others"
	case !ok || st.Uid != 0:
		return path + " is not owned by root"
	}
	return ""
}

// readIBMBobPolicyFile reads a root-owned, not group/other-writable regular
// file (no symlink) and parses it, after convert when non-nil. A file a
// non-root user could have written is reported Untrusted: anyone able to
// write it could otherwise make Observer stand its own hooks down.
func readIBMBobPolicyFile(path string, convert func([]byte) ([]byte, error)) IBMBobPolicy {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return IBMBobPolicy{}
		}
		return IBMBobPolicy{Source: path, Found: true, Untrusted: path + " could not be inspected"}
	}
	p := IBMBobPolicy{Source: path, Found: true}
	switch {
	case !fi.Mode().IsRegular():
		p.Untrusted = path + " is not a regular file"
		return p
	case fi.Size() > ibmBobPolicyMaxBytes:
		p.Untrusted = path + " is too large"
		return p
	}
	// Ownership decides trust, not readability: Bob reads the file either
	// way, so its values are still reported (a refusal that protects the
	// export must see them), but an untrusted file never stands Observer down.
	untrusted := ibmBobOwnerUntrusted(path, fi)
	f, err := os.Open(path) //nolint:gosec // G304: a fixed policy path.
	if err != nil {
		p.Untrusted = path + " could not be read"
		return p
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, ibmBobPolicyMaxBytes+1))
	if err != nil || len(data) > ibmBobPolicyMaxBytes {
		p.Untrusted = path + " could not be read"
		return p
	}
	if convert != nil {
		if data, err = convert(data); err != nil {
			p.Untrusted = path + " could not be converted from a property list"
			return p
		}
	}
	p = ParseIBMBobPolicyDocument(path, data)
	if p.Untrusted == "" {
		p.Untrusted = untrusted
	}
	return p
}

// plistToJSON converts a (binary or XML) plist to JSON with plutil, reading
// stdin so the converted document is exactly the checked bytes.
func plistToJSON(data []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, ibmBobPlutil, "-convert", "json", "-o", "-", "--", "-")
	cmd.Stdin = bytes.NewReader(data)
	cmd.Env = []string{}
	return cmd.Output()
}
