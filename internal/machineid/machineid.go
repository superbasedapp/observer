package machineid

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// readFile, hostname, and runTool are the injectable I/O seams (CLAUDE.md #1).
// Tests override them; the defaults perform the real OS reads. runTool wraps a
// platform helper (ioreg on darwin, reg.exe on windows) and returns its stdout.
var (
	readFile = os.ReadFile
	hostname = os.Hostname
	runTool  = func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).Output()
	}
	// goos is a seam so a test can exercise every platform branch of
	// rawIdentity regardless of the host it runs on.
	goos = runtime.GOOS
)

// The PERSISTED-SEED rung's own I/O seams, kept separate from the read-only
// ones above because this rung is the only part of the package that WRITES.
// Tests override all four; a test that leaves them at their defaults would
// touch the developer's real data dir.
var (
	homeDir  = os.UserHomeDir
	mkdirAll = os.MkdirAll
	randRead = rand.Read
	// writeFileExcl creates path with O_EXCL — the create itself, not a
	// check-then-write, is what arbitrates between two processes racing to
	// mint the seed. The loser gets fs.ErrExist and re-reads the winner's
	// value, so a machine never ends up with two identities.
	writeFileExcl = func(path string, data []byte, perm fs.FileMode) error {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if err != nil {
			return err
		}
		if _, err := f.Write(data); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	}
)

const (
	// seedDirName / seedFileName locate the persisted seed inside the observer
	// data dir (~/.observer/machine-id), alongside config.toml and observer.db
	// — so any deployment that already mounts a volume for its database
	// automatically persists its identity too.
	seedDirName  = ".observer"
	seedFileName = "machine-id"
	// seedBytes is the minted seed's entropy. 16 bytes (128 bits) makes an
	// accidental collision across a fleet impossible in practice; the value is
	// hashed with the org salt before it ever leaves the host anyway.
	seedBytes = 16
)

// ForOrg returns the org-salted, one-way machine fingerprint for orgID, or the
// empty string when no stable OS source is available on this host. The empty
// string is a first-class value: the caller treats an unbindable node as a
// visible "unbound" managed node rather than an error, so ForOrg returns a nil
// error in that case — err is non-nil only for an unexpected I/O failure the
// caller may want to log.
//
// orgID must be non-empty; salting with it guarantees the same machine yields
// unrelated identities across orgs and that the raw OS id never leaves the host.
func ForOrg(orgID string) (string, error) {
	raw, err := rawIdentity()
	if err != nil {
		return "", err
	}
	raw = strings.TrimSpace(raw)
	if raw == "" || orgID == "" {
		return "", nil
	}
	return hashIdentity(orgID, raw), nil
}

// hashIdentity is the pure salt-and-hash core: SHA-256 over a domain-separated
// (org, raw) pair, hex-encoded. Domain separation (the "\x00" delimiter between
// the salt and the raw id) prevents a different (org, raw) split from colliding.
func hashIdentity(orgID, raw string) string {
	h := sha256.New()
	h.Write([]byte("sbo-machineid\x00"))
	h.Write([]byte(orgID))
	h.Write([]byte{0})
	h.Write([]byte(raw))
	return hex.EncodeToString(h.Sum(nil))
}

// rawIdentity selects the most stable machine source available on this host,
// walking the ordered ladder documented in the package doc: the OS-native
// source, then a self-minted seed persisted in the observer data dir, then the
// hostname. It returns ("", nil) when nothing usable is found — never an error
// for a merely-absent source, so a host with no writable state and no hostname
// degrades to "unbindable" rather than failing.
func rawIdentity() (string, error) {
	switch goos {
	case "linux":
		// /etc/machine-id is the systemd/D-Bus stable machine id; the
		// /var/lib/dbus path is the same value on non-systemd installs. Under
		// WSL2 this is the DISTRO's id (documented in the package doc).
		if id := firstFileValue("/etc/machine-id", "/var/lib/dbus/machine-id"); id != "" {
			return id, nil
		}
	case "darwin":
		if id := darwinPlatformUUID(); id != "" {
			return id, nil
		}
	case "windows":
		if id := windowsMachineGUID(); id != "" {
			return id, nil
		}
	}
	// Persisted-seed rung. Every OS, and deliberately ABOVE the hostname: a
	// container image carries no /etc/machine-id, so without this rung the
	// hostname is the identity — and orchestrators that remint the hostname per
	// restart (Azure Container Instances' SandboxHost-<n> is the case that
	// prompted this) orphan the machine binding on every restart, leaving the
	// node 409ing until a human re-enrols it. A seed on the data dir survives
	// the restart whenever that dir is a mounted volume, which is exactly the
	// deployment shape that also wants a stable identity.
	if id := persistedIdentity(); id != "" {
		return id, nil
	}
	// Hostname fallback for every OS. Weakest source (hostnames collide and
	// change), but better than an empty identity on a host without a stable id
	// — and the ONLY source left on a read-only filesystem, where the seed
	// above cannot be minted.
	if hn, err := hostname(); err == nil {
		return strings.TrimSpace(hn), nil
	}
	return "", nil
}

// persistedIdentity read-or-mints the self-generated seed at
// <home>/.observer/machine-id and returns its value, or "" when the data dir
// is unreachable or unwritable (the caller then falls through to the hostname).
//
// It is additive and deterministic: once the file exists, every later call on
// that host returns the same value, and a host that ALREADY has an OS-native
// source never reaches this rung at all — so no existing machine's identity
// changes when this rung ships.
//
// Writing is best-effort by design. A read-only root filesystem, a full disk,
// or a home dir the process cannot create all yield "" rather than an error,
// because an unbindable-but-running node is the product's chosen degradation
// (see ForOrg) and a machine fingerprint is evidence, not prevention.
func persistedIdentity() string {
	home, err := homeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ""
	}
	path := filepath.Join(home, seedDirName, seedFileName)
	if v := firstFileValue(path); v != "" {
		return v
	}

	var buf [seedBytes]byte
	if _, err := randRead(buf[:]); err != nil {
		return ""
	}
	id := hex.EncodeToString(buf[:])

	// 0700 dir + 0600 file: the seed is not a secret (it is hashed with the org
	// salt before it is ever sent) but it is machine state that only this user's
	// daemon should write. Filesystems that ignore modes — the SMB shares these
	// containers mount — simply carry the create through.
	if err := mkdirAll(filepath.Dir(path), 0o700); err != nil {
		return ""
	}
	if err := writeFileExcl(path, []byte(id+"\n"), 0o600); err != nil {
		// Either another process won the mint race (fs.ErrExist) or the path is
		// unwritable. Re-reading distinguishes them without branching on the
		// error: a value means the race, nothing means fall through to hostname.
		return firstFileValue(path)
	}
	return id
}

// firstFileValue returns the trimmed contents of the first readable, non-empty
// path, or "" if none read.
func firstFileValue(paths ...string) string {
	for _, p := range paths {
		b, err := readFile(p)
		if err != nil {
			continue
		}
		if v := strings.TrimSpace(string(b)); v != "" {
			return v
		}
	}
	return ""
}

// darwinPlatformUUID extracts IOPlatformUUID from `ioreg`. Returns "" on any
// failure so the caller falls back to the hostname.
func darwinPlatformUUID() string {
	out, err := runTool("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	if err != nil {
		return ""
	}
	return extractQuotedAfter(string(out), "IOPlatformUUID")
}

// windowsMachineGUID reads HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid via
// reg.exe. Returns "" on any failure so the caller falls back to the hostname.
func windowsMachineGUID() string {
	out, err := runTool("reg", "query",
		`HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid")
	if err != nil {
		return ""
	}
	// reg output: a line like "    MachineGuid    REG_SZ    <guid>".
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "MachineGuid") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			return fields[len(fields)-1]
		}
	}
	return ""
}

// extractQuotedAfter finds `key` in text and returns the first double-quoted
// token appearing after it on the same logical run (ioreg renders
// `"IOPlatformUUID" = "<uuid>"`).
func extractQuotedAfter(text, key string) string {
	i := strings.Index(text, key)
	if i < 0 {
		return ""
	}
	rest := text[i+len(key):]
	// Skip to the value's opening quote after the `=`.
	eq := strings.Index(rest, "=")
	if eq < 0 {
		return ""
	}
	rest = rest[eq+1:]
	start := strings.Index(rest, "\"")
	if start < 0 {
		return ""
	}
	rest = rest[start+1:]
	end := strings.Index(rest, "\"")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:end])
}
