package sdkcredsvc

import (
	"path"
	"strings"
)

// The SDK-held credential file (SDK quickstart plan 3.4): the key the SDK's
// own `setup` stores for an app on a machine, read by every SDK, written
// only by `setup`. Observer never writes it and never reads it: `observer sdk
// status` only checks it is there and in a shape the SDKs accept (from its
// file facts, never its content), and names it present but unused when
// Observer's own SDK key wins the credential (ruling R10: the machine's
// record beats the file's).

// SDKHeldFileEnv names a path that replaces the SDK-held file's (a different
// user, a test).
const SDKHeldFileEnv = "SUPERBASED_CREDENTIAL_FILE" //nolint:gosec // G101: an environment variable name, not a credential

// sdkHeldFileRel is the file under its configuration directory.
const sdkHeldFileRel = "superbased/sdk-credential"

// Where the SDK-held file's path came from (HeldFile.Source).
const (
	HeldFileSourceEnv          = "env"
	HeldFileSourceXDG          = "xdg_config_home"
	HeldFileSourceHomeConfig   = "home_config"
	HeldFileSourceLocalAppData = "localappdata"
)

// heldFilePathRow is one rung of the path ladder.
type heldFilePathRow struct {
	source string
	// path returns the file's path, or "" when the rung does not apply.
	path func(goos string, getenv func(string) string, home string) string
}

// heldFilePathLadder is plan 3.4's path table, walked top-down: the first
// rung that names a path wins.
var heldFilePathLadder = []heldFilePathRow{
	{HeldFileSourceEnv, func(_ string, getenv func(string) string, _ string) string {
		return strings.TrimSpace(getenv(SDKHeldFileEnv))
	}},
	{HeldFileSourceLocalAppData, func(goos string, getenv func(string) string, _ string) string {
		base := strings.TrimSpace(getenv("LOCALAPPDATA"))
		if goos != "windows" || base == "" {
			return ""
		}
		return strings.TrimRight(base, `\/`) + `\` + strings.ReplaceAll(sdkHeldFileRel, "/", `\`)
	}},
	// XDG Base Directory: a relative XDG_CONFIG_HOME is invalid and ignored.
	{HeldFileSourceXDG, func(goos string, getenv func(string) string, _ string) string {
		base := strings.TrimSpace(getenv("XDG_CONFIG_HOME"))
		if goos == "windows" || !strings.HasPrefix(base, "/") {
			return ""
		}
		return path.Join(base, sdkHeldFileRel)
	}},
	{HeldFileSourceHomeConfig, func(goos string, _ func(string) string, home string) string {
		if goos == "windows" || !strings.HasPrefix(home, "/") {
			return ""
		}
		return path.Join(home, ".config", sdkHeldFileRel)
	}},
}

// SDKHeldFilePath is the SDK-held file's path on goos, from the environment
// and the home directory, and the rung that named it. ("", "") when no rung
// applies (Windows without LOCALAPPDATA, no home).
func SDKHeldFilePath(goos string, getenv func(string) string, home string) (string, string) {
	for _, r := range heldFilePathLadder {
		if p := r.path(goos, getenv, home); p != "" {
			return p, r.source
		}
	}
	return "", ""
}

// HeldFileMaxBytes is the most the SDKs read of the file (destination.md
// section 6a: section 6's 4096 bytes).
const HeldFileMaxBytes = 4096

// HeldFileFacts are what a stat of the SDK-held file says (never its
// content). The caller stats; the rules below are pure.
type HeldFileFacts struct {
	// Exists: something is at the path.
	Exists bool
	// StatErr is a stat failure other than "not there" ("" when none).
	StatErr string
	// Link: the path is a symbolic link, or on Windows any reparse point (a
	// symlink or a junction).
	Link bool
	// Regular: a regular file.
	Regular bool
	// Size is the file's size in bytes.
	Size int64
	// OpenToOthers: group or other permission bits are set (unix only; a
	// Windows caller leaves it false).
	OpenToOthers bool
	// ForeignOwner: the file belongs to another user (unix uid; a caller
	// that cannot tell leaves it false).
	ForeignOwner bool
	// OutsideLocalAppData: on Windows, the path is not inside the current
	// user's own LOCALAPPDATA (HeldFileOutsideLocalAppData).
	OutsideLocalAppData bool
}

// HeldFileOutsideLocalAppData is destination.md section 6a's Windows read
// rule 3: the path must be inside the current user's own LOCALAPPDATA,
// compared case-insensitively after cleaning, whatever chose the path. False
// on every other OS. Pure: both inputs are already absolute.
func HeldFileOutsideLocalAppData(goos, path, localAppData string) bool {
	if goos != "windows" {
		return false
	}
	clean := func(p string) string {
		p = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), `/`, `\`))
		for strings.Contains(p, `\\`) {
			p = strings.ReplaceAll(p, `\\`, `\`)
		}
		return strings.TrimRight(p, `\`)
	}
	base, file := clean(localAppData), clean(path)
	if base == "" || strings.Contains(file, `\..\`) || strings.HasSuffix(file, `\..`) {
		return true
	}
	return !strings.HasPrefix(file, base+`\`)
}

// SDK-held file states (HeldFile.State).
const (
	HeldFileNoPath    = "no_path"
	HeldFileAbsent    = "absent"
	HeldFileUnchecked = "unchecked"
	HeldFileRefused   = "refused"
	HeldFileUnused    = "unused"
	HeldFilePresent   = "present"
)

// HeldFile is the SDK-held file as `observer sdk status` reports it. It
// never carries the key.
type HeldFile struct {
	Path   string `json:"path"`
	Source string `json:"source,omitempty"`
	State  string `json:"state"`
	// Reason is the SDKs' refusal reason for a refused file, in
	// credential-file-cases.json's closed vocabulary (symlink, not_regular,
	// mode, owner, too_large, empty, reparse_point, outside_localappdata);
	// "" otherwise. The content reasons (bad_key_line, bad_name_line) need
	// the file read, which Observer never does.
	Reason string `json:"reason,omitempty"`
	// Text is the state in a plain sentence.
	Text string `json:"text"`
}

// heldFileInput is the input of the state table.
type heldFileInput struct {
	goos         string
	path         string
	facts        HeldFileFacts
	machineKeyOK bool
}

// heldFileAgain is the fix every refusal names.
const heldFileAgain = "; run the SDK's setup again"

// heldFileStateRows decides the state, walked top-down. The refusals follow
// destination.md section 6a's read order for the OS. One test case per row
// (heldfile_test.go).
var heldFileStateRows = []struct {
	state, reason string
	applies       func(in heldFileInput) bool
	text          func(in heldFileInput) string
}{
	{HeldFileNoPath, "", func(in heldFileInput) bool { return in.path == "" }, func(heldFileInput) string {
		return "this machine names no place for it (no home directory, or LOCALAPPDATA is not set)"
	}},
	{HeldFileUnchecked, "", func(in heldFileInput) bool { return in.facts.StatErr != "" }, func(in heldFileInput) string {
		return "could not be checked (" + in.facts.StatErr + ")"
	}},
	{HeldFileAbsent, "", func(in heldFileInput) bool { return !in.facts.Exists }, func(heldFileInput) string {
		return "none (the SDK's setup writes one for an app that sends online without this machine's key)"
	}},
	{HeldFileRefused, "reparse_point", func(in heldFileInput) bool { return in.goos == "windows" && in.facts.Link }, func(heldFileInput) string {
		return "refused by the SDKs: it is a link (a reparse point)" + heldFileAgain
	}},
	{HeldFileRefused, "symlink", func(in heldFileInput) bool { return in.facts.Link }, func(heldFileInput) string {
		return "refused by the SDKs: it is a symbolic link" + heldFileAgain
	}},
	{HeldFileRefused, "not_regular", func(in heldFileInput) bool { return !in.facts.Regular }, func(heldFileInput) string {
		return "refused by the SDKs: it is not a regular file" + heldFileAgain
	}},
	{HeldFileRefused, "outside_localappdata", func(in heldFileInput) bool { return in.facts.OutsideLocalAppData }, func(heldFileInput) string {
		return "refused by the SDKs: it is not inside your own LOCALAPPDATA folder" + heldFileAgain
	}},
	{HeldFileRefused, "mode", func(in heldFileInput) bool { return in.facts.OpenToOthers }, func(heldFileInput) string {
		return "refused by the SDKs: other users can read it; make it readable by you only (chmod 600)" + heldFileAgain
	}},
	{HeldFileRefused, "owner", func(in heldFileInput) bool { return in.facts.ForeignOwner }, func(heldFileInput) string {
		return "refused by the SDKs: it belongs to another user" + heldFileAgain
	}},
	{HeldFileRefused, "too_large", func(in heldFileInput) bool { return in.facts.Size > HeldFileMaxBytes }, func(heldFileInput) string {
		return "refused by the SDKs: it is larger than 4096 bytes" + heldFileAgain
	}},
	{HeldFileRefused, "empty", func(in heldFileInput) bool { return in.facts.Size == 0 }, func(heldFileInput) string {
		return "refused by the SDKs: it is empty" + heldFileAgain
	}},
	// Ruling R10: the machine's record wins the credential.
	{HeldFileUnused, "", func(in heldFileInput) bool { return in.machineKeyOK }, func(heldFileInput) string {
		return "present but unused: this machine's own SDK key wins, so apps send with that key, not the file's"
	}},
	{HeldFilePresent, "", func(heldFileInput) bool { return true }, func(heldFileInput) string {
		return "present: an app that sets no key of its own sends online with the key in it (written by the SDK's setup)"
	}},
}

// DescribeHeldFile reports the SDK-held file at path on goos from its stat
// facts and whether this machine offers the SDKs its own key
// (Status.Usable). Pure.
func DescribeHeldFile(goos, path, source string, facts HeldFileFacts, machineKeyUsable bool) HeldFile {
	in := heldFileInput{goos: goos, path: path, facts: facts, machineKeyOK: machineKeyUsable}
	out := HeldFile{Path: path, Source: source}
	for _, r := range heldFileStateRows {
		if r.applies(in) {
			out.State, out.Reason, out.Text = r.state, r.reason, r.text(in)
			return out
		}
	}
	return out
}
