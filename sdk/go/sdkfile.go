package superbased

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"runtime"
	"strings"
	"time"
)

// The SDK-held credential file (SDK quickstart plan section 3.4, contract
// destination.md section 6a; cases sdk/contract/credential-file-cases.json):
// an owner-only file outside the project, written only by
// `npx @superbased/sdk setup` or `uvx superbased-sdk setup` (a Go app gets
// its key with `setup --key-only`), read by every SDK. The runtime SDK never
// writes it.

// EnvCredentialFile replaces the SDK-held credential file's path.
const EnvCredentialFile = "SUPERBASED_CREDENTIAL_FILE" //nolint:gosec // a variable name, not a credential

const (
	sdkFileDir           = "superbased"
	sdkFileName          = "sdk-credential"
	credDestinationField = "destination"
	credDashboardField   = "dashboard_url"
	credExpiresField     = "expires_at"
	credRecordLimit      = 4096
	// expiryWarnWindow is how long before expires_at the SDK starts warning.
	expiryWarnWindow = 14 * 24 * time.Hour
	// setupFix is the fix named when the SDK-held file is the problem.
	setupFix = "run setup again (npx @superbased/sdk setup --key-only, or uvx superbased-sdk setup --key-only)"
)

// Why a credential file was refused (credential-file-cases.json reasons, a
// closed vocabulary; "" for an I/O error).
const (
	reasonSymlink             = "symlink"
	reasonNotRegular          = "not_regular"
	reasonMode                = "mode"
	reasonOwner               = "owner"
	reasonTooLarge            = "too_large"
	reasonEmpty               = "empty"
	reasonBadKeyLine          = "bad_key_line"
	reasonBadNameLine         = "bad_name_line"
	reasonReparsePoint        = "reparse_point"
	reasonOutsideLocalAppData = "outside_localappdata"
)

// Where the SDK-held file stands after a plan (Diagnostics.SDKFile.State).
const (
	sdkFileAbsent  = "absent"   // read, and there is no file
	sdkFileUsed    = "used"     // its key is the online credential
	sdkFileUnused  = "unused"   // valid, but another record won or no key was needed
	sdkFileRefused = "refused"  // present, but the read rules refused it
	sdkFileExpired = "expired"  // valid, but its expires_at has passed
	sdkFileNotRead = "not_read" // an explicit local: never read
)

// sourceSDKFile is the destination source (rung 3) and the credential
// source (record 3) the SDK-held file gives.
const sourceSDKFile = "sdk_file"

// sdkFileGOOS is the OS whose path ladder applies (a variable for tests).
var sdkFileGOOS = runtime.GOOS

// processUID is this process's uid, which the unix rules compare a file's
// owner with (a variable so tests can stand in for another user's file
// without chown; -1 on Windows, where the owner SID is compared instead).
var processUID = os.Getuid

// sdkFilePath is the SDK-held credential file's path, "" when none can be
// named: SUPERBASED_CREDENTIAL_FILE (not blank); on Windows
// %LOCALAPPDATA%\superbased\sdk-credential (no LOCALAPPDATA: no default
// path); elsewhere $XDG_CONFIG_HOME/superbased/sdk-credential (an absolute
// XDG_CONFIG_HOME only, per the XDG spec), else
// $HOME/.config/superbased/sdk-credential.
func sdkFilePath(env envFunc, goos string) string {
	if v := strings.TrimSpace(env.get(EnvCredentialFile)); v != "" {
		return v
	}
	if goos == "windows" {
		base := windowsCredentialRoot(env)
		if base == "" {
			return ""
		}
		return base + `\` + sdkFileDir + `\` + sdkFileName
	}
	if x := strings.TrimSpace(env.get("XDG_CONFIG_HOME")); strings.HasPrefix(x, "/") {
		return path.Join(x, sdkFileDir, sdkFileName)
	}
	if home := strings.TrimSpace(env.get("HOME")); home != "" {
		return path.Join(home, ".config", sdkFileDir, sdkFileName)
	}
	return ""
}

// windowsCredentialRoot is the folder the Windows rule requires the file to
// be inside: %LOCALAPPDATA% ("" when unset).
func windowsCredentialRoot(env envFunc) string {
	return strings.TrimRight(strings.TrimSpace(env.get("LOCALAPPDATA")), `\/`)
}

// credFormatProblem refuses a bad key line or name line (the machine's file
// says the same since 0.1).
const credFormatProblem = "the SDK credential file is not one key line followed by name=value lines; refused" //nolint:gosec // a message, not a credential

// credRecord is one parsed credential record (contract destination.md
// section 6 and 6a). It holds the key: never log it.
type credRecord struct {
	key          string
	gateway      string // "" when absent or unusable
	destination  string // online | both | ""
	destLine     bool   // the file has a destination line (valid or not)
	dashboardURL string // https base, "" when absent or unusable
	expiresAt    time.Time
	gatewayIssue string   // why a gateway_url line was ignored
	ignored      []string // the names whose line was ignored, in file order
	warnings     []string // why each was ignored
}

// parseCredentialRecord parses a credential file's bytes: the first line is
// <key_id>.<secret>, each further line is name=value, at most 4096 bytes, an
// optional final newline, CRLF read as LF. Unknown names are ignored. A
// refusal is a problem and its reason, with an empty record.
func parseCredentialRecord(raw []byte) (credRecord, string, string) {
	switch {
	case len(raw) == 0:
		return credRecord{}, "the SDK credential file is empty; refused", reasonEmpty
	case len(raw) > credRecordLimit:
		return credRecord{}, "the SDK credential file is over 4096 bytes; refused", reasonTooLarge
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	key := lines[0]
	keyID, secret, dot := strings.Cut(key, ".")
	if !dot || keyID == "" || secret == "" || !printableNoSpace(key) {
		return credRecord{}, credFormatProblem, reasonBadKeyLine
	}
	rec := credRecord{key: key}
	fields := map[string]string{}
	for _, line := range lines[1:] {
		name, value, eq := strings.Cut(line, "=")
		if !eq || name == "" || !asciiText(line) {
			return credRecord{}, credFormatProblem, reasonBadNameLine
		}
		fields[name] = strings.TrimSpace(value)
	}
	ignore := func(name, why string) {
		rec.ignored = append(rec.ignored, name)
		rec.warnings = append(rec.warnings, why)
	}
	if g, ok := fields[credGatewayField]; ok {
		if p := gatewayProblem(g); p != "" {
			rec.gatewayIssue = fmt.Sprintf("the SDK credential file names a gateway address that is not usable (%s); it is ignored", p)
			ignore(credGatewayField, rec.gatewayIssue)
		} else {
			rec.gateway = strings.TrimRight(g, "/")
		}
	}
	if d, ok := fields[credDestinationField]; ok {
		rec.destLine = true
		if v := strings.ToLower(d); v == DestinationOnline || v == DestinationBoth {
			rec.destination = v
		} else {
			ignore(credDestinationField, fmt.Sprintf("the SDK credential file names destination %q, which is not online or both; it is ignored", d))
		}
	}
	if u, ok := fields[credDashboardField]; ok {
		if p := dashboardURLProblem(u); p != "" {
			ignore(credDashboardField, fmt.Sprintf("the SDK credential file names a dashboard address that is not usable (%s); it is ignored", p))
		} else {
			rec.dashboardURL = strings.TrimRight(u, "/")
		}
	}
	if e, ok := fields[credExpiresField]; ok {
		if t, err := time.Parse(time.RFC3339, e); err != nil {
			ignore(credExpiresField, fmt.Sprintf("the SDK credential file's expires_at %q is not an RFC 3339 time with a zone; it is ignored", e))
		} else {
			rec.expiresAt = t
		}
	}
	return rec, "", ""
}

// printableNoSpace reports whether s is printable ASCII with no space.
func printableNoSpace(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// asciiText reports whether s is printable ASCII (a tab allowed).
func asciiText(s string) bool {
	for i := 0; i < len(s); i++ {
		if (s[i] < ' ' && s[i] != '\t') || s[i] > '~' {
			return false
		}
	}
	return true
}

// dashboardURLProblem is "" when raw is a usable dashboard base for links:
// https with a host, no user info, path, query or fragment. It is never a
// place the key or any data is sent.
func dashboardURLProblem(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Sprintf("%q is not a URL", raw)
	}
	switch {
	case u.Scheme != "https" || u.Hostname() == "":
		return fmt.Sprintf("%q is not an https address with a host", raw)
	case u.User != nil:
		return fmt.Sprintf("%q carries a user name or password", raw)
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/"):
		return fmt.Sprintf("%q is not a base address", raw)
	}
	return ""
}

// sdkHeld is the SDK-held file as one read gave it.
type sdkHeld struct {
	path     string
	present  bool       // the file exists (refused or not)
	ok       bool       // it passed the read rules and parsed
	rec      credRecord // zero unless ok
	problem  string     // why a present file is refused
	reason   string     // the refused rule (credential-file-cases.json reasons)
	expired  bool       // ok, but expires_at has passed
	warnings []string   // ignored lines and the expiry diagnostic
}

// usable reports whether the file's record may serve as record 3: it was
// read and has not expired.
func (h sdkHeld) usable() bool { return h.ok && !h.expired }

// readSDKHeld reads the SDK-held credential file at p under the read rules
// (readSDKHeldFile; root is the Windows rule's %LOCALAPPDATA%) and the
// record format. A missing file is not a problem.
func readSDKHeld(p, root string, now time.Time) sdkHeld {
	h := sdkHeld{path: p}
	if p == "" {
		return h
	}
	raw, problem, reason, missing := readSDKHeldFile(p, root, credRecordLimit+1)
	if missing {
		return h
	}
	h.present = true
	if problem == "" {
		h.rec, problem, reason = parseCredentialRecord(raw)
	}
	if problem != "" {
		h.problem, h.reason, h.rec = problem, reason, credRecord{}
		return h
	}
	h.ok = true
	h.warnings = append(h.warnings, h.rec.warnings...)
	if !h.rec.expiresAt.IsZero() {
		day := h.rec.expiresAt.UTC().Format("2006-01-02")
		switch left := h.rec.expiresAt.Sub(now); {
		case left <= 0:
			h.expired = true
			h.warnings = append(h.warnings, fmt.Sprintf("the SDK key in %s expired on %s, so it is not used: %s to get a new one", p, day, setupFix))
		case left <= expiryWarnWindow:
			h.warnings = append(h.warnings, fmt.Sprintf("your SDK key expires on %s; %s to get a new one", day, setupFix))
		}
	}
	return h
}

// refusal is the one warning a refused SDK-held file gives.
func (h sdkHeld) refusal() string {
	if !h.present || h.problem == "" {
		return ""
	}
	return fmt.Sprintf("the SDK-held key file %s is not used: %s", h.path, h.problem)
}

// underWindowsDir reports whether the Windows path file is strictly inside
// dir: both as GetFinalPathNameByHandle gives them (an optional \\?\
// prefix), compared without case after turning / into \.
func underWindowsDir(file, dir string) bool {
	norm := func(p string) string {
		p = strings.ReplaceAll(p, "/", `\`)
		p = strings.TrimPrefix(p, `\\?\`)
		return strings.ToLower(strings.TrimRight(p, `\`))
	}
	f, d := norm(file), norm(dir)
	return d != "" && strings.HasPrefix(f, d+`\`) && len(f) > len(d)+1
}

// sdkFileReader reads the SDK-held file at most once per plan and adds its
// warnings the first time.
type sdkFileReader struct {
	path string
	root string
	now  time.Time
	done bool
	h    sdkHeld
}

func newSDKFileReader(env envFunc, now time.Time) *sdkFileReader {
	return &sdkFileReader{path: sdkFilePath(env, sdkFileGOOS), root: windowsCredentialRoot(env), now: now}
}

func (r *sdkFileReader) get(warnings *[]string) sdkHeld {
	if !r.done {
		r.done = true
		r.h = readSDKHeld(r.path, r.root, r.now)
		*warnings = append(*warnings, r.h.warnings...)
		if w := r.h.refusal(); w != "" {
			*warnings = append(*warnings, w)
		}
	}
	return r.h
}

// destination is rung 3: the file's destination line when the file passes
// the read rules (an expired key included: the person chose online) and the
// line is online or both, with source sdk_file; ("", "") otherwise. A file
// with no destination line says so once.
func (r *sdkFileReader) destination(warnings *[]string) (string, string) {
	h := r.get(warnings)
	if !h.ok {
		return "", ""
	}
	if h.rec.destination != "" {
		return h.rec.destination, sourceSDKFile
	}
	if !h.rec.destLine {
		*warnings = append(*warnings, fmt.Sprintf("the SDK-held key file %s has no destination line (online or both), so it does not choose the destination", h.path))
	}
	return "", ""
}

// SDKFileInfo is the SDK-held credential file in Diagnostics. It never
// holds the key.
type SDKFileInfo struct {
	// Path is the file's path ("" when none can be named).
	Path string `json:"path"`
	// State is absent, used, unused (valid, but the machine's record or an
	// argument or env key won, or the destination needs no key), refused,
	// expired, or not_read (an explicit local).
	State string `json:"state"`
	// Reason is the refused rule (symlink, not_regular, mode, owner,
	// too_large, empty, bad_key_line, bad_name_line, reparse_point,
	// outside_localappdata), or "".
	Reason string `json:"reason"`
}

// info is the file's Diagnostics entry for a plan whose credential came
// from keySource.
func (r *sdkFileReader) info(keySource string) SDKFileInfo {
	out := SDKFileInfo{Path: r.path}
	switch {
	case !r.done:
		out.State = sdkFileNotRead
	case !r.h.present:
		out.State = sdkFileAbsent
	case !r.h.ok:
		out.State, out.Reason = sdkFileRefused, r.h.reason
	case r.h.expired:
		out.State = sdkFileExpired
	case keySource == sourceSDKFile:
		out.State = sdkFileUsed
	default:
		out.State = sdkFileUnused
	}
	return out
}

// applySDKFile applies credential record 3 (the SDK-held file) to a plan
// whose destination includes online: (key, keySource, gateway, dashboard,
// warnings). A key and its gateway travel together: the file's key is used
// only with the file's own gateway_url (record 1, an explicit key, may take
// that gateway line, as with the machine's file). The machine's record, when
// it gave a key, wins (ruling R10); the file is then named as unused.
func applySDKFile(r *sdkFileReader, machineRecord, machineKeyUsed bool, key, keySource, gateway, dashboard string) (string, string, string, string, []string) {
	var w []string
	if machineKeyUsed {
		if h := r.get(&w); h.usable() {
			w = append(w, fmt.Sprintf("the SDK-held key file %s is present but unused: this machine's own SDK key (observer sdk sign-in) is used", h.path))
		}
		return key, keySource, gateway, dashboard, w
	}
	if machineRecord || (key != "" && gateway != "") {
		return key, keySource, gateway, dashboard, w
	}
	h := r.get(&w)
	if !h.usable() {
		return key, keySource, gateway, dashboard, w
	}
	if key == "" {
		if gateway != "" && !strings.EqualFold(strings.TrimRight(gateway, "/"), h.rec.gateway) {
			w = append(w, fmt.Sprintf("the SDK-held key in %s is for %s, not for the organization address the app named (%s); it is not sent there", h.path, h.rec.gateway, gateway))
			return key, keySource, gateway, dashboard, w
		}
		key, keySource, dashboard = h.rec.key, sourceSDKFile, h.rec.dashboardURL
	}
	if gateway == "" {
		// Record 1 (an explicit key) may take the gateway line, never the
		// dashboard: no link base under record 1 (sdk-api-surface.md §16).
		gateway = h.rec.gateway
	}
	return key, keySource, gateway, dashboard, w
}

// degradedFix is the fix §7 names: run setup again when the online side
// leans on the SDK-held file (rung 3 chose it, record 3 is in use, or the
// file's key expired), else sign in or set the variables.
func (r *sdkFileReader) degradedFix(source, keySource string) string {
	if source == sourceSDKFile || keySource == sourceSDKFile || (r.done && r.h.expired) {
		return setupFix + ", or set SUPERBASED_ORG_URL and SUPERBASED_API_KEY"
	}
	return "run `observer sdk sign-in`, or set SUPERBASED_ORG_URL and SUPERBASED_API_KEY"
}

// discoveredDashboard is discovery's online.dashboard_url when it is a
// usable https base ("" otherwise).
func discoveredDashboard(online map[string]any) string {
	v, _ := online["dashboard_url"].(string)
	v = strings.TrimSpace(v)
	if v == "" || dashboardURLProblem(v) != "" {
		return ""
	}
	return strings.TrimRight(v, "/")
}

// windowsFacts are what the Windows rule (ruling R4) decides on, gathered
// from one open handle (credfile_windows.go).
type windowsFacts struct {
	reparsePoint bool   // a symlink, junction or any other reparse point
	directory    bool   // not a regular file
	insideRoot   bool   // its final path is inside %LOCALAPPDATA%
	ownerIsUser  bool   // its owner SID is the current user's
	ownerError   string // why the owner could not be read ("" when it was)
}

// windowsFileProblem is the Windows rule, an ordered table over plain facts:
// (problem, reason), ("", "") when the file may be read.
func windowsFileProblem(f windowsFacts) (string, string) {
	switch {
	case f.reparsePoint:
		return "the SDK credential file is a symlink or another reparse point; refused", reasonReparsePoint
	case f.directory:
		return "the SDK credential file is not a regular file; refused", reasonNotRegular
	case !f.insideRoot:
		return "the SDK credential file is not inside this user's %LOCALAPPDATA%; refused", reasonOutsideLocalAppData
	case f.ownerError != "":
		return f.ownerError, reasonOwner
	case !f.ownerIsUser:
		return "the SDK credential file is owned by another user; refused", reasonOwner
	}
	return "", ""
}
