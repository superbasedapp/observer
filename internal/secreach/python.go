package secreach

import (
	"sort"
	"strings"
)

// NormalizePEP503 is PEP 503's name normalisation: lower case, every run
// of '-', '_' and '.' a single '-'.
func NormalizePEP503(name string) string {
	var b strings.Builder
	sep := false
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '-' || c == '_' || c == '.' {
			sep = true
			continue
		}
		if sep && b.Len() > 0 {
			b.WriteByte('-')
		}
		sep = false
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

// pythonDistModules is the built-in table of distributions whose import
// names differ from their own name (PEP 503 normalised distribution ->
// the module paths it installs). Installed metadata wins over it; a
// distribution in neither falls to the approximate own-name rule.
var pythonDistModules = map[string][]string{
	"beautifulsoup4":                 {"bs4"},
	"dnspython":                      {"dns"},
	"djangorestframework":            {"rest_framework"},
	"faiss-cpu":                      {"faiss"},
	"faiss-gpu":                      {"faiss"},
	"gitpython":                      {"git"},
	"google-cloud-storage":           {"google.cloud.storage"},
	"grpcio":                         {"grpc"},
	"msgpack-python":                 {"msgpack"},
	"mysqlclient":                    {"MySQLdb"},
	"opencv-contrib-python":          {"cv2"},
	"opencv-contrib-python-headless": {"cv2"},
	"opencv-python":                  {"cv2"},
	"opencv-python-headless":         {"cv2"},
	"pillow":                         {"PIL"},
	"pillow-simd":                    {"PIL"},
	"protobuf":                       {"google.protobuf"},
	"psycopg2-binary":                {"psycopg2"},
	"pycrypto":                       {"Crypto"},
	"pycryptodome":                   {"Crypto"},
	"pycryptodomex":                  {"Cryptodome"},
	"pygithub":                       {"github"},
	"pyjwt":                          {"jwt"},
	"pymongo":                        {"pymongo", "bson", "gridfs"},
	"pyopenssl":                      {"OpenSSL"},
	"pysaml2":                        {"saml2"},
	"pyserial":                       {"serial"},
	"python-dateutil":                {"dateutil"},
	"python-docx":                    {"docx"},
	"python-dotenv":                  {"dotenv"},
	"python-engineio":                {"engineio"},
	"python-gnupg":                   {"gnupg"},
	"python-jose":                    {"jose"},
	"python-ldap":                    {"ldap", "ldapurl", "ldif"},
	"python-magic":                   {"magic"},
	"python-multipart":               {"multipart", "python_multipart"},
	"python-socketio":                {"socketio"},
	"python3-saml":                   {"onelogin"},
	"pyusb":                          {"usb"},
	"pywin32":                        {"win32api", "win32con", "win32com", "pywintypes", "pythoncom"},
	"pyxdg":                          {"xdg"},
	"pyyaml":                         {"yaml", "_yaml"},
	"pyzmq":                          {"zmq"},
	"ruamel-yaml":                    {"ruamel.yaml"},
	"scikit-image":                   {"skimage"},
	"scikit-learn":                   {"sklearn"},
	"setuptools":                     {"setuptools", "pkg_resources", "_distutils_hack"},
	"attrs":                          {"attr", "attrs"},
	"tensorflow-cpu":                 {"tensorflow"},
	"tensorflow-gpu":                 {"tensorflow"},
	"websocket-client":               {"websocket"},
}

// pythonModules returns the modules a distribution installs and whether
// they are known: the project's installed metadata first, then the
// built-in table.
func pythonModules(dist string, set ImportSet) ([]string, bool) {
	if mods, ok := set.Provides[dist]; ok && len(mods) > 0 {
		return mods, true
	}
	mods, ok := pythonDistModules[dist]
	return mods, ok
}

// matchPyPIRecord decides a PyPI finding at import level. With the
// distribution's modules known (installed metadata, the built-in table) it
// is decided like any import list; with none known, the distribution's
// own name as a module ("requests", "typing-extensions" as
// typing_extensions, case folded) can prove Imported, approximate, and its
// absence proves nothing (ReasonNoNameMapping).
func matchPyPIRecord(adv Advisory, _ Record, set ImportSet, paths []string) Tier {
	dist := NormalizePEP503(adv.Package)
	if mods, ok := pythonModules(dist, set); ok {
		found, nonTest, match := matchModules(set, paths, mods, false)
		return decide(set, found, nonTest, match)
	}
	guess := strings.ReplaceAll(dist, "-", "_")
	if found, nonTest, match := matchModules(set, paths, []string{guess}, true); found {
		return Tier{Level: Imported, Source: set.Source, TestsOnly: !nonTest, Approximate: true, Match: match}
	}
	return UnknownTier(ReasonNoNameMapping)
}

// matchModules finds an imported module path that is one of mods or under
// one (sorted order), preferring a non-test use; fold compares case
// insensitively.
func matchModules(set ImportSet, paths, mods []string, fold bool) (found, nonTest bool, match string) {
	for _, p := range paths {
		if !underAny(p, mods, fold) {
			continue
		}
		if set.Uses[p].NonTest {
			return true, true, p
		}
		if !found {
			found, match = true, p
		}
	}
	return found, false, match
}

func underAny(p string, mods []string, fold bool) bool {
	if fold {
		p = strings.ToLower(p)
	}
	for _, m := range mods {
		if fold {
			m = strings.ToLower(m)
		}
		if p == m || strings.HasPrefix(p, m+".") {
			return true
		}
	}
	return false
}

// Caps on what one distribution's metadata contributes.
const (
	// MaxDistModules caps the module paths read for one distribution.
	MaxDistModules = 256
)

// PythonDistOfMetadataDir returns the PEP 503 normalised distribution of
// an installed metadata directory name ("PyYAML-6.0.1.dist-info",
// "requests-2.31.0-py3.11.egg-info", "mypkg.egg-info"), ok false for any
// other name.
func PythonDistOfMetadataDir(name string) (string, bool) {
	var stem string
	switch {
	case strings.HasSuffix(name, ".dist-info"):
		stem = strings.TrimSuffix(name, ".dist-info")
	case strings.HasSuffix(name, ".egg-info"):
		stem = strings.TrimSuffix(name, ".egg-info")
	default:
		return "", false
	}
	dist, _, _ := strings.Cut(stem, "-")
	if dist == "" {
		return "", false
	}
	for i := 0; i < len(dist); i++ {
		c := dist[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.') {
			return "", false
		}
	}
	return NormalizePEP503(dist), true
}

// PythonModulesFromRecord reads the module paths a distribution installs
// from its RECORD: each installed .py, .so or .pyd file outside the
// metadata and data directories gives the dotted path of its shallowest
// regular package (a directory the RECORD gives an __init__.py), or, for
// a namespace package with none, of the module itself ("six.py" -> six,
// "yaml/__init__.py" -> yaml, "google/cloud/storage/__init__.py" ->
// google.cloud.storage). At most MaxDistModules, sorted.
func PythonModulesFromRecord(record []byte) []string {
	var files [][]string
	inits := map[string]bool{}
	for _, line := range strings.Split(string(record), "\n") {
		p := recordPath(strings.TrimRight(line, "\r"))
		if p == "" || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "../") || strings.Contains(p, "__pycache__") {
			continue
		}
		segs := strings.Split(p, "/")
		if metadataDir(segs[0]) {
			continue
		}
		mod, ok := moduleFileName(segs[len(segs)-1])
		if !ok {
			continue
		}
		if mod == "__init__" && len(segs) > 1 {
			inits[strings.Join(segs[:len(segs)-1], "/")] = true
		}
		files = append(files, append(segs[:len(segs)-1:len(segs)-1], mod))
	}
	seen := map[string]bool{}
	for _, f := range files {
		dirs, mod := f[:len(f)-1], f[len(f)-1]
		valid := true
		for _, d := range dirs {
			if !identifier(d) {
				valid = false
			}
		}
		if !valid || (len(dirs) == 0 && (mod == "__init__" || !identifier(mod))) {
			continue
		}
		prefix := ""
		for k := 1; k <= len(dirs); k++ {
			if inits[strings.Join(dirs[:k], "/")] {
				prefix = strings.Join(dirs[:k], ".")
				break
			}
		}
		if prefix == "" {
			if mod == "__init__" || !identifier(mod) {
				continue
			}
			prefix = strings.Join(append(append([]string{}, dirs...), mod), ".")
		}
		seen[prefix] = true
	}
	return sortedCapped(seen)
}

// PythonModulesFromTopLevel reads top_level.txt: one top-level module per
// line. At most MaxDistModules, sorted.
func PythonModulesFromTopLevel(b []byte) []string {
	seen := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		m := strings.ReplaceAll(strings.TrimSpace(line), "/", ".")
		ok := m != ""
		for _, seg := range strings.Split(m, ".") {
			ok = ok && identifier(seg)
		}
		if ok {
			seen[m] = true
		}
	}
	return sortedCapped(seen)
}

func sortedCapped(seen map[string]bool) []string {
	out := make([]string, 0, len(seen))
	for m := range seen {
		out = append(out, m)
	}
	sort.Strings(out)
	if len(out) > MaxDistModules {
		out = out[:MaxDistModules]
	}
	return out
}

// recordPath is a RECORD line's path field (CSV: quoted when it holds a
// comma).
func recordPath(line string) string {
	if strings.HasPrefix(line, `"`) {
		end := strings.Index(line[1:], `"`)
		if end < 0 {
			return ""
		}
		return line[1 : end+1]
	}
	p, _, _ := strings.Cut(line, ",")
	return p
}

// metadataDir reports a RECORD path root that installs no module.
func metadataDir(seg string) bool {
	return strings.HasSuffix(seg, ".dist-info") || strings.HasSuffix(seg, ".egg-info") || strings.HasSuffix(seg, ".data")
}

// moduleFileName returns the module name of an installed source or
// extension file ("six.py", "_yaml.cpython-311-x86_64-linux-gnu.so",
// "win32api.pyd"); ok false for any other file.
func moduleFileName(base string) (string, bool) {
	switch {
	case strings.HasSuffix(base, ".py"):
		return strings.TrimSuffix(base, ".py"), true
	case strings.HasSuffix(base, ".so"), strings.HasSuffix(base, ".pyd"):
		name, _, _ := strings.Cut(base, ".")
		return name, name != ""
	}
	return "", false
}
