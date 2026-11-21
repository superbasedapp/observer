package secassess

// Shape checks for the weakness and requirement ids a threat or a finding
// cites. Only the shape is checked; names are not stored (a later decision
// covers third-party names), so a well-formed id Observer has no name for is
// accepted and shown as the bare id.

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ValidCWE reports whether s has the shape CWE-<1 to 5 digits>, no leading
// zero.
func ValidCWE(s string) bool {
	n, ok := cutPrefix(s, "CWE-")
	return ok && len(n) <= 5 && allDigits(n) && n[0] != '0'
}

// ValidCAPEC reports whether s has the shape CAPEC-<1 to 4 digits>, no
// leading zero.
func ValidCAPEC(s string) bool {
	n, ok := cutPrefix(s, "CAPEC-")
	return ok && len(n) <= 4 && allDigits(n) && n[0] != '0'
}

// ValidASVS reports whether s has the shape V<chapter>.<section>.<requirement>
// with one or two digits each (for example V2.1.1).
func ValidASVS(s string) bool {
	n, ok := cutPrefix(s, "V")
	if !ok {
		return false
	}
	parts := splitDots(n)
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if len(p) > 2 || !allDigits(p) {
			return false
		}
	}
	return true
}

func cutPrefix(s, prefix string) (string, bool) {
	if len(s) > len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):], true
	}
	return "", false
}

func splitDots(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}
