package latencygate

import "strings"

// splitLines returns the [package, test] pairs of a list file body.
func splitLines(body string) [][2]string {
	var out [][2]string
	for _, l := range strings.Split(body, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if p, n, ok := strings.Cut(l, "\t"); ok {
			out = append(out, [2]string{strings.TrimSpace(p), strings.TrimSpace(n)})
		}
	}
	return out
}

// containsFunc reports whether src declares func name(.
func containsFunc(src, name string) bool {
	return strings.Contains(src, "func "+name+"(")
}
