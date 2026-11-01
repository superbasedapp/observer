package sandboxsbpl

import "strings"

// eval.go is a small evaluator over checked rules, the oracle the tests use
// to ask "would this profile allow X" without a Mac. It models the SBPL
// semantics the generator relies on and the register (MAC-37) must confirm
// against Seatbelt itself: the LAST matching rule decides; an operation
// ending in '*' covers every operation it prefixes ("file-read*" covers
// file-read-data and file-read-metadata); a rule with several filters
// matches when any one does; a rule with none matches every object of its
// operations; a filter of another kind than the query's object never
// matches. Paths are compared as given (the cmd seam resolves them first).

// Query is one access to decide.
type Query struct {
	// Op is a concrete operation, for example "file-read-data",
	// "file-write-data", "file-ioctl", "network-outbound", "mach-lookup".
	Op string
	// Path is the file path of a file operation.
	Path string
	// RemoteIP is "host:port" of an outbound IP connection.
	RemoteIP string
	// Socket is the path of an outbound unix-socket connection.
	Socket string
	// GlobalName is the mach service of a mach-lookup.
	GlobalName string
	// IPCName is the POSIX shared-memory segment of an ipc-posix-shm
	// operation.
	IPCName string
	// SameSandbox marks a signal or process-info target inside the box.
	SameSandbox bool
}

// Allowed reports whether rules allow q with params.
func Allowed(rules []Rule, params map[string]string, q Query) bool {
	allowed := false
	for _, r := range rules {
		if ruleMatches(r, params, q) {
			allowed = r.Allow
		}
	}
	return allowed
}

func opCovers(ruleOp, op string) bool {
	if ruleOp == "default" || ruleOp == op {
		return true
	}
	if strings.HasSuffix(ruleOp, "*") {
		return strings.HasPrefix(op, strings.TrimSuffix(ruleOp, "*"))
	}
	return false
}

func ruleMatches(r Rule, params map[string]string, q Query) bool {
	covered := false
	for _, op := range r.Ops {
		covered = covered || opCovers(op, q.Op)
	}
	if !covered {
		return false
	}
	if len(r.Filters) == 0 {
		return true
	}
	for _, f := range r.Filters {
		if filterMatches(f, params, q) {
			return true
		}
	}
	return false
}

func filterMatches(f Filter, params map[string]string, q Query) bool {
	v := f.Value
	if f.Param {
		v = params[f.Value]
	}
	switch f.Kind {
	case "literal":
		return q.Path != "" && q.Path == v
	case "subpath":
		return q.Path != "" && within(q.Path, v)
	case "path-literal":
		return q.Socket != "" && q.Socket == v
	case "remote-ip":
		return q.RemoteIP != "" && remoteMatches(v, q.RemoteIP)
	case "global-name":
		return q.GlobalName == v
	case "ipc-posix-name":
		return q.IPCName != "" && q.IPCName == v
	case "target":
		return q.SameSandbox
	}
	return false
}

// remoteMatches compares a rule's "host:port" (a "*" in either half is a
// wildcard, the forms the checker refuses in an allow but a deny may use)
// with a query's. "localhost" covers 127.0.0.1 and ::1, as Seatbelt's
// documented localhost does.
func remoteMatches(rule, q string) bool {
	rh, rp, _ := strings.Cut(rule, ":")
	qh, qp := splitHostPort(q)
	if rp != "*" && rp != qp {
		return false
	}
	switch rh {
	case "*":
		return true
	case "localhost":
		return qh == "localhost" || qh == "127.0.0.1" || qh == "::1"
	}
	return rh == qh
}

func splitHostPort(s string) (string, string) {
	if i := strings.LastIndex(s, ":"); i >= 0 {
		h := strings.TrimSuffix(strings.TrimPrefix(s[:i], "["), "]")
		return h, s[i+1:]
	}
	return s, ""
}
