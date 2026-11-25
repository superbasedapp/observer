// Package parseutil holds the small, pure parse helpers more than one
// adapter needs byte for byte: RFC 3339 timestamp parsing, the canonical
// UUID shape check, a bufio.SplitFunc that keeps line terminators, and an
// OS-agnostic absolute-path check. Each helper is the one copy of a rule
// several adapters had re-implemented identically; an adapter whose rule
// differs keeps its own.
//
// It is pure: no SQL, HTTP, fsnotify or file I/O (imports_test.go pins it).
package parseutil
