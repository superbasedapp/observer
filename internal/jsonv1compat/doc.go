// Package jsonv1compat restores the Go 1.26 encoding/json result where Go
// 1.27 changed it (lane GO127, joint roadmap piece F0-1; security pillar
// plan section 8.4, risk T17).
//
// Go 1.27 backs encoding/json with the v2 implementation. The one decode
// difference the hook payload differential found (internal/hook
// TestHookJSONGolden over the real fixtures in testdata/) is this: a JSON
// number outside the float64 range (1e400) that lands in an untyped slot
// (an any, a map[string]any value, a []any element) was left nil by Go
// 1.26 and is now stored as 0. Both versions return an error, so the
// difference only shows where a caller keeps the partial result of a
// failed decode, which several hook paths do on purpose (a hook must still
// reply, and a tool input with one odd value must still be judged).
//
// UnmarshalObject is the drop-in for those callers: it decodes exactly as
// json.Unmarshal into a map[string]any did under Go 1.26.
//
// The package is pure: no database/sql, net/http or fsnotify (pinned by
// imports_test.go).
package jsonv1compat
