package otlpjson

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPurity keeps the decoder free of SQL, HTTP and fsnotify, so every
// receiver (node, org gateway, otel-direct) can share it.
func TestPurity(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net/http", "github.com/fsnotify/fsnotify"},
		Reason:    "otlpjson is a pure decoder",
	})
}
