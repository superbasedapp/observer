package main

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/diag"
)

// TestLoginEnvDriftCheck (CLI-4, lane w4-homes-b): a tool home variable the
// login shell sets that this process lacks or spells differently is a WARN
// naming it; agreement, a failed capture and Windows are OK. Red before: no
// probe read anything but PATH from the login shell.
func TestLoginEnvDriftCheck(t *testing.T) {
	login := func(vals map[string]string, err error) func(string, []string, time.Duration) (map[string]string, error) {
		return func(_ string, names []string, _ time.Duration) (map[string]string, error) {
			if !slices.Contains(names, "QWEN_HOME") || !slices.Contains(names, "GROK_HOME") {
				t.Errorf("probe names %v lack the relocation variables", names)
			}
			return vals, err
		}
	}
	for _, tc := range []struct {
		name    string
		goos    string
		login   map[string]string
		process map[string]string
		err     error
		status  diag.Status
		detail  string
	}{
		{"agreement", "linux", map[string]string{"QWEN_HOME": "/q"}, map[string]string{"QWEN_HOME": "/q"}, nil, diag.StatusOK, ""},
		{"set in the login shell only", "linux", map[string]string{"QWEN_HOME": "/q"}, nil, nil, diag.StatusWarn, "QWEN_HOME: login shell /q, this process (unset)"},
		{"different values", "darwin", map[string]string{"GROK_HOME": "/a"}, map[string]string{"GROK_HOME": "/b"}, nil, diag.StatusWarn, "GROK_HOME: login shell /a, this process /b"},
		{"set here only is the operator's choice", "linux", nil, map[string]string{"QWEN_HOME": "/q"}, nil, diag.StatusOK, ""},
		{"capture failed", "linux", nil, nil, errors.New("no shell"), diag.StatusOK, ""},
		{"windows", "windows", map[string]string{"QWEN_HOME": "/q"}, nil, nil, diag.StatusOK, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proc := tc.process
			c := loginEnvDriftCheckWith(tc.goos, "/bin/bash", func(k string) string { return proc[k] }, login(tc.login, tc.err))
			if c.Name != loginEnvCheckName || c.Status != tc.status {
				t.Fatalf("check = %+v, want status %v", c, tc.status)
			}
			if tc.detail != "" && (len(c.Details) != 1 || !strings.HasPrefix(c.Details[0], tc.detail)) {
				t.Errorf("details = %v, want one starting %q", c.Details, tc.detail)
			}
		})
	}
}
