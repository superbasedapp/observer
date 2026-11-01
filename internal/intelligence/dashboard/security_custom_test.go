//go:build !sbo_omit_security && !sbo_omit_security_scan_custom

package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/seccustom"
	"github.com/marmutapp/superbased-observer/internal/seccustomsvc"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// The real service fits the routes' interface: a renamed or changed method
// fails the build here instead of hiding the custom scanner page at run time
// (customScanners' type assertion would just answer false).
var _ customScanners = (*seccustomsvc.Service)(nil)

// fakeCustom records what the routes asked of the service.
type fakeCustom struct {
	accepted string
	via      string
	ranRoot  string
	// records is what Records returns; recordCalls counts the calls and
	// missingGot is what RequiredMissingAmong was handed.
	records     []seccustom.Record
	recordCalls int
	missingGot  []seccustom.Record
}

func (f *fakeCustom) Layout() seccustomsvc.Layout { return seccustomsvc.Layout{Dir: "/nonexistent"} }

func (f *fakeCustom) Records(context.Context) ([]seccustom.Record, map[string]string) {
	f.recordCalls++
	return f.records, nil
}

func (f *fakeCustom) Prepare(context.Context, seccustomsvc.Source, seccustom.Choices) (seccustomsvc.Prepared, error) {
	return seccustomsvc.Prepared{ID: "gosec", ManifestSHA256: strings.Repeat("a", 64)}, nil
}

func (f *fakeCustom) Accept(_ context.Context, _ seccustomsvc.Source, _ seccustom.Choices, confirmed, via string) (seccustom.Record, error) {
	if confirmed != strings.Repeat("a", 64) {
		return seccustom.Record{}, errors.New("the manifest changed since it was shown")
	}
	f.accepted, f.via = confirmed, via
	return seccustom.Record{ID: "gosec"}, nil
}

func (f *fakeCustom) Remove(context.Context, string, string) error { return seccustomsvc.ErrNotFound }

func (f *fakeCustom) SelfTest(context.Context, string) (seccustom.SelfTestState, error) {
	return seccustom.SelfTestState{}, nil
}

func (f *fakeCustom) RequiredMissingAmong(_ context.Context, checked []seccustom.Record) []string {
	f.missingGot = checked
	return nil
}

func (f *fakeCustom) Run(_ context.Context, _, root string, _ secfinding.Scope) (seccustomsvc.RunReport, error) {
	f.ranRoot = root
	return seccustomsvc.RunReport{}, nil
}

func TestHandleSecurityCustom(t *testing.T) {
	t.Parallel()
	// Inactive: 404 component_not_installed.
	off := &Server{}
	w := httptest.NewRecorder()
	off.handleSecurityCustom(w, httptest.NewRequest(http.MethodGet, "/api/security/scanners/custom", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("inactive: %d", w.Code)
	}

	fake := &fakeCustom{}
	s := &Server{opts: dashapi.Options{CustomScanners: fake}}
	w = httptest.NewRecorder()
	s.handleSecurityCustom(w, httptest.NewRequest(http.MethodGet, "/api/security/scanners/custom", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("get: %d %s", w.Code, w.Body)
	}
	var got struct {
		Templates []customTemplateJS `json:"templates"`
		Pickers   customPickersJS    `json:"pickers"`
		Token     string             `json:"confirm_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Templates) != 3 || got.Pickers.Limits["child_processes"][0] != 64 || got.Pickers.ChildrenUnit == "" || got.Token == "" {
		t.Fatalf("get reply %+v", got)
	}

	post := func(verb, body, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/security/scanners/custom/"+verb, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set(remoteConfirmHeader, token)
			r.AddCookie(&http.Cookie{Name: remoteConfirmCookie, Value: token})
		}
		w := httptest.NewRecorder()
		s.handleSecurityCustomSub(w, r)
		return w
	}
	if w := post("accept", `{"template":"gosec","manifest_sha256":"`+strings.Repeat("a", 64)+`"}`, ""); w.Code != http.StatusForbidden || fake.accepted != "" {
		t.Fatalf("a write without the confirm token: %d", w.Code)
	}
	if w := post("accept", `{"template":"gosec","manifest_sha256":"bad"}`, got.Token); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a digest that was never shown: %d", w.Code)
	}
	if w := post("accept", `{"template":"gosec","manifest_sha256":"`+strings.Repeat("a", 64)+`"}`, got.Token); w.Code != http.StatusOK || fake.via != "dashboard" {
		t.Fatalf("accept: %d %s via %q", w.Code, w.Body, fake.via)
	}
	if w := post("remove", `{"id":"nope"}`, got.Token); w.Code != http.StatusNotFound {
		t.Fatalf("remove unknown: %d", w.Code)
	}
	if w := post("run", `{"id":"gosec","dir":"relative"}`, got.Token); w.Code != http.StatusBadRequest {
		t.Fatalf("run relative dir: %d", w.Code)
	}
}

// TestHandleSecurityCustomChecksRecordsOnce: the GET loads and checks the
// records once and hands those same records to the org requirement check
// (PT-32: it used to check every record twice).
func TestHandleSecurityCustomChecksRecordsOnce(t *testing.T) {
	t.Parallel()
	fake := &fakeCustom{records: []seccustom.Record{{ID: "gosec"}, {ID: "bandit"}}}
	s := &Server{opts: dashapi.Options{CustomScanners: fake}}
	w := httptest.NewRecorder()
	s.handleSecurityCustom(w, httptest.NewRequest(http.MethodGet, "/api/security/scanners/custom", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("get: %d %s", w.Code, w.Body)
	}
	if fake.recordCalls != 1 {
		t.Fatalf("Records called %d times, want 1", fake.recordCalls)
	}
	if len(fake.missingGot) != 2 || fake.missingGot[0].ID != "gosec" || fake.missingGot[1].ID != "bandit" {
		t.Fatalf("the requirement check got %+v, want the records the GET listed", fake.missingGot)
	}
}

// TestCustomRunTakesAKnownProject: the run route accepts only the root of a
// project the projects table knows, never a typed directory (the pickers
// rule).
func TestCustomRunTakesAKnownProject(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t)
	var known string
	if err := s.db().QueryRowContext(context.Background(), `SELECT root_path FROM projects LIMIT 1`).Scan(&known); err != nil {
		t.Fatal(err)
	}
	fake := &fakeCustom{}
	s.opts.CustomScanners = fake
	token := "tok"
	post := func(dir string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"id": "gosec", "dir": dir})
		r := httptest.NewRequest(http.MethodPost, "/api/security/scanners/custom/run", strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(remoteConfirmHeader, token)
		r.AddCookie(&http.Cookie{Name: remoteConfirmCookie, Value: token})
		w := httptest.NewRecorder()
		s.handleSecurityCustomSub(w, r)
		return w
	}
	for _, dir := range []string{"/etc", filepath.Join(known, "sub"), "relative", ""} {
		if w := post(dir); w.Code != http.StatusBadRequest {
			t.Fatalf("run against %q: %d %s", dir, w.Code, w.Body)
		}
	}
	if fake.ranRoot != "" {
		t.Fatalf("a refused run reached the service: %q", fake.ranRoot)
	}
	if w := post(known); w.Code != http.StatusOK || fake.ranRoot != known {
		t.Fatalf("run against the known project: %d %s, ran %q", w.Code, w.Body, fake.ranRoot)
	}
}
