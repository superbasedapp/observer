package api

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
)

// retired_test.go pins the personal-plane retirement switch (retired.go;
// D-IND-7; docs/security.md IND-3): the mode parser, one case per table row
// in both modes, the 410 body, and the structural rule that every registered
// /v1 and /portal/api route is a row of personalPlaneRoutes (and every row is
// registered), so a new route cannot land unclassified.

func TestParsePersonalPlane(t *testing.T) {
	cases := []struct {
		raw     string
		want    string
		wantErr bool
	}{
		{"", PersonalPlaneServing, false},
		{"  ", PersonalPlaneServing, false},
		{"serving", PersonalPlaneServing, false},
		{" retired ", PersonalPlaneRetired, false},
		{"Retired", "", true},
		{"off", "", true},
		{"1", "", true},
	}
	for _, tc := range cases {
		got, err := ParsePersonalPlane(tc.raw)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("ParsePersonalPlane(%q) = %q, %v; want %q, err=%v", tc.raw, got, err, tc.want, tc.wantErr)
		}
	}
}

// requestFor builds a request that the mux matches to pattern: wildcards are
// filled with a fixed id.
func requestFor(pattern string) *http.Request {
	method, path, _ := strings.Cut(pattern, " ")
	path = strings.NewReplacer("{id}", "abc123").Replace(path)
	return httptest.NewRequest(method, path, nil)
}

// assertMovedToOrgPlane checks a 410 answer's status and body.
func assertMovedToOrgPlane(t *testing.T, label string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusGone {
		t.Fatalf("%s: status %d, want 410", label, rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s: body %q: %v", label, rec.Body.String(), err)
	}
	if body["error"] != "moved_to_org_plane" || body["code"] != "moved_to_org_plane" ||
		!strings.Contains(body["message"], "1.39") || !strings.Contains(body["message"], `"observer connect"`) ||
		!strings.Contains(body["message"], "personal organization") || !strings.HasPrefix(body["docs"], "https://superbased.app/docs/") {
		t.Fatalf("%s: 410 body = %v", label, body)
	}
	if len(body) != 4 {
		t.Fatalf("%s: 410 body has keys %v, want exactly error, code, message, docs", label, body)
	}
}

// TestRetirePersonalPlaneEveryRow walks every table row in both modes over a
// mux whose handlers only say which pattern served: serving serves every
// row; retired answers 410 for a retired row and serves a kept one.
func TestRetirePersonalPlaneEveryRow(t *testing.T) {
	mux := http.NewServeMux()
	for _, r := range personalPlaneRoutes {
		pattern := r.pattern
		mux.HandleFunc(pattern, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-Pattern", pattern)
			w.WriteHeader(http.StatusTeapot)
		})
	}
	for _, mode := range []string{PersonalPlaneServing, PersonalPlaneRetired} {
		s := &Server{personalPlane: mode}
		h := s.retirePersonalPlane(mux)
		for _, r := range personalPlaneRoutes {
			t.Run(mode+" "+r.pattern, func(t *testing.T) {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, requestFor(r.pattern))
				if mode == PersonalPlaneRetired && r.fate == routeRetired {
					assertMovedToOrgPlane(t, r.pattern, rec)
					return
				}
				if rec.Code != http.StatusTeapot || rec.Header().Get("X-Pattern") != r.pattern {
					t.Fatalf("served by %q with %d, want %q", rec.Header().Get("X-Pattern"), rec.Code, r.pattern)
				}
			})
		}
	}
}

// TestRetiredRoutesAnswerBeforeAuth drives the REAL Handler in retired mode
// with no store at all: a retired route must answer 410 without reaching
// authentication or the database, device and portal alike, with or without a
// credential. The browser sign-in sessions route, a sibling pattern of a
// retired one, is not caught by it.
func TestRetiredRoutesAnswerBeforeAuth(t *testing.T) {
	empty := ""
	h := New(Options{RateLimit: &RateLimitConfig{}, RootRedirectURL: &empty, PersonalPlane: PersonalPlaneRetired}).Handler()
	for _, r := range personalPlaneRoutes {
		if r.fate != routeRetired {
			continue
		}
		t.Run(r.pattern, func(t *testing.T) {
			req := requestFor(r.pattern)
			req.Header.Set("Authorization", "Bearer stale-token")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			assertMovedToOrgPlane(t, r.pattern, rec)
		})
	}
	// The retired switch never touches an unregistered path or the SPA.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/no-such-route", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown /v1 path: %d, want 404", rec.Code)
	}
}

func TestNewInvalidPersonalPlaneKeepsServing(t *testing.T) {
	empty := ""
	s := New(Options{RateLimit: &RateLimitConfig{}, RootRedirectURL: &empty, PersonalPlane: "bogus"})
	if s.personalPlane != PersonalPlaneServing {
		t.Fatalf("personalPlane = %q, want serving", s.personalPlane)
	}
	if New(Options{RateLimit: &RateLimitConfig{}, RootRedirectURL: &empty}).personalPlane != PersonalPlaneServing {
		t.Fatal("the zero Options must serve the personal plane")
	}
}

// classifiedPrefixes are the route families the table must cover.
var classifiedPrefixes = []string{" /v1/", " /portal/api/"}

// unresolvedRegistrationFiles are the files whose registrations build their
// pattern from something the source scan cannot read, each outside the
// classified families (TestUnresolvedRegistrationsAreOutsideTheFamilies
// checks the values): staff.go (the staff process's own table, /staff),
// oidcroutes.go (oidcissuer's /oauth2 paths) and rootredirect.go (the
// marketing redirect paths).
var unresolvedRegistrationFiles = map[string]bool{"staff.go": true, "oidcroutes.go": true, "rootredirect.go": true}

// registeredRoutes parses this package's non-test sources and returns every
// pattern passed to mux.Handle or mux.HandleFunc, resolving a pattern built
// as "METHOD " + aPackageStringConstant. A registration whose pattern it
// cannot resolve fails the test unless its file is in
// unresolvedRegistrationFiles.
func registeredRoutes(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, f)
	}
	consts := map[string]string{}
	for _, f := range files {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if i < len(vs.Values) {
						if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
							if v, err := strconv.Unquote(lit.Value); err == nil {
								consts[n.Name] = v
							}
						}
					}
				}
			}
		}
	}
	var resolve func(e ast.Expr) (string, bool)
	resolve = func(e ast.Expr) (string, bool) {
		switch v := e.(type) {
		case *ast.BasicLit:
			if v.Kind != token.STRING {
				return "", false
			}
			s, err := strconv.Unquote(v.Value)
			return s, err == nil
		case *ast.Ident:
			s, ok := consts[v.Name]
			return s, ok
		case *ast.BinaryExpr:
			if v.Op != token.ADD {
				return "", false
			}
			l, lok := resolve(v.X)
			r, rok := resolve(v.Y)
			return l + r, lok && rok
		}
		return "", false
	}
	var out []string
	for _, f := range files {
		file := filepath.Base(fset.Position(f.Pos()).Filename)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc") {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "mux" {
				return true
			}
			p, ok := resolve(call.Args[0])
			if !ok {
				if !unresolvedRegistrationFiles[file] {
					t.Errorf("%s: a mux registration whose pattern this test cannot resolve: %s", file, fset.Position(call.Pos()))
				}
				return true
			}
			out = append(out, p)
			return true
		})
	}
	return out
}

func TestPersonalPlaneTableClassifiesEveryRoute(t *testing.T) {
	rows := map[string]routeFate{}
	for _, r := range personalPlaneRoutes {
		if _, dup := rows[r.pattern]; dup {
			t.Errorf("row %q is in the table twice", r.pattern)
		}
		if r.fate != routeKept && r.fate != routeRetired {
			t.Errorf("row %q has no fate", r.pattern)
		}
		rows[r.pattern] = r.fate
	}
	registered := map[string]bool{}
	for _, p := range registeredRoutes(t) {
		registered[p] = true
		classified := false
		for _, prefix := range classifiedPrefixes {
			if strings.Contains(p, prefix) {
				classified = true
			}
		}
		if !classified {
			continue
		}
		if _, ok := rows[p]; !ok {
			t.Errorf("route %q is registered but not classified in personalPlaneRoutes (retired.go): decide whether it retires with the personal plane", p)
		}
	}
	for p := range rows {
		if !registered[p] {
			t.Errorf("personalPlaneRoutes row %q names no registered route", p)
		}
	}
	// The sanity floor: the scan found the device and portal surfaces.
	if len(registered) < 50 {
		t.Fatalf("found only %d registrations; the scan is broken", len(registered))
	}
}

// TestUnresolvedRegistrationsAreOutsideTheFamilies checks, by value, that
// the registrations the source scan skips are not /v1 or /portal/api routes.
func TestUnresolvedRegistrationsAreOutsideTheFamilies(t *testing.T) {
	paths := []string{oidcissuer.DiscoveryPath, oidcissuer.JWKSPath, oidcissuer.AuthorizePath, oidcissuer.TokenPath}
	paths = append(paths, marketingRedirectPaths...)
	for _, rt := range staffRoutes {
		_, p, _ := strings.Cut(rt.pattern, " ")
		paths = append(paths, p)
	}
	for _, p := range paths {
		for _, prefix := range classifiedPrefixes {
			if strings.HasPrefix(" "+p, prefix) {
				t.Errorf("%q is registered from an unscanned file but is in the %q family: classify it", p, prefix)
			}
		}
	}
}

// TestPersonalPlaneKeptRowsAreTheBriefs pins the explicit keep list of
// D-IND-7: sign-in, devices, logout, consents, deletion, export and the org
// routes never retire.
func TestPersonalPlaneKeptRowsAreTheBriefs(t *testing.T) {
	mustKeep := []string{
		"GET /v1/auth/nonce", "POST /v1/auth/exchange", "GET /v1/devices", "DELETE /v1/devices/{id}",
		"GET /v1/consents", "PUT /v1/consents", "POST /v1/logout", "POST /v1/deletion-requests",
		"POST /v1/export", "GET /v1/exports/{id}", "GET /v1/orgs", "POST /v1/orgs/personal:ensure",
		"GET /portal/api/sessions/browser", "POST /portal/api/sessions/browser/revoke-all",
		"GET /portal/api/session", "GET /portal/api/auth-config", "GET /portal/api/consents",
		"GET /portal/api/consent", "POST /portal/api/consent", "POST /portal/api/orgs/personal",
		"GET /portal/api/billing", "POST /portal/api/deletion-requests", "POST /portal/api/exports",
	}
	for _, p := range mustKeep {
		if retiredPatterns[p] {
			t.Errorf("%q must be kept", p)
		}
	}
}
