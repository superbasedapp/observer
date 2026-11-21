package secdast

import (
	"strings"
	"testing"
)

const htmlPage = "<!doctype html><html><head><title>App</title></head><body>hi</body></html>"

// hardened is a page that every header and cookie row accepts.
func hardened() Header {
	return Header{
		"content-type":              {"text/html; charset=utf-8"},
		"content-security-policy":   {"default-src 'self'; frame-ancestors 'self'"},
		"x-content-type-options":    {"nosniff"},
		"referrer-policy":           {"no-referrer"},
		"strict-transport-security": {"max-age=31536000"},
		"server":                    {"nginx"},
	}
}

func with(h Header, kv ...string) Header {
	out := Header{}
	for k, v := range h {
		out[k] = append([]string(nil), v...)
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			delete(out, kv[i])
			continue
		}
		out[kv[i]] = append(out[kv[i]], kv[i+1])
	}
	return out
}

func page(h Header) Response {
	return Response{RequestID: ProbePage, Path: "/", Status: 200, Header: h, Body: []byte(htmlPage)}
}

func probe(id, path string, status int, ct, body string) Response {
	h := Header{}
	if ct != "" {
		h["content-type"] = []string{ct}
	}
	return Response{RequestID: id, Path: path, Status: status, Header: h, Body: []byte(body)}
}

// TestChecks is the table test: one case where each row fires and one
// near miss where it must not, per row of Checks().
func TestChecks(t *testing.T) {
	t.Parallel()
	httpT, _ := ParseTarget("http://localhost:3000/")
	httpsT, _ := ParseTarget("https://localhost:3443/")
	spaFallback := probe(ProbeEnv, "/.env", 200, "text/html", htmlPage)
	type tc struct {
		target Target
		rs     []Response
		hits   int
	}
	cases := map[string]struct{ fire, miss tc }{
		"dast.headers.csp-missing": {
			fire: tc{httpT, []Response{page(with(hardened(), "content-security-policy", ""))}, 1},
			miss: tc{httpT, []Response{page(hardened())}, 0},
		},
		"dast.headers.nosniff-missing": {
			fire: tc{httpT, []Response{page(with(hardened(), "x-content-type-options", ""))}, 1},
			miss: tc{httpT, []Response{page(with(hardened(), "x-content-type-options", "", "x-content-type-options", " NoSniff "))}, 0},
		},
		"dast.headers.framing-missing": {
			fire: tc{httpT, []Response{page(with(hardened(), "content-security-policy", "", "content-security-policy", "default-src 'self'"))}, 1},
			miss: tc{httpT, []Response{page(with(hardened(), "content-security-policy", "", "x-frame-options", "DENY"))}, 0},
		},
		"dast.headers.hsts-missing": {
			fire: tc{httpsT, []Response{page(with(hardened(), "strict-transport-security", ""))}, 1},
			// Plain HTTP: HSTS does not apply.
			miss: tc{httpT, []Response{page(with(hardened(), "strict-transport-security", ""))}, 0},
		},
		"dast.headers.referrer-policy-missing": {
			fire: tc{httpT, []Response{page(with(hardened(), "referrer-policy", ""))}, 1},
			// A JSON API answer is not a page.
			miss: tc{httpT, []Response{{RequestID: ProbePage, Path: "/", Status: 200, Header: Header{"content-type": {"application/json"}}, Body: []byte(`{}`)}}, 0},
		},
		"dast.cookies.httponly-missing": {
			fire: tc{httpT, []Response{page(with(hardened(), "set-cookie", "sessionid=abc; Path=/; SameSite=Lax"))}, 1},
			miss: tc{httpT, []Response{page(with(hardened(), "set-cookie", "XSRF-TOKEN=abc; Path=/; SameSite=Lax", "set-cookie", "sid=1; HttpOnly; SameSite=Lax"))}, 0},
		},
		"dast.cookies.secure-missing": {
			fire: tc{httpsT, []Response{page(with(hardened(), "set-cookie", "sid=1; HttpOnly; SameSite=Lax"))}, 1},
			miss: tc{httpT, []Response{page(with(hardened(), "set-cookie", "sid=1; HttpOnly; SameSite=Lax"))}, 0},
		},
		"dast.cookies.samesite-missing": {
			fire: tc{httpT, []Response{page(with(hardened(), "set-cookie", "a=1; HttpOnly", "set-cookie", "b=2; HttpOnly; SameSite=None"))}, 2},
			miss: tc{httpT, []Response{page(with(hardened(), "set-cookie", "a=1; HttpOnly; samesite=strict", "set-cookie", "b=2; HttpOnly; SameSite=None; Secure"))}, 0},
		},
		"dast.cors.origin-reflected-credentials": {
			fire: tc{httpT, []Response{page(with(hardened(), "access-control-allow-origin", CanaryOrigin, "access-control-allow-credentials", "true"))}, 1},
			miss: tc{httpT, []Response{page(with(hardened(), "access-control-allow-origin", CanaryOrigin))}, 0},
		},
		"dast.cors.origin-reflected": {
			fire: tc{httpT, []Response{page(with(hardened(), "access-control-allow-origin", CanaryOrigin))}, 1},
			miss: tc{httpT, []Response{page(with(hardened(), "access-control-allow-origin", "http://localhost:3000"))}, 0},
		},
		"dast.cors.wildcard-credentials": {
			fire: tc{httpT, []Response{page(with(hardened(), "access-control-allow-origin", "*", "access-control-allow-credentials", "true"))}, 1},
			miss: tc{httpT, []Response{page(with(hardened(), "access-control-allow-origin", "*"))}, 0},
		},
		"dast.exposed.git": {
			fire: tc{httpT, []Response{page(hardened()), probe(ProbeGitHead, "/.git/HEAD", 200, "application/octet-stream", "ref: refs/heads/main\n")}, 1},
			// An SPA answering every path with its index page.
			miss: tc{httpT, []Response{page(hardened()), probe(ProbeGitHead, "/.git/HEAD", 200, "text/html", htmlPage)}, 0},
		},
		"dast.exposed.env": {
			fire: tc{httpT, []Response{page(hardened()), probe(ProbeEnv, "/.env", 200, "", "# local\nDATABASE_URL=postgres://u:p@h/db\nexport API_KEY=sk-123\n")}, 1},
			miss: tc{httpT, []Response{page(hardened()), spaFallback, probe(ProbeEnv, "/.env", 404, "text/plain", "A=1\n")}, 0},
		},
		"dast.listing.directory": {
			fire: tc{httpT, []Response{{RequestID: ProbePage, Path: "/", Status: 200, Header: Header{"content-type": {"text/html"}}, Body: []byte("<html><head><title>Directory listing for /</title></head></html>")}}, 1},
			miss: tc{httpT, []Response{{RequestID: ProbePage, Path: "/", Status: 200, Header: Header{"content-type": {"text/html"}}, Body: []byte("<html><head><title>Index of products</title></head></html>")}}, 0},
		},
		"dast.exposed.sourcemap": {
			fire: tc{httpT, []Response{page(hardened()), probe("map-1", "/main.js.map", 200, "application/json", `{"version":3,"sources":["a.ts"],"sourcesContent":["x"],"mappings":"AAAA"}`)}, 1},
			miss: tc{httpT, []Response{page(hardened()), probe("map-1", "/main.js.map", 200, "text/html", htmlPage)}, 0},
		},
		"dast.debug.page": {
			fire: tc{httpT, []Response{page(hardened()), probe(ProbeNotFound, "/observer-dast-x", 404, "text/html", "<p>You're seeing this error because you have <code>DEBUG = True</code> in your Django settings file.</p>")}, 1},
			miss: tc{httpT, []Response{page(hardened()), probe(ProbeNotFound, "/observer-dast-x", 404, "text/html", "<h1>Not Found</h1>"), probe("script-1", "/a.js", 200, "text/javascript", "// Werkzeug Debugger\n")}, 0},
		},
		"dast.banner.version": {
			fire: tc{httpT, []Response{page(with(hardened(), "server", "", "server", "Apache/2.4.41 (Ubuntu)", "x-powered-by", "Express"))}, 2},
			miss: tc{httpT, []Response{page(hardened())}, 0},
		},
	}
	rows := Checks()
	if len(rows) != len(cases) {
		t.Errorf("%d rows, %d test cases: every row needs a case", len(rows), len(cases))
	}
	seen := map[string]bool{}
	for _, row := range rows {
		if seen[row.ID] {
			t.Errorf("duplicate row id %s", row.ID)
		}
		seen[row.ID] = true
		if !strings.HasPrefix(row.ID, "dast.") || row.Message == "" || row.FixHint == "" || len(row.CWE) == 0 || row.Title == "" {
			t.Errorf("%s: row is missing an id prefix, title, message, fix hint or CWE", row.ID)
		}
		c, ok := cases[row.ID]
		if !ok {
			t.Errorf("%s: no test case", row.ID)
			continue
		}
		for name, k := range map[string]tc{"fire": c.fire, "miss": c.miss} {
			n := 0
			for _, h := range Evaluate(k.target, k.rs) {
				if h.Check == row.ID {
					n++
					if h.Evidence == "" || h.Path == "" {
						t.Errorf("%s %s: hit without evidence or path: %+v", row.ID, name, h)
					}
				}
			}
			if n != k.hits {
				t.Errorf("%s %s: %d hits, want %d", row.ID, name, n, k.hits)
			}
		}
	}
}

// TestEvidenceNeverCarriesBodies: an exposed .env and a source map are
// counted, never copied into the evidence.
func TestEvidenceNeverCarriesBodies(t *testing.T) {
	t.Parallel()
	tg, _ := ParseTarget("http://localhost:3000/")
	rs := []Response{
		page(hardened()),
		probe(ProbeEnv, "/.env", 200, "", "SECRET_KEY=hunter2-super-secret\n"),
		probe("map-1", "/a.js.map", 200, "", `{"sources":["s"],"sourcesContent":["const token='tok-abc'"],"mappings":""}`),
		probe(ProbeGitHead, "/.git/HEAD", 200, "", "ref: refs/heads/secret-branch-name\n"),
	}
	for _, h := range Evaluate(tg, rs) {
		for _, s := range []string{"hunter2", "SECRET_KEY", "tok-abc", "secret-branch-name"} {
			if strings.Contains(h.Evidence, s) {
				t.Errorf("%s evidence carries body text %q: %s", h.Check, s, h.Evidence)
			}
		}
	}
}

func TestEnvLines(t *testing.T) {
	t.Parallel()
	for body, want := range map[string]int{
		"A=1\nB=2\n":                  2,
		"# c\n\nexport X_Y=3\n":       1,
		"<html>A=1</html>":            0,
		`{"a":1}`:                     0,
		"A=1\nnot a line\nother\n":    0,
		"A=1\nB=2\nsome prose line\n": 2,
	} {
		if got := envLines([]byte(body)); got != want {
			t.Errorf("envLines(%q) = %d, want %d", body, got, want)
		}
	}
}
