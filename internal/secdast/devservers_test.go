package secdast

import (
	"reflect"
	"testing"
)

// TestScriptPortTable is one case per scriptRules row, plus the explicit
// port forms and a negative case.
func TestScriptPortTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		cmd  string
		port int
		rule string
	}{
		{"next dev", 3000, "next"},
		{"nuxi dev", 3000, "nuxt"},
		{"remix vite:dev", 3000, "remix"},
		{"react-scripts start", 3000, "react-scripts"},
		{"astro dev", 4321, "astro"},
		{"ng serve", 4200, "angular"},
		{"svelte-kit dev", 5173, "sveltekit"},
		{"vite", 5173, "vite"},
		{"vite dev --host", 5173, "vite"},
		{"gatsby develop", 8000, "gatsby"},
		{"vue-cli-service serve", 8080, "vue-cli"},
		{"webpack serve --mode development", 8080, "webpack"},
		{"parcel src/index.html", 1234, "parcel"},
		{"storybook dev", 6006, "storybook"},
		{"expo start", 8081, "expo"},
		{"python manage.py runserver", 8000, "django"},
		{"flask run", 5000, "flask"},
		{"bin/rails server", 3000, "rails"},
		{"hugo server -D", 1313, "hugo"},
		{"bundle exec jekyll serve", 4000, "jekyll"},
		{"nodemon src/server.js", 3000, "express"},
		// Explicit ports win over the row's default.
		{"next dev -p 4000", 4000, "next"},
		{"vite --port=5555", 5555, "vite"},
		{"PORT=3100 react-scripts start", 3100, "react-scripts"},
		{"python manage.py runserver 0.0.0.0:8100", 8100, "django"},
	}
	for _, c := range cases {
		p, rule, ok := ScriptPort(c.cmd)
		if !ok || p != c.port || rule != c.rule {
			t.Errorf("ScriptPort(%q) = %d %q %v, want %d %q", c.cmd, p, rule, ok, c.port, c.rule)
		}
	}
	for _, cmd := range []string{"tsc -p tsconfig.json", "eslint .", "vitest run", "jest"} {
		if _, _, ok := ScriptPort(cmd); ok {
			t.Errorf("ScriptPort(%q) matched a dev server", cmd)
		}
	}
}

// TestProjectCandidates walks fileTable: one case per row, dedup by URL,
// first source wins.
func TestProjectCandidates(t *testing.T) {
	t.Parallel()
	got := ProjectCandidates([]ProjectFile{
		{Rel: ".claude/launch.json", Data: []byte(`{"configurations":[{"name":"web","port":5173}]}`)},
		{Rel: "package.json", Data: []byte(`{"scripts":{"dev":"vite","storybook":"storybook dev -p 6007","lint":"eslint ."}}`)},
		{Rel: "vite.config.ts", Data: []byte(`export default { server: { host: true, port: 5180 } }`)},
		{Rel: "manage.py", Data: []byte(`os.environ.setdefault("DJANGO_SETTINGS_MODULE", "x")  # django`)},
		{Rel: ".flaskenv", Data: []byte("FLASK_APP=app\nFLASK_RUN_PORT=5050\n")},
		{Rel: "config/puma.rb", Data: []byte(`port ENV.fetch("PORT") { 3030 }`)},
		{Rel: "hugo.toml", Data: []byte("baseURL = 'x'\n")},
		{Rel: "_config.yml", Data: []byte("theme: minima\nport: 4001\n")},
		{Rel: "README.md", Data: []byte("next dev")},
	})
	want := []Candidate{
		{URL: "http://localhost:5173/", Name: "web", Source: SourceLaunchJSON},
		{URL: "http://localhost:6007/", Name: "npm run storybook (storybook)", Source: SourcePackageJSON},
		{URL: "http://localhost:5180/", Name: "vite", Source: SourceViteConfig},
		{URL: "http://localhost:8000/", Name: "django", Source: SourceDjango},
		{URL: "http://localhost:5050/", Name: "flask", Source: SourceFlask},
		{URL: "http://localhost:1313/", Name: "hugo", Source: SourceHugo},
		{URL: "http://localhost:4001/", Name: "jekyll", Source: SourceJekyll},
	}
	want = append(want[:5], append([]Candidate{{URL: "http://localhost:3030/", Name: "rails", Source: SourceRails}}, want[5:]...)...)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ProjectCandidates =\n%+v\nwant\n%+v", got, want)
	}
	if c := ProjectCandidates([]ProjectFile{{Rel: "package.json", Data: make([]byte, MaxProjectFile+1)}}); len(c) != 0 {
		t.Errorf("an over-cap file produced %v", c)
	}
	if c := ProjectCandidates([]ProjectFile{{Rel: "_config.yml", Data: []byte("title: docs\n")}}); len(c) != 0 {
		t.Errorf("a _config.yml with no Jekyll signal produced %v", c)
	}
}

func TestCandidatePort(t *testing.T) {
	t.Parallel()
	if p := CandidatePort("http://localhost:5173/"); p != 5173 {
		t.Errorf("CandidatePort = %d", p)
	}
	if p := CandidatePort("http://example.com:80/"); p != 0 {
		t.Errorf("a non-loopback URL gave %d", p)
	}
}

// TestListeningPorts: LISTEN rows on loopback or wildcard addresses only.
func TestListeningPorts(t *testing.T) {
	t.Parallel()
	tcp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:1435 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1 1\n" + // 127.0.0.1:5173 LISTEN
		"   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 2 1\n" + // 0.0.0.0:8080 LISTEN
		"   2: 0100007F:0BB8 0100007F:D2F0 01 00000000:00000000 00:00000000 00000000  1000        0 3 1\n" + // established
		"   3: 0A00020F:0FA0 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4 1\n" + // 15.2.0.10:4000, not local
		"garbage\n"
	tcp6 := "  sl  local_address remote_address st\n" +
		"   0: 00000000000000000000000001000000:0BB8 00000000000000000000000000000000:0000 0A 0 0 0 0 0 0 5 1\n" + // [::1]:3000
		"   1: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 0 0 0 0 0 0 6 1\n" + // [::]:8080 (dup)
		"   2: 0000000000000000FFFF00000100007F:115C 00000000000000000000000000000000:0000 0A 0 0 0 0 0 0 7 1\n" + // ::ffff:127.0.0.1:4444
		"   3: 20010DB8000000000000000000000001:2710 00000000000000000000000000000000:0000 0A 0 0 0 0 0 0 8 1\n" // global v6
	got := ListeningPorts(tcp, tcp6)
	want := []int{3000, 4444, 5173, 8080}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListeningPorts = %v, want %v", got, want)
	}
}
