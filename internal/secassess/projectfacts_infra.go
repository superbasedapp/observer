package secassess

import (
	"encoding/json"
	"sort"
	"strings"
)

// projInfraRule is one row of the infrastructure table: closed id, and what in
// the top-level listing names it.
type projInfraRule struct {
	id      string
	names   []string // exact top-level file names
	prefix  []string // file name prefixes
	suffix  []string // file name suffixes
	dirs    []string // top-level directory names
	present []string // existence probe ids (SurveyInput.Present)
}

// projInfraRules is THE infrastructure table (one test row per row), in the
// order the ids are listed.
var projInfraRules = []projInfraRule{
	{id: "dockerfile", names: []string{"Dockerfile"}, prefix: []string{"Dockerfile."}, suffix: []string{".dockerfile"}},
	{id: "compose", names: []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}, prefix: []string{"docker-compose."}},
	{id: "terraform", suffix: []string{".tf"}, dirs: []string{"terraform"}},
	{id: "kubernetes", names: []string{"Chart.yaml", "kustomization.yaml", "kustomization.yml"}, dirs: []string{"k8s", "kubernetes", "helm", "charts"}},
	{id: "github_actions", present: []string{".github/workflows"}},
	{id: "gitlab_ci", names: []string{".gitlab-ci.yml"}},
	{id: "circleci", dirs: []string{".circleci"}},
	{id: "bicep", suffix: []string{".bicep"}},
}

// projInfra returns the closed infrastructure ids the project shows.
func projInfra(names, dirs, present map[string]bool) []string {
	var out []string
	for _, r := range projInfraRules {
		hit := false
		for _, n := range r.names {
			hit = hit || names[n]
		}
		for _, d := range r.dirs {
			hit = hit || dirs[d]
		}
		for _, p := range r.present {
			hit = hit || present[p]
		}
		for n := range names {
			for _, p := range r.prefix {
				hit = hit || strings.HasPrefix(n, p)
			}
			for _, s := range r.suffix {
				hit = hit || strings.HasSuffix(n, s)
			}
		}
		if hit {
			out = append(out, r.id)
		}
	}
	return out
}

// projSpecJSONPaths are the OpenAPI JSON files the survey reads, in order of
// preference; projSpecYAMLNames and the GraphQL names set SpecPath only.
var (
	projSpecJSONPaths = []string{"openapi.json", "swagger.json", "docs/openapi.json", "api/openapi.json", "openapi/openapi.json"}
	projSpecYAMLNames = []string{"openapi.yaml", "openapi.yml", "swagger.yaml", "swagger.yml"}
)

// projHTTPMethods are the keys of an OpenAPI path item that are operations.
var projHTTPMethods = map[string]bool{
	"get": true, "put": true, "post": true, "delete": true, "options": true, "head": true, "patch": true, "trace": true,
}

// projSpec fills SpecPath and Spec: an OpenAPI JSON file read by the survey
// (operations, security scheme names, server count), else the name of a YAML
// spec or a GraphQL schema among the top-level names.
func projSpec(c *projCollector, in SurveyInput, names map[string]bool, f *ProjectFacts) {
	for _, p := range projSpecJSONPaths {
		for _, file := range in.Files {
			if file.Rel != p || len(file.Data) == 0 || len(file.Data) > MaxProjectFile {
				continue
			}
			if s, ok := projSummariseSpec(c, p, file.Data); ok && c.keep(p) {
				f.SpecPath, f.Spec = p, &s
				return
			}
		}
	}
	for _, p := range projSpecJSONPaths {
		if names[p] && c.keep(p) {
			f.SpecPath = p
			return
		}
	}
	for _, p := range projSpecYAMLNames {
		if names[p] && c.keep(p) {
			f.SpecPath = p
			return
		}
	}
	var gql []string
	for n := range names {
		if strings.HasSuffix(n, ".graphql") || strings.HasSuffix(n, ".graphqls") || strings.HasSuffix(n, ".gql") {
			gql = append(gql, n)
		}
	}
	sort.Strings(gql)
	for _, n := range gql {
		if n == "schema.graphql" {
			gql = []string{n}
			break
		}
	}
	for _, n := range gql {
		if c.keep(n) {
			f.SpecPath = n
			return
		}
	}
}

// projSummariseSpec reads an OpenAPI or Swagger JSON document. It reports false
// for JSON that is not an API description.
func projSummariseSpec(c *projCollector, path string, data []byte) (SpecSummary, bool) {
	var doc struct {
		OpenAPI    string                                `json:"openapi"`
		Swagger    string                                `json:"swagger"`
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Servers    []json.RawMessage                     `json:"servers"`
		Host       string                                `json:"host"`
		Components struct {
			SecuritySchemes map[string]json.RawMessage `json:"securitySchemes"`
		} `json:"components"`
		SecurityDefinitions map[string]json.RawMessage `json:"securityDefinitions"`
	}
	if json.Unmarshal(data, &doc) != nil || (doc.OpenAPI == "" && doc.Swagger == "") {
		return SpecSummary{}, false
	}
	s := SpecSummary{Path: path, Servers: len(doc.Servers)}
	if s.Servers == 0 && doc.Host != "" {
		s.Servers = 1
	}
	for _, item := range doc.Paths {
		for k := range item {
			if projHTTPMethods[strings.ToLower(k)] {
				s.Operations++
			}
		}
	}
	schemes := doc.Components.SecuritySchemes
	if len(schemes) == 0 {
		schemes = doc.SecurityDefinitions
	}
	for _, n := range projSortedKeys(schemes) {
		if len(s.AuthSchemes) == projMaxListed {
			break
		}
		if c.keep(n) {
			s.AuthSchemes = append(s.AuthSchemes, n)
		}
	}
	return s, true
}

// projEnvExampleNames are the only environment files whose contents the
// analysis reads.
var projEnvExampleNames = []string{".env.example", ".env.sample", ".env.template"}

// projIsEnvName reports whether a top-level file name is an environment file
// (which may hold real values) or an example of one. It asks the one table of
// environment and key files (ClassifyEnvKey), so it cannot disagree with the
// refuse setting or the survey's guard; a key or credential file is not an
// environment file here (the plan counts only the environment ones).
func projIsEnvName(n string) (env, example bool) {
	k := ClassifyEnvKey(n)
	if k.Class != EnvKeyEnv {
		return false, false
	}
	return !k.Example, k.Example
}

// projEnvNames fills EnvFiles and EnvExamples from the top-level names. It
// reads no contents.
func projEnvNames(c *projCollector, names []string, f *ProjectFacts) {
	for _, n := range names {
		env, ex := projIsEnvName(n)
		switch {
		case env && c.keep(n):
			if len(f.EnvFiles) < projMaxListed {
				f.EnvFiles = append(f.EnvFiles, n)
			}
		case ex && c.keep(n):
			if len(f.EnvExamples) < projMaxListed {
				f.EnvExamples = append(f.EnvExamples, n)
			}
		}
	}
	sort.Strings(f.EnvFiles)
	sort.Strings(f.EnvExamples)
}

// projNeedImages maps what an image name's last path segment (or its last two,
// joined with "/") is to the service kind. Exact segments only: an exporter, a
// web console or a UI for a service is not the service.
var projNeedImages = []struct {
	kind     string
	segments []string
}{
	{"postgres", []string{"postgres", "postgresql", "postgis", "timescaledb", "pgvector"}},
	{"mysql", []string{"mysql", "mysql-server"}},
	{"mariadb", []string{"mariadb"}},
	{"redis", []string{"redis", "redis-stack", "redis-stack-server", "valkey", "keydb"}},
	{"mongodb", []string{"mongo", "mongodb", "mongodb-community-server"}},
	{"rabbitmq", []string{"rabbitmq"}},
	{"kafka", []string{"kafka", "cp-kafka"}},
	{"elasticsearch", []string{"elasticsearch"}},
	{"memcached", []string{"memcached"}},
	{"clickhouse", []string{"clickhouse", "clickhouse-server"}},
	{"cassandra", []string{"cassandra"}},
	{"nats", []string{"nats"}},
	{"sqlserver", []string{"mssql/server", "mssql-server"}},
}

// projNeedServiceNames maps a compose service NAME (when it has no image of a
// known kind) to the kind; only unambiguous names ("db" and "cache" are not).
var projNeedServiceNames = map[string]string{
	"postgres": "postgres", "postgresql": "postgres", "mysql": "mysql", "mariadb": "mariadb", "redis": "redis",
	"mongo": "mongodb", "mongodb": "mongodb", "rabbitmq": "rabbitmq", "kafka": "kafka",
	"elasticsearch": "elasticsearch", "memcached": "memcached", "clickhouse": "clickhouse",
	"cassandra": "cassandra", "nats": "nats",
}

// projNeedSchemes maps the scheme word of a URL (before any "+driver") to the
// service kind; anything not here is ignored, and nothing else of the URL is
// kept.
var projNeedSchemes = map[string]string{
	"postgres": "postgres", "postgresql": "postgres", "mysql": "mysql", "mariadb": "mariadb",
	"redis": "redis", "rediss": "redis", "valkey": "redis", "mongodb": "mongodb",
	"amqp": "rabbitmq", "amqps": "rabbitmq", "kafka": "kafka", "mssql": "sqlserver", "sqlserver": "sqlserver",
	"nats": "nats", "memcached": "memcached", "clickhouse": "clickhouse", "cassandra": "cassandra",
}

// projNeedFromImage returns the kind of a compose image reference ("" none).
func projNeedFromImage(image string) string {
	image = strings.ToLower(strings.TrimSpace(strings.Trim(image, `"'`)))
	if i := strings.IndexByte(image, '@'); i >= 0 {
		image = image[:i]
	}
	segs := strings.Split(image, "/")
	last := segs[len(segs)-1]
	if i := strings.IndexByte(last, ':'); i >= 0 {
		last = last[:i]
	}
	segs[len(segs)-1] = last
	two := last
	if len(segs) >= 2 {
		two = segs[len(segs)-2] + "/" + last
	}
	for _, r := range projNeedImages {
		for _, s := range r.segments {
			if s == last || s == two {
				return r.kind
			}
		}
	}
	return ""
}

// composeNames are the compose file names the analysis reads.
var composeNames = map[string]bool{
	"docker-compose.yml": true, "docker-compose.yaml": true, "compose.yml": true, "compose.yaml": true,
}

// yamlIndent is the number of leading spaces (a tab counts one).
func yamlIndent(s string) int {
	n := 0
	for n < len(s) && (s[n] == ' ' || s[n] == '\t') {
		n++
	}
	return n
}

// yamlKey returns the key of a "key:" or "key: value" line and its value
// ("" when none), without quotes or a trailing comment.
func yamlKey(t string) (key, val string, ok bool) {
	k, v, found := strings.Cut(t, ":")
	if !found || k == "" || strings.ContainsAny(k, " \t\"'{[#&*!|>%@`") {
		return "", "", false
	}
	if v != "" && v[0] != ' ' && v[0] != '\t' {
		return "", "", false // "a:b" is a scalar, not a key
	}
	v = strings.TrimSpace(v)
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return k, strings.Trim(v, `"'`), true
}

// projComposeNeeds reads the services of one compose file with a small
// indentation parser (no YAML library): the first indent level under
// "services:" names the services, and an "image:" key one level deeper names
// the image.
func projComposeNeeds(c *projCollector, data []byte) []Need {
	var out []Need
	inServices := false
	svcIndent, keyIndent := -1, -1
	svc := ""
	svcImage := ""
	flush := func() {
		if svc == "" {
			return
		}
		kind := projNeedFromImage(svcImage)
		if kind == "" {
			kind = projNeedServiceNames[strings.ToLower(svc)]
		}
		if kind != "" {
			n := Need{Kind: kind, From: "compose"}
			if projStrict(svc) {
				n.Service = svc
			} else {
				c.dropped++
			}
			out = append(out, n)
		}
		svc, svcImage = "", ""
	}
	for _, ln := range projLines(data) {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		ind := yamlIndent(ln)
		if ind == 0 {
			flush()
			k, v, ok := yamlKey(t)
			inServices = ok && k == "services" && v == ""
			svcIndent, keyIndent = -1, -1
			continue
		}
		if !inServices {
			continue
		}
		if svcIndent < 0 {
			svcIndent = ind
		}
		if ind == svcIndent {
			flush()
			if k, _, ok := yamlKey(t); ok {
				svc, keyIndent = k, -1
			}
			continue
		}
		if svc == "" || ind < svcIndent {
			continue
		}
		if keyIndent < 0 {
			keyIndent = ind
		}
		if ind == keyIndent {
			if k, v, ok := yamlKey(t); ok && k == "image" {
				svcImage = v
			}
		}
	}
	flush()
	return out
}

// projEnvExampleNeeds reads an example environment file: for a key ending in
// _URL, _URI or _DSN (or DATABASE_URL) the scheme word of its value, mapped
// through the closed scheme table. Nothing else of the file is kept.
func projEnvExampleNeeds(data []byte) []Need {
	var out []Need
	for _, ln := range projLines(data) {
		t := strings.TrimSpace(ln)
		t = strings.TrimPrefix(t, "export ")
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			continue
		}
		k = strings.ToUpper(strings.TrimSpace(k))
		if !strings.HasSuffix(k, "_URL") && !strings.HasSuffix(k, "_URI") && !strings.HasSuffix(k, "_DSN") {
			continue
		}
		v = strings.ToLower(strings.Trim(strings.TrimSpace(v), `"'`))
		v = strings.TrimPrefix(v, "jdbc:")
		scheme, _, found := strings.Cut(v, "://")
		if !found {
			continue
		}
		scheme, _, _ = strings.Cut(scheme, "+")
		if kind := projNeedSchemes[scheme]; kind != "" {
			out = append(out, Need{Kind: kind, From: "env_example"})
		}
	}
	return out
}

// projNeeds collects the services the project needs from its compose files and
// its example environment files, each (kind, source, service) once, at most
// projMaxNeeds.
func projNeeds(c *projCollector, files []ProjectFile) []Need {
	var out []Need
	seen := map[Need]bool{}
	add := func(ns []Need) {
		for _, n := range ns {
			if !seen[n] && len(out) < projMaxNeeds {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	for _, file := range files {
		if len(file.Data) == 0 || len(file.Data) > MaxProjectFile {
			continue
		}
		switch {
		case composeNames[file.Rel]:
			add(projComposeNeeds(c, file.Data))
		case strSliceHas(projEnvExampleNames, file.Rel):
			add(projEnvExampleNeeds(file.Data))
		}
	}
	return out
}

// projStartFiles keeps the files the start table reads, in survey order.
func projStartFiles(files []ProjectFile) []ProjectFile {
	var out []ProjectFile
	for _, file := range files {
		if len(file.Data) == 0 || len(file.Data) > MaxProjectFile || !splReads(file.Rel) {
			continue
		}
		out = append(out, file)
	}
	return out
}
