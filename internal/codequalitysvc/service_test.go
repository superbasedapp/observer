package codequalitysvc

import (
	"context"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/marmutapp/superbased-observer/internal/codequality"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// fakeStore is an in-memory Store.
type fakeStore struct {
	roots  map[int64]string
	active []store.ProjectRoot
	dup    codequality.DuplicationInput
	cx     codequality.ComplexityInput
	keys   []string
	days   map[int64][]codequality.DayPoint
}

func (f *fakeStore) ProjectRootByID(_ context.Context, id int64) (string, error) {
	return f.roots[id], nil
}

func (f *fakeStore) ActiveProjectRoots(context.Context, int) ([]store.ProjectRoot, error) {
	return f.active, nil
}

func (f *fakeStore) LoadCodeQualityDuplication(_ context.Context, keys []string) (codequality.DuplicationInput, error) {
	f.keys = keys
	return f.dup, nil
}

func (f *fakeStore) LoadCodeQualityComplexity(_ context.Context, keys []string) (codequality.ComplexityInput, error) {
	f.keys = keys
	return f.cx, nil
}

func (f *fakeStore) UpsertProjectQualityDay(_ context.Context, id int64, p codequality.DayPoint) error {
	if f.days == nil {
		f.days = map[int64][]codequality.DayPoint{}
	}
	pts := f.days[id]
	for i := range pts {
		if pts[i].Day == p.Day {
			pts[i] = p
			return nil
		}
	}
	f.days[id] = append(pts, p)
	return nil
}

func (f *fakeStore) LoadProjectQualityHistory(_ context.Context, id int64, _ time.Time) ([]codequality.DayPoint, error) {
	return f.days[id], nil
}

func (f *fakeStore) LatestProjectQualityDay(_ context.Context, id int64) (codequality.DayPoint, bool, error) {
	pts := f.days[id]
	if len(pts) == 0 {
		return codequality.DayPoint{}, false, nil
	}
	return pts[len(pts)-1], true, nil
}

const lcov = "TN:\nSF:/repo/app/src/a.ts\nDA:1,1\nDA:2,0\nDA:3,1\nDA:4,1\nDA:5,1\nDA:6,0\nDA:7,1\nDA:8,1\nDA:9,1\nDA:10,1\nend_of_record\n"

func mapFS() fstest.MapFS {
	mt := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	return fstest.MapFS{
		"coverage/lcov.info":         {Data: []byte(lcov), ModTime: mt},
		"api/coverage.out":           {Data: []byte("mode: set\nexample.com/api/h.go:1.1,4.2 2 0\n"), ModTime: mt},
		"web/coverage.xml":           {Data: []byte("not xml at all"), ModTime: mt},
		"node_modules/x/lcov.info":   {Data: []byte(lcov), ModTime: mt}, // never probed
		"linked/lcov.info":           {Data: []byte(lcov), Mode: fs.ModeSymlink},
		"docs/coverage.txt":          {Data: []byte("TN:\n"), ModTime: mt},
		"svc/target/site/README.txt": {Data: []byte("x")},
	}
}

func newSvc(st *fakeStore, cfg Config, fsys fs.FS, now time.Time) *Service {
	return New(st, cfg, WithFS(func(string) fs.FS { return fsys }), WithClock(func() time.Time { return now }))
}

func TestMeasureReadsReportsAndNamesProblems(t *testing.T) {
	now := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	st := &fakeStore{roots: map[int64]string{1: "/repo/app"}}
	m, err := newSvc(st, Config{Enabled: true}, mapFS(), now).Measure(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	c := m.Coverage
	if c.State != codequality.StateMeasured || c.Lines != 14 || c.Covered != 8 {
		t.Fatalf("coverage = %+v", c)
	}
	kinds := map[string]codequality.ProblemKind{}
	for _, p := range c.Problems {
		kinds[p.RelPath] = p.Kind
	}
	if kinds["web/coverage.xml"] != codequality.ProblemUnrecognized || kinds["docs/coverage.txt"] != codequality.ProblemNoLines {
		t.Fatalf("problems = %+v", c.Problems)
	}
	if _, ok := kinds["node_modules/x/lcov.info"]; ok {
		t.Fatal("node_modules must never be probed")
	}
	// lcov's absolute SF is shown relative to the root.
	if len(c.LeastCovered) != 1 || c.LeastCovered[0].Path != "src/a.ts" {
		t.Fatalf("least covered = %+v", c.LeastCovered)
	}
	// Duplication with no index and code intelligence off.
	if m.Duplication.State != codequality.StateCodeIntelOff {
		t.Fatalf("duplication = %+v", m.Duplication)
	}
	if strings.Join(st.keys, "|") == "" {
		t.Fatal("the codeintel keys were not passed")
	}
}

func TestMeasureRefusesSymlinks(t *testing.T) {
	fsys := fstest.MapFS{
		"lcov.info": {Data: []byte("/elsewhere"), Mode: fs.ModeSymlink},
	}
	st := &fakeStore{roots: map[int64]string{1: "/repo/s"}}
	m, err := newSvc(st, Config{Enabled: true}, fsys, time.Now()).Measure(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if m.Coverage.State != codequality.StateUnreadable || len(m.Coverage.Problems) != 1 || m.Coverage.Problems[0].Kind != codequality.ProblemSymlink {
		t.Fatalf("coverage = %+v", m.Coverage)
	}
}

func TestMeasureStates(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		root string
		fsys fs.FS
		cov  codequality.State
		dup  codequality.State
	}{
		{"off", Config{Enabled: false}, "/repo/a", mapFS(), codequality.StateOff, codequality.StateOff},
		{"placeholder root", Config{Enabled: true}, "[cursor]", mapFS(), codequality.StateRootMissing, codequality.StateCodeIntelOff},
		{"missing folder", Config{Enabled: true, CodeIntelOn: true}, "/repo/gone", fstest.MapFS{}, codequality.StateRootMissing, codequality.StateNotIndexed},
		{"no report", Config{Enabled: true}, "/repo/empty", fstest.MapFS{"README.md": {Data: []byte("x")}}, codequality.StateNoReport, codequality.StateCodeIntelOff},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := &fakeStore{roots: map[int64]string{1: c.root}}
			fsys := c.fsys
			if mf, ok := fsys.(fstest.MapFS); ok && len(mf) == 0 {
				fsys = missingFS{}
			}
			m, err := newSvc(st, c.cfg, fsys, time.Now()).Measure(context.Background(), 1)
			if err != nil {
				t.Fatal(err)
			}
			if m.Coverage.State != c.cov || m.Duplication.State != c.dup {
				t.Fatalf("states = %s / %s", m.Coverage.State, m.Duplication.State)
			}
		})
	}
}

// missingFS is a root that does not exist.
type missingFS struct{}

func (missingFS) Open(string) (fs.File, error) { return nil, fs.ErrNotExist }

func TestRecordDue(t *testing.T) {
	now := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	st := &fakeStore{
		roots:  map[int64]string{1: "/repo/a", 2: "/repo/b", 3: "/repo/c"},
		active: []store.ProjectRoot{{ID: 1, RootPath: "/repo/a"}, {ID: 2, RootPath: "/repo/b"}, {ID: 3, RootPath: "/repo/c"}},
		days: map[int64][]codequality.DayPoint{
			// measured an hour ago today: not due
			2: {{Day: "2026-11-04", MeasuredAt: now.Add(-time.Hour)}},
			// measured yesterday: due
			3: {{Day: "2026-11-03", MeasuredAt: now.Add(-2 * time.Hour)}},
		},
	}
	svc := newSvc(st, Config{Enabled: true, MaxPerPass: 5}, mapFS(), now)
	n, err := svc.RecordDue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || len(st.days[1]) != 1 || len(st.days[2]) != 1 || len(st.days[3]) != 2 {
		t.Fatalf("recorded %d: %+v", n, st.days)
	}
	if st.days[1][0].CoverageState != codequality.StateMeasured || st.days[1][0].CoverageLines != 14 {
		t.Fatalf("point = %+v", st.days[1][0])
	}
	// A disabled service records nothing.
	if n, _ := newSvc(st, Config{Enabled: false}, mapFS(), now).RecordDue(context.Background()); n != 0 {
		t.Fatalf("disabled recorded %d", n)
	}
	// The per-pass cap.
	st2 := &fakeStore{active: st.active, roots: st.roots}
	if n, _ := newSvc(st2, Config{Enabled: true, MaxPerPass: 1}, mapFS(), now).RecordDue(context.Background()); n != 1 {
		t.Fatalf("capped pass recorded %d", n)
	}
}

func TestRelTo(t *testing.T) {
	cases := []struct{ base, p, want string }{
		{"/repo/app", "/repo/app/src/a.ts", "src/a.ts"},
		{"/repo/app/", "/repo/app/a.go", "a.go"},
		{`C:\repo\app`, `C:\repo\app\src\a.ts`, "src/a.ts"},
		{"/repo/app", "/repo/other/a.ts", "/repo/other/a.ts"},
		{"/repo/app", "src/a.ts", "src/a.ts"},
		{"", "/x", "/x"},
	}
	for _, c := range cases {
		if got := relTo(c.base, c.p); got != c.want {
			t.Errorf("relTo(%q, %q) = %q, want %q", c.base, c.p, got, c.want)
		}
	}
}

func TestMeasureComplexityRelativizesAndRecords(t *testing.T) {
	now := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	st := &fakeStore{
		roots: map[int64]string{1: "/repo/app"},
		cx: codequality.ComplexityInput{
			Index:  codequality.IndexFacts{Key: "/repo/app", IndexedFiles: 3},
			Files:  []codequality.ComplexityFiles{{Lang: "go", Counter: true, Current: true, Files: 3}},
			Values: []codequality.FuncValue{{Lang: "go", Complexity: 1}, {Lang: "go", Complexity: 4}, {Lang: "go", Complexity: 14}},
			Top:    []codequality.ComplexFunction{{Name: "Big", Kind: "function", Lang: "go", File: "/repo/app/big.go", StartLine: 3, EndLine: 90, Complexity: 14}},
		},
	}
	svc := newSvc(st, Config{Enabled: true, CodeIntelOn: true}, fstest.MapFS{}, now)
	m, err := svc.Record(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	c := m.Complexity
	if c.State != codequality.StateMeasured || c.Functions != 3 || c.Over != 1 || c.Max != 14 {
		t.Fatalf("complexity %+v", c)
	}
	if len(c.Top) != 1 || c.Top[0].File != "big.go" {
		t.Errorf("top %+v, want big.go relative to the project", c.Top)
	}
	p := st.days[1][0]
	if p.ComplexityState != codequality.StateMeasured || p.ComplexityFunctions != 3 || p.ComplexityOver != 1 || p.ComplexitySum != 19 {
		t.Errorf("point %+v", p)
	}
}
