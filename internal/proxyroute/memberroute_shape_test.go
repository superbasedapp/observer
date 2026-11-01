package proxyroute

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

// FU-139: the switch-on checklist for the member-route writers, encoded.

// TestMemberRouteRecordsItsKey: every member-route write records the member
// it lives at (RouteKey = the row's primary member), so Leave and the port
// move read the record with that row's reader.
func TestMemberRouteRecordsItsKey(t *testing.T) {
	runLiveGated(t)
	for _, tc := range memberCases {
		t.Run(tc.tool, func(t *testing.T) {
			spec, _ := memberSpecFor(tc.tool, tc.defaultProvider)
			home := t.TempDir()
			writeFixture(t, home, tc.ok)
			r, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home, Writer: routeprov.WriterManaged})
			if err != nil {
				t.Fatal(err)
			}
			res := runMember(r, spec)
			if res.Error != nil || !res.Added || !slices.Equal(res.RouteKey, []string(spec.members[0].path)) {
				t.Fatalf("write: %+v, want RouteKey %v", res, spec.members[0].path)
			}
			f, err := loadProvenance(r.ProvenancePath())
			if err != nil {
				t.Fatal(err)
			}
			rec := f.Find(tc.tool, res.ConfigPath)
			if rec == nil || !slices.Equal(rec.RouteKey, []string(spec.members[0].path)) || rec.Value != tc.want {
				t.Fatalf("record %+v, want RouteKey %v value %q", rec, spec.members[0].path, tc.want)
			}
		})
	}
}

// TestMemberShapeRefusesAnotherWritersRecord: a record of the same tool at a
// key no member-route row owns (a later writer's route, such as the provider
// entry's base_url) is never read or removed with the default-provider
// reader: the read and the removal refuse, and the file is untouched.
func TestMemberShapeRefusesAnotherWritersRecord(t *testing.T) {
	runLiveGated(t)
	for _, tc := range memberCases {
		t.Run(tc.tool, func(t *testing.T) {
			spec, _ := memberSpecFor(tc.tool, tc.defaultProvider)
			home := t.TempDir()
			writeFixture(t, home, tc.ok)
			path := memberPath(t, home, spec.artifact)
			before, _ := os.ReadFile(path)
			shape, _ := shapeFor(tc.tool)
			other := routeprov.Record{Tool: tc.tool, ConfigPath: path, Value: "http://127.0.0.1:8820/v1", RouteKey: []string{"providers", "observer", "base_url"}}
			if _, _, err := shape.read(path, &other); err == nil {
				t.Error("read accepted a record no member-route row owns")
			}
			if err := shape.remove(path, other); err == nil {
				t.Error("remove accepted a record no member-route row owns")
			}
			if _, ok := shape.want(other, 8821); ok {
				t.Error("want answered for a record no member-route row owns")
			}
			if got, _ := os.ReadFile(path); string(got) != string(before) {
				t.Error("the file changed")
			}
		})
	}
}

// TestMemberRoutePortMove: an organization-written base-URL route (goose's
// OPENAI_HOST, Open Interpreter's base_url, Stakpak's api_endpoint,
// Poolside's api_url) moves to the daemon's current proxy port in place,
// keeping every other byte, and its record follows; a provider selector
// (hermes, pi, prime-agent) names no port and is never moved.
func TestMemberRoutePortMove(t *testing.T) {
	runLiveGated(t)
	for _, tc := range memberCases {
		t.Run(tc.tool, func(t *testing.T) {
			spec, _ := memberSpecFor(tc.tool, tc.defaultProvider)
			home := t.TempDir()
			writeFixture(t, home, tc.ok)
			old, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home, Writer: routeprov.WriterManaged})
			if err != nil {
				t.Fatal(err)
			}
			res := runMember(old, spec)
			if res.Error != nil || !res.Added {
				t.Fatalf("write: %+v", res)
			}
			path := res.ConfigPath
			written, _ := os.ReadFile(path)
			moved, err := NewRegistrar(RegisterOptions{ProxyPort: 8821, HomeDir: home, Writer: routeprov.WriterManaged})
			if err != nil {
				t.Fatal(err)
			}
			err = moved.moveRoutePort(tc.tool, path, time.Now())
			after, _ := os.ReadFile(path)
			if spec.members[0].kind != memberURL {
				if err == nil {
					t.Fatal("a provider selector was moved")
				}
				if string(after) != string(written) {
					t.Fatal("a refused move changed the file")
				}
				return
			}
			if err != nil {
				t.Fatalf("move: %v", err)
			}
			want := strings.Replace(tc.want, ":8820", ":8821", 1)
			if got := strings.Replace(string(after), want, tc.want, 1); got != string(written) {
				t.Errorf("the move changed more than the port:\nbefore:\n%s\nafter:\n%s", written, after)
			}
			f, _ := loadProvenance(moved.ProvenancePath())
			if rec := f.Find(tc.tool, path); rec == nil || rec.Value != want {
				t.Fatalf("record after the move %+v, want value %q", rec, want)
			}
			// Leave still removes the moved route, byte for byte back to the
			// file before the write.
			shape, _ := shapeFor(tc.tool)
			rec := f.Find(tc.tool, path)
			if err := shape.remove(path, *rec); err != nil {
				t.Fatalf("remove after the move: %v", err)
			}
			if back, _ := os.ReadFile(path); string(back) != tc.ok[spec.artifact] {
				t.Errorf("remove after the move is not byte-identical:\n%s", back)
			}
		})
	}
}
