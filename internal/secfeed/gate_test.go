package secfeed

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

func TestGate(t *testing.T) {
	ix := buildIndex(t)
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	specs := specsOf(t, "npm install evil-pkg react lodahs brand-new cached-one @corp/secret ./x").Specs
	var asked []string
	in := GateInput{
		Specs: specs, Index: ix, IndexFreshness: content.Fresh, Now: now, MinAge: 72 * time.Hour,
		Public: func(s InstallSpec) bool { return s.Name != "@corp/secret" },
		Cache: func(eco Ecosystem, name, version string) (OnlineAnswer, bool) {
			if name == "cached-one" {
				return OnlineAnswer{Eco: eco, Name: name, Status: OnlineNotFound}, true
			}
			return OnlineAnswer{}, false
		},
		Ask: func(_ context.Context, ss []InstallSpec) ([]OnlineAnswer, error) {
			var out []OnlineAnswer
			for _, s := range ss {
				asked = append(asked, s.Name)
				if s.Name == "brand-new" {
					out = append(out, OnlineAnswer{Eco: s.Eco, Name: s.Name, Status: OnlineAnswered, FirstPublished: now.Add(-time.Hour)})
				}
			}
			// an answer about a package nobody asked about is ignored
			out = append(out, OnlineAnswer{Eco: EcoNpm, Name: "react", Status: OnlineAnswered, MalIDs: []string{"MAL-9"}})
			return out, nil
		},
	}
	got := Gate(context.Background(), in)
	want := []policy.InstallVerdict{
		policy.InstallMalicious, policy.InstallKnownGood, policy.InstallNearMiss, policy.InstallTooNew,
		policy.InstallUnknownName, policy.InstallNotChecked, policy.InstallNotChecked,
	}
	if len(got) != len(want) {
		t.Fatalf("checks %+v", got)
	}
	for i, w := range want {
		if got[i].Verdict != w {
			t.Errorf("%s: %s (%s), want %s", got[i].Name, got[i].Verdict, got[i].Reason, w)
		}
	}
	// Only the public, uncached, unlisted, unpopular names were asked: the
	// listed, popular, cached, private and invalid ones never leave.
	if len(asked) != 2 || asked[0] != "lodahs" || asked[1] != "brand-new" {
		t.Errorf("asked %v", asked)
	}
	if !got[5].Private {
		t.Error("the private name is marked private")
	}

	in.Ask = func(context.Context, []InstallSpec) ([]OnlineAnswer, error) { return nil, errors.New("timeout") }
	in.Cache = nil
	got = Gate(context.Background(), in)
	if got[3].Verdict != policy.InstallOnlineUnknown || got[0].Verdict != policy.InstallMalicious {
		t.Errorf("a failed ask is online_unknown and never clears an offline hit: %+v", got)
	}
	// A local classifier that defers to the asker: the asker classifies
	// again, and a name it calls private is never a near miss.
	in.Public = func(s InstallSpec) bool { return !s.Private }
	in.Ask = func(_ context.Context, ss []InstallSpec) ([]OnlineAnswer, error) {
		var out []OnlineAnswer
		for _, s := range ss {
			out = append(out, OnlineAnswer{Eco: s.Eco, Name: s.Name, Status: OnlineNotAsked, Private: s.Name == "lodahs" || s.Name == "@corp/secret"})
		}
		return out, nil
	}
	got = Gate(context.Background(), in)
	if got[2].Verdict != policy.InstallNotChecked || !got[2].Private || !got[5].Private || got[3].Private {
		t.Errorf("the asker's private marks: %+v", got)
	}
}

// TestGateNilClassifierAsksNothing: with no classifier nothing is known to
// be public, so nothing is asked and nothing is called a near miss.
func TestGateNilClassifierAsksNothing(t *testing.T) {
	asked := 0
	got := Gate(context.Background(), GateInput{
		Specs: specsOf(t, "npm install lodahs brand-new").Specs, Index: buildIndex(t), IndexFreshness: content.Fresh,
		Ask: func(context.Context, []InstallSpec) ([]OnlineAnswer, error) { asked++; return nil, nil },
	})
	if asked != 0 {
		t.Errorf("asked %d times", asked)
	}
	for _, c := range got {
		if !c.Private || c.Verdict == policy.InstallNearMiss {
			t.Errorf("%+v", c)
		}
	}
}

// TestGateCommandPrivate is X4: a registry or index flag or variable on
// the command line makes every package of the unit private, whatever the
// classifier says: never asked, never a near miss.
func TestGateCommandPrivate(t *testing.T) {
	for _, cmd := range []string{
		"pip install --index-url https://corp.example/simple lodahs brand-new",
		"pip install --extra-index-url https://attacker.example/simple lodahs brand-new",
		"pip install -i https://corp.example/simple lodahs brand-new",
		"PIP_INDEX_URL=https://corp.example/simple pip install lodahs brand-new",
		"UV_INDEX_URL=https://corp.example/simple uv pip install lodahs brand-new",
		"npm i --registry https://corp.example lodahs brand-new",
		"npm --registry=https://corp.example install lodahs brand-new",
		"NPM_CONFIG_REGISTRY=https://corp.example npm i lodahs brand-new",
		"npm_config_registry=https://corp.example npm i lodahs brand-new",
		"yarn add --registry https://corp.example lodahs brand-new",
		"cargo install --registry corp lodahs brand-new",
		"cargo install --index sparse+https://corp.example/ lodahs brand-new",
		"GOPROXY=https://corp.example go get corp.example/a/lodahs corp.example/a/brand-new",
		"GOPRIVATE=corp.example go get corp.example/a/lodahs corp.example/a/brand-new",
		"env PIP_INDEX_URL=https://corp.example/simple pip install lodahs brand-new",
		"export PIP_INDEX_URL=https://corp.example/simple && pip install lodahs brand-new",
		"export NPM_CONFIG_REGISTRY=https://corp.example; npm install lodahs brand-new",
		"sudo -E env NPM_CONFIG_REGISTRY=https://corp.example npm i lodahs brand-new",
		"npm i --@corp:registry=https://corp.example lodahs brand-new",
	} {
		t.Run(cmd, func(t *testing.T) {
			in := specsOf(t, cmd)
			if !in.CustomRegistry || len(in.Specs) != 2 {
				t.Fatalf("installs %+v", in)
			}
			for _, s := range in.Specs {
				if !s.Private {
					t.Errorf("%s is not private", s.Name)
				}
			}
			asked := 0
			got := Gate(context.Background(), GateInput{
				Specs: in.Specs, Index: buildIndex(t), IndexFreshness: content.Fresh,
				Public: func(InstallSpec) bool { return true },
				Ask:    func(context.Context, []InstallSpec) ([]OnlineAnswer, error) { asked++; return nil, nil },
			})
			if asked != 0 {
				t.Error("a command-private name was asked about")
			}
			for _, c := range got {
				if !c.Private || c.Verdict == policy.InstallNearMiss {
					t.Errorf("%+v", c)
				}
			}
		})
	}
	// The export reaches only the units after it, and an unrelated unit of
	// the same command keeps its classification.
	in := specsOf(t, "npm i lodahs && export PIP_INDEX_URL=https://corp.example/simple && pip install brand-new")
	if len(in.Specs) != 2 || in.Specs[0].Private || !in.Specs[1].Private {
		t.Errorf("%+v", in.Specs)
	}
}

func TestEventSpecs(t *testing.T) {
	s, reg, man := EventSpecs(&policy.Event{Kind: policy.KindShellExec, Target: "npm i --registry=https://x y"})
	if len(s) != 1 || !reg || man {
		t.Errorf("shell: %+v %v %v", s, reg, man)
	}
	s, _, man = EventSpecs(&policy.Event{Kind: policy.KindFileAccess, Target: "/r/package.json", Edits: []policy.ProposedEdit{{Old: "", New: `{"dependencies":{"x":"1"}}`}}})
	if len(s) != 1 || !man {
		t.Errorf("manifest: %+v %v", s, man)
	}
	if s, _, _ := EventSpecs(&policy.Event{Kind: policy.KindFileAccess, Target: "/r/main.go", Edits: []policy.ProposedEdit{{New: "x"}}}); s != nil {
		t.Error("a non-manifest edit has no specs")
	}
}

func TestCacheFile(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	var es []CacheEntry
	for _, a := range []OnlineAnswer{
		{Eco: EcoNpm, Name: "Exists", Status: OnlineAnswered},
		{Eco: EcoNpm, Name: "gone", Status: OnlineNotFound},
		{Eco: EcoNpm, Name: "adv", Status: OnlineAnswered, VulnIDs: []string{"GHSA-1"}},
		{Eco: EcoNpm, Name: "failed", Status: OnlineFailed},
		{Eco: EcoNpm, Name: "priv", Status: OnlineNotAsked, Private: true},
	} {
		if e, ok := NewCacheEntry(a, now); ok {
			es = append(es, e)
		}
	}
	if len(es) != 3 {
		t.Fatalf("failures and private answers are never cached: %d", len(es))
	}
	b, err := EncodeCacheFile(es, now)
	if err != nil {
		t.Fatal(err)
	}
	c, err := DecodeCacheFile(b, now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Lookup(EcoNpm, "exists", ""); !ok {
		t.Error("a positive answer lives 24 h (and is keyed normalized)")
	}
	if _, ok := c.Lookup(EcoNpm, "gone", ""); ok {
		t.Error("not found lives 1 h")
	}
	c, _ = DecodeCacheFile(b, now.Add(7*time.Hour))
	if _, ok := c.Lookup(EcoNpm, "adv", ""); ok {
		t.Error("an advisory answer lives 6 h")
	}
	if _, err := DecodeCacheFile([]byte(`{"v":1,"entries":[],"x":1}`), now); err == nil {
		t.Error("unknown fields refused")
	}
	var nilCache *Cache
	if _, ok := nilCache.Lookup(EcoNpm, "x", ""); ok {
		t.Error("nil cache")
	}
}

// TestGateOverflowNeverHidesAPackage is RB1 sweep finding P1: an install
// naming more packages than one check holds used to drop every name after
// the 64th without a trace, so `npm i a1 ... a64 evil-pkg` never reached
// S-741. Every parsed name is now looked up offline, the malicious one
// keeps a slot, and one too_many_packages check stands for the rest.
func TestGateOverflowNeverHidesAPackage(t *testing.T) {
	cmd := "npm i"
	for i := 0; i < 70; i++ {
		cmd += fmt.Sprintf(" filler-%d", i)
	}
	cmd += " evil-pkg"
	in := specsOf(t, cmd)
	if len(in.Specs) != 71 {
		t.Fatalf("parsed %d specs, want 71 (the parse cap must sit above the check cap)", len(in.Specs))
	}
	for _, online := range []bool{false, true} {
		g := GateInput{Specs: in.Specs, Index: buildIndex(t), IndexFreshness: content.Fresh, Now: time.Now()}
		if online {
			g.Ask = func(_ context.Context, ss []InstallSpec) ([]OnlineAnswer, error) {
				var out []OnlineAnswer
				for _, s := range ss {
					out = append(out, OnlineAnswer{Eco: s.Eco, Name: Normalize(s.Eco, s.Name), Status: OnlineAnswered})
				}
				return out, nil
			}
		}
		got := Gate(context.Background(), g)
		if len(got) != policy.InstallChecksMax {
			t.Fatalf("online=%v: %d checks, want %d", online, len(got), policy.InstallChecksMax)
		}
		var mal, many int
		for _, c := range got {
			if c.Verdict == policy.InstallMalicious && c.Name == "evil-pkg" {
				mal++
			}
			if c.Reason == ReasonTooMany {
				many++
				want := policy.InstallUnknownName
				if online {
					want = policy.InstallOnlineUnknown
				}
				if c.Verdict != want {
					t.Fatalf("online=%v: too_many verdict %q, want %q", online, c.Verdict, want)
				}
			}
		}
		if mal != 1 || many != 1 {
			t.Fatalf("online=%v: malicious checks %d, too_many checks %d; want 1 and 1", online, mal, many)
		}
	}
	// Repeats are one package: 70 copies of one name fit in one check.
	rep := specsOf(t, "npm i"+strings.Repeat(" left-pad", 70)).Specs
	if got := Gate(context.Background(), GateInput{Specs: rep, Index: buildIndex(t), IndexFreshness: content.Fresh, Now: time.Now()}); len(got) != 1 {
		t.Fatalf("70 repeats of one name: %d checks, want 1", len(got))
	}
}
