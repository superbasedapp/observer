package sandboxopenshell

import "testing"

// TestClassifyGatewayDrift walks the drift table, one case per row.
func TestClassifyGatewayDrift(t *testing.T) {
	rec := GatewayDriftFacts{Recorded: true, RecordValid: true}
	with := func(f GatewayDriftFacts, edit func(*GatewayDriftFacts)) GatewayDriftFacts { edit(&f); return f }
	for _, tc := range []struct {
		rule string
		in   GatewayDriftFacts
		want GatewayDrift
	}{
		{"D0", GatewayDriftFacts{Read: GatewayConfigMissing, DatabasePresent: true}, GatewayDriftChanged},
		{"D1", GatewayDriftFacts{Read: GatewayConfigMissing}, GatewayDriftNone},
		{"D2", GatewayDriftFacts{Read: GatewayConfigReadOK, MatchesWanted: true}, GatewayDriftNone},
		{"D3", GatewayDriftFacts{Read: GatewayConfigReadOK}, GatewayDriftUnknown},
		{"D4", GatewayDriftFacts{Recorded: true, Read: GatewayConfigReadOK, MatchesRecord: true}, GatewayDriftUnknown},
		{"D5", with(rec, func(f *GatewayDriftFacts) { f.Read = GatewayConfigUnreadable }), GatewayDriftUnknown},
		{"D6", with(rec, func(f *GatewayDriftFacts) { f.Read = GatewayConfigMissing }), GatewayDriftChanged},
		{"D7", with(rec, func(f *GatewayDriftFacts) { f.MatchesRecord = true }), GatewayDriftMatch},
		{"D7", with(rec, func(f *GatewayDriftFacts) { f.MatchesWanted = true }), GatewayDriftMatch},
		{"D8", rec, GatewayDriftChanged},
	} {
		got, rule := ClassifyGatewayDrift(tc.in)
		if got != tc.want || rule != tc.rule {
			t.Errorf("%+v: got %s (%s), want %s (%s)", tc.in, got, rule, tc.want, tc.rule)
		}
	}
}

// TestGatewayDriftUnderTheRunningNamespace (integration of lanes O4 and
// OC2): the drift's "current render" is the render under the namespace the
// recorded gateway runs under (RunningSandboxLabel), so a gateway in its
// own namespace reads clean, and a config in another namespace than the
// one it runs under reads changed.
func TestGatewayDriftUnderTheRunningNamespace(t *testing.T) {
	const name, host = "observer-0123456789ab", "unix:///run/d.sock"
	render := func(label string) string {
		r, err := RenderGatewayConfig(GatewayConfigInput{Name: name, SandboxLabel: label})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	digestFor := func(label string) string { return GatewayConfigDigest(render(label), host) }
	own, def := render(name), render(DefaultSandboxLabel)
	earlier := GatewayConfigDigest("earlier = 1\n", host)
	for _, tc := range []struct {
		why    string
		rec    *GatewayRecord
		config string
		label  string
		want   GatewayDrift
	}{
		{"no record", nil, own, name, GatewayDriftNone},
		{"own label, start in progress", &GatewayRecord{SandboxLabel: name, ConfigDigest: earlier}, own, name, GatewayDriftMatch},
		{"no label, own-name digest", &GatewayRecord{ConfigDigest: digestFor(name)}, own, name, GatewayDriftMatch},
		{"no label, pre-namespace digest", &GatewayRecord{ConfigDigest: digestFor(DefaultSandboxLabel)}, def, DefaultSandboxLabel, GatewayDriftMatch},
		{"own label, config in the default namespace", &GatewayRecord{SandboxLabel: name, ConfigDigest: digestFor(name)}, def, name, GatewayDriftChanged},
		{"default label, config in its own namespace", &GatewayRecord{SandboxLabel: DefaultSandboxLabel, ConfigDigest: digestFor(DefaultSandboxLabel)}, own, DefaultSandboxLabel, GatewayDriftChanged},
	} {
		label := RunningSandboxLabel(name, tc.rec, digestFor)
		if label != tc.label {
			t.Errorf("%s: running label %q, want %q", tc.why, label, tc.label)
		}
		f := GatewayDriftFacts{Read: GatewayConfigReadOK, MatchesWanted: tc.config == render(label)}
		if tc.rec != nil {
			f.Recorded, f.RecordValid = true, true
			f.MatchesRecord = GatewayConfigDigest(tc.config, host) == tc.rec.ConfigDigest
		}
		if got, _ := ClassifyGatewayDrift(f); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.why, got, tc.want)
		}
	}
}
