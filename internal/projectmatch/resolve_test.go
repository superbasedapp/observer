package projectmatch

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// resolveFixture is a composed v3 bundle (epoch 3, version 9), a request and
// a valid signed answer for it matching project Z with Z's envelope.
func resolveFixture(t *testing.T, priv ed25519.PrivateKey, now time.Time) (orgcontract.PolicyBundle, orgcontract.ProjectResolveRequest, orgcontract.ProjectResolveAnswer) {
	t.Helper()
	composed := delivery(t, priv, 3)
	composed.Projects = nil
	req := orgcontract.ProjectResolveRequest{RemoteHashes: []string{Hash("github.com/acme/zeta")}, Nonce: "n-0123456789abcdef"}
	env := orgcontract.PolicyBundle{
		Version: 9, BundleTOML: "[[override]]\nrule = \"R-110\"\n", PublicKey: composed.PublicKey,
		ProjectBinding: &orgcontract.ProjectBinding{OrgID: "org", Subject: "u-dana", OrgProjectID: "Z", Epoch: 3},
	}
	env.Signature = orgcontract.SignPolicyBundleEnvelope(priv, env)
	a := orgcontract.SignProjectResolveAnswer(priv, orgcontract.ProjectResolveAnswer{
		OrgID: "org", Subject: "u-dana", Epoch: 3, BundleVersion: 9,
		RequestDigest: orgcontract.ProjectResolveRequestDigest(req), Nonce: req.Nonce,
		OrgProjectIDs: []string{"Z"}, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		Envelopes: []orgcontract.PolicyBundle{env},
	})
	return composed, req, a
}

// TestAcceptResolve is milestone 1's refusal table: a forged or foreign-key
// answer, another org or member, another epoch or bundle version, a replay
// for another request or nonce, an expired or future answer and an envelope
// of another delivery are refused; the good answer passes.
func TestAcceptResolve(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	composed, req, good := resolveFixture(t, priv, now)
	if err := AcceptResolve(good, req, composed, pub, now); err != nil {
		t.Fatalf("a good answer: %v", err)
	}
	resign := func(a orgcontract.ProjectResolveAnswer) orgcontract.ProjectResolveAnswer {
		return orgcontract.SignProjectResolveAnswer(priv, a)
	}
	rows := []struct {
		name string
		ans  func() orgcontract.ProjectResolveAnswer
		req  func() orgcontract.ProjectResolveRequest
		at   time.Time
		want error
	}{
		{name: "forged: an id added after signing", ans: func() orgcontract.ProjectResolveAnswer {
			a := good
			a.OrgProjectIDs = []string{"Z", "ADMIN"}
			return a
		}, want: ErrResolveSignature},
		{name: "signed by another key", ans: func() orgcontract.ProjectResolveAnswer {
			return orgcontract.SignProjectResolveAnswer(other, good)
		}, want: ErrResolveSignature},
		{name: "a mapping signature is not a resolve signature (domain)", ans: func() orgcontract.ProjectResolveAnswer {
			a := good
			m := orgcontract.SignProjectMapping(priv, orgcontract.ProjectMapping{OrgID: "org", Subject: "u-dana", Epoch: 3})
			a.Signature = m.Signature
			return a
		}, want: ErrResolveSignature},
		{name: "another org", ans: func() orgcontract.ProjectResolveAnswer { a := good; a.OrgID = "evil"; return resign(a) }, want: ErrResolveOwner},
		{name: "another member", ans: func() orgcontract.ProjectResolveAnswer { a := good; a.Subject = "u-sam"; return resign(a) }, want: ErrResolveOwner},
		{name: "a lower epoch", ans: func() orgcontract.ProjectResolveAnswer { a := good; a.Epoch = 2; return resign(a) }, want: ErrResolveDelivery},
		{name: "a higher epoch", ans: func() orgcontract.ProjectResolveAnswer { a := good; a.Epoch = 4; return resign(a) }, want: ErrResolveDelivery},
		{name: "another bundle version", ans: func() orgcontract.ProjectResolveAnswer { a := good; a.BundleVersion = 8; return resign(a) }, want: ErrResolveDelivery},
		{name: "replayed for another request", req: func() orgcontract.ProjectResolveRequest {
			r := req
			r.RemoteHashes = []string{Hash("github.com/acme/other")}
			return r
		}, want: ErrResolveReplay},
		{name: "replayed for another call (nonce)", req: func() orgcontract.ProjectResolveRequest {
			r := req
			r.Nonce = "n-fedcba9876543210"
			return r
		}, want: ErrResolveReplay},
		{name: "expired", at: now.Add(2 * time.Hour), want: ErrResolveExpired},
		{name: "issued in the future", at: now.Add(-time.Hour), want: ErrResolveExpired},
		{name: "an envelope for a project the answer does not list", ans: func() orgcontract.ProjectResolveAnswer {
			a := good
			env := a.Envelopes[0]
			env.ProjectBinding = &orgcontract.ProjectBinding{OrgID: "org", Subject: "u-dana", OrgProjectID: "Q", Epoch: 3}
			env.Signature = orgcontract.SignPolicyBundleEnvelope(priv, env)
			a.Envelopes = []orgcontract.PolicyBundle{env}
			return resign(a)
		}, want: ErrEnvelope},
		{name: "an envelope of another epoch", ans: func() orgcontract.ProjectResolveAnswer {
			a := good
			env := a.Envelopes[0]
			env.ProjectBinding = &orgcontract.ProjectBinding{OrgID: "org", Subject: "u-dana", OrgProjectID: "Z", Epoch: 2}
			env.Signature = orgcontract.SignPolicyBundleEnvelope(priv, env)
			a.Envelopes = []orgcontract.PolicyBundle{env}
			return resign(a)
		}, want: ErrEnvelope},
	}
	for _, row := range rows {
		a, r, at := good, req, now
		if row.ans != nil {
			a = row.ans()
		}
		if row.req != nil {
			r = row.req()
		}
		if !row.at.IsZero() {
			at = row.at
		}
		if err := AcceptResolve(a, r, composed, pub, at); !errors.Is(err, row.want) {
			t.Errorf("%s: err = %v, want %v", row.name, err, row.want)
		}
	}
	// No project audience in force: refused.
	if err := AcceptResolve(good, req, orgcontract.PolicyBundle{Version: 9}, pub, now); !errors.Is(err, ErrResolveDelivery) {
		t.Errorf("no v3 bundle: %v", err)
	}
}

// TestDecideResolveAndTruncation covers the new Decide rows: a current
// resolve record answers (matched, or unknown), a resolve record of another
// bundle version is stale, and above the cap an unmatched directory with no
// record is unknown, never unmatched.
func TestDecideResolveAndTruncation(t *testing.T) {
	now := time.Now()
	pb := &orgcontract.ProjectBinding{OrgID: "org", Subject: "u", Epoch: 3}
	m := orgcontract.ProjectMapping{
		OrgID: "org", Subject: "u", Epoch: 3, MaxAgeSeconds: orgcontract.DefaultProjectMappingMaxAge, Truncated: true,
		Projects: []orgcontract.ProjectMappingEntry{{OrgProjectID: "X", Repos: []orgcontract.ProjectRepoHashes{{RemoteHash: "rx"}}}},
	}
	pb.MappingDigest = orgcontract.ProjectMappingDigest(m)
	mf := &MappingFile{Mapping: m, BundleVersion: 9, AcceptedAt: now}
	sig := func() (Signals, error) { return Signals{IsGit: true, RemoteHash: "nope"}, nil }
	rec := func(mut func(*MatchFile)) *MatchFile {
		r := &MatchFile{Epoch: 3, MappingDigest: pb.MappingDigest, Source: SourceResolve, BundleVersion: 9, OrgProjectIDs: []string{"Z"}, ValidUntil: now.Add(time.Hour)}
		if mut != nil {
			mut(r)
		}
		return r
	}
	rows := []struct {
		name   string
		record *MatchFile
		want   string
		ids    int
	}{
		{name: "current resolve record", record: rec(nil), want: StateMatched, ids: 1},
		{name: "current unknown record", record: rec(func(r *MatchFile) { r.OrgProjectIDs, r.Unknown, r.Reason = nil, true, ReasonResolveFailed }), want: StateUnknown},
		{name: "resolve record of another version", record: rec(func(r *MatchFile) { r.BundleVersion = 8 }), want: StateUnknown},
		{name: "expired resolve record", record: rec(func(r *MatchFile) { r.ValidUntil = now.Add(-time.Minute) }), want: StateUnknown},
		{name: "no record above the cap", record: nil, want: StateUnknown},
	}
	for _, row := range rows {
		d := Decide(DecideInput{Composed: pb, ComposedVersion: 9, Mapping: mf, Record: row.record, Signals: sig, Now: now})
		if d.State != row.want || len(d.IDs) != row.ids {
			t.Errorf("%s: %+v, want %s with %d ids", row.name, d, row.want, row.ids)
		}
	}
	// The same unmatched directory under a mapping that is NOT truncated is
	// unmatched: the mapping lists every project that reaches the member.
	full := m
	full.Truncated = false
	pb2 := *pb
	pb2.MappingDigest = orgcontract.ProjectMappingDigest(full)
	if d := Decide(DecideInput{Composed: &pb2, ComposedVersion: 9, Mapping: &MappingFile{Mapping: full, BundleVersion: 9, AcceptedAt: now}, Signals: sig, Now: now}); d.State != StateUnmatched {
		t.Fatalf("complete mapping: %+v, want unmatched", d)
	}
}
