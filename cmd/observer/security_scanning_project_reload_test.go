//go:build !sbo_omit_security

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
)

// projectPublisher writes what the org client caches for a v3 delivery: the
// composed bundle, the signed mapping, one project's envelope with its
// security.scanning member, and the daemon's match record for a root. Every
// file is replaced by rename, as the org client does.
type projectPublisher struct {
	t      *testing.T
	priv   ed25519.PrivateKey
	path   string
	layout projectmatch.Layout
	digest string
	epoch  int64
}

func newProjectPublisher(t *testing.T, bundlePath string) *projectPublisher {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &projectPublisher{t: t, priv: priv, path: bundlePath, layout: projectmatch.LayoutFor(bundlePath), epoch: 3}
}

func (p *projectPublisher) pin() string {
	return orgcontract.PublicKeyPinHash(p.priv.Public().(ed25519.PublicKey))
}

func (p *projectPublisher) write(path string, v any) {
	p.t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		p.t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		p.t.Fatal(err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		p.t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		p.t.Fatal(err)
	}
}

// publish writes composed bundle version v with project X carrying one
// security.scanning member of sequence v, and matches root to X.
func (p *projectPublisher) publish(version int64, body, root string) {
	p.t.Helper()
	pub := base64.RawURLEncoding.EncodeToString(p.priv.Public().(ed25519.PublicKey))
	m := orgcontract.ProjectMapping{
		OrgID: "org", Subject: "u-dana", Epoch: p.epoch, MaxAgeSeconds: orgcontract.DefaultProjectMappingMaxAge,
		Projects: []orgcontract.ProjectMappingEntry{{OrgProjectID: "X", Repos: []orgcontract.ProjectRepoHashes{{RemoteHash: "rh-X"}}}},
	}
	m = orgcontract.SignProjectMapping(p.priv, m)
	p.digest = orgcontract.ProjectMappingDigest(m)
	composed := orgcontract.PolicyBundle{
		Version: version, BundleTOML: "[[override]]\nrule = \"R-153\"\ndecision = \"deny\"\nenforce = true\n", PublicKey: pub,
		ProjectBinding: &orgcontract.ProjectBinding{OrgID: "org", Subject: "u-dana", Epoch: p.epoch, MappingDigest: p.digest},
	}
	composed.Signature = orgcontract.SignPolicyBundleEnvelope(p.priv, composed)
	member := sectionMember(p.t, version, body, "X")
	env := orgcontract.PolicyBundle{
		Version: version, BundleTOML: "", PublicKey: pub, Families: []orgcontract.ProjectFamilyMember{member},
		ProjectBinding: &orgcontract.ProjectBinding{
			OrgID: "org", Subject: "u-dana", OrgProjectID: "X", Epoch: p.epoch,
			FamiliesDigest: orgcontract.ProjectFamiliesDigest([]orgcontract.ProjectFamilyMember{member}),
		},
	}
	env.Signature = orgcontract.SignPolicyBundleEnvelope(p.priv, env)
	p.write(p.layout.MappingPath(), projectmatch.MappingFile{Mapping: m, BundleVersion: version, AcceptedAt: time.Now()})
	p.write(p.layout.EnvelopePath("X"), env)
	p.write(p.layout.MatchPath(projectmatch.RootHash(root)), projectmatch.MatchFile{
		ProjectRootHash: projectmatch.RootHash(root), OrgProjectIDs: []string{"X"}, Epoch: p.epoch, MappingDigest: p.digest,
		MatchedAt: time.Now(), ValidUntil: time.Now().Add(time.Hour),
	})
	p.write(p.path, composed)
}

// TestSecurityProjectGuardFollowsPublishes is SEC-P3 merge finding 1: on a
// daemon whose guard is off, the guard the project floors are read through
// follows each publish (version 1, then version 2 with its re-bound
// envelope) instead of failing open on the stale composed bundle; it is built
// with the enrolment key pin; and its family status is reported, so Fleet
// shows what the node applies.
func TestSecurityProjectGuardFollowsPublishes(t *testing.T) {
	dir := t.TempDir()
	setTestHome(t, dir)
	bundlePath := filepath.Join(dir, ".observer", "org-policy-bundle.json")
	dbPath := filepath.Join(dir, "observer.db")
	root := filepath.Join(dir, "repo")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		securityProjectGuards.mu.Lock()
		delete(securityProjectGuards.m, dbPath)
		securityProjectGuards.mu.Unlock()
	})
	if lookupProcessGuard(dbPath) != nil {
		t.Fatal("a process guard exists; the test needs the guard off")
	}
	pub := newProjectPublisher(t, bundlePath)
	sc := config.DefaultSecurityConfig() // online checks on
	gcfg := config.GuardConfig{Enabled: false, Rules: config.GuardRulesConfig{OrgBundle: bundlePath}}
	bind := func(pin string) {
		withSecurityScanningNode(t, false, sc, "security.deps")
		secScanning.mu.Lock()
		secScanning.load = func(_ context.Context) (securityScanningBase, error) {
			return securityScanningBase{Security: sc, FamilyAccepted: true, FamilyInEffect: true, DBPath: dbPath, Guard: gcfg, OrgKeyPin: pin}, nil
		}
		secScanning.baseOK = false
		secScanning.mu.Unlock()
	}
	bind(pub.pin())
	forbid := `{"allow":{"online_checks":"forbidden"}}`

	check := func(version int64) {
		t.Helper()
		if got := securityFloorsAppliedAt(sc, root); got.Deps.Online {
			t.Fatalf("v%d: the project's forbid of online checks does not apply", version)
		}
		view := secScanning.projectView(root)
		if len(view.Sections) != 1 || view.Sections[0].Version != version || view.Sections[0].State != securitySectionApplied {
			t.Fatalf("v%d: sections = %+v", version, view.Sections)
		}
		status, truncated := projectFamilyStatusFrom(nil, time.Now)()
		if truncated || len(status) != 1 || status[0].OrgProjectID != "X" || status[0].Version != version || status[0].Status != orgcontract.ProjectFamilyApplied {
			t.Fatalf("v%d: reported family status = %+v (truncated %v)", version, status, truncated)
		}
	}
	pub.publish(1, forbid, root)
	check(1)
	pub.publish(2, forbid, root)
	check(2)

	// The key pin is passed: a guard built under another pin refuses the
	// bundle, so no section applies and online checks stay on.
	bind(strings.Repeat("0", 64))
	if got := securityFloorsAppliedAt(sc, root); !got.Deps.Online {
		t.Fatal("a bundle signed under another key than the enrolment pin applied")
	}
}

// TestSecurityProjectUnknownListsEachSection is the SEC-P3 merge ruling on
// the lane's deviation: a directory whose project match is unknown reports
// each section the node holds as unknown (never "none"), while an unmatched
// directory reports none.
func TestSecurityProjectUnknownListsEachSection(t *testing.T) {
	forbid := `{"allow":{"online_checks":"forbidden"}}`
	withProjectSections(t, false, true, config.DefaultSecurityConfig(), map[string]guard.ProjectFamilyLoad{
		"/unknown":   {InForce: true, State: projectmatch.StateUnknown},
		"/unmatched": {InForce: true, State: projectmatch.StateUnmatched},
	})
	saved := securityProjectHeldSections
	securityProjectHeldSections = func() []guard.ProjectFamilySection {
		return []guard.ProjectFamilySection{
			{OrgProjectID: "Y", Status: orgcontract.ProjectSectionUnknown, Member: sectionMember(t, 4, forbid, "Y")},
			{OrgProjectID: "X", Status: orgcontract.ProjectSectionUnknown, Member: sectionMember(t, 3, forbid, "X")},
		}
	}
	t.Cleanup(func() { securityProjectHeldSections = saved })

	view := secScanning.projectView("/unknown")
	if len(view.Sections) != 2 || view.Sections[0].OrgProjectID != "X" || view.Sections[1].OrgProjectID != "Y" {
		t.Fatalf("unknown directory sections = %+v", view.Sections)
	}
	for _, s := range view.Sections {
		if s.State != securitySectionUnknown {
			t.Fatalf("section %s reads %s, want unknown", s.OrgProjectID, s.State)
		}
	}
	out := strings.Join(securityProjectStatusLines("/unknown"), "\n")
	for _, want := range []string{"project X section v3: unknown (project_unknown)", "project Y section v4: unknown (project_unknown)"} {
		if !strings.Contains(out, want) {
			t.Fatalf("unknown status lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "none") {
		t.Fatalf("an unknown directory reads none:\n%s", out)
	}
	if got := securityFloorsAppliedAt(config.DefaultSecurityConfig(), "/unknown"); !got.Deps.Online {
		t.Fatal("an unknown directory applied a project section")
	}
	if l := securityProjectStatusLines("/unmatched"); len(l) != 1 || !strings.Contains(l[0], "none") {
		t.Fatalf("unmatched = %v", l)
	}
}

// TestSecurityProjectPartialSection is SEC-P3 merge finding 2 on the node: a
// section that conflicts on one axis is refused on that axis only, its other
// raises apply, status names the axis and the project, and the wire reports
// it as partial with the axis (a NACK).
func TestSecurityProjectPartialSection(t *testing.T) {
	body := `{"allow":{"online_checks":"forbidden"},"require":{"finding_retention_days":730}}`
	withProjectSections(t, true, true, config.DefaultSecurityConfig(), map[string]guard.ProjectFamilyLoad{
		"/repo": matched(guard.ProjectFamilySet{OrgProjectID: "X", Members: []orgcontract.ProjectFamilyMember{sectionMember(t, 3, body, "X")}}),
	})
	installFloor(t, `{"require":{"online_checks":"required"}}`, 1, true)

	got := securityFloorsAppliedAt(config.DefaultSecurityConfig(), "/repo")
	if got.Retention.Days != 730 || !got.Deps.Online {
		t.Fatalf("retention=%d online=%v, want the retention raise applied and online kept", got.Retention.Days, got.Deps.Online)
	}
	view := secScanning.projectView("/repo")
	if len(view.Sections) != 1 || view.Sections[0].State != securitySectionPartial || strings.Join(view.Sections[0].RefusedAxes, ",") != "allow.online_checks" {
		t.Fatalf("sections = %+v", view.Sections)
	}
	out := strings.Join(securityProjectStatusLines("/repo"), "\n")
	if !strings.Contains(out, "project X section v3: partial") || !strings.Contains(out, "allow.online_checks: refused in project X (NACK)") {
		t.Fatalf("status lacks the partial section:\n%s", out)
	}
	list, _ := secScanning.familyStatus([]guard.ProjectFamilySection{{OrgProjectID: "X", Status: orgcontract.ProjectSectionApplied, Member: sectionMember(t, 3, body, "X")}})
	if len(list) != 1 || list[0].Status != orgcontract.ProjectFamilyPartial || strings.Join(list[0].RefusedAxes, ",") != "allow.online_checks" || !orgcontract.ValidProjectFamilyStatus(list) || orgcontract.ProjectFamilyAcked(list[0].Status) {
		t.Fatalf("wire status = %+v", list)
	}
}
