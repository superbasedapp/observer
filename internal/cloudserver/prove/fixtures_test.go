package prove_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/prove"
	"github.com/marmutapp/superbased-observer/internal/dataauthority"
)

// TestCatalogIsNonEmptyAndStable pins that the compiled-in catalog exists and
// names are unique — a duplicate name would make --fixture ambiguous.
func TestCatalogIsNonEmptyAndStable(t *testing.T) {
	cat := prove.Catalog()
	if len(cat) < 2 {
		t.Fatalf("catalog has %d fixtures, want at least 2", len(cat))
	}
	seen := map[string]bool{}
	for _, f := range cat {
		if f.Name == "" || f.Purpose == "" {
			t.Fatalf("fixture %+v missing name or purpose", f)
		}
		if seen[f.Name] {
			t.Fatalf("duplicate fixture name %q", f.Name)
		}
		seen[f.Name] = true
		if _, ok := prove.FixtureByName(f.Name); !ok {
			t.Fatalf("FixtureByName(%q) did not find a catalog member", f.Name)
		}
	}
	if _, ok := prove.FixtureByName("no-such-fixture"); ok {
		t.Fatal("FixtureByName invented a fixture that is not in the catalog")
	}
}

// TestEveryFixtureValidates is deliverable 1's core claim: every compiled-in
// fixture passes cloudcontract.Envelope.Validate, so the proving lane can never
// burn a provider call on a malformed envelope.
func TestEveryFixtureValidates(t *testing.T) {
	for _, f := range prove.Catalog() {
		t.Run(f.Name, func(t *testing.T) {
			if err := f.Validate(); err != nil {
				t.Fatalf("fixture does not validate: %v", err)
			}
			env, err := f.Envelope()
			if err != nil {
				t.Fatalf("Envelope: %v", err)
			}
			if err := env.Validate(); err != nil {
				t.Fatalf("envelope does not validate: %v", err)
			}
			if env.SchemaVersion != cloudcontract.EnvelopeSchemaVersion {
				t.Fatalf("schema_version %q, want %q", env.SchemaVersion, cloudcontract.EnvelopeSchemaVersion)
			}
			if env.Authority.Authority != dataauthority.AuthorityPersonal {
				t.Fatalf("fixture authority %q — a proving fixture must be personal-authority "+
					"(an org-authority envelope is INELIGIBLE and would prove nothing)", env.Authority.Authority)
			}
		})
	}
}

// TestFixtureDigestsRoundTrip proves the two-digest protocol holds for every
// fixture: the evidence-content digest is over the preimage with BOTH digest
// fields absent, the upload digest is over the exact serialized bytes, and
// neither covers itself.
func TestFixtureDigestsRoundTrip(t *testing.T) {
	for _, f := range prove.Catalog() {
		t.Run(f.Name, func(t *testing.T) {
			env, err := f.Envelope()
			if err != nil {
				t.Fatalf("Envelope: %v", err)
			}
			digests, err := f.Digests()
			if err != nil {
				t.Fatalf("Digests: %v", err)
			}
			body, err := f.UploadBytes()
			if err != nil {
				t.Fatalf("UploadBytes: %v", err)
			}

			// The evidence-content digest carried on the envelope must equal the
			// digest recomputed from the envelope itself.
			recomputed, err := cloudcontract.EvidenceContentDigest(env)
			if err != nil {
				t.Fatalf("EvidenceContentDigest: %v", err)
			}
			if recomputed != env.EvidenceContentDigest || recomputed != digests.EvidenceContent {
				t.Fatalf("evidence digest drift: carried=%q recomputed=%q reported=%q",
					env.EvidenceContentDigest, recomputed, digests.EvidenceContent)
			}
			if !strings.HasPrefix(digests.EvidenceContent, "sha256:") || !strings.HasPrefix(digests.Upload, "sha256:") {
				t.Fatalf("digests missing the sha256: prefix: %+v", digests)
			}
			if digests.EvidenceContent == digests.Upload {
				t.Fatal("evidence and upload digests are equal — the two preimages must differ " +
					"(the upload bytes carry the evidence digest, the preimage does not)")
			}

			// The upload digest is over the exact bytes, and those bytes carry the
			// evidence digest but never an upload digest.
			if got := cloudcontract.UploadDigest(body); got != digests.Upload {
				t.Fatalf("upload digest %q does not cover the upload bytes (%q)", digests.Upload, got)
			}
			if bytes.Contains(body, []byte(`"upload_digest"`)) {
				t.Fatal("the upload bytes contain an upload_digest field — it would cover itself")
			}
			if !bytes.Contains(body, []byte(digests.EvidenceContent)) {
				t.Fatal("the upload bytes do not carry the evidence-content digest")
			}
			preimage, err := cloudcontract.EvidencePreimage(env)
			if err != nil {
				t.Fatalf("EvidencePreimage: %v", err)
			}
			if bytes.Contains(preimage, []byte(`"evidence_content_digest"`)) {
				t.Fatal("the evidence preimage contains evidence_content_digest — it would cover itself")
			}

			// The serialized bytes must round-trip back into an equal envelope.
			var back cloudcontract.Envelope
			if err := json.Unmarshal(body, &back); err != nil {
				t.Fatalf("upload bytes are not valid JSON: %v", err)
			}
			if err := back.Validate(); err != nil {
				t.Fatalf("round-tripped envelope does not validate: %v", err)
			}
			if again, err := cloudcontract.EvidenceContentDigest(back); err != nil || again != digests.EvidenceContent {
				t.Fatalf("round-trip changed the evidence digest: %q vs %q (err %v)", again, digests.EvidenceContent, err)
			}
		})
	}
}

// TestEveryFixtureIsObviouslySynthetic pins the tripwire: every free-text byte
// a fixture contributes carries the SYNTHETIC FIXTURE marker, so a fixture can
// never be mistaken for a real developer's evidence in a provider log, a prompt
// dump, or a proving-run report.
func TestEveryFixtureIsObviouslySynthetic(t *testing.T) {
	for _, f := range prove.Catalog() {
		t.Run(f.Name, func(t *testing.T) {
			env, err := f.Envelope()
			if err != nil {
				t.Fatalf("Envelope: %v", err)
			}
			for i, c := range env.Context {
				if !strings.Contains(c.Text, prove.SyntheticMarker) {
					t.Fatalf("context[%d] excerpt does not carry %q: %q", i, prove.SyntheticMarker, c.Text)
				}
			}
			if env.UserFeedback != nil && env.UserFeedback.Note != "" &&
				!strings.Contains(env.UserFeedback.Note, prove.SyntheticMarker) {
				t.Fatalf("user feedback note does not carry %q: %q", prove.SyntheticMarker, env.UserFeedback.Note)
			}
			if !strings.HasPrefix(env.CloudSessionID, "fixture-") || !strings.HasPrefix(env.CloudProjectID, "fixture-") {
				t.Fatalf("pseudonyms are not fixture-labelled: %q / %q", env.CloudSessionID, env.CloudProjectID)
			}
			if env.ScrubberVersion != prove.ScrubberVersion {
				t.Fatalf("scrubber_version %q, want the lane's own %q", env.ScrubberVersion, prove.ScrubberVersion)
			}
		})
	}
}

// TestCatalogIsImmutable proves a caller holding a returned fixture cannot
// mutate the compiled-in catalog — the fixtures are server-minted, and a
// caller-reachable mutation would be a client-supplied-evidence hole.
func TestCatalogIsImmutable(t *testing.T) {
	first := prove.Catalog()
	env, err := first[0].Envelope()
	if err != nil {
		t.Fatalf("Envelope: %v", err)
	}
	before, err := first[0].Digests()
	if err != nil {
		t.Fatalf("Digests: %v", err)
	}

	// Mutate everything reachable through the returned value.
	env.CloudSessionID = "attacker-controlled"
	if len(env.Actions) > 0 {
		env.Actions[0].Ref = "tampered"
	}
	if env.UserFeedback != nil {
		env.UserFeedback.Note = "tampered"
	}
	for i := range env.Context {
		env.Context[i].Text = "tampered"
	}

	after, err := prove.Catalog()[0].Digests()
	if err != nil {
		t.Fatalf("Digests (re-read): %v", err)
	}
	if after != before {
		t.Fatalf("mutating a returned envelope changed the catalog: %+v → %+v", before, after)
	}
}

// TestInjectionCanaryCarriesTheBait pins that the adversarial fixture still
// actually contains the bait it exists to test. A "cleanup" that softened this
// text would silently turn the FE2/FE3 proof into a no-op.
func TestInjectionCanaryCarriesTheBait(t *testing.T) {
	f, ok := prove.FixtureByName("injection_canary")
	if !ok {
		t.Fatal("injection_canary fixture missing from the catalog")
	}
	body, err := f.UploadBytes()
	if err != nil {
		t.Fatalf("UploadBytes: %v", err)
	}
	text := string(body)
	for _, want := range []string{
		prove.SyntheticMarker,
		"IGNORE PREVIOUS INSTRUCTIONS",
		"END EVIDENCE", // a forged close marker, which the FE2 fence must neutralize
		"a99",          // an ungrounded ref the FE3 check must reject if the model cites it
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("injection_canary no longer contains %q — the FE2/FE3 proof is now vacuous", want)
		}
	}
	// The bait must not make the envelope invalid — it has to actually reach the
	// provider to prove anything.
	if err := f.Validate(); err != nil {
		t.Fatalf("injection_canary does not validate: %v", err)
	}
}
