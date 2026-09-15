package cloudcontract

import (
	"bytes"
	"strings"
	"testing"
)

// TestEvidencePreimageOmitsDigestFields pins the non-self-reference property
// of the evidence-content digest: its preimage contains neither digest field.
func TestEvidencePreimageOmitsDigestFields(t *testing.T) {
	e := validEnvelope()
	e.EvidenceContentDigest = "sha256:should-not-appear"
	e.UploadDigest = "sha256:should-never-appear"
	pre, err := EvidencePreimage(e)
	if err != nil {
		t.Fatalf("EvidencePreimage: %v", err)
	}
	if bytes.Contains(pre, []byte("evidence_content_digest")) {
		t.Errorf("preimage contains evidence_content_digest field (self-referential)")
	}
	if bytes.Contains(pre, []byte("upload_digest")) {
		t.Errorf("preimage contains upload_digest field")
	}
	if bytes.Contains(pre, []byte("should-not-appear")) || bytes.Contains(pre, []byte("should-never-appear")) {
		t.Errorf("preimage leaked a preset digest value")
	}
}

// TestUploadBytesOmitUploadDigest pins that the final upload bytes carry the
// evidence digest but never the upload digest — the upload digest cannot
// cover itself.
func TestUploadBytesOmitUploadDigest(t *testing.T) {
	e := validEnvelope()
	d, err := EvidenceContentDigest(e)
	if err != nil {
		t.Fatalf("EvidenceContentDigest: %v", err)
	}
	e.EvidenceContentDigest = d
	e.UploadDigest = "sha256:must-not-serialize"
	final, err := UploadBytes(e)
	if err != nil {
		t.Fatalf("UploadBytes: %v", err)
	}
	if !bytes.Contains(final, []byte("evidence_content_digest")) {
		t.Errorf("final bytes missing evidence_content_digest")
	}
	if bytes.Contains(final, []byte("upload_digest")) || bytes.Contains(final, []byte("must-not-serialize")) {
		t.Errorf("final bytes contain the upload digest (self-referential)")
	}
	ud := UploadDigest(final)
	if !strings.HasPrefix(ud, "sha256:") {
		t.Errorf("upload digest %q missing sha256: prefix", ud)
	}
	if bytes.Contains(final, []byte(ud)) {
		t.Errorf("upload digest value appears inside the bytes it covers")
	}
}

// TestEvidenceDigestStability pins determinism and sensitivity: structurally
// equal envelopes hash equal; any field change changes the hash.
func TestEvidenceDigestStability(t *testing.T) {
	a := validEnvelope()
	b := validEnvelope()
	da, err := EvidenceContentDigest(a)
	if err != nil {
		t.Fatalf("digest a: %v", err)
	}
	db, err := EvidenceContentDigest(b)
	if err != nil {
		t.Fatalf("digest b: %v", err)
	}
	if da != db {
		t.Fatalf("equal envelopes produced different digests: %s vs %s", da, db)
	}

	// A preset evidence-content digest must NOT change the evidence digest
	// (it is omitted from its own preimage).
	c := validEnvelope()
	c.EvidenceContentDigest = "sha256:whatever"
	dc, err := EvidenceContentDigest(c)
	if err != nil {
		t.Fatalf("digest c: %v", err)
	}
	if dc != da {
		t.Errorf("presetting evidence_content_digest changed the evidence digest")
	}

	mutations := []func(*Envelope){
		func(e *Envelope) { e.Tool = "claude-code" },
		func(e *Envelope) { e.Metrics.TokensIn++ },
		func(e *Envelope) { e.Actions[0].Status = "error" },
		func(e *Envelope) { e.DurationSeconds++ },
		func(e *Envelope) { e.DisclosurePurposes = []Purpose{PurposeContextEnrichment} },
	}
	for i, m := range mutations {
		e := validEnvelope()
		m(&e)
		d, err := EvidenceContentDigest(e)
		if err != nil {
			t.Fatalf("mutation %d digest: %v", i, err)
		}
		if d == da {
			t.Errorf("mutation %d did not change the evidence digest", i)
		}
	}
}

// TestUploadDigestFollowsBytes pins that the upload digest tracks the final
// bytes: same bytes → same digest, changed evidence digest field → changed
// bytes → changed upload digest.
func TestUploadDigestFollowsBytes(t *testing.T) {
	e := validEnvelope()
	ecd, _ := EvidenceContentDigest(e)
	e.EvidenceContentDigest = ecd
	f1, err := UploadBytes(e)
	if err != nil {
		t.Fatalf("UploadBytes: %v", err)
	}
	f2, err := UploadBytes(e)
	if err != nil {
		t.Fatalf("UploadBytes: %v", err)
	}
	if !bytes.Equal(f1, f2) {
		t.Fatalf("UploadBytes not deterministic")
	}
	if UploadDigest(f1) != UploadDigest(f2) {
		t.Fatalf("upload digest not deterministic")
	}
	e.EvidenceContentDigest = "sha256:0000"
	f3, _ := UploadBytes(e)
	if UploadDigest(f3) == UploadDigest(f1) {
		t.Errorf("changing the embedded evidence digest did not change the upload digest")
	}
}
