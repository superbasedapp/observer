package telemetrylog

import (
	"errors"
	"testing"
)

func validPushRecord() Record {
	org := "acme"
	subj := PushSubject(org)
	payload := []byte("body")
	return Record{
		Org:        org,
		Subject:    subj,
		DedupID:    DedupID(org, subj, payload),
		PayloadVer: PushPayloadVer,
		Payload:    payload,
		Attrs:      map[string]string{AttrUserID: "u1"},
	}
}

func TestValidateRecordAcceptsValid(t *testing.T) {
	if err := ValidateRecord(validPushRecord()); err != nil {
		t.Fatalf("ValidateRecord(valid) = %v, want nil", err)
	}
	// A nil Attrs map is equivalent to empty and must be accepted.
	r := validPushRecord()
	r.Attrs = nil
	if err := ValidateRecord(r); err != nil {
		t.Fatalf("ValidateRecord(nil attrs) = %v, want nil", err)
	}
}

func TestValidateRecordRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(r *Record)
	}{
		{"empty org", func(r *Record) { r.Org = "" }},
		{"empty subject", func(r *Record) { r.Subject = "" }},
		{"empty dedup id", func(r *Record) { r.DedupID = "" }},
		{"nil payload", func(r *Record) { r.Payload = nil }},
		{"empty payload", func(r *Record) { r.Payload = []byte{} }},
		{"subject org mismatch", func(r *Record) { r.Subject = PushSubject("other") }},
		{"malformed subject", func(r *Record) { r.Subject = "not.a.valid.subject.here" }},
		{"empty attr key", func(r *Record) { r.Attrs = map[string]string{"": "x"} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := validPushRecord()
			c.mutate(&r)
			err := ValidateRecord(r)
			if !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("ValidateRecord = %v, want ErrInvalidRecord", err)
			}
		})
	}
}
