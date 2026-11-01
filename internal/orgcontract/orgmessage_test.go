package orgcontract

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func sampleOrgMessageBody() OrgMessageBody {
	return OrgMessageBody{
		Version:   7,
		After:     0,
		NextAfter: 12,
		Threads: []OrgMessageThreadRow{{
			ID: "t1", Subject: "Opus for lint fixes", Kind: OrgMessageKindCoaching,
			StartedBy: OrgMessageAuthorAdmin, Status: "open", UpdatedAt: "2026-10-15T14:31:00Z",
		}},
		Messages: []OrgMessageRow{{
			ID: 12, ThreadID: "t1", AuthorKind: OrgMessageAuthorAdmin, AuthorName: "Asha Kim",
			Body: "Hi", RequireAck: true, CreatedAt: "2026-10-15T14:31:00Z",
			Attachments: []OrgMessageAttachment{{Type: "session", Ref: "0f3c9a2e", Label: "payments-api"}},
		}},
		Policy:   OrgMessageNodePolicy{DevThreadsAllowed: true, Topics: []string{"budget"}, RetentionDays: 365, ReadReceiptsDefault: true},
		IssuedAt: "2026-10-15T14:32:00Z",
	}
}

func TestOrgMessageSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := SignOrgMessages(priv, "org1", "user1", sampleOrgMessageBody())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		org     string
		subject string
		mutate  func(*OrgMessageDoc)
		wantErr bool
	}{
		{name: "genuine", org: "org1", subject: "user1"},
		{name: "other subject", org: "org1", subject: "user2", wantErr: true},
		{name: "other org", org: "org2", subject: "user1", wantErr: true},
		{name: "body edited", org: "org1", subject: "user1", mutate: func(d *OrgMessageDoc) { d.Messages[0].Body = "changed" }, wantErr: true},
		{name: "version replayed", org: "org1", subject: "user1", mutate: func(d *OrgMessageDoc) { d.Version = 99 }, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := doc
			d.OrgMessageBody = sampleOrgMessageBody()
			if tc.mutate != nil {
				tc.mutate(&d)
			}
			err := VerifyOrgMessages(pub, tc.org, tc.subject, d)
			if tc.wantErr && !errors.Is(err, ErrOrgMessageSignature) {
				t.Fatalf("want signature error, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("want ok, got %v", err)
			}
		})
	}
}

func TestOrgMessageDigestIgnoresIssuedAt(t *testing.T) {
	a := sampleOrgMessageBody()
	b := sampleOrgMessageBody()
	b.IssuedAt = "2026-10-15T15:00:00Z"
	da, err := OrgMessageDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	db, _ := OrgMessageDigest(b)
	if da != db {
		t.Fatalf("digest changed with IssuedAt only")
	}
	b.Messages[0].Body = "x"
	dc, _ := OrgMessageDigest(b)
	if dc == da {
		t.Fatalf("digest did not change with content")
	}
	if a.IssuedAt == "" {
		t.Fatalf("digest mutated its input")
	}
}

func TestOrgMessageSignRejectsBadKey(t *testing.T) {
	if _, err := SignOrgMessages(ed25519.PrivateKey{1}, "o", "s", OrgMessageBody{}); err == nil {
		t.Fatal("want error")
	}
	if err := VerifyOrgMessages(ed25519.PublicKey{1}, "o", "s", OrgMessageDoc{}); err == nil {
		t.Fatal("want error")
	}
}
