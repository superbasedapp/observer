package diag

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// insertEnrolmentRow seeds the singleton org_enrolment row the way a real
// `observer enroll` would, via raw SQL (this package's standalone
// discipline — no internal/store import).
func insertEnrolmentRow(t *testing.T, database *sql.DB, orgURL string) {
	t.Helper()
	_, err := database.Exec(`
		INSERT INTO org_enrolment (id, org_id, org_name, org_server_url, user_id, user_email, enrolled_at, bearer_key_id)
		VALUES (1, 'org-1', 'Acme', ?, 'u-1', 'dev@acme.example', '2026-08-01T00:00:00Z', 'sbo-org-bearer-v1')`, orgURL)
	if err != nil {
		t.Fatalf("insert org_enrolment: %v", err)
	}
}

// TestOrgEnrolmentWarnsWhenEnrolledButDisabled is tracker #41: an enrolment
// row with [org_client] enabled = false means the node looks enrolled (to
// its operator AND to the org that minted the token) while pushing nothing
// and polling no policy — silently ungoverned. "Disabled" may only read as
// innocuous OK on a machine that never enrolled.
func TestOrgEnrolmentWarnsWhenEnrolledButDisabled(t *testing.T) {
	cfg, database, _, _ := newTestEnv(t)
	cfg.OrgClient.Enabled = false
	insertEnrolmentRow(t, database, "https://org.acme.example")

	c := checkOrgEnrolment(context.Background(), database, cfg)
	if c.Status != StatusWarn {
		t.Fatalf("status=%s want WARN — %q", c.Status, c.Message)
	}
	if !strings.Contains(c.Message, "enrolled but [org_client] enabled = false") {
		t.Errorf("message=%q", c.Message)
	}
}

// TestOrgEnrolmentDisabledNeverEnrolledStaysOK pins the innocuous half so
// the #41 warn cannot creep onto genuinely solo machines.
func TestOrgEnrolmentDisabledNeverEnrolledStaysOK(t *testing.T) {
	cfg, database, _, _ := newTestEnv(t)
	cfg.OrgClient.Enabled = false

	c := checkOrgEnrolment(context.Background(), database, cfg)
	if c.Status != StatusOK {
		t.Fatalf("status=%s want OK — %q", c.Status, c.Message)
	}
}

// TestOrgEnrolmentServerURLUnsetStaysOK is #41's second half, REVISED
// after a code review found the original version's premise false: it
// claimed the guard policy-bundle poll reads [org_client].org_server_url
// from config and "has no target until it's set". It does not — like
// every other org loop, FetchPolicyBundle dials enr.OrgServerURL off the
// PERSISTED row (LoadEnrolment → genClient), never this config field. The
// field is used in exactly one place when blank: cmd/observer/start.go
// passes it into newPolicyBundleRunner as R-205 audit metadata, so a
// bundle-REJECTED finding's Target string loses its server-URL prefix
// (cosmetic only — the finding, the rule, and every loop's real behavior
// are unaffected). That does not warrant WARN — the check must stay OK
// while still surfacing the config-gap detail line for the operator who
// wants the prefix restored.
func TestOrgEnrolmentServerURLUnsetStaysOK(t *testing.T) {
	cfg, database, _, _ := newTestEnv(t)
	cfg.OrgClient.Enabled = true
	cfg.OrgClient.OrgServerURL = ""
	insertEnrolmentRow(t, database, "https://org.acme.example")

	c := checkOrgEnrolment(context.Background(), database, cfg)
	if c.Status != StatusOK {
		t.Fatalf("status=%s want OK (a blank org_server_url on an already-enrolled node is cosmetic, not a degradation) — %q %v", c.Status, c.Message, c.Details)
	}
	found := false
	for _, d := range c.Details {
		if strings.Contains(d, "org_server_url is unset") && strings.Contains(d, "https://org.acme.example") {
			found = true
		}
		if strings.Contains(d, "no target until it's set") {
			t.Errorf("details still carry the false claim that the guard policy-bundle poll has no target: %v", c.Details)
		}
	}
	if !found {
		t.Errorf("details missing the org_server_url config-gap line: %v", c.Details)
	}
}

// TestOrgEnrolmentServerURLUnsetMessageStaysActive is the BLOCK-1 review
// fix: a real persisted org_enrolment row with a blank config
// org_server_url is a genuinely ACTIVE node — cmd/observer/start.go's
// orgClientShouldStart starts the whole org client for this exact shape
// (a config URL is not the only way to satisfy the gate; a persisted row
// does too), because the push/announcement/routing-policy loops dial the
// ROW's own server, never this config field. The top-level Message must
// say so — ACTIVE, naming the persisted server — and must NOT say
// INACTIVE or "not enrolled", which would be false for this node.
func TestOrgEnrolmentServerURLUnsetMessageStaysActive(t *testing.T) {
	cfg, database, _, _ := newTestEnv(t)
	cfg.OrgClient.Enabled = true
	cfg.OrgClient.OrgServerURL = ""
	insertEnrolmentRow(t, database, "https://org.acme.example")

	c := checkOrgEnrolment(context.Background(), database, cfg)
	if !strings.Contains(c.Message, "ACTIVE") {
		t.Errorf("Message = %q, want it to call out ACTIVE", c.Message)
	}
	if !strings.Contains(c.Message, "https://org.acme.example") {
		t.Errorf("Message = %q, want it to name the persisted server it's dialing", c.Message)
	}
	if strings.Contains(c.Message, "INACTIVE") {
		t.Errorf("Message = %q, must not say INACTIVE — a persisted row means the org client actually starts", c.Message)
	}
	if strings.Contains(strings.ToLower(c.Message), "not enrolled") {
		t.Errorf("Message = %q, must not say 'not enrolled' — this node IS enrolled and running", c.Message)
	}
}

// TestOrgEnrolmentFullyWiredMessageStaysPlainEnrolled is the control case:
// a real org_server_url must NOT trip the config-gap wording — behavior
// for a real URL is unchanged.
func TestOrgEnrolmentFullyWiredMessageStaysPlainEnrolled(t *testing.T) {
	cfg, database, _, _ := newTestEnv(t)
	cfg.OrgClient.Enabled = true
	cfg.OrgClient.OrgServerURL = "https://org.acme.example"
	insertEnrolmentRow(t, database, "https://org.acme.example")

	c := checkOrgEnrolment(context.Background(), database, cfg)
	if !strings.HasPrefix(c.Message, "enrolled — ") {
		t.Errorf("Message = %q, want it to start with %q", c.Message, "enrolled — ")
	}
	if strings.Contains(c.Message, "INACTIVE") || strings.Contains(c.Message, "ACTIVE, dialing") {
		t.Errorf("Message = %q, should not mention the blank-URL wording when org_server_url is set", c.Message)
	}
}
