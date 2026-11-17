package store_test

import (
	"context"
	"errors"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/db/migrations"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// orgs_test.go holds the org registry's pure tests (no Postgres): the slug
// rule table, the personal slug shape, input refusals that happen before any
// statement, and the equality of the Go vocabularies with the SQL CHECKs of
// cloud migrations 0047 and 0049 (read from the embedded lineage). The RLS
// and grant proofs are in orgs_rls_test.go.

func TestValidateOrgSlug(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		slug string
		kind store.OrgKind
		want error
	}{
		{"team ok", "acme-labs", store.OrgTeam, nil},
		{"digits ok", "a1b2c3", store.OrgTeam, nil},
		{"min length", "abc", store.OrgTeam, nil},
		{"max length", strings.Repeat("a", 40), store.OrgTeam, nil},
		{"too short", "ab", store.OrgTeam, store.ErrOrgSlugInvalid},
		{"too long", strings.Repeat("a", 41), store.OrgTeam, store.ErrOrgSlugInvalid},
		{"uppercase", "Acme", store.OrgTeam, store.ErrOrgSlugInvalid},
		{"dot", "acme.labs", store.OrgTeam, store.ErrOrgSlugInvalid},
		{"underscore", "acme_labs", store.OrgTeam, store.ErrOrgSlugInvalid},
		{"non-ascii", "acmé", store.OrgTeam, store.ErrOrgSlugInvalid},
		{"leading hyphen", "-acme", store.OrgTeam, store.ErrOrgSlugInvalid},
		{"trailing hyphen", "acme-", store.OrgTeam, store.ErrOrgSlugInvalid},
		{"double hyphen", "xn--acme", store.OrgTeam, store.ErrOrgSlugInvalid},
		{"team with personal prefix", "u-abcdefgh", store.OrgTeam, store.ErrOrgSlugInvalid},
		{"personal ok", "u-abcd2345", store.OrgPersonal, nil},
		{"personal without prefix", "abcd2345", store.OrgPersonal, store.ErrOrgSlugInvalid},
		{"personal too short", "u-abcd234", store.OrgPersonal, store.ErrOrgSlugInvalid},
		{"personal non-base32 digit", "u-abcd2341", store.OrgPersonal, store.ErrOrgSlugInvalid},
		{"reserved www", "www", store.OrgTeam, store.ErrOrgSlugReserved},
		{"reserved demo", "demo", store.OrgTeam, store.ErrOrgSlugReserved},
		{"reserved staff", "staff", store.OrgTeam, store.ErrOrgSlugReserved},
		{"reserved superbased", "superbased", store.OrgTeam, store.ErrOrgSlugReserved},
		{"reserved prefix is not reserved", "www-acme", store.OrgTeam, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := store.ValidateOrgSlug(tc.slug, tc.kind)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("ValidateOrgSlug(%q, %s) = %v, want nil", tc.slug, tc.kind, err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("ValidateOrgSlug(%q, %s) = %v, want %v", tc.slug, tc.kind, err, tc.want)
			}
		})
	}
}

func TestNewPersonalOrgSlugIsValid(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		s, err := store.NewPersonalOrgSlug()
		if err != nil {
			t.Fatalf("NewPersonalOrgSlug: %v", err)
		}
		if err := store.ValidateOrgSlug(s, store.OrgPersonal); err != nil {
			t.Fatalf("minted slug %q is not a valid personal slug: %v", s, err)
		}
		seen[s] = true
	}
	if len(seen) < 60 {
		t.Fatalf("64 mints gave only %d distinct slugs", len(seen))
	}
}

// TestProvisionOrgRefusesBadInputBeforeAnyStatement runs against a Store with
// no pool: every case must be refused by validation, before a transaction is
// opened (a nil pool would panic otherwise).
func TestProvisionOrgRefusesBadInputBeforeAnyStatement(t *testing.T) {
	t.Parallel()
	s := store.New(nil)
	cases := []struct {
		name string
		in   store.ProvisionOrgInput
		want error
	}{
		{"unknown kind", store.ProvisionOrgInput{Kind: "club", Slug: "acme", DisplayName: "Acme", Tenancy: store.TenancyManaged}, store.ErrOrgInputInvalid},
		{"team without tenancy", store.ProvisionOrgInput{Kind: store.OrgTeam, Slug: "acme", DisplayName: "Acme"}, store.ErrOrgInputInvalid},
		{"personal managed", store.ProvisionOrgInput{Kind: store.OrgPersonal, DisplayName: "Me", Tenancy: store.TenancyManaged}, store.ErrOrgInputInvalid},
		{"blank display name", store.ProvisionOrgInput{Kind: store.OrgTeam, Slug: "acme", DisplayName: "   ", Tenancy: store.TenancyManaged}, store.ErrOrgInputInvalid},
		{"long display name", store.ProvisionOrgInput{Kind: store.OrgTeam, Slug: "acme", DisplayName: strings.Repeat("é", store.OrgDisplayNameMaxRunes+1), Tenancy: store.TenancyManaged}, store.ErrOrgInputInvalid},
		{"bad slug", store.ProvisionOrgInput{Kind: store.OrgTeam, Slug: "Acme", DisplayName: "Acme", Tenancy: store.TenancyManaged}, store.ErrOrgSlugInvalid},
		{"reserved slug", store.ProvisionOrgInput{Kind: store.OrgTeam, Slug: "admin", DisplayName: "Acme", Tenancy: store.TenancyManaged}, store.ErrOrgSlugReserved},
		{"personal custom slug", store.ProvisionOrgInput{Kind: store.OrgPersonal, Slug: "my-own", DisplayName: "Me"}, store.ErrOrgSlugInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := s.ProvisionOrg(context.Background(), "00000000-0000-0000-0000-000000000001", tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("ProvisionOrg(%+v) = %v, want %v", tc.in, err, tc.want)
			}
		})
	}
}

// sqlCheckValues returns the quoted values of the first `CHECK (<col> IN (...))`
// in the named embedded cloud migration.
func sqlCheckValues(t *testing.T, file, col string) []string {
	t.Helper()
	b, err := fs.ReadFile(migrations.Files, file)
	if err != nil {
		t.Fatalf("read embedded %s: %v", file, err)
	}
	sql := string(b)
	marker := "CHECK (" + col + " IN ("
	i := strings.Index(sql, marker)
	if i < 0 {
		t.Fatalf("%s has no %q", file, marker)
	}
	rest := sql[i+len(marker):]
	j := strings.Index(rest, ")")
	if j < 0 {
		t.Fatalf("%s: unterminated %q", file, marker)
	}
	var out []string
	for _, v := range strings.Split(rest[:j], ",") {
		out = append(out, strings.Trim(strings.TrimSpace(v), "'"))
	}
	return out
}

func toStrings[T ~string](in []T) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}

// TestOrgVocabulariesMatchSchema pins each closed vocabulary of the org
// registry to its SQL CHECK. orgs.status is the platform tenant lifecycle
// (internal/platformcontract KnownTenantStates), copied once into SQL
// (design 4.1); the others are this package's own.
func TestOrgVocabulariesMatchSchema(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, file, col string
		want            []string
	}{
		{"orgs.status", "0047_org_registry.sql", "status", toStrings(platformcontract.KnownTenantStates)},
		{"orgs.kind", "0047_org_registry.sql", "kind", toStrings([]store.OrgKind{store.OrgPersonal, store.OrgTeam})},
		{"orgs.tenancy", "0047_org_registry.sql", "tenancy", toStrings([]store.OrgTenancy{store.TenancyIndividual, store.TenancyManaged})},
		{"org_members.console_role", "0047_org_registry.sql", "console_role", toStrings(store.KnownConsoleRoles())},
		{"org_outbox.verb", "0049_org_outbox_and_deletion_requests.sql", "verb", toStrings(store.KnownOrgOutboxVerbs())},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := sqlCheckValues(t, tc.file, tc.col)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("%s CHECK = %v, Go vocabulary = %v (same values, same order)", tc.name, got, tc.want)
			}
		})
	}
}
