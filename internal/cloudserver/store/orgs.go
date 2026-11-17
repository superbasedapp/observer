package store

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// orgs.go is the store seam of the control plane's org registry (managed-SaaS
// M6.1a, cloud migrations 0047-0050; design
// docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 4.1). It
// owns the provisioning transaction and the reads the console needs. Every
// statement runs under WithAccount, so the membership-class policies (0048)
// decide what the caller sees and writes; nothing here reads the tenant GUC.

// ConsoleRole is a member's control-plane console role (design A2). It governs
// control-plane acts only (rename, billing, delete org, create team); tenant
// RBAC stays in the tenant.
type ConsoleRole string

// Console roles, highest first. The SQL CHECK on org_members.console_role and
// the rank in sbci_is_org_member hold the same three values.
const (
	ConsoleOwner  ConsoleRole = "owner"
	ConsoleAdmin  ConsoleRole = "admin"
	ConsoleMember ConsoleRole = "member"
)

// KnownConsoleRoles returns every ConsoleRole, highest first.
func KnownConsoleRoles() []ConsoleRole {
	return []ConsoleRole{ConsoleOwner, ConsoleAdmin, ConsoleMember}
}

// OrgKind says whether an org is a user's personal org or a team org.
type OrgKind string

// Org kinds.
const (
	OrgPersonal OrgKind = "personal"
	OrgTeam     OrgKind = "team"
)

// OrgTenancy is the tenancy an org's tenant runs under. A personal org is
// always individual (orgs_personal_is_individual).
type OrgTenancy string

// Org tenancies.
const (
	TenancyIndividual OrgTenancy = "individual"
	TenancyManaged    OrgTenancy = "managed"
)

// OrgOutboxVerb is a host-API intent queued in org_outbox. The SQL CHECK on
// org_outbox.verb holds the same values (pinned by a store test).
type OrgOutboxVerb string

// Outbox verbs: the mutating host-API verbs of internal/platformcontract.
const (
	OutboxCreateTenant      OrgOutboxVerb = "create_tenant"
	OutboxSetState          OrgOutboxVerb = "set_state"
	OutboxSetEntitlements   OrgOutboxVerb = "set_entitlements"
	OutboxMembersDeactivate OrgOutboxVerb = "members_deactivate"
	OutboxEvict             OrgOutboxVerb = "evict"
)

// KnownOrgOutboxVerbs returns every OrgOutboxVerb.
func KnownOrgOutboxVerbs() []OrgOutboxVerb {
	return []OrgOutboxVerb{OutboxCreateTenant, OutboxSetState, OutboxSetEntitlements, OutboxMembersDeactivate, OutboxEvict}
}

// OrgDisplayNameMaxRunes bounds an org's display name (the SQL CHECK allows
// 200 characters; the console offers fewer).
const OrgDisplayNameMaxRunes = 100

// PersonalSlugPrefix starts every personal org slug ("u-" + 8 base32
// characters); a team slug may not start with it.
const PersonalSlugPrefix = "u-"

// personalSlugChars is the length of a personal slug after its prefix: 40
// random bits in lowercase base32.
const personalSlugChars = 8

// Org registry errors.
var (
	// ErrOrgSlugInvalid: the slug breaks the shape rules.
	ErrOrgSlugInvalid = errors.New("cloudserver/store: org slug is invalid")
	// ErrOrgSlugReserved: the slug is a reserved name.
	ErrOrgSlugReserved = errors.New("cloudserver/store: org slug is reserved")
	// ErrOrgSlugTaken: another org holds the slug, as its current slug or as
	// a rename alias.
	ErrOrgSlugTaken = errors.New("cloudserver/store: org slug is taken")
	// ErrPersonalOrgExists: the account already has its personal org.
	ErrPersonalOrgExists = errors.New("cloudserver/store: personal org already exists")
	// ErrOrgInputInvalid: the kind, tenancy or display name is invalid.
	ErrOrgInputInvalid = errors.New("cloudserver/store: org input is invalid")
)

// Org is one orgs row.
type Org struct {
	OrgID               string
	Kind                OrgKind
	Slug                string
	DisplayName         string
	Status              platformcontract.TenantState
	LifecycleGen        int64
	HostID              string // empty until the host-API client assigns one (M6.4)
	Tenancy             OrgTenancy
	PlatformRailEnabled bool
	CreatedBy           string
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// MyOrg is an org seen through the caller's own membership.
type MyOrg struct {
	Org
	ConsoleRole    ConsoleRole
	IsBillingOwner bool
}

// OrgMember is one org_members row.
type OrgMember struct {
	AccountID      string
	ConsoleRole    ConsoleRole
	IsBillingOwner bool
	CreatedAt      time.Time
}

// ProvisionOrgInput is what the console's create routes (M6.5) and the
// device route that ensures a personal org (M8.4) pass to ProvisionOrg.
type ProvisionOrgInput struct {
	Kind OrgKind
	// Slug may be empty for a personal org: one is minted (u-<8 base32>).
	Slug        string
	DisplayName string
	// Tenancy may be empty for a personal org (it is always individual).
	Tenancy OrgTenancy
	// TenantDomain is the parent domain of tenant dashboards
	// (SBCI_TENANT_DOMAIN); the org's platform OIDC client is registered under
	// it. Empty registers none (orgoidcclient.go).
	TenantDomain string
	// TeamAllowlist, when true, refuses a TEAM create unless the caller is
	// on the team create allow-list (cloud 0130, teamallowlist.go): the
	// platform switch SBCI_TEAM_CREATE_ALLOWLIST, on until GO-3 on the
	// production kit. A personal org ignores it.
	TeamAllowlist bool
}

// reservedOrgSlugs are names no org may take: platform hosts, auth and
// support paths, and words that would read as Superbased's own (design 4.1:
// the reserved list lives in Go, not SQL).
var reservedOrgSlugs = map[string]bool{
	"admin": true, "api": true, "app": true, "assets": true, "auth": true,
	"billing": true, "blog": true, "cdn": true, "cloud": true, "console": true,
	"demo": true, "dev": true, "docs": true, "help": true, "id": true,
	"login": true, "mail": true, "mcp": true, "oauth": true, "oauth2": true,
	"observer": true, "oidc": true, "org": true, "platform": true, "portal": true,
	"prod": true, "root": true, "security": true, "signin": true, "signup": true,
	"sso": true, "staff": true, "staging": true, "static": true, "status": true,
	"superbased": true, "support": true, "system": true, "test": true, "www": true,
}

// slugRule is one row of the slug rule table: refused when bad is true.
type slugRule struct {
	id  string
	bad func(slug string, kind OrgKind) bool
	err error
}

// slugRules is walked top-down; the first row that refuses decides.
var slugRules = []slugRule{
	{id: "length", err: ErrOrgSlugInvalid, bad: func(s string, _ OrgKind) bool { return len(s) < 3 || len(s) > 40 }},
	{id: "charset", err: ErrOrgSlugInvalid, bad: func(s string, _ OrgKind) bool {
		for i := 0; i < len(s); i++ {
			c := s[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return true
			}
		}
		return false
	}},
	{id: "hyphen-edges", err: ErrOrgSlugInvalid, bad: func(s string, _ OrgKind) bool {
		return strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") || strings.Contains(s, "--")
	}},
	{id: "personal-shape", err: ErrOrgSlugInvalid, bad: func(s string, k OrgKind) bool {
		if k != OrgPersonal {
			return strings.HasPrefix(s, PersonalSlugPrefix)
		}
		rest, ok := strings.CutPrefix(s, PersonalSlugPrefix)
		if !ok || len(rest) != personalSlugChars {
			return true
		}
		for i := 0; i < len(rest); i++ {
			if c := rest[i]; (c < 'a' || c > 'z') && (c < '2' || c > '7') {
				return true
			}
		}
		return false
	}},
	{id: "reserved", err: ErrOrgSlugReserved, bad: func(s string, _ OrgKind) bool { return reservedOrgSlugs[s] }},
}

// ValidateOrgSlug reports whether slug may name an org of kind: 3 to 40
// characters from a-z, 0-9 and '-', no leading, trailing or doubled hyphen
// (it is a DNS label), the personal shape "u-" plus 8 lowercase base32
// characters exactly when kind is personal (a team slug may not start with
// "u-"), and not a reserved name. It returns ErrOrgSlugInvalid or ErrOrgSlugReserved.
func ValidateOrgSlug(slug string, kind OrgKind) error {
	for _, r := range slugRules {
		if r.bad(slug, kind) {
			return fmt.Errorf("cloudserver/store.ValidateOrgSlug: %s: %w", r.id, r.err)
		}
	}
	return nil
}

// NewPersonalOrgSlug mints a personal org slug: "u-" and 8 lowercase base32
// characters (40 random bits).
func NewPersonalOrgSlug() (string, error) {
	var b [5]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("cloudserver/store.NewPersonalOrgSlug: %w", err)
	}
	return PersonalSlugPrefix + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:])), nil
}

// normalizeProvisionInput validates in and fills the personal defaults.
func normalizeProvisionInput(in ProvisionOrgInput) (ProvisionOrgInput, error) {
	switch in.Kind {
	case OrgPersonal:
		if in.Tenancy == "" {
			in.Tenancy = TenancyIndividual
		}
		if in.Tenancy != TenancyIndividual {
			return in, fmt.Errorf("a personal org is individual, not %q: %w", in.Tenancy, ErrOrgInputInvalid)
		}
		if in.Slug == "" {
			s, err := NewPersonalOrgSlug()
			if err != nil {
				return in, err
			}
			in.Slug = s
		}
	case OrgTeam:
		if in.Tenancy != TenancyIndividual && in.Tenancy != TenancyManaged {
			return in, fmt.Errorf("unknown tenancy %q: %w", in.Tenancy, ErrOrgInputInvalid)
		}
	default:
		return in, fmt.Errorf("unknown org kind %q: %w", in.Kind, ErrOrgInputInvalid)
	}
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if in.DisplayName == "" || !utf8.ValidString(in.DisplayName) || utf8.RuneCountInString(in.DisplayName) > OrgDisplayNameMaxRunes {
		return in, fmt.Errorf("display name must be 1 to %d characters of valid UTF-8: %w", OrgDisplayNameMaxRunes, ErrOrgInputInvalid)
	}
	if err := ValidateOrgSlug(in.Slug, in.Kind); err != nil {
		return in, err
	}
	return in, nil
}

// createTenantPayload is the create_tenant outbox payload. It carries no
// secrets; the sender (M6.4) adds the owner identity and the signed
// entitlement document when it builds platformcontract.CreateTenantRequest.
type createTenantPayload struct {
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
}

// orgUniqueErrors maps the unique constraints provisioning can hit to the
// caller-facing error.
var orgUniqueErrors = map[string]error{
	"orgs_slug_lower":               ErrOrgSlugTaken,
	"org_slugs_pkey":                ErrOrgSlugTaken,
	"orgs_one_personal_per_account": ErrPersonalOrgExists,
}

// mapOrgWriteErr turns a known unique violation into its error.
func mapOrgWriteErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		if mapped, ok := orgUniqueErrors[pgErr.ConstraintName]; ok {
			return mapped
		}
	}
	return err
}

// ProvisionOrg creates an org for accountID in ONE transaction (design 4.1
// step 1): the orgs row (status provisioning), the caller's owner and
// billing-owner membership, the current slug in org_slugs, and the
// create_tenant intent in org_outbox keyed by the org id. Either all four
// commit or none does. The worker (M6.4) sends the intent and moves the org
// to active.
//
// It returns ErrOrgSlugInvalid, ErrOrgSlugReserved or ErrOrgInputInvalid for
// bad input, ErrOrgSlugTaken when the slug (or a live alias of it) belongs to
// another org, ErrPersonalOrgExists for a second personal org, and a
// *TeamOrgLimitError (errors.Is ErrTeamOrgLimit) for a team org past the
// account's cap (W15-D12, teamorglimit.go), and ErrTeamCreateNotAllowed for a
// team org when in.TeamAllowlist is set and the caller is not allow-listed
// (W17, teamallowlist.go).
func (s *Store) ProvisionOrg(ctx context.Context, accountID string, in ProvisionOrgInput) (MyOrg, error) {
	in, err := normalizeProvisionInput(in)
	if err != nil {
		return MyOrg{}, fmt.Errorf("cloudserver/store.ProvisionOrg: %w", err)
	}
	var out MyOrg
	err = s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		// W15-D12: at most the account's cap of team orgs (teamorglimit.go),
		// checked under the account's advisory lock so concurrent creates
		// cannot both pass. A personal org is not counted.
		if in.Kind == OrgTeam {
			// W17: the allow-list first, so a refused account is told it is
			// invitation-only rather than that it hit a cap it never had.
			if in.TeamAllowlist {
				if err := enforceTeamCreateAllowlistTx(ctx, tx); err != nil {
					return err
				}
			}
			if err := enforceTeamOrgCapTx(ctx, tx, accountID); err != nil {
				return err
			}
		}
		// The id is minted first so no statement needs RETURNING on orgs
		// before the caller's membership (and so the SELECT policy) exists.
		var orgID string
		if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&orgID); err != nil {
			return fmt.Errorf("mint org id: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO orgs (org_id, kind, slug, display_name, tenancy, created_by)
			 VALUES ($1::uuid, $2, $3, $4, $5, $6::uuid)`,
			orgID, string(in.Kind), in.Slug, in.DisplayName, string(in.Tenancy), accountID); err != nil {
			return fmt.Errorf("insert org: %w", mapOrgWriteErr(err))
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO org_members (org_id, account_id, console_role, is_billing_owner)
			 VALUES ($1::uuid, $2::uuid, 'owner', true)`, orgID, accountID); err != nil {
			return fmt.Errorf("insert owner membership: %w", mapOrgWriteErr(err))
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO org_slugs (slug, org_id) VALUES ($1, $2::uuid)`, in.Slug, orgID); err != nil {
			return fmt.Errorf("insert slug: %w", mapOrgWriteErr(err))
		}
		// The org's platform OIDC client, in the same transaction, so the
		// owner's first authorize on the tenant host finds it (CPSIGN-9/10).
		if err := RegisterProvisionedOIDCClientTx(ctx, tx, orgID, in.Slug, in.TenantDomain); err != nil {
			return fmt.Errorf("register oidc client: %w", err)
		}
		payload, err := json.Marshal(createTenantPayload{TenantID: orgID, Name: in.DisplayName})
		if err != nil {
			return fmt.Errorf("encode outbox payload: %w", err)
		}
		// The one outbox writer (orgoutbox.go). The key is the org id, just
		// minted, so the row is always new; a false here would mean the
		// provisioning intent was not written, which must not commit.
		inserted, err := EnqueueOrgIntentTx(ctx, tx, OrgIntent{
			OrgID: orgID, Verb: OutboxCreateTenant, IdempotencyKey: orgID, Payload: payload,
		})
		if err != nil {
			return fmt.Errorf("insert create_tenant intent: %w", mapOrgWriteErr(err))
		}
		if !inserted {
			return errors.New("insert create_tenant intent: a row with the new org's key already exists")
		}
		got, err := getMyOrgTx(ctx, tx, orgID)
		if err != nil {
			return fmt.Errorf("read back org: %w", err)
		}
		out = got
		return nil
	})
	if err != nil {
		return MyOrg{}, fmt.Errorf("cloudserver/store.ProvisionOrg: %w", err)
	}
	return out, nil
}

// myOrgColumns selects an orgs row (alias o) plus the caller's membership
// (alias m), in scanMyOrg's order.
const myOrgColumns = `o.org_id::text, o.kind, o.slug, o.display_name, o.status, o.lifecycle_gen,
	coalesce(o.host_id, ''), o.tenancy, o.platform_rail_enabled, o.created_by::text,
	o.created_at, o.updated_at, m.console_role, m.is_billing_owner`

func scanMyOrg(row pgx.Row) (MyOrg, error) {
	var o MyOrg
	var kind, status, tenancy, role string
	if err := row.Scan(&o.OrgID, &kind, &o.Slug, &o.DisplayName, &status, &o.LifecycleGen,
		&o.HostID, &tenancy, &o.PlatformRailEnabled, &o.CreatedBy,
		&o.CreatedAt, &o.UpdatedAt, &role, &o.IsBillingOwner); err != nil {
		return MyOrg{}, err
	}
	o.Kind, o.Status, o.Tenancy, o.ConsoleRole = OrgKind(kind), platformcontract.TenantState(status), OrgTenancy(tenancy), ConsoleRole(role)
	return o, nil
}

// getMyOrgTx reads one org through the caller's membership; ErrNotFound when
// the caller is not a member (the row is invisible under RLS).
func getMyOrgTx(ctx context.Context, tx pgx.Tx, orgID string) (MyOrg, error) {
	o, err := scanMyOrg(tx.QueryRow(ctx,
		`SELECT `+myOrgColumns+`
		   FROM orgs o
		   JOIN org_members m ON m.org_id = o.org_id AND m.account_id = sbci_current_account()
		  WHERE o.org_id = $1::uuid`, orgID))
	if errors.Is(err, pgx.ErrNoRows) || isInvalidUUIDErr(err) {
		return MyOrg{}, ErrNotFound
	}
	return o, err
}

// ListMyOrgs returns every org accountID is a member of, with its console
// role, oldest first. Orgs in any lifecycle state are listed; the console
// decides what to show.
func (s *Store) ListMyOrgs(ctx context.Context, accountID string) ([]MyOrg, error) {
	var out []MyOrg
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+myOrgColumns+`
			   FROM orgs o
			   JOIN org_members m ON m.org_id = o.org_id AND m.account_id = sbci_current_account()
			  ORDER BY o.created_at, o.org_id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			o, err := scanMyOrg(rows)
			if err != nil {
				return err
			}
			out = append(out, o)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ListMyOrgs: %w", err)
	}
	return out, nil
}

// GetOrg returns org orgID as accountID sees it, with accountID's console
// role. It returns ErrNotFound when accountID is not a member: a non-member
// cannot tell an org it does not belong to from one that does not exist.
func (s *Store) GetOrg(ctx context.Context, accountID, orgID string) (MyOrg, error) {
	var out MyOrg
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		o, err := getMyOrgTx(ctx, tx, orgID)
		out = o
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return MyOrg{}, ErrNotFound
	}
	if err != nil {
		return MyOrg{}, fmt.Errorf("cloudserver/store.GetOrg: %w", err)
	}
	return out, nil
}

// ListOrgMembers returns the members of org orgID, owners first, for a caller
// who is a member of it. It returns ErrNotFound when accountID is not a member.
func (s *Store) ListOrgMembers(ctx context.Context, accountID, orgID string) ([]OrgMember, error) {
	var out []OrgMember
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := getMyOrgTx(ctx, tx, orgID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx,
			`SELECT account_id::text, console_role, is_billing_owner, created_at
			   FROM org_members
			  WHERE org_id = $1::uuid
			  ORDER BY CASE console_role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END,
			           created_at, account_id`, orgID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m OrgMember
			var role string
			if err := rows.Scan(&m.AccountID, &role, &m.IsBillingOwner, &m.CreatedAt); err != nil {
				return err
			}
			m.ConsoleRole = ConsoleRole(role)
			out = append(out, m)
		}
		return rows.Err()
	})
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ListOrgMembers: %w", err)
	}
	return out, nil
}
