package api_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// No-merge-by-email (plan §3 W1 "Lifecycle phase 1" / D18: "no merge policy —
// and merging by email must never happen").
//
// Email is a MUTABLE, provider-controlled, re-assignable attribute. Two WorkOS
// users can present the same address at different times; a directory can hand a
// departed employee's address to their replacement. Keying account identity on
// it — even as a "helpful" merge heuristic — would let one person inherit
// another's sessions, results, and devices. The account key is
// (provider, subject) and nothing else; email reaches this system only as a
// display-only field on identity.Identity and is never persisted.
//
// This file pins that from both directions: the BEHAVIOUR (same email, different
// subjects ⇒ two accounts, on both the device and the portal surface) and the
// SOURCE (no SQL in the store package can join or filter identity_links by
// email, so a future merge cannot be written accidentally).

// --- behaviour -------------------------------------------------------------

// TestSameEmailDifferentSubjectsAreDistinctAccounts drives the real exchange and
// portal-login paths with dev-auth credentials that carry the SAME email and
// different subjects. The dev-auth verifier parses "dev:<subject>:<email>", so
// both halves genuinely present an email — and it must change nothing.
func TestSameEmailDifferentSubjectsAreDistinctAccounts(t *testing.T) {
	h := newHarness(t)
	const sharedEmail = "shared@example.com"

	// Device surface.
	alice := h.loginBroker(t, "dev:subject-alice:"+sharedEmail)
	bob := h.loginBroker(t, "dev:subject-bob:"+sharedEmail)
	if alice.accountID == "" || bob.accountID == "" {
		t.Fatalf("empty account ids: %q / %q", alice.accountID, bob.accountID)
	}
	if alice.accountID == bob.accountID {
		t.Fatalf("two subjects sharing an email were MERGED into account %s — email must never key an account", alice.accountID)
	}

	// The same subject, with or without the email attached, is still ONE account:
	// the key is the subject, and email neither merges nor splits.
	aliceAgain := h.loginBroker(t, "dev:subject-alice")
	if aliceAgain.accountID != alice.accountID {
		t.Fatalf("the same subject resolved to two accounts (%s vs %s) — the key must be (provider, subject) alone",
			alice.accountID, aliceAgain.accountID)
	}

	// Portal surface: the same rule, through PortalLogin's identity bootstrap.
	// portalLogin composes "dev:"+arg, so appending ":<email>" here produces the
	// same three-part dev-auth credential the device half used.
	pAlice := h.portalLogin(t, "portal-alice:"+sharedEmail)
	pBob := h.portalLogin(t, "portal-bob:"+sharedEmail)
	if pAlice.accountID == pBob.accountID {
		t.Fatalf("portal sign-in merged two subjects sharing an email into account %s", pAlice.accountID)
	}

	// And the two planes agree: a subject that signed in on a device and then in
	// the browser is ONE account (the intended sharing), which is what makes the
	// email-merge absence a deliberate policy rather than an accident of two
	// unrelated code paths.
	pSameAsDevice := h.portalLogin(t, "subject-alice:"+sharedEmail)
	if pSameAsDevice.accountID != alice.accountID {
		t.Fatalf("device and portal disagreed for one subject: %s vs %s", alice.accountID, pSameAsDevice.accountID)
	}

	// Neither account can see the other's devices — the merge would have been
	// observable exactly here.
	resp := alice.do(alice.signedReq("GET", "/v1/devices", nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list devices status=%d", resp.StatusCode)
	}
	var list struct {
		Devices []struct {
			Thumbprint string `json:"thumbprint"`
		} `json:"devices"`
	}
	decode(t, resp, &list)
	for _, d := range list.Devices {
		if d.Thumbprint == bob.thumbprint {
			t.Fatal("alice's account listed bob's device — the accounts were merged")
		}
	}
}

// --- source tripwire -------------------------------------------------------

// storePkgDir is the store package, addressed relative to this test's own
// directory. The scan lives HERE, beside the behavioural test it backs, so the
// policy reads as one thing.
const storePkgDir = "../store"

// emailIdentifierExemptFile is the ONE store file allowed to name an email, and
// the narrowing is deliberate (migration 0033 / the tripwire's own instruction
// to narrow rather than delete it).
//
// `accountprofile.go` owns `account_profiles`: a DISPLAY-ONLY row keyed by
// account_id, written after a sign-in has already resolved an account from
// (provider, subject), and read only to render the portal's own top bar. It
// resolves nothing and looks nothing up — the merge-by-email hazard this
// tripwire exists for is a LOOKUP hazard, and there is no lookup here.
//
// The exemption is narrow in three ways, all enforced below:
//
//   - it names one file, not a pattern;
//   - the identity_links+email literal check still applies to it, and to every
//     other file, unexempted (so even this file cannot write a merge query);
//   - the exempt file is separately checked to contain no lookup-shaped SQL:
//     it may only ever touch `account_profiles`, every WHERE/HAVING/JOIN-ON/
//     ON-CONFLICT predicate in it must be keyed by account_id and may not
//     name email or display_name, and no statement may SELECT account_id back
//     out of the display row. Naming the table was NOT enough — `SELECT
//     account_id FROM account_profiles WHERE email = $1` passed the earlier,
//     relation-only form of this check, which is precisely the query the
//     tripwire exists to prohibit (see profileSQLViolations).
const emailIdentifierExemptFile = "accountprofile.go"

// TestStoreSQLNeverJoinsIdentityLinksByEmail is the cheap tripwire behind the
// behavioural test: it reads every non-test source file in the store package —
// the ONE SQL owner — and fails if any string literal mentions identity_links
// and email together. A merge-by-email would have to be written as such a
// statement, so this catches it at the moment it is typed rather than at the
// moment a user inherits someone else's account.
func TestStoreSQLNeverJoinsIdentityLinksByEmail(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(storePkgDir, "*.go"))
	if err != nil {
		t.Fatalf("glob %s: %v", storePkgDir, err)
	}
	if len(files) == 0 {
		t.Fatalf("no source files found under %s — the scan would pass vacuously", storePkgDir)
	}

	scanned := 0
	literals := 0
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		scanned++
		ast.Inspect(af, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				s = lit.Value // a raw literal that failed to unquote: scan it as-is
			}
			literals++
			lower := strings.ToLower(s)
			if strings.Contains(lower, "identity_links") && strings.Contains(lower, "email") {
				t.Errorf("%s:%d: a statement names BOTH identity_links and email:\n%s\n\n"+
					"Accounts are keyed by (provider, subject) ONLY. Email is mutable and "+
					"re-assignable; joining or filtering identity_links by it would let one "+
					"person inherit another's account (plan §3 W1 / D18).",
					filepath.Base(f), fset.Position(lit.Pos()).Line, s)
			}
			return true
		})
	}
	if scanned == 0 || literals == 0 {
		t.Fatalf("scan covered %d files / %d string literals — it must actually read the store package", scanned, literals)
	}

	// Second, broader tripwire: the store package — the only place an account
	// could be resolved — must not mention email AT ALL, save the one
	// display-only file named by emailIdentifierExemptFile (read its comment
	// before adding a second). If another legitimate email use ever lands here,
	// narrow this check deliberately in the same change; do not delete it.
	exemptSeen := false
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		if filepath.Base(f) == emailIdentifierExemptFile {
			exemptSeen = true
			continue
		}
		src, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, decl := range src.Decls {
			ast.Inspect(decl, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if ok && strings.EqualFold(id.Name, "email") {
					t.Errorf("%s:%d: the store package declares/uses an identifier %q — "+
						"account identity must never touch email. If this use is legitimate, "+
						"narrow this tripwire deliberately in the same change.",
						filepath.Base(f), fset.Position(id.Pos()).Line, id.Name)
				}
				return true
			})
		}
	}
	// The exemption must not go stale: if the file is renamed or deleted, the
	// carve-out has to be revisited rather than silently protecting nothing.
	if !exemptSeen {
		t.Errorf("emailIdentifierExemptFile %q is not in the store package any more — "+
			"re-examine the carve-out instead of leaving a dead exemption", emailIdentifierExemptFile)
	}
	assertProfileFileTouchesOnlyItsOwnTable(t, filepath.Join(storePkgDir, emailIdentifierExemptFile))
}

// assertProfileFileTouchesOnlyItsOwnTable is the price of the exemption: the
// one file allowed to say "email" must be a pure per-account read/write of
// `account_profiles`, never a lookup. It runs the real file through
// profileSQLViolations — the same checker the fixtures in
// TestProfileExemptionCheckerRejectsEmailLookups exercise — so the guard and
// its proof cannot drift apart.
func assertProfileFileTouchesOnlyItsOwnTable(t *testing.T, path string) {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	violations, sawOwnTable := profileSQLViolations(t, filepath.Base(path), src)
	for _, v := range violations {
		t.Error(v)
	}
	if !sawOwnTable {
		t.Errorf("%s names no account_profiles statement — the exemption is checking nothing",
			filepath.Base(path))
	}
}

// forbiddenProfileRelations lists every table an identity lookup could reach.
// account_profiles is the only relation the exempt file may name.
var forbiddenProfileRelations = []string{
	"identity_links", "accounts", "api_tokens", "device_registrations",
	"browser_sessions", "auth_transactions", "sbci_find_identity_link",
}

// sqlishLiteral recognizes a string literal that is (or contains) a SQL
// statement, so prose and error-message literals are not run through the
// clause checker.
var sqlishLiteral = regexp.MustCompile(`(?is)\b(select|insert\s+into|update|delete\s+from)\b`)

// sqlClauseKeyword splits a statement into clauses. The keyword a segment
// follows is what decides whether the segment is a PREDICATE (a lookup: where /
// having / join-on / on-conflict target) or not (a select list, a SET
// assignment list, a VALUES tuple).
var sqlClauseKeyword = regexp.MustCompile(`(?is)\b(where|having|on\s+conflict|on|do\s+update|set|values|select|from|into|returning|group\s+by|order\s+by|limit|offset|union|insert|update|delete|join)\b`)

// predicateClauses are the clause keywords that introduce a LOOKUP — the
// regions where naming a column means "resolve a row BY this". Everything else
// (a select list, a SET assignment list, a VALUES tuple) is not a lookup and is
// deliberately out of scope.
var predicateClauses = []string{"where", "having", "on", "on conflict"}

// profileSQLViolations is the whole contract of the email exemption, expressed
// as one checker over Go source so the real file and the negative fixtures are
// judged identically.
//
// The hazard the exemption must not re-open is a LOOKUP: resolving an account
// from a mutable, provider-controlled, re-assignable attribute. Three rules:
//
//  1. No relation but account_profiles may be named (the original check).
//  2. Every lookup PREDICATE — WHERE, HAVING, JOIN ... ON, ON CONFLICT — must
//     be keyed by account_id and must not reference email or display_name.
//     `SELECT account_id FROM account_profiles WHERE email = $1` is exactly the
//     query the tripwire promises to prohibit, and the relation-name check
//     alone waved it through.
//  3. No statement may SELECT account_id out of the profile table. The callers
//     of this file are handed an account id by an already-resolved session;
//     reading one BACK from a display row is account resolution however the
//     predicate is spelled (including with no predicate at all, filtered in Go).
//
// A SET assignment list is deliberately NOT a predicate: `SET display_name =
// EXCLUDED.display_name` writes the column, it does not look a row up by it.
// That distinction is the reason this is a clause-aware check and not a
// substring scan.
//
// It returns one message per violation plus whether the source named
// account_profiles at all (a checker that matched nothing is a vacuous guard).
func profileSQLViolations(t *testing.T, name string, src []byte) (violations []string, sawOwnTable bool) {
	t.Helper()
	fset := token.NewFileSet()
	af, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	ast.Inspect(af, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			s = lit.Value
		}
		line := fset.Position(lit.Pos()).Line
		lower := strings.ToLower(s)
		if strings.Contains(lower, "account_profiles") {
			sawOwnTable = true
		}
		for _, bad := range forbiddenProfileRelations {
			if strings.Contains(lower, bad) {
				violations = append(violations, fmt.Sprintf(
					"%s:%d: the email-exempt store file names %q:\n%s\n\n"+
						"It may only read and write account_profiles by account_id. Resolving an "+
						"account is the exempt file's one forbidden power.", name, line, bad, s,
				))
			}
		}
		if !sqlishLiteral.MatchString(lower) {
			return true
		}
		violations = append(violations, checkProfileStatement(name, line, s)...)
		return true
	})
	return violations, sawOwnTable
}

// wildcardProjection matches a `*` select list, whether bare (`SELECT *`) or
// qualified (`SELECT p.*`). A wildcard is UNREVIEWABLE: it yields whatever
// columns the table has today, so it yields account_id the moment the table has
// one — which account_profiles does. Rule 3 cannot be checked against a
// projection that does not name its columns, so the projection itself is the
// violation (A9).
var wildcardProjection = regexp.MustCompile(`(?is)(^|[\s,(])([a-z_][a-z0-9_]*\.)?\*`)

// accountIDEquality matches a predicate that is EXACTLY an `account_id = $n`
// equality (either operand order, optional cast on the placeholder). Requiring
// the shape — rather than merely "mentions account_id somewhere" — is what
// closes `WHERE account_id = $1 OR true`: the OR made the predicate match every
// row while still naming the id, so a scan of the display table passed a check
// whose whole purpose is to forbid scans.
var accountIDEquality = regexp.MustCompile(
	`(?is)^\s*\(*\s*(?:[a-z_][a-z0-9_]*\.)?account_id\s*(?:::\s*[a-z_]+\s*)?=\s*` +
		`(?:\$\d+|:[a-z_][a-z0-9_]*|\?)(?:\s*::\s*[a-z_]+)?\s*\)*\s*$`,
)

// predicateDisjunction matches any OR / UNION-shaped widening inside a
// predicate. Kept separate from the equality check so the failure message can
// name what actually went wrong.
var predicateDisjunction = regexp.MustCompile(`(?is)(^|[\s)])or($|[\s(])`)

// checkProfileStatement applies rules 2, 3 and 4 to one SQL literal.
func checkProfileStatement(name string, line int, stmt string) []string {
	var out []string
	lower := strings.ToLower(stmt)

	// Rule 4 (A9): no wildcard projection. `SELECT * FROM account_profiles` and
	// `SELECT p.* FROM account_profiles p` both yield account_id without ever
	// naming it, so the column-level checks below had nothing to look at and
	// waved them through.
	for _, seg := range sqlClauseSegments(lower, "select") {
		if wildcardProjection.MatchString(seg) {
			out = append(out, fmt.Sprintf(
				"%s:%d: the email-exempt store file uses a WILDCARD projection:\n%s\n\n"+
					"A `*` select list yields whatever columns the table has, which includes "+
					"account_id — so it is account RESOLUTION that no column-level review can "+
					"see. List the columns explicitly.", name, line, stmt,
			))
			break
		}
	}

	// Rule 3: the select list may not yield account_id.
	for _, seg := range sqlClauseSegments(lower, "select") {
		if containsIdent(seg, "account_id") {
			out = append(out, fmt.Sprintf(
				"%s:%d: the email-exempt store file SELECTs account_id from a display row:\n%s\n\n"+
					"Reading an account id back out of account_profiles is account RESOLUTION. "+
					"The account id arrives from an already-resolved session; it is never a "+
					"result of this table (plan §3 W1 / D18: no merge by email, ever).",
				name, line, stmt,
			))
			break
		}
	}

	// Rule 2: every lookup predicate is EXACTLY an account_id equality, and
	// names no profile content column.
	for kw, segs := range sqlPredicateSegments(lower) {
		for _, seg := range segs {
			if strings.TrimSpace(seg) == "" {
				continue
			}
			for _, col := range []string{"email", "display_name"} {
				if containsIdent(seg, col) {
					out = append(out, fmt.Sprintf(
						"%s:%d: a %s predicate references %q:\n%s\n\n"+
							"Email and display name are MUTABLE, provider-controlled and "+
							"re-assignable; keying any lookup on them would let one person "+
							"inherit another's account. account_profiles is keyed by account_id "+
							"and nothing else. (Writing the column in a SET list is fine — "+
							"looking a row up BY it is not.)",
						name, line, strings.ToUpper(kw), col, stmt,
					))
				}
			}
			// ON CONFLICT names a conflict TARGET — a column list, not an
			// equality — so it is checked for the column name only.
			if kw == "on conflict" {
				if !containsIdent(seg, "account_id") {
					out = append(out, fmt.Sprintf(
						"%s:%d: an ON CONFLICT target is not account_id:\n%s", name, line, stmt,
					))
				}
				continue
			}
			if !accountIDEquality.MatchString(seg) {
				why := "A predicate on anything else is a lookup."
				if predicateDisjunction.MatchString(seg) {
					why = "This one widens with OR: `account_id = $1 OR true` names the id and " +
						"still matches every row, which is the scan the rule exists to forbid."
				}
				out = append(out, fmt.Sprintf(
					"%s:%d: a %s predicate is not exactly `account_id = $n`:\n%s\n\n"+
						"Every statement in the email-exempt file must address exactly one "+
						"account, by its id. %s",
					name, line, strings.ToUpper(kw), stmt, why,
				))
			}
		}
	}
	return out
}

// sqlPredicateSegments returns the lookup-predicate regions of a statement,
// keyed by the clause keyword that introduced each one.
func sqlPredicateSegments(lower string) map[string][]string {
	out := map[string][]string{}
	for _, kw := range predicateClauses {
		if segs := sqlClauseSegments(lower, kw); len(segs) > 0 {
			out[kw] = segs
		}
	}
	return out
}

// sqlClauseSegments returns every region of lower that follows the clause
// keyword kw and runs to the next clause keyword (or the end of the statement).
// Matching is normalized on whitespace so "on   conflict" and "on conflict"
// are the same keyword.
func sqlClauseSegments(lower, kw string) []string {
	locs := sqlClauseKeyword.FindAllStringIndex(lower, -1)
	var out []string
	for i, loc := range locs {
		got := strings.Join(strings.Fields(lower[loc[0]:loc[1]]), " ")
		if got != kw {
			continue
		}
		// "on conflict" also matches the bare "on" caller; skip so a conflict
		// target is not double-counted under two keywords.
		if kw == "on" && strings.HasPrefix(strings.TrimSpace(lower[loc[1]:]), "conflict") {
			continue
		}
		end := len(lower)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		out = append(out, lower[loc[1]:end])
	}
	return out
}

// identBoundary finds an identifier as a whole word: `email` matches
// `lower(email)` and `email=$1`, but not `email_hash` or `raw_email`.
func containsIdent(s, ident string) bool {
	re := regexp.MustCompile(`(?i)(^|[^a-z0-9_])` + regexp.QuoteMeta(ident) + `($|[^a-z0-9_])`)
	return re.MatchString(s)
}

// TestProfileExemptionCheckerRejectsEmailLookups is the guard's own proof. The
// narrowed exemption is only worth what its checker actually rejects, so the
// checker is run against source snippets that ARE the hazard — and against the
// real exempt file, which must stay clean.
func TestProfileExemptionCheckerRejectsEmailLookups(t *testing.T) {
	const header = "package store\n\nfunc q() string {\n\treturn "

	negatives := []struct {
		name string
		sql  string
		why  string
	}{
		{
			name: "account resolution by email",
			sql:  "SELECT account_id FROM account_profiles WHERE email = $1",
			why:  "the exact merge-by-email lookup the tripwire promises to prohibit",
		},
		{
			name: "account resolution by normalized email",
			sql:  "SELECT account_id FROM account_profiles WHERE lower(email) = lower($1)",
			why:  "case-folding the address does not make it an identity key",
		},
		{
			name: "email predicate without account resolution",
			sql:  "SELECT display_name FROM account_profiles WHERE email=$1",
			why:  "a row addressed by a mutable attribute is a lookup even when it returns no id",
		},
		{
			name: "display_name predicate",
			sql:  "DELETE FROM account_profiles WHERE display_name = $1",
			why:  "the display name is provider-controlled too",
		},
		{
			name: "unkeyed scan",
			sql:  "SELECT account_id, email FROM account_profiles WHERE updated_at < $1",
			why:  "resolving accounts from the display table, filtered in Go, is still resolution",
		},
		// The three shapes GPT-6 Astra's review walked straight through the
		// earlier checker (A9). Each names account_profiles and (the third) even
		// names account_id, and each is account resolution.
		{
			name: "bare wildcard projection",
			sql:  "SELECT * FROM account_profiles WHERE account_id = $1",
			why:  "`*` yields account_id without naming it, so no column-level check can see it",
		},
		{
			name: "qualified wildcard projection",
			sql:  "SELECT p.* FROM account_profiles p WHERE p.account_id = $1",
			why:  "an alias does not make a wildcard reviewable",
		},
		{
			name: "predicate widened with OR",
			sql:  "SELECT display_name FROM account_profiles WHERE account_id = $1 OR true",
			why:  "it names account_id and still matches every row — the scan the rule forbids",
		},
		{
			name: "predicate widened with a second disjunct",
			sql:  "SELECT display_name FROM account_profiles WHERE account_id = $1 OR updated_at > $2",
			why:  "a disjunction reaches rows that are not the addressed account",
		},
		{
			name: "join predicate that is not an equality",
			sql:  "SELECT display_name FROM account_profiles p JOIN sessions s ON s.account_id > p.account_id",
			why:  "an inequality join over the display table addresses more than one account",
		},
	}
	for _, tc := range negatives {
		t.Run(tc.name, func(t *testing.T) {
			src := header + "`" + tc.sql + "`\n}\n"
			got, _ := profileSQLViolations(t, "fixture.go", []byte(src))
			if len(got) == 0 {
				t.Fatalf("the checker ACCEPTED a forbidden statement (%s):\n%s", tc.why, tc.sql)
			}
		})
	}

	positives := []struct {
		name string
		sql  string
	}{
		{
			name: "read by account_id",
			sql:  "SELECT email, display_name, updated_at FROM account_profiles WHERE account_id = $1::uuid",
		},
		{
			name: "upsert keyed by account_id",
			sql: "INSERT INTO account_profiles (account_id, email, display_name, updated_at)\n" +
				"VALUES ($1::uuid, nullif($2, ''), nullif($3, ''), $4)\n" +
				"ON CONFLICT (account_id) DO UPDATE\n" +
				"   SET email = EXCLUDED.email,\n" +
				"       display_name = EXCLUDED.display_name,\n" +
				"       updated_at = EXCLUDED.updated_at",
		},
	}
	for _, tc := range positives {
		t.Run(tc.name, func(t *testing.T) {
			src := header + "`" + tc.sql + "`\n}\n"
			got, sawOwn := profileSQLViolations(t, "fixture.go", []byte(src))
			if len(got) != 0 {
				t.Fatalf("the checker REJECTED a legitimate account_id-keyed statement:\n%s\n\n%s",
					tc.sql, strings.Join(got, "\n"))
			}
			if !sawOwn {
				t.Fatal("fixture did not register as naming account_profiles")
			}
		})
	}

	// And the file the exemption actually protects, today.
	t.Run("real exempt file", func(t *testing.T) {
		path := filepath.Join(storePkgDir, emailIdentifierExemptFile)
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		got, sawOwn := profileSQLViolations(t, emailIdentifierExemptFile, src)
		if len(got) != 0 {
			t.Fatalf("%s violates its own exemption:\n%s", emailIdentifierExemptFile, strings.Join(got, "\n"))
		}
		if !sawOwn {
			t.Fatalf("%s names no account_profiles statement", emailIdentifierExemptFile)
		}
	})
}
