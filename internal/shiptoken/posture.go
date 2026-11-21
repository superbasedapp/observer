package shiptoken

import (
	"reflect"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// posture.go is the share posture of a cloud sandbox (decision CA-D19): the
// sandbox's capture follows the member's enrolment, exactly as the member's
// own node does (CLAUDE.md "enterprise / org-managed nodes ship full
// content"). The org server derives the posture from its own enrolment
// records, never from anything the sandbox or the envelope says; the mint
// response carries it so `observer cloud-session init --share` can bake it
// into the committed flush hooks; and the org route refuses raw content
// from a member whose posture is metadata only.

// Share postures.
const (
	// PostureFullContent: the member's enrolment is managed (enterprise),
	// so the sandbox ships the raw content columns like the member's node.
	PostureFullContent = "full_content"
	// PostureMetadataOnly: an individual (or unknown) enrolment; the sandbox
	// ships hashes and metadata only, and the org refuses raw content.
	PostureMetadataOnly = "metadata_only"
)

// PostureForEnrolment is the posture of a member whose enrolment is managed
// (true) or not. Anything that is not positively managed (individual, mixed,
// unknown) is metadata only: fail closed.
func PostureForEnrolment(managed bool) string {
	if managed {
		return PostureFullContent
	}
	return PostureMetadataOnly
}

// CodeContentNotPermitted refuses a batch that carries raw content for a
// member whose posture is metadata only (CA-D19).
const CodeContentNotPermitted = "ship_token_content_not_permitted"

// contentRule is one row of the raw-content table: an admitted family, and
// either the whole family (the node attaches it only under full content) or
// the JSON names of the row fields the node fills only under full content.
// A row with neither declares, with its reason, that the family carries no
// raw content column.
type contentRule struct {
	family string
	whole  bool
	fields []string
	reason string
}

// contentRules is THE raw-content table. It mirrors the node's push seam
// (internal/store/orgpush.go and the Select* composers it calls): every
// column that seam strips, or every family it attaches only, under
// !shipsRawContent(). TestEveryAdmittedFamilyHasAContentRule forces a row
// for every admitted family and TestContentFieldsExist pins every named
// field to the row type, so a renamed column cannot silently stop being
// checked.
var contentRules = []contentRule{
	{family: "sessions", fields: []string{"project_root", "git_remote", "git_branch", "git_upstream_remote", "workspace"}},
	{family: "actions", fields: []string{"target", "source_file", "raw_tool_input", "raw_tool_output", "preceding_reasoning", "error_message"}},
	{family: "api_turns", fields: []string{"project_root"}},
	{family: "token_usage", fields: []string{"project_root", "source_file"}},
	{family: "otel_content", fields: []string{"content"}},
	{family: "session_task_items", fields: []string{"content", "active_form", "owner"}},
	{family: "session_tool_accounts", fields: []string{"email", "name", "account_id"}},
	{family: "session_loc", fields: []string{"language_mix_json"}},
	{family: "session_verbosity", whole: true},
	{family: "session_cache", whole: true},
	{family: "session_cache_events", whole: true},
	{family: "session_quality", reason: "derived scores only; rides the metadata posture"},
	{family: "session_task_transitions", reason: "statuses and timestamps only; the item prose is in session_task_items"},
	{family: "session_hook_activity", reason: "the node drops content-level env classes before the row is built; what remains is the closed coarse vocabulary"},
}

// RawContent counts, per admitted family, the rows of env that carry raw
// content (a non-empty content field, or any row of a whole-family rule).
// An empty result means the batch is metadata only.
func RawContent(env orgcontract.PushEnvelope) map[string]int {
	out := map[string]int{}
	v := reflect.ValueOf(env)
	t := v.Type()
	for _, r := range contentRules {
		if !r.whole && len(r.fields) == 0 {
			continue
		}
		for i := 0; i < t.NumField(); i++ {
			if jsonName(t.Field(i)) != r.family {
				continue
			}
			if n := contentRows(v.Field(i), r); n > 0 {
				out[r.family] = n
			}
		}
	}
	return out
}

// contentRows counts the rows of one family value that carry raw content.
func contentRows(fam reflect.Value, r contentRule) int {
	if fam.Kind() != reflect.Slice {
		return 0
	}
	if r.whole {
		return fam.Len()
	}
	n := 0
	for i := 0; i < fam.Len(); i++ {
		row := fam.Index(i)
		for row.Kind() == reflect.Pointer {
			if row.IsNil() {
				break
			}
			row = row.Elem()
		}
		if row.Kind() != reflect.Struct {
			continue
		}
		if rowHasContent(row, r.fields) {
			n++
		}
	}
	return n
}

// rowHasContent reports whether any named field of row is non-empty.
func rowHasContent(row reflect.Value, fields []string) bool {
	rt := row.Type()
	for j := 0; j < rt.NumField(); j++ {
		name := jsonName(rt.Field(j))
		for _, f := range fields {
			if f != name {
				continue
			}
			fv := row.Field(j)
			switch fv.Kind() {
			case reflect.String:
				if strings.TrimSpace(fv.String()) != "" {
					return true
				}
			case reflect.Slice, reflect.Map:
				if fv.Len() > 0 {
					return true
				}
			}
		}
	}
	return false
}

// ContentFamilies returns the families the table checks, sorted (docs).
func ContentFamilies() []string {
	var out []string
	for _, r := range contentRules {
		if r.whole || len(r.fields) > 0 {
			out = append(out, r.family)
		}
	}
	sort.Strings(out)
	return out
}

// ContentAllowed reports whether a batch with the given raw-content counts
// may land for a member of posture: metadata-only batches always may; raw
// content only under PostureFullContent.
func ContentAllowed(posture string, raw map[string]int) bool {
	return len(raw) == 0 || posture == PostureFullContent
}
