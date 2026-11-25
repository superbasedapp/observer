package explorerview

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

// Pages a saved view belongs to: the trace list and the trace groups of the
// explorer.
const (
	PageTraces = "traces"
	PageGroups = "groups"
)

// Scopes a saved view is shared with. A machine has one user, so its views
// are always ScopePrivate.
const (
	ScopePrivate = "private" // only the member who saved it
	ScopeTeam    = "team"    // the members of one team
	ScopeOrg     = "org"     // every member who can read the explorer
)

// Bounds on a view.
const (
	MaxNameLen    = 120
	MaxValueLen   = 256 // the identity value bound (otelident.MaxValueLen)
	MaxQueryLen   = 512 // the explorer's full-text bound
	MaxColumns    = 24
	MaxGroupByLen = 300
	// MaxViewsPerOwner bounds the views one member (or one machine) keeps.
	MaxViewsPerOwner = 200
)

// filterKeys is the closed set of explorer query parameters a view may save:
// the explorer contract's names (contracts/alerts.md "Explorer"). contentGated
// marks the ones that are raw customer text (D23, D25): a view carrying one
// is redacted for a viewer without read:content.
var filterKeys = map[string]struct{ contentGated bool }{
	"days":        {},
	"status":      {},
	"service":     {},
	"environment": {},
	"release":     {},
	"model":       {},
	"q":           {},
	"user":        {contentGated: true},
	"trace_tag":   {contentGated: true},
	"meta":        {contentGated: true},
	"content":     {contentGated: true},
}

// columns is the closed set of optional trace-list columns a view may save.
var columns = map[string]bool{
	"model": true, "evals": true, "end_user": true, "service": true, "environment": true,
	"release": true, "tags": true, "pushed_by": true, "source": true, "input_preview": true,
	"output_preview": true, "tokens": true, "cost": true, "duration": true, "session": true,
}

// groupModes are the explorer's trace group modes (contracts/alerts.md);
// groupPrefixes take a key after the colon.
var (
	groupModes = map[string]struct{ contentGated bool }{
		"user": {}, "session": {}, "service": {}, "environment": {}, "release": {}, "model": {},
		"tag": {contentGated: true}, "metadata": {contentGated: true},
	}
	groupPrefixes = map[string]struct{ contentGated bool }{
		"metadata:":   {contentGated: true},
		"annotation:": {},
	}
)

// View is one saved explorer view: a filter set, a grouping and a column
// set, saved by one member (or the machine's user) and shared per Scope.
type View struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Page    string            `json:"page"`
	Filters map[string]string `json:"filters"`
	GroupBy string            `json:"group_by"`
	Columns []string          `json:"columns"`
	Scope   string            `json:"scope"`
	// TeamID names the team a ScopeTeam view is shared with; "" otherwise.
	TeamID string `json:"team_id,omitempty"`
	// Owner is the member id who saved it ("" on the machine).
	Owner     string `json:"owner,omitempty"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	// Mine reports that the viewer saved it (the viewer may edit it).
	Mine bool `json:"mine"`
	// Redacted reports that content-gated values were removed for a viewer
	// without read:content (Redact).
	Redacted bool `json:"redacted,omitempty"`
}

// ErrInvalid wraps every validation failure; handlers map it to 400.
var ErrInvalid = errors.New("explorerview: invalid view")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, a...)...)
}

// Normalize trims the view's text and drops empty filters, columns
// duplicates, and a TeamID on a non-team scope. It does not validate.
func Normalize(v View) View {
	v.Name = strings.TrimSpace(v.Name)
	v.Page = strings.TrimSpace(v.Page)
	if v.Page == "" {
		v.Page = PageTraces
	}
	v.Scope = strings.TrimSpace(v.Scope)
	if v.Scope == "" {
		v.Scope = ScopePrivate
	}
	v.GroupBy = strings.TrimSpace(v.GroupBy)
	v.TeamID = strings.TrimSpace(v.TeamID)
	if v.Scope != ScopeTeam {
		v.TeamID = ""
	}
	f := make(map[string]string, len(v.Filters))
	for k, val := range v.Filters {
		val = strings.TrimSpace(val)
		if val != "" {
			f[strings.TrimSpace(k)] = val
		}
	}
	v.Filters = f
	seen := map[string]bool{}
	cols := make([]string, 0, len(v.Columns))
	for _, c := range v.Columns {
		c = strings.TrimSpace(c)
		if c != "" && !seen[c] {
			seen[c] = true
			cols = append(cols, c)
		}
	}
	v.Columns = cols
	return v
}

// Validate checks a normalized view. allowShared is false on the machine
// (only ScopePrivate). Error texts name the field, never a filter value
// (a value may be an end user).
func Validate(v View, allowShared bool) error {
	if v.Name == "" || len(v.Name) > MaxNameLen || !utf8.ValidString(v.Name) || hasControl(v.Name) {
		return invalid("name must be 1 to %d characters with no control characters", MaxNameLen)
	}
	if v.Page != PageTraces && v.Page != PageGroups {
		return invalid("page must be %q or %q", PageTraces, PageGroups)
	}
	switch v.Scope {
	case ScopePrivate:
	case ScopeTeam, ScopeOrg:
		if !allowShared {
			return invalid("a machine view is private")
		}
		if v.Scope == ScopeTeam && v.TeamID == "" {
			return invalid("a team view needs team_id")
		}
	default:
		return invalid("scope must be private, team or org")
	}
	for k, val := range v.Filters {
		if _, ok := filterKeys[k]; !ok {
			return invalid("filter %q is not an explorer filter", k)
		}
		limit := MaxValueLen
		if k == "q" {
			limit = MaxQueryLen
		}
		if len(val) > limit || hasControl(val) {
			return invalid("filter %s is longer than %d bytes or carries a control character", k, limit)
		}
	}
	if c, ok := v.Filters["content"]; ok && c != "1" && c != "0" {
		return invalid("filter content must be 0 or 1")
	}
	if v.Filters["content"] == "1" && v.Filters["q"] == "" {
		return invalid("filter content=1 needs q")
	}
	if len(v.Columns) > MaxColumns {
		return invalid("at most %d columns", MaxColumns)
	}
	for _, c := range v.Columns {
		if !columns[c] {
			return invalid("column %q is not an explorer column", c)
		}
	}
	if v.GroupBy != "" {
		if _, ok := groupModeOf(v.GroupBy); !ok || len(v.GroupBy) > MaxGroupByLen || hasControl(v.GroupBy) {
			return invalid("group_by is not an explorer group mode")
		}
	}
	return nil
}

func groupModeOf(by string) (struct{ contentGated bool }, bool) {
	if m, ok := groupModes[by]; ok {
		return m, true
	}
	for p, m := range groupPrefixes {
		if strings.HasPrefix(by, p) && len(by) > len(p) {
			return m, true
		}
	}
	return struct{ contentGated bool }{}, false
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// NeedsContentRead reports whether the view carries raw customer text: a
// content-gated filter or a tag/metadata grouping.
func NeedsContentRead(v View) bool {
	for k := range v.Filters {
		if filterKeys[k].contentGated {
			return true
		}
	}
	if m, ok := groupModeOf(v.GroupBy); ok && m.contentGated {
		return true
	}
	return false
}

// Redact removes the content-gated values from a view shown to a viewer
// without read:content, the search term of a content search included. The
// view keeps its name, page, columns and the ungated filters; Redacted tells the page that applying it shows less than
// its author saved.
func Redact(v View) View {
	if !NeedsContentRead(v) {
		return v
	}
	// With content=1 the search term q is a content search: the words the
	// author looked for in prompts and completions, gated like them (review
	// finding R-C22).
	contentSearch := v.Filters["content"] == "1"
	f := make(map[string]string, len(v.Filters))
	for k, val := range v.Filters {
		if filterKeys[k].contentGated || (k == "q" && contentSearch) {
			continue
		}
		f[k] = val
	}
	v.Filters = f
	if m, ok := groupModeOf(v.GroupBy); ok && m.contentGated {
		v.GroupBy = ""
	}
	v.Redacted = true
	return v
}

// Query renders a view's filters (and group_by as "by" on the groups page)
// as explorer query parameters.
func Query(v View) url.Values {
	q := url.Values{}
	for k, val := range v.Filters {
		q.Set(k, val)
	}
	if v.Page == PageGroups && v.GroupBy != "" {
		q.Set("by", v.GroupBy)
	}
	return q
}

// Visible reports whether a viewer sees a view: their own, an org view, or a
// team view of a team they belong to.
func Visible(v View, viewer string, teams map[string]bool) bool {
	switch v.Scope {
	case ScopeOrg:
		return true
	case ScopeTeam:
		return v.Owner == viewer || teams[v.TeamID]
	default:
		return v.Owner == viewer
	}
}
