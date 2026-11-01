package orgcontract

import (
	"regexp"
	"strings"
)

// Match forms of a normalized remote (security plan section 7.11 hard cases,
// spike JSP-10 finding F9, lane sec-p2a). git.NormalizeRemote keeps the
// path's case and gives the Azure DevOps https, ssh and visualstudio.com
// shapes three different strings, so an exact hash alone misses
// `github.com/Acme/Widget` against `github.com/acme/widget` and an ssh clone
// of a repository the org learned over https.
//
// The fix never changes git.NormalizeRemote (that would change every hash
// nodes already ship). Instead BOTH sides derive the same extra forms from
// the normalized string with the one table below: the org server publishes
// the extra forms' hashes beside the exact one in the signed mapping (and
// matches them in the resolve call), and the node looks up its own forms'
// hashes. Matching is symmetric because both sides apply the same function.
// It is the ONE owner of the forms: internal/orgserver/projectaudience
// publishes them and internal/projectmatch matches them, and neither keeps a
// table of its own.

// caseInsensitiveHosts are the hosts whose repository paths are
// case-insensitive, so the lowercased path names the same repository. A host
// not listed (a self-hosted server) gets no lowercased form: lowercasing
// there could fold two distinct repositories together.
var caseInsensitiveHosts = map[string]bool{
	"github.com":              true,
	"gitlab.com":              true,
	"bitbucket.org":           true,
	"dev.azure.com":           true,
	"ssh.dev.azure.com":       true,
	"vs-ssh.visualstudio.com": true,
}

// caseInsensitiveHostSuffixes extend caseInsensitiveHosts to every
// `<org>.visualstudio.com` (the legacy Azure DevOps host).
var caseInsensitiveHostSuffixes = []string{".visualstudio.com"}

// azureDevOpsAlias is one row of the Azure DevOps alias table: a lowercased
// normalized remote matching Pattern names the repository whose canonical
// form is Template expanded over the match. Rows are walked top-down and the
// first match wins.
type azureDevOpsAlias struct {
	Name     string
	Pattern  *regexp.Regexp
	Template string
}

// azureDevOpsAliases maps every Azure DevOps URL shape onto the canonical
// `dev.azure.com/<org>/<project>/_git/<repo>` form (lowercased: Azure DevOps
// names are case-insensitive).
var azureDevOpsAliases = []azureDevOpsAlias{
	{Name: "https", Pattern: regexp.MustCompile(`^dev\.azure\.com/([^/]+)/([^/]+)/_git/([^/]+)$`), Template: "dev.azure.com/$1/$2/_git/$3"},
	{Name: "ssh", Pattern: regexp.MustCompile(`^ssh\.dev\.azure\.com/v3/([^/]+)/([^/]+)/([^/]+)$`), Template: "dev.azure.com/$1/$2/_git/$3"},
	{Name: "visualstudio-ssh", Pattern: regexp.MustCompile(`^vs-ssh\.visualstudio\.com/v3/([^/]+)/([^/]+)/([^/]+)$`), Template: "dev.azure.com/$1/$2/_git/$3"},
	{Name: "visualstudio-collection", Pattern: regexp.MustCompile(`^([^./]+)\.visualstudio\.com/defaultcollection/([^/]+)/_git/([^/]+)$`), Template: "dev.azure.com/$1/$2/_git/$3"},
	{Name: "visualstudio", Pattern: regexp.MustCompile(`^([^./]+)\.visualstudio\.com/([^/]+)/_git/([^/]+)$`), Template: "dev.azure.com/$1/$2/_git/$3"},
}

// remoteHostCaseInsensitive reports whether a normalized remote's host is in
// the case-insensitive table.
func remoteHostCaseInsensitive(normalized string) bool {
	host, _, _ := strings.Cut(normalized, "/")
	if caseInsensitiveHosts[host] {
		return true
	}
	for _, suf := range caseInsensitiveHostSuffixes {
		if strings.HasSuffix(host, suf) {
			return true
		}
	}
	return false
}

// ProjectRemoteForms returns the match forms of a normalized remote (the
// output of git.NormalizeRemote): the exact string first, then, for a
// case-insensitive host, the lowercased string, then the canonical Azure
// DevOps form when an alias row matches. Duplicates are dropped; an empty
// remote has no forms. The exact form is always the string itself, so the
// first form's hash is the hash nodes already ship.
func ProjectRemoteForms(normalized string) []string {
	if normalized == "" {
		return nil
	}
	out := []string{normalized}
	add := func(s string) {
		for _, have := range out {
			if have == s {
				return
			}
		}
		out = append(out, s)
	}
	if !remoteHostCaseInsensitive(normalized) {
		return out
	}
	lower := strings.ToLower(normalized)
	add(lower)
	for _, row := range azureDevOpsAliases {
		if m := row.Pattern.FindStringSubmatchIndex(lower); m != nil {
			add(string(row.Pattern.ExpandString(nil, row.Template, lower, m)))
			break
		}
	}
	return out
}
