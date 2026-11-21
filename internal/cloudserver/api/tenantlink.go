package api

// tenantlink.go: the ONE place the console's links into an org's own
// dashboard are composed (hosted sign-in fix, lane A). Every response field
// that opens a tenant dashboard page (open_url, machines_page_url,
// invite_url, launch_url, the connect views' open link, the device
// discovery server_url) is built by tenantLink, so the browser never
// composes a tenant host or path itself.
//
// The link is a plain https://<host><path>. On a hosted org the org server
// (lane B) guarantees that an unauthenticated browser GET of any dashboard
// path starts the platform sign-in and returns to that same path, so the
// console needs no sign-in hint of its own on these links.

// tenantPage is a page of a tenant dashboard the console links to. The set
// is closed: tenantLink takes only these constants.
type tenantPage string

const (
	// tenantPageOrigin is the dashboard's bare origin (no path), the device
	// discovery wire's server_url.
	tenantPageOrigin tenantPage = ""
	// tenantPageDashboard is the dashboard's home: every "Open your
	// dashboard" button (open_url).
	tenantPageDashboard tenantPage = "/"
	// tenantPageMachines is where a member sees their own enrolled machines
	// (web2 /me/profile). The console links to it for each active org
	// instead of reading every tenant from the browser (C2.front-door-4 B,
	// wave 15: the cross-origin machine aggregation of M6.0 A13 is dropped,
	// so no tenant needs CORS for the portal origin; docs/security.md
	// PORTALORG-8).
	tenantPageMachines tenantPage = "/me/profile"
	// tenantPageInvites is the team dashboard's invite page (web2
	// /people-access, its invites tab), where "Invite people" lands.
	tenantPageInvites tenantPage = "/people-access?tab=invites"
	// tenantPageInstall is the tenant dashboard's "Connect a machine" page
	// (web2 /me/install), where the org detail's launch link lands.
	tenantPageInstall tenantPage = "/me/install"
)

// tenantLink is https://<slug>.<tenant domain><page>, or "" when no tenant
// domain is configured or the slug is empty. Whether an org's state allows
// a link at all (active, or a personal org still being set up) stays the
// caller's decision; this function only composes.
func (s *Server) tenantLink(slug string, page tenantPage) string {
	host := s.tenantHost(slug)
	if host == "" {
		return ""
	}
	return "https://" + host + string(page)
}
