package dashboard

import (
	"context"
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/announce"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// announcementsResponse is the wire shape of GET /api/announcements. The
// list is always present and always an array (never null) — the banner
// treats a missing key as "backend too old" and a null as a bug, so the
// empty case must be an explicit [].
type announcementsResponse struct {
	Announcements []announce.Announcement `json:"announcements"`
}

// releaseAnnouncementSource is rail R1's feed, indirected through a
// package-level var so tests can inject announcements without editing
// the compiled-in release set (the house seam — same pattern as
// enableHostDetector in remote_manage.go).
var releaseAnnouncementSource = announce.Release

// announcementNow is the clock Merge is evaluated against. Indirected
// for the same reason: expiry is the interesting behaviour and a test
// must be able to stand either side of an expiry instant.
var announcementNow = func() time.Time { return time.Now().UTC() }

// handleAnnouncements serves GET /api/announcements: the merged,
// unexpired banner list (plan §5 — all rails converge here except R2,
// which stays frontend-only inside the click-gated update check).
//
// This handler makes NO network call and reads no request state. It is a
// pure fold over sources that are already on this machine: the release
// set compiled into the binary (R1) plus, when enrolled, the org
// document the push loop already fetched and cached (R3). Rail order is
// release-then-org, which matters only for id collisions — Merge keeps
// the FIRST occurrence, so a release announcement wins a duplicate id
// and an org admin cannot overwrite one of ours by reusing its id.
//
// Solo installs degrade silently to the release set alone, exactly like
// handleEnrolmentStatus does for org mode: no cache row, no error, no
// difference in the response shape.
func (s *Server) handleAnnouncements(w http.ResponseWriter, r *http.Request) {
	sources := [][]announce.Announcement{
		releaseAnnouncementSource(),
		s.orgAnnouncements(r.Context()),
	}
	// An announcement whose fixed_in this node has reached is no news here
	// (WINNODE2 16b).
	writeJSON(w, announcementsResponse{
		Announcements: announce.ForVersion(announce.Merge(announcementNow(), sources...), s.opts.Version),
	})
}

// orgAnnouncements decodes rail R3's node-local cache (migration 076,
// written only by the org push loop after signature + TOFU-key
// verification). It returns nil for every "nothing to show" case —
// the rail switched off, no cache row (solo install / never published),
// a retraction (empty body), or a body that fails to decode.
//
// Every failure here is silent on purpose. This is a banner: the honest
// degradation is no banner. A 500 on the announcements endpoint would
// take the surface down for the release rail too, and the org document
// is the one input to it that arrives over a wire.
//
// Source is FORCED to "org" on every decoded announcement rather than
// trusted from the body. The server already refuses to sign anything
// else, so this is belt-and-braces — but provenance is what the banner
// tells the reader ("from your org"), and it should be decided by which
// cache the row came out of, not by a string inside it.
func (s *Server) orgAnnouncements(ctx context.Context) []announce.Announcement {
	if !s.opts.Dashboard.OrgAnnouncements {
		return nil
	}
	// CURRENT enrolment is required, not merely a cache row. The cache
	// is deleted on unenrolment (store.DeleteEnrolment), so this is
	// belt-and-braces — but it is the belt that matters: it is the only
	// check that holds when a row survives by any route the delete does
	// not cover (a crash between the two writes, an older DB, a manual
	// restore, a bug in a future unenrol path). A departed org must
	// never be able to speak into this dashboard, and "the row is gone"
	// is a weaker guarantee than "we are still enrolled".
	//
	// The seam is the same one handleEnrolmentStatus uses (Options.
	// OrgClient), so a solo-local install — where it is a nil interface
	// by construction in cmd/observer — degrades silently exactly like
	// the enrolment endpoints do.
	if s.opts.OrgClient == nil {
		return nil
	}
	st, err := s.opts.OrgClient.Status(ctx)
	if err != nil || !st.Enrolled {
		return nil
	}
	row, ok, err := store.New(s.db()).GetOrgAnnouncement(ctx)
	if err != nil || !ok {
		return nil
	}
	// Decode tolerates both §1 document shapes — a single object (what
	// the composer publishes today) and an array (accepted from day one
	// so a multi-announcement composer needs no wire change later).
	list, err := announce.Decode(row.Body)
	if err != nil {
		return nil
	}
	for i := range list {
		list[i].Source = announce.SourceOrg
	}
	return list
}
