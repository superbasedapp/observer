import { useEffect, useRef, useState } from "react";
import { FadeIn } from "@shared/primitives/Motion";
import { Icon } from "@shared/primitives/Icon";
import { ChevronRight } from "lucide-react";
import { Button } from "@shared/primitives/Button";
import { EmptyState } from "@shared/primitives/EmptyState";
import { usePortalQuery } from "../lib/query";
import { ErrorPanel, ListSkeleton } from "../components/LoadState";
import { Link } from "react-router-dom";
import { getSessions } from "../api";
import type { SessionSummary, SessionsPage } from "../api";
import { Pill } from "@shared/primitives/Pill";
import { ModelId } from "@shared/primitives/ModelId";
import { fmtDateTime } from "@shared/lib/format";
import { ToolGlyph } from "@shared/lib/toolGlyph";
import { toolMeta } from "@shared/lib/tools";
import { Card } from "@shared/primitives/Card";
import { PageHeader } from "@shared/primitives/PageHeader";
import { routeIcon } from "../lib/nav";

// Sessions list (divergence plan §3 W6c / D4). One page of the account's
// enriched sessions, newest-first, over GET /portal/api/sessions. Each row's
// title is the EFFECTIVE title — the latest user correction if there is one,
// else the AI original — so an edited session reads as the user left it. The
// list is honest about what it shows: an un-enriched account gets the elegant
// empty state, not a fabricated row.

function SessionRow({ s }: { s: SessionSummary }) {
  const title = s.effective_title.trim() || "Untitled session";
  return (
    <li className="session-row">
      <Link
        className="session-link sb-lift"
        to={"/sessions/" + encodeURIComponent(s.cloud_session_id)}
      >
        <div className="session-main">
          <div className="session-title">
            <span className={s.tombstoned ? "muted" : undefined}>{title}</span>
            {s.edited && !s.tombstoned && <Pill variant="info">Edited</Pill>}
            {s.tombstoned && <Pill variant="danger">Deleted</Pill>}
          </div>
          <div className="session-meta">
            {/* The row is a link, so the tool is the plain logo + label (the
                shared ToolBadge's frame is itself focusable and would nest an
                interactive element inside the link). */}
            <span className="inline-flex items-center gap-1 text-fg-2">
              <span className="inline-flex shrink-0" style={{ color: toolMeta(s.tool).colorVar }}>
                <ToolGlyph tool={s.tool} size={12} />
              </span>
              {toolMeta(s.tool).label}
            </span>
            {s.model_family && (
              <>
                <span className="session-dot" aria-hidden>
                  ·
                </span>
                <ModelId model={s.model_family} mono={false} markSize={12} />
              </>
            )}
            <span className="session-dot" aria-hidden>
              ·
            </span>
            <span>{fmtDateTime(s.created_at)}</span>
          </div>
        </div>
        <div className="session-aside">
          <span className="session-count">
            {s.result_count} result{s.result_count === 1 ? "" : "s"}
          </span>
          <span className="session-chevron" aria-hidden>
            <Icon icon={ChevronRight} size="md" />
          </span>
        </div>
      </Link>
    </li>
  );
}

export function Sessions() {
  // Page one is a cached query: coming back to Sessions paints the last list
  // at once and revalidates. Further pages are appended locally.
  const first = usePortalQuery<SessionsPage>("sessions:first", () => getSessions());
  const [more, setMore] = useState<SessionSummary[]>([]);
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [hasMore, setHasMore] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [moreError, setMoreError] = useState<string | null>(null);
  // Every "Load more" gets a sequence number; a response for an older one (or
  // after unmount, or after page one refreshed underneath it) is dropped.
  const seq = useRef(0);
  useEffect(() => () => {
    seq.current++;
  }, []);

  // Page one (re)loaded: reset the appended pages to its cursor.
  useEffect(() => {
    if (!first.data) return;
    seq.current++;
    setMore([]);
    setCursor(first.data.next_cursor);
    setHasMore(first.data.has_more);
    setLoadingMore(false);
  }, [first.data]);

  function loadMore() {
    const my = ++seq.current;
    setLoadingMore(true);
    setMoreError(null);
    getSessions(cursor)
      .then((page) => {
        if (seq.current !== my) return;
        setMore((prev) => prev.concat(page.sessions));
        setHasMore(page.has_more);
        setCursor(page.next_cursor);
      })
      .catch((err: unknown) => {
        if (seq.current !== my) return;
        setMoreError(err instanceof Error ? err.message : "failed to load");
      })
      .finally(() => {
        if (seq.current === my) setLoadingMore(false);
      });
  }

  const rows = first.data ? first.data.sessions.concat(more) : [];
  const loading = first.loading;
  const error = first.error;

  return (
    <div>
      <PageHeader
        title="Sessions"
        icon={routeIcon("/sessions")}
        sub="Sessions your devices synced for cloud enrichment, newest first. The title shown is the latest one you saved, or the AI suggestion if you have not edited it. Open a session to see the AI original, its edit history, and to correct the title, description or tags."
        className="mb-6"
      />

      {error && !first.data && (
        <ErrorPanel variant="page" what="sessions" error={error} onRetry={first.reload} />
      )}

      {loading && !error && <ListSkeleton rows={8} header={false} />}

      {!loading && !error && rows.length === 0 && (
        <EmptyState
          className="mb-4"
          illustration="enrich"
          title="No enriched sessions yet"
          body="Enrichment runs on the bounded excerpts you grant; once a device runs and syncs an enrichment job, its sessions appear here."
        />
      )}

      {rows.length > 0 && (
        <FadeIn as={Card} className="mb-4 session-card">
          <ul className="session-list sb-stagger">
            {rows.map((s) => (
              <SessionRow key={s.cloud_session_id} s={s} />
            ))}
          </ul>
        </FadeIn>
      )}

      {moreError && (
        <div className="mt-3">
          <ErrorPanel variant="compact" what="more sessions" error={moreError} onRetry={loadMore} />
        </div>
      )}

      {hasMore && (
        <div className="load-more">
          <Button variant="secondary" loading={loadingMore} onClick={loadMore}>
            {loadingMore ? "Loading more" : "Load more"}
          </Button>
        </div>
      )}
    </div>
  );
}
