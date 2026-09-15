import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getSessions } from "../api";
import type { SessionSummary } from "../api";
import { Pill } from "@shared/primitives/Pill";
import { fmtDateTime } from "@shared/lib/format";

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
        className="session-link"
        to={"/sessions/" + encodeURIComponent(s.cloud_session_id)}
      >
        <div className="session-main">
          <div className="session-title">
            <span className={s.tombstoned ? "muted" : undefined}>{title}</span>
            {s.edited && !s.tombstoned && <Pill variant="info">Edited</Pill>}
            {s.tombstoned && <Pill variant="danger">Deleted</Pill>}
          </div>
          <div className="session-meta">
            <span className="mono">{s.tool}</span>
            {s.model_family && (
              <>
                <span className="session-dot" aria-hidden>
                  ·
                </span>
                <span>{s.model_family}</span>
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
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
              <path
                d="M9 6l6 6-6 6"
                stroke="currentColor"
                strokeWidth="1.75"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </span>
        </div>
      </Link>
    </li>
  );
}

export function Sessions() {
  const [rows, setRows] = useState<SessionSummary[]>([]);
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadPage = useCallback((after?: string) => {
    let live = true;
    if (after === undefined) {
      setLoading(true);
    } else {
      setLoadingMore(true);
    }
    getSessions(after)
      .then((page) => {
        if (!live) return;
        setError(null);
        setRows((prev) =>
          after === undefined ? page.sessions : prev.concat(page.sessions),
        );
        setHasMore(page.has_more);
        setCursor(page.next_cursor);
      })
      .catch((err: unknown) => {
        if (live) {
          setError(err instanceof Error ? err.message : "failed to load");
        }
      })
      .finally(() => {
        if (live) {
          setLoading(false);
          setLoadingMore(false);
        }
      });
    return () => {
      live = false;
    };
  }, []);

  useEffect(() => loadPage(undefined), [loadPage]);

  return (
    <div>
      <h1>Sessions</h1>
      <p className="muted small page-intro">
        Sessions your devices synced for cloud enrichment, newest first. The
        title shown is the latest one you saved, or the AI suggestion if you
        have not edited it. Open a session to see the AI original, its edit
        history, and to correct the title, description or tags.
      </p>

      {error && (
        <div className="banner banner-error">Could not load sessions: {error}</div>
      )}

      {loading && !error && <div className="muted">Loading sessions...</div>}

      {!loading && !error && rows.length === 0 && (
        <div className="card">
          <div className="tile-empty">
            <span className="tile-empty-mark" aria-hidden>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
                <rect
                  x="3"
                  y="3"
                  width="18"
                  height="18"
                  rx="4"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeDasharray="3 3"
                />
              </svg>
            </span>
            <span className="tile-empty-text">
              No enriched sessions yet. Enrichment runs on the bounded excerpts
              you grant; once a device runs and syncs an enrichment job, its
              sessions appear here.
            </span>
          </div>
        </div>
      )}

      {rows.length > 0 && (
        <div className="card session-card">
          <ul className="session-list">
            {rows.map((s) => (
              <SessionRow key={s.cloud_session_id} s={s} />
            ))}
          </ul>
        </div>
      )}

      {hasMore && (
        <div className="load-more">
          <button
            className="btn"
            disabled={loadingMore}
            onClick={() => loadPage(cursor)}
          >
            {loadingMore ? "Loading..." : "Load more"}
          </button>
        </div>
      )}
    </div>
  );
}
