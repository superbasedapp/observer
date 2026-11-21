import { useCallback, useEffect, useReducer, useRef } from "react";
import { apiCache, useApi, type ApiState } from "@/lib/useApi";
import { buildUrl, fetchJSON } from "@/lib/api";
import {
  findingGroupsKey,
  findingGroupsQueryParams,
  findingsFilterKey,
  findingsListPage,
  findingsListReducer,
  findingsQueryParams,
  INITIAL_FINDINGS_LIST,
  INITIAL_GROUPS_LIST,
  lastPage,
  type FindingSort,
  type FindingsListAction,
  type FindingsListPage,
  type FindingsListState,
} from "@/lib/codeSecurity";
import {
  findingsApiParams,
  type FindingGroupsPage,
  type FindingsFacets,
  type FindingsFilters,
  type FindingsGroupBy,
} from "@/lib/codeSecurityApi";

// The Findings tab's three server reads, each fed by the filters the tab
// reads from the URL (lib/codeSecurityApi.ts):
//
//   useFindingsList   GET /api/security/findings, the ungrouped page
//   useFindingGroups  GET /api/security/findings/groups?by=, the grouped page
//   useFindingsFacets GET /api/security/findings/facets, the filter counts
//
// The two paged reads own their sort and page (lib/codeSecurity.ts
// findingsListReducer): a filter change reads page 1 at once, a page that
// is past the end after the list shrank (an exception was granted, a scan
// closed findings) steps back to the last page. Only the read the view
// shows is sent: the list while ungrouped, the groups while grouped.

export const FINDINGS_PATH = "/api/security/findings";
export const FINDING_GROUPS_PATH = "/api/security/findings/groups";
export const FINDINGS_FACETS_PATH = "/api/security/findings/facets";

/** How long after a reach_pending page the same page is read again, and
 *  how many times at most. */
export const REACH_RECHECK_MS = 4000;
export const REACH_RECHECK_MAX = 3;

/** A server-paged read with its page and sort. */
export type PagedRead<T> = {
  read: ApiState<T>;
  page: number;
  sorting: FindingSort;
  setPage: (page: number) => void;
  setSorting: (sorting: FindingSort) => void;
};

export type FindingsList = PagedRead<FindingsListPage> & {
  /** The page on screen said some dependency rows' reachability is still
   *  being worked out: their labels and order may change. */
  reachPending: boolean;
};

/** usePaging is the sort and page of one read, keyed on its filters. */
function usePaging(initial: FindingsListState, filterKey: string) {
  const [state, dispatch] = useReducer(findingsListReducer, initial);
  const page = findingsListPage(state, filterKey);
  const setPage = useCallback((p: number) => dispatch({ type: "page", page: p, filterKey }), [filterKey]);
  const setSorting = useCallback((s: FindingSort) => dispatch({ type: "sort", sorting: s, filterKey }), [filterKey]);
  return { state, page, dispatch, setPage, setSorting };
}

/** useLastPageClamp steps back to the last page when the page on screen is
 *  past the end. */
function useLastPageClamp(
  read: ApiState<{ total: number; limit: number }>,
  page: number,
  filterKey: string,
  dispatch: (a: FindingsListAction) => void,
) {
  const data = read.data;
  useEffect(() => {
    if (!data || read.isStale) return;
    const last = lastPage(data.total, data.limit);
    if (page > last) dispatch({ type: "page", page: last, filterKey });
  }, [data, read.isStale, page, filterKey, dispatch]);
}

/** useReachRecheck reads a reach_pending page again, quietly (no skeleton,
 *  not counted in the top bar's activity), after REACH_RECHECK_MS, at most
 *  REACH_RECHECK_MAX times for one request. */
function useReachRecheck(
  read: ApiState<FindingsListPage>,
  params: Record<string, string | number | undefined>,
  enabled: boolean,
): boolean {
  const key = enabled ? buildUrl(FINDINGS_PATH, params) : null;
  const pending = enabled && Boolean(read.data?.reach_pending) && !read.isStale;
  const tries = useRef<{ key: string | null; n: number }>({ key: null, n: 0 });
  const paramsRef = useRef(params);
  paramsRef.current = params;
  useEffect(() => {
    if (!key || !pending) return;
    if (tries.current.key !== key) tries.current = { key, n: 0 };
    if (tries.current.n >= REACH_RECHECK_MAX) return;
    const at = tries.current;
    const p = paramsRef.current;
    const t = setTimeout(() => {
      at.n++;
      void apiCache
        .fetch(key, (signal) => fetchJSON<FindingsListPage>(FINDINGS_PATH, p, { signal }), { force: true, foreground: false })
        .catch(() => undefined);
    }, REACH_RECHECK_MS);
    return () => clearTimeout(t);
    // read.updatedAt re-arms the timer after each answer, even one equal to
    // the last (the cache keeps the same object for an equal response).
  }, [key, pending, read.updatedAt]);
  return pending;
}

/** useFindingsList is the ungrouped findings page for these filters; it
 *  sends nothing while disabled (a grouped view). */
export function useFindingsList(filters: FindingsFilters, enabled = true): FindingsList {
  const filterKey = findingsFilterKey(filters);
  const paging = usePaging(INITIAL_FINDINGS_LIST, filterKey);
  const params = findingsQueryParams(filters, paging.state);
  const read = useApi<FindingsListPage>(enabled ? FINDINGS_PATH : null, params);
  useLastPageClamp(read, paging.page, filterKey, paging.dispatch);
  const reachPending = useReachRecheck(read, params, enabled);
  return {
    read,
    page: paging.page,
    sorting: paging.state.sorting,
    setPage: paging.setPage,
    setSorting: paging.setSorting,
    reachPending,
  };
}

/** useFindingGroups is the grouped page for these filters; it sends
 *  nothing while the view is ungrouped. */
export function useFindingGroups(group: FindingsGroupBy, filters: FindingsFilters): PagedRead<FindingGroupsPage> {
  const enabled = group !== "none";
  const by = group === "none" ? "issue" : group;
  const filterKey = findingGroupsKey(by, filters);
  const paging = usePaging(INITIAL_GROUPS_LIST, filterKey);
  const params = findingGroupsQueryParams(by, filters, paging.state);
  const read = useApi<FindingGroupsPage>(enabled ? FINDING_GROUPS_PATH : null, params);
  useLastPageClamp(read, paging.page, filterKey, paging.dispatch);
  return {
    read,
    page: paging.page,
    sorting: paging.state.sorting,
    setPage: paging.setPage,
    setSorting: paging.setSorting,
  };
}

/** useFindingsFacets is the filter counts for these filters (each facet's
 *  counts apply every filter but its own). */
export function useFindingsFacets(filters: FindingsFilters): ApiState<FindingsFacets> {
  return useApi<FindingsFacets>(FINDINGS_FACETS_PATH, findingsApiParams(filters));
}
