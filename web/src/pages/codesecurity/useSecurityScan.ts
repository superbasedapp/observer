import { useEffect, useRef, useState } from "react";
import { useApi } from "@/lib/useApi";
import { securityPost } from "@/lib/codeSecurityExceptions";
import { scanRunning, scanToast, type ScanJob, type ScanView } from "@/lib/codeSecurity";
import type { ScanStartBody } from "@/lib/codeSecurityApi";
import { pushToast } from "@/components/Toast";

// useSecurityScan is the Code security page's one owner of the "Scan now"
// job (GET/POST /api/security/scan): it polls while a job runs, raises one
// toast when a job this page is watching ends, and tells the caller to
// reload the posture and findings when it does. Every start and cancel
// carries the confirm token the GET minted.

const POLL_MS = 1500;

export type SecurityScan = {
  view: ScanView | null;
  loading: boolean;
  error: Error | null;
  denied: boolean;
  job: ScanJob | null;
  running: boolean;
  /** A start or cancel request is in flight. */
  sending: boolean;
  /** start begins a scan of exactly one of project, projects or all, with the chosen steps. */
  start: (body: ScanStartBody) => Promise<void>;
  startProject: (hash: string) => Promise<void>;
  startAll: () => Promise<void>;
  cancel: () => Promise<void>;
  reload: () => void;
};

export function useSecurityScan(onFinished: () => void): SecurityScan {
  const [polling, setPolling] = useState(false);
  const scan = useApi<ScanView>("/api/security/scan", undefined, [], { refreshMs: polling ? POLL_MS : 0 });
  const [sending, setSending] = useState(false);
  const job = scan.data?.job ?? null;
  const running = scanRunning(job);
  // The job id this page saw running: its end raises the toast once.
  const watched = useRef<string | null>(null);
  const finishedRef = useRef(onFinished);
  finishedRef.current = onFinished;

  useEffect(() => {
    setPolling(running);
    if (running && job) {
      watched.current = job.id;
      return;
    }
    if (job && watched.current === job.id) {
      watched.current = null;
      const t = scanToast(job);
      pushToast(t.text, t.variant);
      finishedRef.current();
    }
  }, [running, job]);

  async function send(body: Record<string, unknown>, started: boolean) {
    const token = scan.data?.confirm_token ?? "";
    setSending(true);
    try {
      const out = await securityPost<ScanJob | { ok: boolean }>("/api/security/scan", token, body);
      if (started && out && "id" in out) watched.current = out.id;
      setPolling(true);
      scan.reload();
    } catch (e: unknown) {
      pushToast(e instanceof Error ? e.message : String(e), "danger");
    } finally {
      setSending(false);
    }
  }

  return {
    view: scan.data,
    loading: scan.loading,
    error: scan.error,
    denied: scan.denied,
    job,
    running,
    sending,
    start: (body) => send({ ...body }, true),
    startProject: (hash) => send({ project: hash }, true),
    startAll: () => send({ all: true }, true),
    cancel: () => send({ cancel: true }, false),
    reload: scan.reload,
  };
}
