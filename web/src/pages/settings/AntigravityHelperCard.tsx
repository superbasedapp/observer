import { useEffect, useState } from "react";
import { Tooltip } from "@/components/primitives";

// AntigravityHelperCard — the Windows bridge helper card from legacy
// SPA (tmp/legacy/index.html:3100-3133). Antigravity stores its
// session protobufs under %APPDATA% on Windows; when observer runs
// inside WSL2 the files are reachable via /mnt/c/, but reads can hit
// permissions issues. The "bridge" is a tiny Windows-side helper
// binary that proxies file reads over a localhost socket — when
// NetworkRecovery=local is enabled, the adapter falls back to it.
//
// The card HEAD-probes /api/admin/antigravity-bridge.exe on mount.
// When the backend ships the binary (every `make build` does, via the
// Makefile's GOOS=windows cross-build) the card renders a one-click
// download. When it doesn't, the card explains exactly which command
// produces the binary on this install.

const ENDPOINT = "/api/admin/antigravity-bridge.exe";

type Probe =
  | { state: "loading" }
  | { state: "available"; sizeBytes: number }
  | { state: "missing"; message?: string };

export function AntigravityHelperCard() {
  const [probe, setProbe] = useState<Probe>({ state: "loading" });

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(ENDPOINT, { method: "HEAD" });
        if (cancelled) return;
        if (res.ok) {
          const len = Number(res.headers.get("Content-Length") ?? "0");
          setProbe({
            state: "available",
            sizeBytes: Number.isFinite(len) ? len : 0,
          });
          return;
        }
        if (res.status === 404) {
          // Try to surface the server's helpful 404 body via GET — HEAD
          // strips the body. Cheap second roundtrip for the error path.
          let message: string | undefined;
          try {
            const r2 = await fetch(ENDPOINT, { method: "GET" });
            if (!r2.ok) message = (await r2.text()).trim();
          } catch {
            // Best-effort; fall through to the static missing copy.
          }
          if (!cancelled) setProbe({ state: "missing", message });
          return;
        }
        if (!cancelled)
          setProbe({
            state: "missing",
            message: `bridge probe returned HTTP ${res.status}`,
          });
      } catch (e) {
        if (!cancelled)
          setProbe({
            state: "missing",
            message: e instanceof Error ? e.message : String(e),
          });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <section className="mt-6 rounded-3 border border-line-2 bg-bg-1 p-4">
      <header className="flex items-baseline justify-between gap-3 pb-2">
        <h4 className="text-[13px] font-semibold text-fg-0">
          Windows bridge helper
        </h4>
        <span className="rounded-pill border border-info/30 bg-info-soft px-2 py-0.5 text-[10px] font-semibold lowercase text-info">
          WSL2 users
        </span>
      </header>
      <p className="text-[11.5px] leading-relaxed text-fg-2">
        When observer runs inside WSL2 but Antigravity stores its session
        protobufs on the Windows side (under{" "}
        <code className="rounded-1 bg-bg-3 px-1 py-0.5 font-mono text-[11px] text-fg-1">
          %APPDATA%\Google\Antigravity
        </code>
        ), <strong className="text-fg-0">NetworkRecovery=local</strong>{" "}
        falls back to a tiny Windows-side helper that proxies file reads over
        a localhost socket. Without this, observer reads only see what
        <code className="ml-1 rounded-1 bg-bg-3 px-1 py-0.5 font-mono text-[11px] text-fg-1">
          /mnt/c/
        </code>{" "}
        exposes and can mis-handle some lock states.
      </p>

      <DownloadStrip probe={probe} />

      <details className="mt-3 group">
        <summary className="cursor-pointer text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3 hover:text-fg-1">
          Manual setup steps
          <span className="ml-1 text-fg-4 group-open:hidden">+</span>
          <span className="ml-1 hidden text-fg-4 group-open:inline">−</span>
        </summary>
        <ol className="mt-3 list-decimal space-y-1 pl-5 text-[11.5px] leading-relaxed text-fg-2">
          <li>
            Build the bridge helper on the Windows side:{" "}
            <code className="rounded-1 bg-bg-3 px-1 py-0.5 font-mono text-[11px] text-fg-1">
              make antigravity-bridge.exe
            </code>{" "}
            (it cross-builds from the same repo).
          </li>
          <li>
            Copy{" "}
            <code className="rounded-1 bg-bg-3 px-1 py-0.5 font-mono text-[11px] text-fg-1">
              bin/antigravity-bridge.exe
            </code>{" "}
            to the Windows host and run it once - the helper listens on{" "}
            <code className="rounded-1 bg-bg-3 px-1 py-0.5 font-mono text-[11px] text-fg-1">
              127.0.0.1:18801
            </code>{" "}
            and keeps a small file-read cache.
          </li>
          <li>
            Set the field above to{" "}
            <code className="rounded-1 bg-bg-3 px-1 py-0.5 font-mono text-[11px] text-fg-1">
              local
            </code>{" "}
            and restart{" "}
            <code className="rounded-1 bg-bg-3 px-1 py-0.5 font-mono text-[11px] text-fg-1">
              observer serve
            </code>
            .
          </li>
        </ol>
      </details>

      <p className="mt-3 text-[10.5px] text-fg-3">
        macOS / Linux native installs don't need this - the adapter reads
        directly from the local filesystem.
      </p>
    </section>
  );
}

function DownloadStrip({ probe }: { probe: Probe }) {
  if (probe.state === "loading") {
    return (
      <div className="mt-3 flex items-center gap-2 rounded-3 border border-line-2 bg-bg-2 px-3 py-2 text-[11px] text-fg-3">
        <span className="inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-fg-3" />
        Checking bridge availability…
      </div>
    );
  }
  if (probe.state === "available") {
    return (
      <div className="mt-3 flex flex-wrap items-center justify-between gap-3 rounded-3 border border-success/40 bg-success-soft/40 px-3 py-2.5">
        <div className="text-[11.5px] text-fg-1">
          <strong className="text-fg-0">antigravity-bridge.exe</strong> is
          available on this install ({fmtBytes(probe.sizeBytes)}). Download
          it, copy to the Windows host, and run once.
        </div>
        <Tooltip content="Stream antigravity-bridge.exe from the dashboard daemon" maxWidth={320}>
          <a
            href={ENDPOINT}
            download="antigravity-bridge.exe"
            className="inline-flex items-center gap-1.5 rounded-2 border border-accent bg-accent px-3 py-1.5 text-[11px] font-semibold text-accent-on hover:opacity-90"
          >
            <DownloadIcon />
            Download .exe
          </a>
        </Tooltip>
      </div>
    );
  }
  return (
    <div className="mt-3 rounded-3 border border-warn/40 bg-warn-soft/40 px-3 py-2.5 text-[11.5px] leading-relaxed text-fg-1">
      <div className="flex items-baseline gap-2">
        <span className="font-semibold text-fg-0">
          antigravity-bridge.exe is not shipped on this install.
        </span>
      </div>
      <p className="mt-1 text-[11px] text-fg-2">
        Rebuild observer with{" "}
        <code className="rounded-1 bg-bg-3 px-1 py-0.5 font-mono text-[11px] text-fg-1">
          make build
        </code>{" "}
        to produce{" "}
        <code className="rounded-1 bg-bg-3 px-1 py-0.5 font-mono text-[11px] text-fg-1">
          bin/antigravity-bridge.exe
        </code>
        , or set{" "}
        <code className="rounded-1 bg-bg-3 px-1 py-0.5 font-mono text-[11px] text-fg-1">
          $OBSERVER_ANTIGRAVITY_BRIDGE
        </code>{" "}
        to point at an existing build, then restart{" "}
        <code className="rounded-1 bg-bg-3 px-1 py-0.5 font-mono text-[11px] text-fg-1">
          observer dashboard
        </code>
        .
      </p>
      {probe.message && (
        <p className="mt-1.5 font-mono text-[10.5px] text-fg-3">
          probe: {probe.message}
        </p>
      )}
    </div>
  );
}

function fmtBytes(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return "unknown size";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function DownloadIcon() {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 16 16"
      fill="none"
      aria-hidden
    >
      <path
        d="M8 2v8m0 0l-3-3m3 3l3-3M3 13h10"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
