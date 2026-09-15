import { useCallback, useEffect, useState, type ReactNode } from "react";
import { ApiError, fetchJSON } from "@/lib/api";
import { clearRemoteAuthLost, isRemoteAuthLost, onRemoteAuthLost } from "@/lib/authLoss";
import { isRemoteView, setRemoteCSRF } from "@/lib/remote";

// RemotePairingGate completes the "open the pairing link on your phone" flow.
// A pairing URL is `https://<tailnet-host>/#pair=<encoded-secret>` — the secret
// rides the URL FRAGMENT (never sent to the server as a query, never logged).
// The device that opens it must exchange that secret for a device-session
// cookie by POSTing it to /api/remote/pair (Public, body-only); without this
// handshake every View API call is anonymous and 401s. The gate runs ONCE on
// load: if a `#pair=` fragment is present it captures + strips it, pairs, and
// reloads so the whole app re-fetches authenticated. With no fragment (the
// local owner dashboard, or an already-paired device) it is a transparent
// pass-through.

// takePairingSecret reads the `#pair=<secret>` fragment and IMMEDIATELY strips
// it from the URL + history (defence: the secret must never linger in the
// address bar, back button, or a copied link). Returns null when absent.
function takePairingSecret(): string | null {
  const m = /^#pair=(.+)$/.exec(window.location.hash);
  if (!m) return null;
  const secret = m[1];
  history.replaceState(null, "", window.location.pathname + window.location.search);
  return secret;
}

type PairState = "pairing" | "error";

// EXPIRED_TITLE / EXPIRED_BODY are the copy for the full-screen prompt shown
// when a remote-paired device's session is confirmed gone. It replaces the
// whole app rather than sitting behind a half-rendered dashboard, because with
// no session EVERY panel is empty and the old behaviour ("api 401 …" strings in
// a working-looking shell) read as a broken product.
const EXPIRED_TITLE = "Session expired - pair this device again";
const EXPIRED_BODY =
  "This device's secure session with your SuperBased dashboard has ended, so it can't load your data. On the host machine open Remote → Pair a device, then scan the QR code (or open the pairing link) here to sign back in.";

export function RemotePairingGate({ children }: { children: ReactNode }) {
  // Capture the secret during the first render pass (before any data fetch
  // fires), so a paired device never flashes anonymous 401s.
  const [secret] = useState<string | null>(takePairingSecret);
  const [state, setState] = useState<PairState | null>(secret ? "pairing" : null);
  const [msg, setMsg] = useState("");
  // Central auth-loss detection: the API layer confirms the loss once (a single
  // /api/remote/whoami probe, shared by every concurrent failing request) and
  // latches it; this gate is the ONE place that renders it, so a hundred failed
  // calls produce one prompt instead of a hundred error strings.
  const [authLost, setAuthLost] = useState(isRemoteAuthLost);
  useEffect(() => {
    // Loopback (owner-local) dashboards never authenticate; the latch is never
    // set there, and not subscribing makes that immunity structural.
    if (!isRemoteView()) return;
    return onRemoteAuthLost(() => setAuthLost(true));
  }, []);

  useEffect(() => {
    if (!secret) return;
    let cancelled = false;
    (async () => {
      try {
        const paired = await fetchJSON<{ csrf?: string }>("/api/remote/pair", undefined, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ secret }),
        });
        setRemoteCSRF(paired.csrf || "");
        if (cancelled) return;
        // The device-session cookie is now set. Reload so every useApi hook
        // re-fetches authenticated (the fragment is already stripped).
        window.location.reload();
      } catch (e) {
        if (cancelled) return;
        setState("error");
        // 409 is the device-cap refusal: the link is fine, there is simply no
        // free slot, and the remedy is a revoke — not a fresh link.
        setMsg(
          e instanceof ApiError && e.status === 409
            ? "This host already has the maximum number of paired devices. On the host dashboard open Remote → Paired devices, revoke one you no longer use, then open this pairing link again."
            : "This pairing link didn't work - it may have expired or been rotated. Generate a fresh pairing link on the host dashboard (Remote → Enable / Rotate) and open it again.",
        );
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [secret]);

  useEffect(() => {
    if (secret || !isRemoteView()) return;
    let cancelled = false;
    (async () => {
      const who = await fetchJSON<{ authenticated?: boolean; csrf?: string }>(
        "/api/remote/whoami",
      ).catch(() => null);
      if (cancelled) return;
      setRemoteCSRF(who?.authenticated ? who.csrf || "" : "");
    })();
    return () => {
      cancelled = true;
    };
  }, [secret]);

  if (state === "pairing") {
    return (
      <PairingScreen
        title="Pairing this device…"
        body="Securely linking to your SuperBased dashboard over your tailnet."
      />
    );
  }
  if (state === "error") {
    return <PairingScreen title="Couldn't pair this device" body={msg} tone="error" />;
  }
  if (authLost) {
    return (
      <PairingScreen
        title={EXPIRED_TITLE}
        body={EXPIRED_BODY}
        tone="error"
        action={<RecheckButton onStillPaired={() => setAuthLost(false)} />}
      />
    );
  }
  return <>{children}</>;
}

// RecheckButton lets the device re-ask whether it is paired, so a session that
// came back (re-paired in another tab, or a transient server-side blip) clears
// the prompt without a reload. It is the only ACTION available here: the
// pairing secret arrives as a fresh link from the host, never from this screen.
function RecheckButton({ onStillPaired }: { onStillPaired: () => void }) {
  const [busy, setBusy] = useState(false);
  const [stillGone, setStillGone] = useState(false);
  const recheck = useCallback(async () => {
    setBusy(true);
    setStillGone(false);
    const who = await fetchJSON<{ authenticated?: boolean; csrf?: string }>(
      "/api/remote/whoami",
    ).catch(() => null);
    setBusy(false);
    if (who?.authenticated) {
      setRemoteCSRF(who.csrf || "");
      clearRemoteAuthLost();
      onStillPaired();
      return;
    }
    setStillGone(true);
  }, [onStillPaired]);
  return (
    <div className="space-y-2">
      <button
        type="button"
        onClick={recheck}
        disabled={busy}
        className="rounded-2 border border-line-2 bg-bg-2 px-3 py-1 text-[12px] text-fg-1 hover:bg-bg-3 disabled:opacity-60"
      >
        {busy ? "Checking…" : "Check again"}
      </button>
      {stillGone && (
        <div className="text-[11.5px] text-fg-3">
          Still not paired. Open a fresh pairing link from the host dashboard.
        </div>
      )}
    </div>
  );
}

function PairingScreen({
  title,
  body,
  tone = "neutral",
  action,
}: {
  title: string;
  body: string;
  tone?: "neutral" | "error";
  action?: ReactNode;
}) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-bg-1 p-6">
      <div className="w-full max-w-sm space-y-3 rounded-3 border border-line-2 bg-bg-2 p-6 text-center">
        <div
          className={
            tone === "error"
              ? "text-[13px] font-semibold text-danger"
              : "text-[13px] font-semibold text-fg-1"
          }
        >
          {title}
        </div>
        {tone === "neutral" && (
          <div className="mx-auto h-6 w-6 animate-spin rounded-full border-2 border-line-2 border-t-accent" />
        )}
        <p className="text-[12px] leading-relaxed text-fg-3">{body}</p>
        {action}
      </div>
    </div>
  );
}
