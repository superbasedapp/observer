import type { FormEvent, ReactNode } from "react";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ApiError, getAuthConfig, getAuthModeHint, login } from "../api";
import type { AuthConfig } from "../api";
import { loadConsent } from "../consent";
import { BrandLockup } from "../components/BrandMark";
import { Pill } from "@shared/primitives/Pill";
import { Skeleton } from "@shared/primitives/Skeleton";

// SignInMode is the fully-resolved decision for what this page renders. It
// starts "loading" while /portal/api/auth-config is in flight and settles
// into exactly one of the other three once we know the deployment's actual
// auth surface (or, on a 404 degrade, the cached hint from a prior sign-in).
//
// The union members keep the internal broker name (WorkOS) because they mirror
// the server's own `auth_mode` wire value; NOTHING here is user-visible. Every
// string an individual developer reads is vendor-neutral by policy.
type SignInMode = "loading" | "workos" | "dev" | "workos-disabled";

/** hintMode is the 404-degrade fallback for servers that predate the
 * auth-config endpoint: the last confirmed auth_mode cached in this browser
 * from a previous sign-in, or the single-sign-on button by default for a brand
 * new visitor - the honest production posture. */
function hintMode(): SignInMode {
  return getAuthModeHint() === "dev" ? "dev" : "workos";
}

function resolveMode(config: AuthConfig): SignInMode {
  if (config.auth_mode === "dev") {
    return "dev";
  }
  return config.workos_browser_enabled ? "workos" : "workos-disabled";
}

// Notice is the page's one message surface: the 501 "pending" path, the
// dev-auth error path, and the "not enabled here" notice all render through
// it, styled from the shared semantic tokens (no hand-rolled colors).
function Notice({
  tone,
  title,
  children,
}: {
  tone: "warn" | "danger" | "neutral";
  title?: string;
  children?: ReactNode;
}) {
  const toneClass =
    tone === "danger"
      ? "border-danger/40 bg-danger-soft text-fg-0"
      : tone === "warn"
        ? "border-warn/40 bg-warn-soft text-fg-0"
        : "border-line-2 bg-bg-2 text-fg-1";
  return (
    <div
      role="status"
      className={`rounded-2 border px-3 py-2.5 text-[12.5px] leading-relaxed ${toneClass}`}
    >
      {title && <strong className="font-semibold">{title} </strong>}
      {children}
    </div>
  );
}

const BUTTON_BASE =
  "inline-flex h-10 w-full items-center justify-center rounded-2 text-[13px] font-semibold transition-colors duration-150 ease-smooth focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)] disabled:cursor-default disabled:opacity-60";

const PRIMARY_BUTTON = `${BUTTON_BASE} bg-accent text-accent-on hover:bg-accent-strong`;

export function SignIn() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<SignInMode>("loading");
  const [subject, setSubject] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let live = true;
    getAuthConfig()
      .then((config) => {
        if (live) setMode(resolveMode(config));
      })
      .catch(() => {
        // 404 (server predates this endpoint) and any other failure (network
        // error, 5xx) both degrade the same honest way: never hard-block the
        // sign-in page on this probe.
        if (live) setMode(hintMode());
      });
    return () => {
      live = false;
    };
  }, []);

  // Starts the hosted single-sign-on redirect. The path is the server's
  // contract and keeps the broker name; the label the developer reads does not.
  function onSingleSignOnClick() {
    window.location.assign("/portal/auth/workos/start");
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setPending(null);
    if (subject.trim().length === 0) {
      setError("Enter a developer subject.");
      return;
    }
    setBusy(true);
    try {
      await login(subject.trim());
      // Load this account's consent state before routing: "/" decides between
      // the consent screen and the app from it, and the login broadcast does
      // not deliver to the tab that sent it, so this tab has to fetch its own.
      await loadConsent();
      navigate("/", { replace: true });
    } catch (err) {
      if (err instanceof ApiError && err.status === 501) {
        setPending(err.message);
      } else if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("Sign-in failed.");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="relative flex min-h-screen w-full items-center justify-center overflow-x-hidden bg-bg-0 px-4 py-10">
      {/* Ambient wash, drawn from the accent token so it flips with the
          theme. Purely decorative. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 bg-[radial-gradient(44rem_26rem_at_50%_44%,var(--accent-soft),transparent_70%)]"
      />

      <main className="relative w-full max-w-[420px]">
        <section className="rounded-3 border border-line-2 bg-bg-1 p-6 shadow-2 sm:p-8">
          <div className="flex flex-col items-center gap-3 text-center">
            <BrandLockup size={30} />
            <h1 className="text-[19px] font-semibold leading-tight tracking-[-0.02em] text-fg-0">
              Sign in to Cloud Intelligence
            </h1>
            <p className="text-[12.5px] leading-relaxed text-fg-2">
              Review the sessions you upload with the{" "}
              <code className="whitespace-nowrap rounded-1 bg-bg-3 px-1 py-0.5 font-mono text-[11.5px] text-fg-1">
                observer cloud
              </code>{" "}
              CLI, and the suggested titles, tags and descriptions that come
              back.
            </p>
          </div>

          <div className="mt-6 flex flex-col gap-3">
            {mode === "loading" && (
              <div aria-busy="true" className="flex flex-col gap-3">
                {/* The shared Skeleton is near-invisible on a white light-theme
                    card, so the placeholder carries a token border and the
                    status line is real text, not a second skeleton bar. */}
                <Skeleton className="h-10 w-full border border-line-2" />
                <p className="text-center text-[11.5px] text-fg-3">
                  Checking sign-in options...
                </p>
              </div>
            )}

            {mode === "workos-disabled" && (
              <>
                <div className="flex justify-center">
                  <Pill variant="warn">browser sign-in off</Pill>
                </div>
                <Notice tone="neutral">
                  Browser sign-in is not enabled yet for this deployment. You
                  can still sign in from your terminal with{" "}
                  <code className="font-mono text-[11.5px] text-fg-0">
                    observer cloud login
                  </code>
                  .
                </Notice>
              </>
            )}

            {mode === "workos" && (
              <>
                {pending && (
                  <Notice tone="warn" title="Sign-in is not yet available.">
                    {pending}
                  </Notice>
                )}
                <button
                  className={PRIMARY_BUTTON}
                  type="button"
                  onClick={onSingleSignOnClick}
                >
                  Continue with your SuperBased account
                </button>
                <p className="text-center text-[11.5px] leading-relaxed text-fg-3">
                  Single sign-on opens in this tab. Signing in uploads nothing
                  from your machine.
                </p>
              </>
            )}

            {mode === "dev" && (
              <>
                {pending && (
                  <Notice tone="warn" title="Dev sign-in is not available here.">
                    {pending}
                  </Notice>
                )}
                {error && <Notice tone="danger">{error}</Notice>}
                <form onSubmit={onSubmit} className="flex flex-col gap-1">
                  <div className="flex items-center justify-between gap-2">
                    <label
                      htmlFor="subject"
                      className="m-0 text-[11.5px] font-medium text-fg-2"
                    >
                      Developer subject
                    </label>
                    <Pill variant="neutral">local test sign-in</Pill>
                  </div>
                  <input
                    id="subject"
                    type="text"
                    autoComplete="off"
                    placeholder="alice"
                    value={subject}
                    onChange={(e) => setSubject(e.target.value)}
                    disabled={busy}
                  />
                  <button
                    className={`${PRIMARY_BUTTON} mt-3`}
                    type="submit"
                    disabled={busy}
                  >
                    {busy ? "Signing in..." : "Sign in"}
                  </button>
                </form>
              </>
            )}
          </div>
        </section>

        <p className="mt-4 text-center text-[11.5px] leading-relaxed text-fg-3">
          Nothing leaves your machine until you preview it and approve it.{" "}
          <a
            className="text-fg-2 underline decoration-line-3 underline-offset-2 transition-colors hover:text-fg-0"
            href="https://superbased.app/privacy"
            target="_blank"
            rel="noreferrer"
          >
            Privacy
          </a>
        </p>
      </main>
    </div>
  );
}
