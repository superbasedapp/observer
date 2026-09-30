import type { FormEvent, ReactNode } from "react";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ApiError, getAuthConfig, getAuthModeHint, login } from "../api";
import type { AuthConfig } from "../api";
import { loadConsent } from "../consent";
import { AuthShell } from "../components/AuthShell";
import { Pill } from "@shared/primitives/Pill";
import { Skeleton } from "@shared/primitives/Skeleton";
import { InlineLoading } from "@shared/primitives/Spinner";
import { Button } from "@shared/primitives/Button";
import { Input } from "@shared/primitives/Input";

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
// NOTICE_TONE: one surface recipe per Notice tone.
const NOTICE_TONE: Readonly<Record<"warn" | "danger" | "neutral", string>> = {
  danger: "border-danger/40 bg-danger-soft text-fg-0",
  warn: "border-warn/40 bg-warn-soft text-fg-0",
  neutral: "border-line-2 bg-bg-2 text-fg-1",
};

function Notice({
  tone,
  title,
  children,
}: {
  tone: "warn" | "danger" | "neutral";
  title?: string;
  children?: ReactNode;
}) {
  return (
    <div
      role="status"
      className={`rounded-2 border px-3 py-2.5 text-[12.5px] leading-relaxed ${NOTICE_TONE[tone]}`}
    >
      {title && <strong className="font-semibold">{title} </strong>}
      {children}
    </div>
  );
}

// The sign-in actions are the shared primary Button, at the card's full
// width and a taller hit area.
const SIGN_IN_BUTTON = "h-10 w-full";

export function SignIn() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<SignInMode>("loading");
  const [subject, setSubject] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // The single-sign-on button's own busy state: the redirect is a full
  // navigation, so the button shows its spinner until the page unloads.
  const [redirecting, setRedirecting] = useState(false);

  // A page restored from the back/forward cache comes back with the spinner
  // still on; clear it so the button is usable again.
  useEffect(() => {
    function onPageShow(e: PageTransitionEvent) {
      if (e.persisted) setRedirecting(false);
    }
    window.addEventListener("pageshow", onPageShow);
    return () => window.removeEventListener("pageshow", onPageShow);
  }, []);

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
    setRedirecting(true);
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
    <AuthShell
      title="Sign in to Cloud Intelligence"
      step="portal"
      intro={
        <p>
          Review the sessions you upload with the{" "}
          <code className="whitespace-nowrap rounded-1 bg-bg-3 px-1 py-0.5 font-mono text-[11.5px] text-fg-1">
            observer cloud
          </code>{" "}
          CLI, and the suggested titles, tags and descriptions that come
          back.
        </p>
      }
    >
      <div className="flex flex-col gap-3">
        {mode === "loading" && (
          <div aria-busy="true" className="flex flex-col gap-3">
            {/* The shared Skeleton is near-invisible on a white light-theme
                card, so the placeholder carries a token border and the
                status line is real text, not a second skeleton bar. */}
            <Skeleton className="h-10 w-full border border-line-2" />
            <InlineLoading
              size="sm"
              label="Checking sign-in options"
              className="justify-center"
            />
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
            <Button
              variant="primary"
              className={SIGN_IN_BUTTON}
              loading={redirecting}
              onClick={onSingleSignOnClick}
            >
              {redirecting ? "Opening sign-in" : "Continue with your SuperBased account"}
            </Button>
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
                  className="text-[11.5px] font-medium text-fg-2"
                >
                  Developer subject
                </label>
                <Pill variant="neutral">local test sign-in</Pill>
              </div>
              <Input
                id="subject"
                type="text"
                autoComplete="off"
                placeholder="alice"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                disabled={busy}
              />
              <Button
                variant="primary"
                type="submit"
                loading={busy}
                className={`${SIGN_IN_BUTTON} mt-3`}
              >
                {busy ? "Signing in" : "Sign in"}
              </Button>
            </form>
          </>
        )}
      </div>
    </AuthShell>
  );
}
