import type { FormEvent, ReactNode } from "react";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ApiError, getAuthConfig, getAuthModeHint, login } from "../api";
import type { AuthConfig } from "../api";
import { loadConsent } from "../consent";
import { AuthShell } from "../components/AuthShell";
import { routerPath, safeReturnTo } from "../lib/connectModel";
import {
  AUTO_START_SECONDS,
  COUNTDOWN_ACTIONS,
  SIGN_IN_COPY,
  autoStarts,
  countdownText,
  otherVariant,
  signInErrorNotice,
  startUrl,
  type SignInVariant,
} from "../lib/signInModel";
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
// the server's own `auth_mode` wire value. The copy names the provider only
// where its own page is next (signInModel.PROVIDER_NAME, operator 2026-11-18).
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

// COUNTDOWN_RING: the countdown ring's geometry (a 40px SVG, r 17).
const COUNTDOWN_RING = { size: 40, r: 17 } as const;

/** CountdownRing is the visible countdown: the seconds left in a ring that
 * empties as they run out. Decorative (aria-hidden): the status line
 * announces the countdown once, not every second. The ring's step is a CSS
 * transition, which reduced motion turns off (motion-safe). */
function CountdownRing({ left, total }: { left: number; total: number }) {
  const { size, r } = COUNTDOWN_RING;
  const circumference = 2 * Math.PI * r;
  const offset = circumference * (1 - Math.max(0, left) / total);
  return (
    <span aria-hidden="true" className="relative inline-flex shrink-0 items-center justify-center text-accent">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth="3" className="stroke-line-2" />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          strokeWidth="3"
          stroke="currentColor"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className="motion-safe:transition-[stroke-dashoffset] motion-safe:duration-1000 motion-safe:ease-linear"
        />
      </svg>
      <span className="absolute font-mono text-[13px] font-semibold tabular-nums text-fg-0">{Math.max(0, left)}</span>
    </span>
  );
}

// The sign-in actions are the shared primary Button, at the card's full
// width and a taller hit area.
const SIGN_IN_BUTTON = "h-10 w-full";

// The page's copy per variant is lib/signInModel.ts SIGN_IN_COPY (index.html
// carries the sign-in lines for a browser with JavaScript off).

/** returnToHere reads the ?return_to= a guarded page sent the visitor with
 * (connectModel.safeReturnTo: a /portal/ path only). */
function returnToHere(): string | null {
  return safeReturnTo(new URLSearchParams(window.location.search).get("return_to"));
}

/** SignIn is the console's signed-out entry. variant "sign-in" is "/";
 * "sign-up" is "/sign-up" (create an account), which leaves for the
 * provider's sign-up screen by itself once browser sign-in is known to be on
 * (signInModel.autoStarts). Both offer the other as a visible action. */
export function SignIn({ variant = "sign-in" }: { variant?: SignInVariant }) {
  const text = SIGN_IN_COPY[variant];
  // A sign-in the server sent back here because it could not finish
  // (signInModel.signInErrorNotice, L-142).
  const returned = signInErrorNotice(window.location.search);
  const other = otherVariant(variant);
  const navigate = useNavigate();
  const [mode, setMode] = useState<SignInMode>("loading");
  const [subject, setSubject] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // The single-sign-on button's own busy state: the redirect is a full
  // navigation, so the button shows its spinner until the page unloads.
  const [redirecting, setRedirecting] = useState(false);
  // The create-an-account entry's countdown (signInModel.autoStarts): the
  // seconds left, or null when none is running (never started, or the
  // visitor chose to stay).
  const [countdown, setCountdown] = useState<number | null>(null);

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

  // Starts the hosted sign-in (or sign-up) redirect. The path is the
  // server's contract and keeps the broker name; the label the developer
  // reads does not.
  function startHosted(v: SignInVariant) {
    setRedirecting(true);
    window.location.assign(startUrl(v, returnToHere()));
  }

  // The create-an-account entry leaves by itself after a countdown that
  // says where it is going (signInModel.autoStarts), with replace so Back
  // from the provider returns to the page before this one (never to a page
  // that leaves again).
  useEffect(() => {
    if (mode === "workos" && autoStarts(variant)) {
      setCountdown(AUTO_START_SECONDS);
    }
  }, [mode, variant]);

  useEffect(() => {
    if (countdown === null) return;
    if (countdown <= 0) {
      setRedirecting(true);
      window.location.replace(startUrl(variant, returnToHere()));
      return;
    }
    const tick = window.setTimeout(() => setCountdown((c) => (c === null ? null : c - 1)), 1000);
    return () => window.clearTimeout(tick);
  }, [countdown, variant]);

  // Continue now: the same replace the countdown ends with.
  function continueNow() {
    setCountdown(null);
    setRedirecting(true);
    window.location.replace(startUrl(variant, returnToHere()));
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
      const back = returnToHere();
      navigate(back ? routerPath(back) : "/", { replace: true });
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
      title={text.title}
      step="portal"
      intro={<p>{text.lead}</p>}
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
                observer connect
              </code>
              .
            </Notice>
          </>
        )}

        {mode === "workos" && countdown !== null && (
          <>
            <div
              role="status"
              className="flex flex-col gap-2 rounded-2 border border-line-2 bg-bg-2 px-3 py-3"
            >
              {/* Announced once: the line below changes every second, so it
                  is hidden from assistive technology and this one is read. */}
              <span className="sr-only">{countdownText(AUTO_START_SECONDS)}</span>
              <div className="flex items-center gap-3" aria-hidden="true">
                <CountdownRing left={countdown} total={AUTO_START_SECONDS} />
                <p className="text-[13px] font-semibold leading-snug text-fg-0">{countdownText(countdown)}</p>
              </div>
              <p className="text-[12px] leading-relaxed text-fg-2">{text.provider}</p>
            </div>
            <Button variant="primary" className={SIGN_IN_BUTTON} loading={redirecting} onClick={continueNow}>
              {redirecting ? text.busy : COUNTDOWN_ACTIONS.now}
            </Button>
            <Button
              variant="secondary"
              className={SIGN_IN_BUTTON}
              disabled={redirecting}
              onClick={() => setCountdown(null)}
            >
              {COUNTDOWN_ACTIONS.stay}
            </Button>
          </>
        )}

        {mode === "workos" && countdown === null && (
          <>
            {returned && (
              <Notice tone="warn" title={returned.title}>
                {returned.body}
              </Notice>
            )}
            {pending && (
              <Notice tone="warn" title="Sign-in is not yet available.">
                {pending}
              </Notice>
            )}
            <Button
              variant="primary"
              className={SIGN_IN_BUTTON}
              loading={redirecting}
              onClick={() => startHosted(variant)}
            >
              {redirecting ? text.busy : text.primary}
            </Button>
            <div className="flex flex-col items-center gap-1.5 pt-1">
              <span className="text-[11.5px] text-fg-3">{text.otherPrompt}</span>
              <Button
                variant="secondary"
                className={SIGN_IN_BUTTON}
                disabled={redirecting}
                onClick={() => startHosted(other)}
              >
                {text.otherAction}
              </Button>
            </div>
            <p className="text-center text-[11.5px] leading-relaxed text-fg-3">
              {text.provider} {text.sendsNothing}
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
