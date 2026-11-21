/**
 * React wrapper for `<superbased-feedback>` (React 18 and 19).
 *
 * ```tsx
 * import { SuperbasedFeedback } from "@superbased/feedback-widget/react";
 *
 * <SuperbasedFeedback traceId={answer.traceId} spanId={answer.spanId} endpoint="/api/feedback" comment="optional" />
 * ```
 *
 * It renders the custom element (registering it on first mount) and wires
 * the callbacks to its events. The browser still never holds an SDK key:
 * the element posts to `endpoint` on your own backend, which calls the
 * SDK's `feedback()`.
 */
import * as React from "react";

import {
  defineFeedbackElement,
  ERROR_EVENT,
  FEEDBACK_EVENT,
  SENT_EVENT,
  TAG,
  type CommentMode,
  type FeedbackElement,
  type FeedbackPayload,
} from "./index.js";

export interface SuperbasedFeedbackProps {
  /** The trace the answer belongs to (32 hex), as your server rendered it. */
  traceId: string;
  /** The answer's span (16 hex). */
  spanId?: string;
  /** Your backend's route (same origin unless `crossOrigin`). Without it, only `onFeedback` runs. */
  endpoint?: string;
  /** The score name (default `user_feedback`). */
  name?: string;
  comment?: CommentMode;
  /** An opaque value your server rendered with the answer, passed through to your endpoint. */
  token?: string;
  crossOrigin?: boolean;
  credentials?: "same-origin" | "include" | "omit";
  disabled?: boolean;
  question?: string;
  labelUp?: string;
  labelDown?: string;
  commentLabel?: string;
  commentPlaceholder?: string;
  submitLabel?: string;
  skipLabel?: string;
  thanks?: string;
  errorText?: string;
  commentRequiredText?: string;
  commentTooLongText?: string;
  /** The nonce of a nonce-based CSP, for browsers without constructable stylesheets. */
  nonce?: string;
  /** Called with the payload before the POST; call `event.preventDefault()` to skip the POST. */
  onFeedback?: (payload: FeedbackPayload, event: CustomEvent<FeedbackPayload>) => void;
  onSent?: (detail: { payload: FeedbackPayload; status: number }) => void;
  onError?: (detail: { payload: FeedbackPayload; status: number; error: string }) => void;
  /** A fetch to use instead of the global one. */
  fetch?: FeedbackElement["fetch"];
  className?: string;
  style?: React.CSSProperties;
}

const ATTRS: Array<[keyof SuperbasedFeedbackProps, string]> = [
  ["traceId", "trace-id"],
  ["spanId", "span-id"],
  ["endpoint", "endpoint"],
  ["name", "name"],
  ["comment", "comment"],
  ["token", "token"],
  ["credentials", "credentials"],
  ["question", "question"],
  ["labelUp", "label-up"],
  ["labelDown", "label-down"],
  ["commentLabel", "comment-label"],
  ["commentPlaceholder", "comment-placeholder"],
  ["submitLabel", "submit-label"],
  ["skipLabel", "skip-label"],
  ["thanks", "thanks"],
  ["errorText", "error-text"],
  ["commentRequiredText", "comment-required-text"],
  ["commentTooLongText", "comment-too-long-text"],
  ["nonce", "nonce"],
];

/** The element's attributes for a set of props (exported for tests and server rendering). */
export function feedbackAttributes(props: SuperbasedFeedbackProps): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [prop, attr] of ATTRS) {
    const v = props[prop];
    if (typeof v === "string" && v !== "") out[attr] = v;
  }
  if (props.crossOrigin) out["cross-origin"] = "";
  if (props.disabled) out.disabled = "";
  return out;
}

export function SuperbasedFeedback(props: SuperbasedFeedbackProps): React.ReactElement {
  const ref = React.useRef<FeedbackElement | null>(null);
  const cb = React.useRef(props);
  cb.current = props;
  React.useEffect(() => {
    defineFeedbackElement();
  }, []);
  React.useEffect(() => {
    const el = ref.current;
    if (!el) return;
    el.fetch = props.fetch ?? null;
  }, [props.fetch]);
  React.useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const onFeedback = (e: Event) => cb.current.onFeedback?.((e as CustomEvent<FeedbackPayload>).detail, e as CustomEvent<FeedbackPayload>);
    const onSent = (e: Event) => cb.current.onSent?.((e as CustomEvent).detail);
    const onError = (e: Event) => cb.current.onError?.((e as CustomEvent).detail);
    el.addEventListener(FEEDBACK_EVENT, onFeedback);
    el.addEventListener(SENT_EVENT, onSent);
    el.addEventListener(ERROR_EVENT, onError);
    return () => {
      el.removeEventListener(FEEDBACK_EVENT, onFeedback);
      el.removeEventListener(SENT_EVENT, onSent);
      el.removeEventListener(ERROR_EVENT, onError);
    };
  }, []);
  // `class` (not className): React passes custom-element props through as attributes.
  const attrs: Record<string, unknown> = { ...feedbackAttributes(props), ref };
  if (props.className) attrs.class = props.className;
  if (props.style) attrs.style = props.style;
  return React.createElement(TAG, attrs);
}
