# @superbased/feedback-widget

A tiny thumbs up / down widget, with an optional comment, that your end users
click on an AI answer. Their vote becomes a superbased `feedback` score on the
trace that produced the answer.

- A framework-agnostic web component, `<superbased-feedback>`, and a React
  wrapper.
- No runtime dependencies (React is an optional peer, for the wrapper only).
- Keyboard and screen-reader accessible; themeable with CSS variables.
- Apache-2.0.

## How it works, and why the browser never holds a key

```
browser                          your backend                       superbased
<superbased-feedback>  -- POST /api/feedback -->  feedback(value, {traceId, ...})  -->  machine / gateway
 (no key, no superbased URL)      (holds the SDK key)
```

The widget never talks to superbased and never holds an SDK key. It only:

1. dispatches a `superbased-feedback` DOM event with the vote, and
2. when you set `endpoint`, POSTs that same body to **your own backend**
   (same origin by default; another origin only with the `cross-origin`
   attribute; never a redirect).

Your backend calls the SDK's `feedback()` with the trace (and span) id it
rendered the answer with. The SDK key stays on your server, where the rest of
your SDK calls already run.

## Install

```bash
npm install @superbased/feedback-widget
```

It releases with the superbased SDKs, on the same version.

## Use it

Render the trace id (and, optionally, the span id) of the answer next to it.
On the server, inside the request that produced the answer:

```ts
import { getCurrentTraceId, getCurrentSpanId } from "@superbased/sdk";
const traceId = getCurrentTraceId(); // send these to the page with the answer
```

### Plain HTML

A browser cannot resolve a package name such as
`@superbased/feedback-widget/define` without a bundler. Serve the package's
`dist/` folder with your static files (here under `/vendor/feedback-widget/`)
and load its `define.js` by path; it registers `<superbased-feedback>`:

```html
<superbased-feedback
  trace-id="4bf92f3577b34da6a3ce929d0e0e4736"
  span-id="00f067aa0ba902b7"
  endpoint="/api/feedback"
  comment="optional"></superbased-feedback>

<script type="module" src="/vendor/feedback-widget/define.js"></script>
```

With a bundler (Vite, webpack, Next.js), import it by name in your client
code instead: `import "@superbased/feedback-widget/define";`.

Or register it yourself: `import { defineFeedbackElement } from
"@superbased/feedback-widget"; defineFeedbackElement();` (idempotent; a no-op
where there is no DOM, so it is safe in server-rendered code).

### React

```tsx
import { SuperbasedFeedback } from "@superbased/feedback-widget/react";

<SuperbasedFeedback
  traceId={answer.traceId}
  spanId={answer.spanId}
  endpoint="/api/feedback"
  comment="optional"
  onSent={() => console.log("thanks")}
/>;
```

### Without an endpoint

Leave `endpoint` out and handle the event yourself (or call
`event.preventDefault()` to stop the POST):

```js
el.addEventListener("superbased-feedback", (e) => myApi.sendFeedback(e.detail));
```

## Attributes

| Attribute | React prop | Default | Meaning |
|---|---|---|---|
| `trace-id` | `traceId` | required | The answer's trace (32 hex). |
| `span-id` | `spanId` | none | The answer's span (16 hex). Without it the score is trace-level. |
| `endpoint` | `endpoint` | none | Your backend's route. Same origin unless `cross-origin`. |
| `name` | `name` | `user_feedback` | The score name the widget sends. Your server decides the name it records (see "The server half"). |
| `comment` | `comment` | `off` | `off`, `optional` (a box after the vote), `required` (a thumbs-down needs a comment). |
| `token` | `token` | none | An opaque value your server rendered with the answer, passed through to your endpoint (see "Trust" below). |
| `cross-origin` | `crossOrigin` | off | Allow an `endpoint` on another origin. |
| `credentials` | `credentials` | `same-origin` | `same-origin`, `include` or `omit` for the POST. |
| `disabled` | `disabled` | off | Turns the buttons off. |
| `nonce` | `nonce` | none | Your Content Security Policy nonce, used only by browsers without constructable stylesheets (see "Content Security Policy"). |
| `question`, `label-up`, `label-down`, `comment-label`, `comment-placeholder`, `submit-label`, `skip-label`, `thanks`, `error-text`, `comment-required-text`, `comment-too-long-text` | camelCase of each | English texts | Every text the widget shows. |

Properties: `fetch` (a fetch to use instead of the global one), `value` (the
vote: `true`, `false` or `null`), `reset()`, `retry()`.

## The body and the events

The POST body, and the `detail` of the `superbased-feedback` event, use the
SDKs' field names:

```json
{ "trace_id": "4bf9...", "span_id": "00f0...", "value": false, "comment": "wrong city", "name": "user_feedback", "token": "..." }
```

| Event | When | `detail` |
|---|---|---|
| `superbased-feedback` | a vote (and its comment) is ready; cancelable | the body |
| `superbased-feedback-sent` | the POST answered 2xx | `{ payload, status }` |
| `superbased-feedback-error` | an invalid id, a refused endpoint, a network error or a non-2xx | `{ payload, status, error }` |

All three bubble and cross the shadow boundary (`composed`). The widget checks
the same rules the SDKs' `feedback()` applies (ids, name, a comment of at most
2,000 bytes) before it sends. The comment bound is in UTF-8 bytes, not
characters: a comment over it is held back with a "too long" hint while the
end user shortens it, and the vote is kept.

## The server half

Your endpoint receives the body above and calls `feedback()`. Each SDK's
snippet:

### TypeScript / Node (`@superbased/sdk`)

```ts
import express from "express";
import { feedback, init } from "@superbased/sdk";

init(); // as everywhere else in your app; the key comes from SUPERBASED_API_KEY or your machine
const app = express();
app.use(express.json());

app.post("/api/feedback", async (req, res) => {
  const { trace_id, span_id, value, comment } = req.body ?? {};
  if (typeof value !== "boolean") return res.sendStatus(400);
  // Check here that trace_id is an answer you rendered for this user (see "Trust").
  // The score name is yours, not the browser's: any page visitor can send any body.
  const r = await feedback(value, { traceId: trace_id, spanId: span_id, comment, name: "user_feedback" });
  res.sendStatus(r.ok ? 204 : 502);
});
```

If your pages use more than one widget name, accept the body's `name` only
from a list you keep on the server.

`sdk/widget/test/server.test.mjs` runs this handler against the TypeScript SDK.

### Python (`superbased-sdk`)

```python
from fastapi import FastAPI, Request, Response
import superbased_sdk as sb

sb.init()
app = FastAPI()

@app.post("/api/feedback")
async def post_feedback(request: Request) -> Response:
    body = await request.json()
    if not isinstance(body.get("value"), bool):
        return Response(status_code=400)
    # Check here that trace_id is an answer you rendered for this user (see "Trust").
    r = await sb.async_feedback(
        body["value"],
        trace_id=body.get("trace_id"),
        span_id=body.get("span_id"),
        comment=body.get("comment"),
        name="user_feedback",  # yours, not the browser's
    )
    return Response(status_code=204 if r.ok else 502)
```

Flask or Django: the same, with the synchronous `sb.feedback(...)`.

### Any other language

Send the score over OpenTelemetry (`gen_ai.evaluation.result`) or to the SDK
control API from your server; see
[superbased.app/docs/sdk/otel-any-language](https://superbased.app/docs/sdk/otel-any-language). The
browser part is the same.

## Trust

The trace id is not a secret: anyone can POST any body to your endpoint. If a
forged vote matters to you, render a `token` with the answer, for example an
HMAC of the trace id with a server-side secret, and check it in your endpoint
before calling `feedback()`. The widget passes `token` through untouched.
Rate-limit the endpoint like any other public form.

The comment is your end user's text: it is content, stored under the same
capture rules as the rest of your app's traced content (scrubbed for
secrets at ingest).

## Content Security Policy

The widget adds no inline script and no inline style. Its styles go on its
shadow root as a constructed stylesheet, which a strict `style-src` allows,
so a policy such as `default-src 'self'` needs no exception. A browser
without constructable stylesheets gets a `<style>` element instead; give the
widget your policy's nonce (`nonce="..."`) and it carries it.

## Theming

Set any of these on the element or an ancestor:

| Variable | Default | Styles |
|---|---|---|
| `--sb-feedback-font` | `inherit` | the whole widget |
| `--sb-feedback-fg` | `inherit` | text |
| `--sb-feedback-muted` | `inherit` | the question |
| `--sb-feedback-bg` | `transparent` | buttons and the comment box |
| `--sb-feedback-border` | `currentColor` | borders |
| `--sb-feedback-accent` | `#2b6cb0` | the chosen button, Send |
| `--sb-feedback-accent-fg` | `#fff` | text on the accent |
| `--sb-feedback-radius` | `0.5em` | corners |
| `--sb-feedback-gap` | `0.5em` | spacing |
| `--sb-feedback-focus` | `#2b6cb0` | the focus ring |
| `--sb-feedback-error` | `#c53030` | the error text and the hint |

```css
superbased-feedback { --sb-feedback-accent: #0f766e; --sb-feedback-radius: 999px; }
superbased-feedback::part(button) { padding: 0.4em 0.8em; }
```

Parts for deeper styling: `root`, `vote`, `question`, `button`, `up`, `down`,
`comment`, `comment-label`, `textarea`, `hint`, `submit`, `skip`, `status`.

## Accessibility

- Native `<button>`s in a labelled group, each with an accessible name and
  `aria-pressed`; 44 px minimum targets.
- The comment box has a visible label and takes focus when it opens.
  Ctrl/Cmd+Enter sends, Escape skips (when the comment is optional).
- A required comment sets `aria-required`, and a missing one `aria-invalid`
  with an announced hint.
- The result ("Thanks for your feedback.", or the error) is announced through
  a polite live region.

## Development

```bash
npm ci
npm run typecheck
npm test   # builds, then node --test (happy-dom; offline)
```

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
