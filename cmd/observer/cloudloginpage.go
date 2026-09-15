package main

import (
	"fmt"
	"net/http"
)

// cloudLoginPageVariant selects one of the fixed, fully static result pages the
// CLI login loopback listener serves after the WorkOS AuthKit redirect. Every
// variant is constant HTML: request data (query params, error descriptions) is
// NEVER interpolated into the page — the terminal receives the detailed error
// through the login flow's error channel instead. That keeps the loopback
// responder free of any reflected-content surface.
type cloudLoginPageVariant int

const (
	cloudLoginPageSuccess cloudLoginPageVariant = iota
	cloudLoginPageStateMismatch
	cloudLoginPageAuthError
	cloudLoginPageNoCode
)

// cloudLoginPageSpec is the per-variant static copy.
type cloudLoginPageSpec struct {
	status  int
	ok      bool
	title   string
	detail  string
	eyebrow string
}

var cloudLoginPageSpecs = map[cloudLoginPageVariant]cloudLoginPageSpec{
	// The "success" variant is the AUTHORIZATION-RECEIVED page, not a
	// signed-in page. It is written the moment the loopback listener takes
	// delivery of the authorization code — BEFORE the CLI exchanges that code
	// for a token and BEFORE the device exchange mints credentials, either of
	// which can still fail. Claiming "You're signed in" here would be a lie
	// often enough to matter (a rejected code, an unreachable provider, a
	// suspended account), and the terminal is where the real outcome lands.
	cloudLoginPageSuccess: {
		status:  http.StatusOK,
		ok:      true,
		eyebrow: "authorization received",
		title:   "Almost signed in",
		detail:  "This window can be closed. Return to the terminal - it is finishing the sign-in now.",
	},
	cloudLoginPageStateMismatch: {
		status:  http.StatusBadRequest,
		ok:      false,
		eyebrow: "sign-in aborted",
		title:   "Sign-in could not be completed",
		detail:  "The response did not match this sign-in attempt (state mismatch), so it was rejected. Close this window and run <code>observer cloud login</code> again.",
	},
	cloudLoginPageAuthError: {
		status:  http.StatusBadRequest,
		ok:      false,
		eyebrow: "sign-in aborted",
		title:   "Authorization was not granted",
		detail:  "The sign-in was cancelled or refused. The exact reason is shown in your terminal. Close this window and run <code>observer cloud login</code> to try again.",
	},
	cloudLoginPageNoCode: {
		status:  http.StatusBadRequest,
		ok:      false,
		eyebrow: "sign-in aborted",
		title:   "Sign-in could not be completed",
		detail:  "The redirect carried no authorization code. Close this window and run <code>observer cloud login</code> to try again.",
	},
}

// writeCloudLoginPage renders the styled loopback result page for a variant.
// The layout follows the SuperBased site theme (docs/website-design-guide.md):
// near-black base, panel card with a hairline border and a colored top rule,
// warm off-white ink, teal for success and red for failure, mono eyebrow.
// Fonts fall back to system stacks so the page renders correctly offline.
func writeCloudLoginPage(w http.ResponseWriter, v cloudLoginPageVariant) {
	spec, found := cloudLoginPageSpecs[v]
	if !found {
		spec = cloudLoginPageSpecs[cloudLoginPageNoCode]
	}
	accent, mark, markClass := "#2EC4B6", "&#10003;", "ok"
	if !spec.ok {
		accent, mark, markClass = "#E63946", "&#10005;", "err"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(spec.status)
	fmt.Fprintf(w, cloudLoginPageTemplate,
		spec.title, accent, markClass, mark, spec.eyebrow, spec.title, spec.detail)
}

// cloudLoginPageTemplate is the static page shell. Placeholders (in order):
// <title>, accent hex, mark class, mark glyph, eyebrow, heading, detail.
// All substituted values come from the constant specs above — never from the
// request.
const cloudLoginPageTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>%s - SuperBased</title>
<style>
  :root {
    --base: #0D0D12;
    --panel: #0F2238;
    --inset: #0c1c2e;
    --ink: #F5F2E8;
    --ink-dim: rgba(245, 242, 232, 0.66);
    --ink-faint: rgba(245, 242, 232, 0.45);
    --line: rgba(245, 242, 232, 0.14);
    --accent: %s;
  }
  * { box-sizing: border-box; }
  html, body { height: 100%%; }
  body {
    margin: 0;
    background: var(--base);
    background-image: radial-gradient(ellipse 80%% 60%% at 50%% -10%%, rgba(46, 196, 182, 0.08), transparent);
    color: var(--ink);
    font-family: "Space Grotesk", system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
  }
  .card {
    width: 100%%;
    max-width: 430px;
    background: var(--panel);
    border: 1px solid var(--line);
    border-top: 3px solid var(--accent);
    border-radius: 10px;
    padding: 40px 36px 32px;
    text-align: center;
  }
  .mark {
    width: 56px;
    height: 56px;
    margin: 0 auto 20px;
    border-radius: 50%%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 26px;
    line-height: 1;
  }
  .mark.ok  { background: rgba(46, 196, 182, 0.14); color: #2EC4B6; border: 1px solid rgba(46, 196, 182, 0.4); }
  .mark.err { background: rgba(230, 57, 70, 0.14);  color: #E63946; border: 1px solid rgba(230, 57, 70, 0.4); }
  .eyebrow {
    font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 11px;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: var(--accent);
    margin: 0 0 10px;
  }
  h1 {
    font-size: 24px;
    font-weight: 700;
    letter-spacing: -0.01em;
    margin: 0 0 12px;
  }
  p.detail {
    font-size: 14.5px;
    line-height: 1.6;
    color: var(--ink-dim);
    margin: 0 0 26px;
  }
  p.detail code {
    font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 13px;
    background: var(--inset);
    border: 1px solid var(--line);
    border-radius: 4px;
    padding: 1px 6px;
    color: var(--ink);
    white-space: nowrap;
  }
  .brand {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding-top: 22px;
    border-top: 1px solid var(--line);
    font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 12px;
    letter-spacing: 0.08em;
    color: var(--ink-faint);
  }
  .brand .dot {
    width: 8px;
    height: 8px;
    border-radius: 2px;
    background: #2EC4B6;
    box-shadow: 10px 0 0 0 #F4A024, 20px 0 0 0 #E63946;
    margin-right: 22px;
  }
</style>
</head>
<body>
  <main class="card">
    <div class="mark %s" aria-hidden="true">%s</div>
    <p class="eyebrow">%s</p>
    <h1>%s</h1>
    <p class="detail">%s</p>
    <div class="brand"><span class="dot"></span>SuperBased Observer</div>
  </main>
</body>
</html>
`
