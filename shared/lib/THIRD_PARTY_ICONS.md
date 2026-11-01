# Third-party icon geometry

The tool, model-family, host and identity-provider marks in `toolLogos.tsx`
and `brandMarks.tsx` are generated from the sources below. The marks are
trademarks of their respective owners. They are used only to identify the
product, model or service an integration talks to, and do not imply
endorsement.

## Lobe Icons (`@lobehub/icons-static-svg` 1.95.1)

MIT License. Copyright (c) LobeHub. https://github.com/lobehub/lobe-icons

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Simple Icons (`simple-icons` 16.33.0)

CC0 1.0 Universal (public domain dedication). https://simpleicons.org
Brand guidelines and per-icon source links are recorded in the package's
`data/simple-icons.json`. Used for: claude-code, opencode, cursor, pi, zed,
okta.

## Vendor-published files

- Factory (droid): the pinwheel from https://factory.ai/favicon.svg
- Prime Intellect (prime-agent): the mark from the primeintellect.ai logo SVG
- Autohand (autohand): the ring grid from https://autohand.ai/logos/ours/autohand-logo-dark.svg
- IBM Bob (ibm-bob): the robot mark from https://bob.ibm.com/icon.svg (not the IBM logo)
- Deep Agents (deepagents-code): the "D" from the langchain-ai/deepagents `.github/images/logo-dark.svg` (MIT repo)
- DimCode (dimcode): the block mark in the https://dimcode.dev header
- Kimchi (kimchi): https://kimchi.dev/favicon.svg
- Stakpak (stakpak): `icons/stakpak.svg` of github.com/stakpak/zed-stakpak-agent-server (Apache-2.0)
- Dirac (dirac): the rule, stem and dot are from https://dirac.run/static/images/dirac.svg (2026-10-22; the vendor file draws its delta as an SVG `<text>` glyph, so the delta itself is outlined from Noto Sans Italic, SIL OFL 1.1, one of the fonts in the vendor's own font stack; the navy tile and amber accent are not used)
- VT Code (vtcode): the V polygon of `resources/icons/vtcode.svg` in github.com/vinhnx/vtcode (Apache-2.0 repo; the V glyph itself derives from kudakurage's LigatureSymbols, OFL), the same mark as the favicon of https://vtcode.vinhnx.chatgpt.site/ (2026-10-22; tan tile dropped, outline filled)
- Snowflake (cortex-code) and CodeBuddy (codebuddy) come from the Lobe Icons set above.

## Redrawn from vendor icons

Aider (pixel "a"), Crush (pixel heart), Freebuff (nested F), and Open
Interpreter (ring). Each is redrawn on a grid from the vendor's official
raster or SVG icon.

The per-key source ledger (which set each tool, model-family, host and
identity-provider mark comes from) is `design/brand-icons/NOTES.md`; the
generators that write `toolLogos.tsx`, `brandMarks.tsx` and `modelFamilies.ts`
live in `design/brand-icons/`.

## Original drawings

The auto-routed, SAML, OIDC and email/password glyphs, the surface pips, and
the empty-state illustrations.
