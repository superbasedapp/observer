package sharecard

// svgTemplateSrc is the static text/template for the 1200×630 social card. It
// references only self-formatted numerics and pre-XML-escaped strings from
// svgView, so the template itself does no escaping. System fonts only; no
// external <image>, <link>, or font resources.
const svgTemplateSrc = `<svg xmlns="http://www.w3.org/2000/svg" width="{{.W}}" height="{{.H}}" viewBox="0 0 {{.W}} {{.H}}" font-family="-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#10131B"/>
      <stop offset="1" stop-color="{{.Colors.Base}}"/>
    </linearGradient>
  </defs>

  <rect x="0" y="0" width="{{.W}}" height="{{.H}}" fill="url(#bg)"/>
  <rect x="0" y="0" width="{{.W}}" height="6" fill="{{.Colors.Gold}}"/>
  <rect x="24" y="24" width="{{sub .W 48}}" height="{{sub .H 48}}" rx="20" fill="none" stroke="{{.Colors.Border}}" stroke-width="1.5"/>

  <!-- header -->
  <rect x="72" y="62" width="24" height="24" rx="7" fill="{{.Colors.Gold}}"/>
  <rect x="79" y="69" width="10" height="10" rx="3" fill="{{.Colors.Base}}"/>
  <text x="110" y="82" fill="{{.Colors.Ink}}" font-size="22" font-weight="700" letter-spacing="1.5">SUPERBASED OBSERVER</text>
  <text x="1128" y="82" fill="{{.Colors.Muted}}" font-size="22" text-anchor="end">{{.Period}}</text>

  <!-- hero: total -->
  <text x="72" y="176" fill="{{.Colors.Muted}}" font-size="20" font-weight="600" letter-spacing="1.5">{{.TotalLabel}}</text>
  <text x="72" y="270" fill="{{.Colors.Gold}}" font-size="88" font-weight="800" font-family="ui-monospace,'SF Mono',Menlo,Consolas,monospace">{{.Total}}</text>
  {{if .HasTurns}}<text x="74" y="308" fill="{{.Colors.Muted}}" font-size="22">across {{.TurnCount}} model turns</text>{{end}}

  <!-- hero: cache-read share -->
  {{if .HasCache}}
  <text x="680" y="176" fill="{{.Colors.Muted}}" font-size="20" font-weight="600" letter-spacing="1.5">CACHE-READ SHARE</text>
  <text x="680" y="270" fill="{{.Colors.Teal}}" font-size="88" font-weight="800" font-family="ui-monospace,'SF Mono',Menlo,Consolas,monospace">{{.CacheShare}}</text>
  <text x="682" y="308" fill="{{.Colors.Muted}}" font-size="22">of input tokens from cache</text>
  {{end}}

  <line x1="72" y1="328" x2="1128" y2="328" stroke="{{.Colors.Border}}" stroke-width="1.5"/>

  {{if .HasEmpty}}
  <text x="600" y="470" fill="{{.Colors.Muted}}" font-size="30" text-anchor="middle">{{.EmptyNote}}</text>
  {{else}}
  <!-- left column: top models -->
  {{if .HasModels}}
  <text x="{{.ModelX}}" y="{{.ModelHeadingY}}" fill="{{.Colors.Muted}}" font-size="18" font-weight="700" letter-spacing="2">TOP MODELS</text>
  {{range .Models}}
  <text x="{{$.ModelX}}" y="{{add .Y 18}}" fill="{{$.Colors.Ink}}" font-size="22" font-weight="600">{{.Label}}</text>
  <text x="{{$.ModelTrackR}}" y="{{add .Y 18}}" fill="{{$.Colors.Ink}}" font-size="22" font-weight="700" text-anchor="end" font-family="ui-monospace,'SF Mono',Menlo,Consolas,monospace">{{.Cost}}</text>
  <rect x="{{$.ModelX}}" y="{{add .Y 28}}" width="{{$.ModelTrackW}}" height="8" rx="4" fill="{{$.Colors.Track}}"/>
  <rect x="{{$.ModelX}}" y="{{add .Y 28}}" width="{{.FillWidth}}" height="8" rx="4" fill="{{$.Colors.Gold}}"/>
  {{end}}
  {{end}}

  <!-- right column: tool mix -->
  {{if .HasTools}}
  <text x="{{.ToolX}}" y="{{.ModelHeadingY}}" fill="{{.Colors.Muted}}" font-size="18" font-weight="700" letter-spacing="2">TOOL MIX</text>
  {{range .Tools}}
  <text x="{{$.ToolX}}" y="{{add .Y 18}}" fill="{{$.Colors.Ink}}" font-size="22" font-weight="600">{{.Label}}</text>
  <text x="{{$.ToolTrackR}}" y="{{add .Y 18}}" fill="{{$.Colors.Ink}}" font-size="22" font-weight="700" text-anchor="end" font-family="ui-monospace,'SF Mono',Menlo,Consolas,monospace">{{.Cost}}</text>
  <rect x="{{$.ToolX}}" y="{{add .Y 28}}" width="{{$.ToolTrackW}}" height="8" rx="4" fill="{{$.Colors.Track}}"/>
  <rect x="{{$.ToolX}}" y="{{add .Y 28}}" width="{{.FillWidth}}" height="8" rx="4" fill="{{$.Colors.Teal}}"/>
  {{end}}
  {{end}}
  {{end}}

  <!-- footer -->
  <line x1="72" y1="566" x2="1128" y2="566" stroke="{{.Colors.Border}}" stroke-width="1"/>
  <text x="72" y="600" fill="{{.Colors.Muted}}" font-size="20">Tracked locally by superbased Observer</text>
  <text x="1128" y="600" fill="{{.Colors.Gold}}" font-size="20" font-weight="700" text-anchor="end">superbased.app</text>
</svg>`
