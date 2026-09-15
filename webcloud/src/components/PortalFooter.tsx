// PortalFooter — the thin legal strip shared by every authenticated portal
// page (mounted once in App.tsx::RequireAuth, alongside Sidebar/TopBar). The
// three links point at the marketing site's legal pages
// (https://superbased.app/{terms,privacy,refund-policy}), which are the
// canonical, already-published copies (operator ruling: link to them here,
// never duplicate them in the portal). All three open in a new tab with
// rel="noopener" — an external origin the portal does not control.

const LEGAL_LINKS: { href: string; label: string }[] = [
  { href: "https://superbased.app/terms", label: "Terms" },
  { href: "https://superbased.app/privacy", label: "Privacy" },
  { href: "https://superbased.app/refund-policy", label: "Refund policy" },
];

export function PortalFooter() {
  return (
    <footer className="portal-footer">
      <nav className="portal-footer-links" aria-label="Legal">
        {LEGAL_LINKS.map((l, i) => (
          <span key={l.href}>
            {i > 0 && <span className="portal-footer-sep" aria-hidden="true">·</span>}
            <a href={l.href} target="_blank" rel="noopener">
              {l.label}
            </a>
          </span>
        ))}
      </nav>
    </footer>
  );
}
