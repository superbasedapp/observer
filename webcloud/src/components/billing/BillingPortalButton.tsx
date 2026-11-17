import { useState } from "react";
import { ExternalLink } from "lucide-react";
import { Button } from "@shared/primitives/Button";
import type { PortalSession } from "../../api";

// BillingPortalButton opens Paddle's hosted customer portal (wave 17):
// invoices, receipts, payment methods and the subscription, all on Paddle's
// pages (Paddle is the merchant of record). The link is minted on click by
// the server for the signed-in payer and followed at once in this tab; it
// carries a short-lived token, so it is never kept in state or shown.
// Presentational: the caller passes the session minting call.

export interface BillingPortalButtonProps {
  /** Mints the portal session; rejects with a worded error. */
  open: () => Promise<PortalSession>;
}

export function BillingPortalButton({ open }: BillingPortalButtonProps) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function go() {
    setError(null);
    setBusy(true);
    try {
      const s = await open();
      window.location.assign(s.url);
    } catch (e) {
      setError(e instanceof Error ? e.message : "could not open the billing portal");
      setBusy(false);
    }
  }

  return (
    <div>
      <Button type="button" size="sm" variant="secondary" iconRight={ExternalLink} loading={busy} onClick={go}>
        {busy ? "Opening billing portal" : "Invoices and billing portal"}
      </Button>
      {error && (
        <p role="alert" className="mt-1 text-[11px] text-danger">
          {error}
        </p>
      )}
    </div>
  );
}
