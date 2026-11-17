// connect.ts: the front door's status on the node dashboard (plan 06
// section 19.3, plan 07 M8.4). GET /api/connect/status answers the one
// sentence the daemon builds (internal/frontdoor), the same one
// `observer status` and `observer connect --status` print.
//
// Getting started v2 retired the Connect card this file used to decide (its
// sign-in and attach steps are now one action, "Sign in and connect this
// machine", in lib/getStarted.ts and lib/useConnectFlow.ts); what is left is
// the status shape those read.

/** ConnectStatus mirrors internal/frontdoor.Status. */
export type ConnectStatus = {
  sentence: string;
  kind: "local" | "managed" | "individual";
  destination?: string;
  signed_in: boolean;
  identity_known: boolean;
  locked: boolean;
  /** The connected dashboard's name, kept by the daemon across restarts. */
  display_name?: string;
  /** The connected dashboard's online address, for a button only. */
  online_url?: string;
};

/** The status route. */
export const CONNECT_STATUS_PATH = "/api/connect/status";
