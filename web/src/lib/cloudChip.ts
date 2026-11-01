// cloudChip - whether the header's "Cloud: ..." chip is shown (WINNODE2 16b).
// Pure, pinned by cloudChip.test.ts.
//
// The chip linked a managed (organization) node to Settings > Cloud
// Intelligence with "Cloud: not signed in", which read as something wrong.
// Cloud Intelligence is the developer's own optional plane: on a node
// enrolled as organization-managed every captured row carries the
// organization's authority and is not eligible for it (docs/cloud-
// intelligence.md, the authority gate), and an organization may hide the
// section outright. So the chip shows only where the feature is offered.

export type CloudChipInput = {
  /** The Cloud Intelligence settings section is offered on this node. */
  sectionOffered: boolean;
  /** The node is enrolled as organization-managed. */
  managed: boolean;
  signedIn: boolean;
  signingIn: boolean;
};

/** The ordered rules; the first match decides. */
const RULES: readonly { name: string; when: (i: CloudChipInput) => boolean; shown: boolean }[] = [
  // The organization hid the section, or this build has no Cloud module.
  { name: "not_offered", when: (i) => !i.sectionOffered, shown: false },
  // A sign-in in progress or done is always reported truthfully.
  { name: "signed_in_or_signing_in", when: (i) => i.signedIn || i.signingIn, shown: true },
  // A managed node has nothing the personal plane may enrich.
  { name: "managed_not_signed_in", when: (i) => i.managed, shown: false },
  { name: "default", when: () => true, shown: true },
];

export function cloudChipShown(i: CloudChipInput): boolean {
  for (const r of RULES) {
    if (r.when(i)) return r.shown;
  }
  return true;
}
