// Compatibility shim: CopyOnClick was promoted into the shared design system
// (shared/primitives) so the node and org session-detail surfaces share one
// click-to-copy affordance. Existing @/components/CopyOnClick importers are
// unchanged.
export { CopyOnClick } from "@shared/primitives/CopyOnClick";
