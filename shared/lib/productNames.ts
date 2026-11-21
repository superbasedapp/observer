// productNames.ts is the typed view of productNames.json, the one owner of
// superbased's external product names (Plane A naming pass, W4-5). The
// website's generators read the same JSON file, so an app, a marketing page
// and a docs page can never name the product area two ways. Change a name in
// the JSON file only.

import names from "./productNames.json" with { type: "json" };

/** ProductNames is every key of productNames.json except its readme. */
export interface ProductNames {
  /** The brand, always lowercase. */
  brand: string;
  /** Plane A's external name, title case, used after the brand. */
  planea: string;
  /** The brand and the Plane A name together. */
  planea_full: string;
  /** Plane A as a navigation area label (sentence case). */
  planea_area: string;
  /** Plane A on a machine's own dashboard: the user's apps. */
  planea_local: string;
  /** The first-run question's options (decision 3): coding agents. */
  first_run_coding: string;
  /** The first-run question's options: the AI apps and agents you build. */
  first_run_apps: string;
  /** The first-run question's options: both. */
  first_run_both: string;
}

/** PRODUCT_NAMES is the vocabulary. */
export const PRODUCT_NAMES: Readonly<ProductNames> = Object.freeze({
  brand: names.brand,
  planea: names.planea,
  planea_full: names.planea_full,
  planea_area: names.planea_area,
  planea_local: names.planea_local,
  first_run_coding: names.first_run_coding,
  first_run_apps: names.first_run_apps,
  first_run_both: names.first_run_both,
});
