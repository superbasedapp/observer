// Words for the sources the 2026-10-21 capture wave adds
// (internal/planlimits/src_wave1021.go, AP-134). Pure data; plans.ts merges
// it. Keys of WAVE_1021 are source ids; keys of WAVE_1021_WORDS are new
// parameter keys and parameter choices.
import type { SourceWords } from "./types.ts";

export const WAVE_1021: Record<string, SourceWords> = {
  "autohand.account": {
    label: "Autohand sign in",
    howto: "Reads the Autohand CLI's own sign in, read-only. Undocumented endpoint. Run autohand login when it expires.",
  },
  "autohand.api": {
    label: "Autohand token",
    howto: "Paste an Autohand account token. Uses an endpoint Autohand has not documented.",
  },
  "kimchi.config": {
    label: "Kimchi saved key",
    howto: "Reads the key Kimchi saved on this machine, read-only, sent only to Kimchi. Undocumented endpoint.",
  },
  "kimchi.api": {
    label: "Kimchi key",
    howto: "Paste a Kimchi API key and pick its region. Uses an endpoint Kimchi has not documented.",
  },
  "stakpak.api": {
    label: "Stakpak key",
    howto: "Paste a Stakpak API key and your Stakpak username. Uses an endpoint Stakpak has not documented.",
  },
};

export const WAVE_1021_WORDS: Record<string, string> = {
  account_username: "Account username",
  us: "United States",
  eu: "Europe",
};
