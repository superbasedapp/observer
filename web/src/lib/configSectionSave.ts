// saveConfigSection is the ONE way the dashboard writes a whole config.toml
// section (PUT /api/config/section/<id>, T-432). Every save previews first:
//
//  1. a dry run (`?dry_run=1`) runs every server check and returns the masked
//     diff of the exact bytes the save would write, the credential-shaped
//     value warnings and whether a sensitive key needs the confirm token;
//  2. the preview dialog (ConfigSavePreviewHost, mounted once in the shell)
//     shows that diff and those warnings and waits for Save or Cancel;
//  3. the real save carries the confirm token and the etag the preview was
//     computed against (`?base_etag=`), so a file that changed in between is
//     refused with 409 instead of overwritten unseen.
//
// The flow itself is the pure runSectionSave (configSectionSaveCore.ts);
// this module wires the transport (fetchJSON + the owner-local confirm
// token) and the dialog registration.

import { fetchJSON, localConfirmHeaders } from "@/lib/api";
import {
  runSectionSave,
  type SectionPreviewRequest,
  type SectionSaveResult,
} from "@/lib/configSectionSaveCore";

export { ConfigSaveCancelled } from "@/lib/configSectionSaveCore";
export type ConfigSectionSaveResult = SectionSaveResult;
export type ConfigSavePreviewRequest = SectionPreviewRequest;

type PreviewPrompt = (req: ConfigSavePreviewRequest) => Promise<boolean>;

/** A review that answers one save's preview in place of the shell's dialog. */
export type ConfigSavePreviewPrompt = PreviewPrompt;

let prompt: PreviewPrompt | null = null;

/**
 * registerConfigSavePreview installs the dialog that answers previews. The
 * shell's ConfigSavePreviewHost calls it on mount; the returned function
 * uninstalls it.
 */
export function registerConfigSavePreview(fn: PreviewPrompt): () => void {
  prompt = fn;
  return () => {
    if (prompt === fn) prompt = null;
  };
}

async function putSection(section: string, params: Record<string, string>, body: string): Promise<unknown> {
  return fetchJSON<unknown>(`/api/config/section/${encodeURIComponent(section)}`, params, {
    method: "PUT",
    headers: await localConfirmHeaders(),
    body,
  });
}

/**
 * saveConfigSection previews then writes one config section. It fails
 * closed: with no preview dialog installed it writes nothing and throws;
 * a cancelled preview rejects with ConfigSaveCancelled.
 */
export function saveConfigSection(
  section: string,
  body: unknown,
  opts: { title?: string } = {},
): Promise<ConfigSectionSaveResult> {
  return runSectionSave(section, body, { put: putSection, prompt }, opts);
}

/**
 * saveConfigEdit is saveConfigSection for a dedicated editor route that owns
 * one section (PUT /api/terminal/ssh/profiles, PUT /api/terminal/policy;
 * REVIEW-3 P3-18): the same preview, the same dialog, the same save at the
 * previewed etag. `headers` carries the route's own confirm token.
 *
 * `opts.prompt` answers the preview in place of the shell's dialog, for a
 * caller that is itself a dialog: the shell's dialog would open behind it
 * (Windows 11 Pro run 4, B4: the New Terminal dialog's inline steps show the
 * diff and Save in place). The dry run, the diff and the save at the
 * previewed etag are the same either way.
 */
export function saveConfigEdit<T = object>(
  url: string,
  section: string,
  body: unknown,
  headers: Record<string, string>,
  opts: { title?: string; prompt?: PreviewPrompt } = {},
): Promise<T & ConfigSectionSaveResult> {
  const put = (_section: string, params: Record<string, string>, payload: string) =>
    fetchJSON<unknown>(url, params, {
      method: "PUT",
      headers: { "Content-Type": "application/json", ...headers },
      body: payload,
    });
  return runSectionSave(section, body, { put, prompt: opts.prompt ?? prompt }, { title: opts.title }) as Promise<
    T & ConfigSectionSaveResult
  >;
}
