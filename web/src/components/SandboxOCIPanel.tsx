// SandboxOCIPanel.tsx is the "Container sandboxes" sub-panel of the
// Sandbox isolation card (sandbox plan v2 sections 9 and 10.1, lane
// SBX-P3A): the editor for [terminal.sandbox.oci], the oci-runc driver
// (Docker Engine or Podman on this machine through its local socket). The
// card mounts it with one line and owns the save; this panel only edits its
// own block. The three authority-expanding switches (a rootful engine, a
// repository's .devcontainer image, the first-start install cache of lane
// SBX-P3C) take a second, explicit click.

import { useState } from "react";
import { ComboChip, type ComboOption } from "@/components/primitives";
import { fetchJSON } from "@/lib/api";
import { packagePinLine, parsePackagePins, type PackagePin } from "@shared/lib/packagePins";

export type SandboxOCIConfig = {
  allow_rootful: boolean;
  socket: string;
  image: string;
  podman_userns: string;
  stop_grace_seconds: number;
  allow_devcontainer_image: boolean;
  // install_cache is optional so an older daemon's payload (no key) reads
  // as off.
  install_cache?: boolean;
  // The first-start install-script allowance and version picker (lane
  // LEFT-SBX, ruling P-136); optional so an older daemon's payload reads as
  // the defaults and an older daemon ignores them.
  install_scripts?: string;
  install_scripts_tools?: string[];
  install_script_pins?: InstallScriptPin[];
  install_versions?: Record<string, string>;
  // install_catalog is read-only: the install-source tools the pickers
  // offer, each with Observer's own reviewed script pins.
  install_catalog?: InstallCatalogRow[];
};

// packages pin what a package-fetching tool's script installs by its
// registry sha512 integrity (R-014, ruling P-142).
export type InstallScriptPin = { tool: string; version: string; sha256: string; added?: string; packages?: PackagePin[] };

export type InstallCatalogRow = {
  tool: string;
  package: string;
  kind: string;
  needs_scripts: boolean;
  doc_url: string;
  builtin_pins: { version: string; sha256: string; file: string; grounding: string; packages?: number }[];
  // script_fetches_packages: the tool's install script fetches more
  // packages, so a pin counts only with their sha512 integrity (an older
  // daemon omits it).
  script_fetches_packages?: boolean;
};

const SCRIPT_MODES: ComboOption[] = [
  { value: "pinned", label: <span className="font-mono">pinned</span>, detail: "Run a tool package's own install script only when its sha256 matches a reviewed pin for that version.", searchable: "pinned" },
  { value: "none", label: <span className="font-mono">none</span>, detail: "Never run a package install script; a tool that needs one is refused naming why.", searchable: "none never" },
];

const SHA_RE = /^[a-f0-9]{64}$/;
const VERSION_RE = /^[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}([-+][0-9A-Za-z][0-9A-Za-z.-]{0,40})?$/;

type ExpandingKey = "allow_rootful" | "allow_devcontainer_image" | "install_cache";

const USERNS_OPTIONS: ComboOption[] = [
  { value: "keep-id", label: <span className="font-mono">keep-id</span>, detail: "The container runs as your own uid (rootless Podman).", searchable: "keep-id uid" },
  { value: "default", label: <span className="font-mono">default</span>, detail: "Container root is you (rootless Podman's default namespace).", searchable: "default root" },
];

const STOP_GRACE = [5, 10, 20, 30, 60, 120];

// DIGEST_RE mirrors the config's digest rule: an image is pinned by
// sha256 digest, never a tag.
const DIGEST_RE = /^[a-z0-9][a-z0-9._/:-]*@sha256:[a-f0-9]{64}$/;

// PIN_PREFIX is how the organization's pins name these keys.
const PIN_PREFIX = "oci.";

export function SandboxOCIPanel({
  value,
  pinned,
  writable,
  onChange,
}: {
  value: SandboxOCIConfig;
  pinned: Set<string>;
  writable: boolean;
  onChange: (next: SandboxOCIConfig) => void;
}) {
  const [arming, setArming] = useState<ExpandingKey | null>(null);
  const editable = (key: keyof SandboxOCIConfig) => writable && !pinned.has(PIN_PREFIX + key);
  const set = <K extends keyof SandboxOCIConfig>(key: K, v: SandboxOCIConfig[K]) => onChange({ ...value, [key]: v });
  const imageBad = value.image.trim() !== "" && !DIGEST_RE.test(value.image.trim());

  const expanding = (key: ExpandingKey, label: string, note: string) => (
    <label className="flex items-start gap-2 rounded-2 border border-warn/30 bg-warn/5 p-3">
      <input
        type="checkbox"
        className="mt-0.5"
        checked={!!value[key]}
        disabled={!editable(key)}
        onChange={(e) => {
          if (!e.target.checked) {
            set(key, false);
            setArming(null);
          } else {
            setArming(key);
          }
        }}
      />
      <span>
        <span className="font-medium text-warn">{label}</span>
        <span className="block text-[11px] text-fg-3">{note}</span>
        {arming === key && !value[key] && (
          <button
            type="button"
            className="mt-1 rounded-2 border border-warn/50 px-2 py-0.5 text-[11px] text-warn"
            onClick={() => {
              set(key, true);
              setArming(null);
            }}
          >
            Yes, allow it
          </button>
        )}
        {pinned.has(PIN_PREFIX + key) && <span className="block text-[11px] text-fg-3">Set by your organization.</span>}
      </span>
    </label>
  );

  return (
    <details className="rounded-2 border border-line-2 bg-bg-3 p-3">
      <summary className="cursor-pointer font-medium text-fg-1">Container sandboxes (Docker, Podman)</summary>
      <div className="mt-3 space-y-3">
        <p className="text-[11px] text-fg-3">
          Used only when <span className="font-mono">oci-runc</span> is in the backend list above and the
          Container sandboxes component is selected in Settings &gt; Components. Nothing reaches the engine
          otherwise. Rootless Docker or rootless Podman is preferred.
        </p>
        <label className="block space-y-1">
          <span className="font-medium text-fg-2">Image (pinned by digest)</span>
          <input
            type="text"
            value={value.image}
            disabled={!writable}
            placeholder="registry/name@sha256:..."
            onChange={(e) => set("image", e.target.value)}
            className="w-full rounded-2 border border-line-2 bg-bg-0 px-2 py-1 font-mono text-[11px] text-fg-1 disabled:opacity-50"
          />
          <span className={`block text-[11px] ${imageBad ? "text-danger" : "text-fg-3"}`}>
            {imageBad
              ? "Use name@sha256:<64 hex>; a tag can change under a run and is refused."
              : "The image every container run starts from. Observer's own default image is not published yet."}
          </span>
        </label>
        <label className="block space-y-1">
          <span className="font-medium text-fg-2">Engine socket</span>
          <input
            type="text"
            value={value.socket}
            disabled={!writable}
            placeholder="empty: DOCKER_HOST, then the rootless sockets, then the system Docker socket"
            onChange={(e) => set("socket", e.target.value)}
            className="w-full rounded-2 border border-line-2 bg-bg-0 px-2 py-1 font-mono text-[11px] text-fg-1 disabled:opacity-50"
          />
          <span className="block text-[11px] text-fg-3">
            A local unix socket only. A symlinked socket, a TCP or SSH endpoint, or a daemon that changed since first
            use is refused.
          </span>
        </label>
        <div className="grid gap-3 md:grid-cols-2">
          <div className="space-y-1">
            <span id="sandbox-oci-userns" className="block font-medium text-fg-1">Rootless Podman user namespace</span>
            <ComboChip
              label="Rootless Podman user namespace"
              labelledBy="sandbox-oci-userns"
              hideTriggerLabel
              fullWidth
              value={value.podman_userns || "keep-id"}
              disabled={!editable("podman_userns")}
              onChange={(v) => set("podman_userns", v)}
              options={USERNS_OPTIONS}
              buttonValueRender={(o) => <span className="font-mono">{o?.value ?? value.podman_userns}</span>}
            />
          </div>
          <div className="space-y-1">
            <span id="sandbox-oci-grace" className="block font-medium text-fg-1">Stop grace</span>
            <ComboChip
              label="Stop grace"
              labelledBy="sandbox-oci-grace"
              hideTriggerLabel
              fullWidth
              value={String(value.stop_grace_seconds)}
              disabled={!editable("stop_grace_seconds")}
              onChange={(v) => set("stop_grace_seconds", Number(v))}
              options={(STOP_GRACE.includes(value.stop_grace_seconds) ? STOP_GRACE : [...STOP_GRACE, value.stop_grace_seconds].sort((a, b) => a - b)).map(
                (n) => ({ value: String(n), label: <span>{n} s</span>, searchable: `${n} s` }),
              )}
              buttonValueRender={() => <span>{value.stop_grace_seconds} s</span>}
            />
          </div>
        </div>
        {value.install_cache && (
          <InstallScriptsEditor value={value} pinned={pinned} writable={writable} onChange={onChange} />
        )}
        <div className="grid gap-3 md:grid-cols-2">
          {expanding(
            "allow_rootful",
            "Allow a rootful engine",
            "A rootful engine's socket is root-equivalent. Even then the container runs as your uid and gid, never as root.",
          )}
          {expanding(
            "allow_devcontainer_image",
            "Allow a repository's .devcontainer image",
            "Only its image by digest, after you consent once per repository and digest; every host-executing or privilege field is ignored.",
          )}
          {expanding(
            "install_cache",
            "Install the agent's CLI on first start",
            "When the image cannot run this machine's copy of the tool, a setup container from the same image installs the vendor's npm package (pinned to your installed version, from the vendor's documented hosts only, with no workspace and no credential) into a per-image cache. Each launch that needs it asks first on its terminal. A tool the image holds itself then runs on a separate tool state, never your real one.",
          )}
        </div>
      </div>
    </details>
  );
}

// InstallScriptsEditor edits the first-start install's script allowance and
// version picker (lane LEFT-SBX, ruling P-136): the mode, the tools whose
// pinned scripts may run (picked from the install-source catalog, never free
// text), the pins you added (each after a confirm step, shown with its
// source beside Observer's own), and the version each tool installs. It is
// shown only with install_cache on, where the keys are read. The
// [terminal.sandbox.oci] keys it edits: "install_scripts",
// "install_scripts_tools", "install_script_pins", "install_versions".
function InstallScriptsEditor({
  value,
  pinned,
  writable,
  onChange,
}: {
  value: SandboxOCIConfig;
  pinned: Set<string>;
  writable: boolean;
  onChange: (next: SandboxOCIConfig) => void;
}) {
  const catalog = value.install_catalog ?? [];
  const mode = value.install_scripts || "pinned";
  const tools = value.install_scripts_tools ?? [];
  const pins = value.install_script_pins ?? [];
  const versions = value.install_versions ?? {};
  const modePinned = pinned.has(PIN_PREFIX + "install_scripts");
  const [draft, setDraft] = useState<InstallScriptPin>({ tool: catalog[0]?.tool ?? "", version: "", sha256: "" });
  const [pkgText, setPkgText] = useState("");
  const [confirming, setConfirming] = useState(false);
  const draftRow = catalog.find((row) => row.tool === draft.tool);
  const draftFetches = !!draftRow?.script_fetches_packages;
  const pkgs = parsePackagePins(pkgText, { required: draftFetches, mainPackage: draftRow?.package });
  const [published, setPublished] = useState<Record<string, string[]>>({});
  const [loadErr, setLoadErr] = useState<string>("");
  const draftOK = !!draft.tool && VERSION_RE.test(draft.version) && SHA_RE.test(draft.sha256) && pkgs.problem === "";
  const set = (patch: Partial<SandboxOCIConfig>) => onChange({ ...value, ...patch });

  const loadVersions = async (tool: string) => {
    setLoadErr("");
    try {
      const res = await fetchJSON<{ versions: string[] }>("/api/terminal/sandbox/install-versions", { tool });
      setPublished((p) => ({ ...p, [tool]: res.versions }));
    } catch (e) {
      setLoadErr(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="space-y-3 rounded-2 border border-line-2 bg-bg-0 p-3">
      <div className="space-y-1">
        <span id="sandbox-oci-scripts" className="block font-medium text-fg-1">Package install scripts</span>
        <ComboChip
          label="Package install scripts"
          labelledBy="sandbox-oci-scripts"
          hideTriggerLabel
          fullWidth
          value={mode}
          disabled={!writable || modePinned}
          onChange={(v) => set({ install_scripts: v })}
          options={SCRIPT_MODES}
          buttonValueRender={(o) => <span className="font-mono">{o?.value ?? mode}</span>}
        />
        <span className="block text-[11px] text-fg-3">
          {modePinned
            ? "Set by your organization."
            : "The install always runs npm with --ignore-scripts; a pinned script then runs under the same host allow-list as the download."}
        </span>
      </div>
      {mode === "pinned" && (
        <>
          <fieldset className="space-y-1">
            <legend className="font-medium text-fg-2">Tools whose pinned scripts may run (none checked: every tool listed)</legend>
            {catalog.map((row) => (
              <label key={row.tool} className="flex items-center gap-2 text-[11px] text-fg-2">
                <input
                  type="checkbox"
                  disabled={!writable}
                  checked={tools.includes(row.tool)}
                  onChange={(e) =>
                    set({ install_scripts_tools: e.target.checked ? [...tools, row.tool] : tools.filter((t) => t !== row.tool) })
                  }
                />
                <span className="font-mono">{row.tool}</span>
                <span className="text-fg-3">{row.package}{row.needs_scripts ? " (needs its install script)" : " (no install script)"}</span>
              </label>
            ))}
          </fieldset>
          <div className="space-y-1">
            <span className="block font-medium text-fg-2">Reviewed pins</span>
            <ul className="space-y-1 text-[11px]">
              {catalog.flatMap((row) =>
                row.builtin_pins.map((p) => (
                  <li key={row.tool + p.version + p.sha256} className="text-fg-3" title={p.grounding}>
                    <span className="font-mono">{row.tool}@{p.version}</span> {p.file} <span className="font-mono">{p.sha256.slice(0, 16)}</span>, source: Observer
                    {p.packages ? `, ${p.packages} package(s) pinned by sha512` : ""}
                  </li>
                )),
              )}
              {pins.map((p, i) => (
                <li key={"u" + i} className="flex items-center gap-2 text-fg-2">
                  <span className="font-mono">{p.tool}@{p.version}</span>
                  <span className="font-mono">{p.sha256.slice(0, 16)}</span>
                  <span className="text-fg-3">source: you{p.added ? ", added " + p.added : ""}</span>
                  {p.packages && p.packages.length > 0 && <span className="text-fg-3">{p.packages.length} package(s) pinned by sha512</span>}
                  {writable && (
                    <button type="button" className="text-danger" onClick={() => set({ install_script_pins: pins.filter((_, j) => j !== i) })}>
                      Remove
                    </button>
                  )}
                </li>
              ))}
            </ul>
            {writable && (
              <div className="grid gap-2 md:grid-cols-4">
                <select
                  aria-label="Pin tool"
                  className="rounded-2 border border-line-2 bg-bg-0 px-2 py-1 text-[11px]"
                  value={draft.tool}
                  onChange={(e) => setDraft({ ...draft, tool: e.target.value })}
                >
                  {catalog.map((row) => (
                    <option key={row.tool} value={row.tool}>
                      {row.tool}
                    </option>
                  ))}
                </select>
                <input
                  aria-label="Pin version"
                  className="rounded-2 border border-line-2 bg-bg-0 px-2 py-1 font-mono text-[11px]"
                  placeholder="version, e.g. 2.1.311"
                  value={draft.version}
                  onChange={(e) => setDraft({ ...draft, version: e.target.value.trim() })}
                />
                <input
                  aria-label="Pin sha256"
                  className="rounded-2 border border-line-2 bg-bg-0 px-2 py-1 font-mono text-[11px] md:col-span-2"
                  placeholder="sha256 of the script file"
                  value={draft.sha256}
                  onChange={(e) => setDraft({ ...draft, sha256: e.target.value.trim().toLowerCase() })}
                />
                {draftFetches && (
                  <label className="block space-y-1 text-[11px] md:col-span-4">
                    <span className="text-fg-2">
                      This tool's install script fetches more packages. List the package itself ({draftRow?.package}) and every platform
                      package, one per line as name@version=sha512-... (the integrity values from the registry's version documents).
                    </span>
                    <textarea
                      aria-label="Pin packages"
                      className="w-full rounded-2 border border-line-2 bg-bg-0 px-2 py-1 font-mono text-[11px]"
                      rows={4}
                      value={pkgText}
                      onChange={(e) => setPkgText(e.target.value)}
                    />
                    {pkgs.problem && <span className="block text-danger">{pkgs.problem}</span>}
                  </label>
                )}
                {!confirming ? (
                  <button
                    type="button"
                    disabled={!draftOK}
                    className="rounded-2 border border-line-2 px-2 py-0.5 text-[11px] disabled:opacity-50"
                    onClick={() => setConfirming(true)}
                  >
                    Add pin
                  </button>
                ) : (
                  <span className="text-[11px] text-warn md:col-span-4">
                    A pin lets that exact script run in the setup container with the download hosts reachable. Add it only for a script
                    you reviewed.{" "}
                    {pkgs.pins.length > 0 && (
                      <span className="block">
                        It runs only after every package the install fetched matches one of these by its sha512 integrity:{" "}
                        <span className="font-mono">{pkgs.pins.map((p) => packagePinLine(p)).join(", ")}</span>.
                      </span>
                    )}
                    <button
                      type="button"
                      className="rounded-2 border border-warn/50 px-2 py-0.5 text-warn"
                      onClick={() => {
                        const added: InstallScriptPin = { ...draft, added: new Date().toISOString().slice(0, 10) };
                        if (pkgs.pins.length > 0) added.packages = pkgs.pins;
                        set({ install_script_pins: [...pins, added] });
                        setDraft({ ...draft, version: "", sha256: "" });
                        setPkgText("");
                        setConfirming(false);
                      }}
                    >
                      Yes, add this pin
                    </button>{" "}
                    <button type="button" className="text-fg-3" onClick={() => setConfirming(false)}>
                      Cancel
                    </button>
                  </span>
                )}
              </div>
            )}
          </div>
        </>
      )}
      <fieldset className="space-y-1">
        <legend className="font-medium text-fg-2">Version to install</legend>
        {catalog.map((row) => {
          const opts = Array.from(new Set([...(published[row.tool] ?? []), ...row.builtin_pins.map((p) => p.version), ...(versions[row.tool] ? [versions[row.tool]] : [])]));
          return (
            <div key={row.tool} className="flex items-center gap-2 text-[11px]">
              <span className="w-28 font-mono text-fg-2">{row.tool}</span>
              <select
                aria-label={"Version of " + row.tool}
                disabled={!writable}
                className="rounded-2 border border-line-2 bg-bg-0 px-2 py-1 font-mono"
                value={versions[row.tool] ?? ""}
                onChange={(e) => {
                  const next = { ...versions };
                  if (e.target.value === "") delete next[row.tool];
                  else next[row.tool] = e.target.value;
                  set({ install_versions: next });
                }}
              >
                <option value="">this machine's installed version</option>
                {opts.map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </select>
              {writable && (
                <button type="button" className="text-fg-3 underline" onClick={() => void loadVersions(row.tool)}>
                  List published versions
                </button>
              )}
            </div>
          );
        })}
        {loadErr && <span className="block text-[11px] text-danger">{loadErr}</span>}
        <span className="block text-[11px] text-fg-3">
          With no version picked and the tool not installed here, the launch is refused because the version to install is unknown. Listing the published
          versions reads the vendor's registry metadata from the install hosts only.
        </span>
      </fieldset>
    </div>
  );
}
