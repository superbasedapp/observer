// packagePins.ts is the one owner of the package-integrity pin text the
// install-script pin editors take (R-014, ruling P-142): the local
// dashboard's container-sandbox Card (web) and the org's sandbox managed
// section (web2). A tool whose install script fetches more packages (opencode,
// kilo) counts a pin only when it names the main package and every platform
// package by its registry sha512 integrity. One package per line,
// `name@version=sha512-<base64>`, the same shape as the setup container's
// --package-integrity flag. Pure; the node's rules (internal/sandboxoci,
// internal/config) are restated here and stay the authority.

/** PackagePin is one fetched npm artifact pinned by its registry integrity. */
export type PackagePin = { name: string; version: string; integrity: string };

const NAME_RE = /^(@[a-z0-9][a-z0-9._-]{0,100}\/)?[a-z0-9][a-z0-9._-]{0,100}$/;
const VERSION_RE = /^[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}([-+][0-9A-Za-z][0-9A-Za-z.-]{0,40})?$/;
const INTEGRITY_RE = /^sha512-[A-Za-z0-9+/]{86}==$/;

/** MAX_PACKAGES mirrors the node's per-pin bound. */
export const MAX_PACKAGES = 64;

/** PackagePinsParse is the editor's reading of the text. */
export type PackagePinsParse = { pins: PackagePin[]; problem: string };

/**
 * parsePackagePins reads one `name@version=integrity` per line (blank lines
 * skipped). problem names the first bad line, a duplicate name, or, when
 * mainPackage is given and pins are required, a missing main package; it is
 * "" when the text is acceptable.
 */
export function parsePackagePins(text: string, opts: { required: boolean; mainPackage?: string }): PackagePinsParse {
  const pins: PackagePin[] = [];
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l !== "");
  for (const [i, line] of lines.entries()) {
    const eq = line.indexOf("=");
    const spec = eq >= 0 ? line.slice(0, eq) : line;
    const at = spec.lastIndexOf("@");
    if (eq < 0 || at <= 0) return { pins: [], problem: `line ${i + 1} is not name@version=sha512-...` };
    const pin = { name: spec.slice(0, at), version: spec.slice(at + 1), integrity: line.slice(eq + 1) };
    if (!NAME_RE.test(pin.name)) return { pins: [], problem: `line ${i + 1}: ${pin.name} is not a package name` };
    if (!VERSION_RE.test(pin.version)) return { pins: [], problem: `line ${i + 1}: ${pin.version} is not a plain package version` };
    if (!INTEGRITY_RE.test(pin.integrity)) return { pins: [], problem: `line ${i + 1}: the integrity is not a registry sha512 value` };
    if (pins.some((p) => p.name === pin.name)) return { pins: [], problem: `line ${i + 1}: ${pin.name} is listed twice` };
    pins.push(pin);
  }
  if (pins.length > MAX_PACKAGES) return { pins: [], problem: `more than ${MAX_PACKAGES} packages` };
  if (opts.required) {
    if (pins.length === 0) {
      return { pins, problem: "this tool's install script fetches more packages: list the package and every platform package with its sha512 integrity" };
    }
    if (opts.mainPackage && !pins.some((p) => p.name === opts.mainPackage)) {
      return { pins, problem: `the list must include the package itself (${opts.mainPackage})` };
    }
  }
  return { pins, problem: "" };
}

/** packagePinsSummary is the confirm step's line for one package. */
export function packagePinLine(p: PackagePin): string {
  return `${p.name}@${p.version} ${p.integrity.slice(0, 19)}...`;
}
