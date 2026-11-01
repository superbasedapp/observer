import { Input, SegmentedControl, Select } from "@/components/primitives";
import { CHOICE_LABELS, PARAM_LABELS, SECRET_LABELS, type CatalogSource } from "@/lib/plans";

// SourceFields: the fields one way of reading a provider takes. Secrets are
// password fields that are never filled back in (a saved one says so in its
// placeholder); a setting with a closed set of choices is a picker, never
// free text: a few choices show at once, a longer list is a Select.

const MAX_SEGMENTS = 4;

export function SourceFields({
  src,
  params,
  secrets,
  setParam,
  setSecret,
  keepSecrets,
}: {
  src: CatalogSource;
  params: Record<string, string>;
  secrets: Record<string, string>;
  setParam: (k: string, v: string) => void;
  setSecret: (k: string, v: string) => void;
  keepSecrets?: string[];
}) {
  return (
    <>
      {src.secrets.map((s) => {
        const stored = keepSecrets?.includes(s.key);
        return (
          <Input
            key={`s-${s.key}`}
            type="password"
            autoComplete="off"
            label={SECRET_LABELS[s.key] ?? "Key"}
            placeholder={stored ? "Saved. Type to replace it." : s.required ? "Required" : "Optional"}
            value={secrets[s.key] ?? ""}
            onChange={(e) => setSecret(s.key, e.target.value)}
          />
        );
      })}
      {src.params.map((p) => {
        const label = PARAM_LABELS[p.key] ?? "Setting";
        if (p.choices && p.choices.length > 0) {
          const options = [
            ...(p.required ? [] : [{ value: "", label: "Default" }]),
            ...p.choices.map((c) => ({ value: c, label: CHOICE_LABELS[c] ?? c })),
          ];
          if (options.length <= MAX_SEGMENTS) {
            return (
              <div key={`p-${p.key}`} className="space-y-1">
                <span className="block text-xs font-medium text-fg-2">{label}</span>
                <SegmentedControl options={options} value={params[p.key] ?? ""} onChange={(v) => setParam(p.key, v)} />
              </div>
            );
          }
          return (
            <Select
              key={`p-${p.key}`}
              label={label}
              value={params[p.key] ?? ""}
              onChange={(e) => setParam(p.key, e.target.value)}
              options={options}
            />
          );
        }
        return (
          <Input
            key={`p-${p.key}`}
            label={label}
            inputMode={p.numeric ? "decimal" : undefined}
            placeholder={p.required ? "Required" : "Optional"}
            value={params[p.key] ?? ""}
            onChange={(e) => setParam(p.key, e.target.value)}
          />
        );
      })}
    </>
  );
}
