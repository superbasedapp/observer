import { GuidanceCard } from "@/components/GuidanceCard";

// GuidanceTab — the existing guidance-file inventory, now one tab among
// several instead of the whole Projects detail view (plan §3.5 GuidanceTab).
export function GuidanceTab({ root }: { root: string }) {
  return (
    <div className="space-y-2">
      <GuidanceCard root={root} />
      <p className="text-[10.5px] text-fg-4">
        Version history and per-session availability of skills: see the Skills tab.
      </p>
    </div>
  );
}
