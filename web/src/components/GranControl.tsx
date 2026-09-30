import { GranularityControl } from "@shared/primitives/GranularityControl";
import { asGranularity, type Granularity } from "@shared/lib/granularity";
import { useGranularity } from "@/lib/filters";

// GranControl binds the shared GranularityControl primitive to the node
// dashboard's global `gran=` filter (lib/filters.tsx useGranularity), so a
// card only says what it was served: `served` is the response's bucket
// metadata (Spec.Meta) - its `bucket` names the granularity, and its
// `tz_fallback` makes the card say the buckets follow UTC because the server
// could not use the viewer's zone.
export function GranControl({
  served,
  only,
}: {
  served?: { bucket?: string | null; tz_fallback?: boolean } | null;
  only?: readonly Granularity[];
}) {
  const g = useGranularity(only);
  const resolved = served?.bucket;
  return (
    <GranularityControl
      value={g.choice}
      onChange={g.setGran}
      spanMs={g.spanMs}
      only={only}
      resolved={resolved ? asGranularity(resolved) : g.expected}
      tzFallback={!!served?.tz_fallback}
    />
  );
}
