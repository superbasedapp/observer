import { Pill } from "./Pill";
import type { Reliability } from "../lib/types";

export function ReliabilityPill({ value }: { value?: Reliability }) {
  if (!value) return <Pill>—</Pill>;
  switch (value) {
    case "accurate":
      return <Pill variant="success">{value}</Pill>;
    case "approximate":
      return <Pill variant="warn">{value}</Pill>;
    case "unreliable":
      return <Pill variant="danger">{value}</Pill>;
    default:
      return <Pill>{value}</Pill>;
  }
}
