import { useEffect, useState } from "react";
import { Monitor } from "lucide-react";
import { Icon, Tooltip } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import type { StatusSnapshot } from "@/lib/types";
import {
  buildVerdict,
  captureRemoteFragment,
  machineName,
  pinHost,
  saveRemoteIdentity,
  type RemoteIdentity,
} from "@/lib/remoteIdentity";

// RemoteMachineChip is the top bar's "which machine is this?" slot (T-425).
// It renders NOTHING on a local dashboard. On a remote machine's dashboard
// opened through the instance switcher it always shows the SSH profile it was
// reached through and the remote daemon's own hostname, and flags a remote
// build or database schema older than the machine it was opened from (D-325:
// a stale sb-devbox dashboard was mistaken for a demo node). It is one small,
// self-contained component so the top bar change is a single slot.

type RemoteStatus = { host_name?: string; version?: string; schema_version?: number };

function selectRemoteStatus(s: StatusSnapshot): RemoteStatus {
  return { host_name: s.host_name, version: s.version, schema_version: s.schema_version };
}

export function RemoteMachineChip() {
  // Captured once at mount: the fragment is stripped from the address bar
  // right away, and the identity lives on for this origin.
  const [id, setId] = useState<RemoteIdentity | null>(() => captureRemoteFragment());
  const status = useApi<StatusSnapshot, RemoteStatus>("/api/status", undefined, [], {
    refreshMs: 30000,
    select: selectRemoteStatus,
  });
  const host = status.data?.host_name;

  useEffect(() => {
    if (!id || !host) return;
    const next = pinHost(id, host);
    if (next !== id) {
      saveRemoteIdentity(next);
      setId(next);
    }
  }, [id, host]);

  if (!id) return null;
  const verdict = buildVerdict(status.data?.version, status.data?.schema_version, id.localVersion, id.localSchema);
  const name = machineName(id);
  const tip = [
    `You are on the superbased dashboard of a REMOTE machine: ${name}.`,
    id.target ? `Reached through the SSH profile ${id.label} (${id.target}).` : `Reached through the SSH profile ${id.label}.`,
    status.data?.version ? `Its build: v${status.data.version}, database schema ${status.data.schema_version ?? "unknown"}.` : "",
    verdict.outdated ? `Older than the machine you opened it from: ${verdict.reason}.` : "",
    "Everything on this page, and every error, comes from that machine.",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <Tooltip content={tip}>
      <span
        tabIndex={0}
        data-testid="remote-machine-chip"
        className={
          "flex h-6 min-w-0 max-w-[260px] cursor-help items-center gap-1.5 rounded-pill border px-2 text-[10.5px] font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)] " +
          (verdict.outdated
            ? "border-warn/50 bg-warn-soft text-warn"
            : "border-accent/50 bg-accent-soft text-accent")
        }
      >
        <Icon icon={Monitor} size={10} className="shrink-0" />
        <span className="truncate">Remote: {name}</span>
        {verdict.outdated && <span className="shrink-0">· older build</span>}
      </span>
    </Tooltip>
  );
}
