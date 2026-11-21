import { useEffect, useMemo, useState } from "react";
import { Button, EntityMultiPicker, Modal, type EntityMultiPickerOption } from "@/components/primitives";
import { projectLabel, type SecurityProject } from "@/lib/codeSecurity";
import {
  SCAN_ONLINE_KEY,
  SCAN_STEPS_KEY,
  defaultSteps,
  onlineFixLabel,
  onlineOption,
  parseRemembered,
  parseRememberedOnline,
  scanChoiceProblem,
  scanStartBody,
  scanStepReasonWords,
  startLabel,
  stepInfo,
} from "@/lib/scanSteps";
import type { SecurityScan } from "./useSecurityScan";

// ScanDialog is where a scan is chosen: which projects (all active ones, or a
// picked set) and which scanners. A scanner that is not ready is listed with
// the reason and a way to set it up. The last scanner choice is remembered in
// this browser. While a scan runs the dialog says so and offers Cancel.
//
// Under the dependency scanner, "Also check online" (decision P-1 of
// docs/plans/dashboard-cli-parity-plan-2026-11-06.md; the CLI's `observer
// security scan --online`): what it sends is stated beside it, and while the
// online gate is closed (online checks off, or their disclosure not
// accepted) it is disabled with why and a link to Scanners > Package checks,
// where that consent is given. The choice is remembered like the scanners.

function readRemembered(): string[] | null {
  try {
    return parseRemembered(window.localStorage.getItem(SCAN_STEPS_KEY));
  } catch {
    return null;
  }
}

function remember(ids: string[]) {
  try {
    window.localStorage.setItem(SCAN_STEPS_KEY, JSON.stringify(ids));
  } catch {
    // Storage can be blocked; the choice is just not remembered.
  }
}

function readRememberedOnline(): boolean {
  try {
    return parseRememberedOnline(window.localStorage.getItem(SCAN_ONLINE_KEY));
  } catch {
    return false;
  }
}

function rememberOnline(on: boolean) {
  try {
    window.localStorage.setItem(SCAN_ONLINE_KEY, on ? "true" : "false");
  } catch {
    // Storage can be blocked; the choice is just not remembered.
  }
}

/** projectOptions lists active projects first, then idle ones. */
function projectOptions(projects: SecurityProject[]): EntityMultiPickerOption[] {
  const mk = (p: SecurityProject, group: string): EntityMultiPickerOption => ({
    id: p.project_root_hash,
    label: projectLabel(p),
    group,
  });
  return [...projects.filter((p) => p.active).map((p) => mk(p, "Active")), ...projects.filter((p) => !p.active).map((p) => mk(p, "Idle"))];
}

export function ScanDialog({
  open,
  onClose,
  scan,
  projects,
  initialProjects,
  onOpenScanners,
}: {
  open: boolean;
  onClose: () => void;
  scan: SecurityScan;
  projects: SecurityProject[];
  initialProjects?: string[];
  onOpenScanners?: () => void;
}) {
  const steps = scan.view?.steps ?? [];
  const ready = useMemo(() => steps.filter((s) => s.ready).map((s) => s.id), [steps]);
  const activeCount = projects.filter((p) => p.active).length;
  const options = useMemo(() => projectOptions(projects), [projects]);

  const [mode, setMode] = useState<"all" | "choose">("all");
  const [picked, setPicked] = useState<string[]>([]);
  // null: the default choice (remembered, else every ready step).
  const [chosen, setChosen] = useState<string[] | null>(null);
  // null: the remembered online choice (off when none).
  const [wantOnline, setWantOnline] = useState<boolean | null>(null);
  const [problem, setProblem] = useState("");

  const initialKey = (initialProjects ?? []).join(",");
  useEffect(() => {
    if (!open) return;
    const init = initialKey ? initialKey.split(",") : [];
    setMode(init.length > 0 ? "choose" : "all");
    setPicked(init);
    setChosen(null);
    setWantOnline(null);
    setProblem("");
  }, [open, initialKey]);

  const effective = chosen ?? defaultSteps(steps, readRemembered());
  const projectCount = mode === "all" ? activeCount : picked.length;
  const online = onlineOption({
    online: scan.view?.online,
    chosen: effective.filter((id) => ready.includes(id)),
    wanted: wantOnline ?? readRememberedOnline(),
  });

  function toggle(id: string, on: boolean) {
    const base = chosen ?? effective;
    setChosen(on ? [...base.filter((x) => x !== id), id] : base.filter((x) => x !== id));
    setProblem("");
  }

  async function begin() {
    const msg = scanChoiceProblem({ projectCount, stepCount: effective.length, readyCount: ready.length });
    if (msg) {
      setProblem(msg);
      return;
    }
    // Keep the node's own step order.
    const ordered = ready.filter((id) => effective.includes(id));
    remember(ordered);
    if (online.enabled) rememberOnline(online.checked);
    await scan.start(
      scanStartBody({ all: mode === "all", projects: picked, chosen: ordered, ready, online: online.enabled && online.checked }),
    );
    onClose();
  }

  if (scan.running) {
    return (
      <Modal
        open={open}
        onClose={onClose}
        title="Scan"
        footer={
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={onClose}>
              Close
            </Button>
            <Button variant="danger-outline" onClick={() => void scan.cancel()} disabled={scan.sending}>
              Cancel scan
            </Button>
          </div>
        }
      >
        <p className="m-0 text-[13px] text-fg-1" data-testid="scan-dialog-running">
          A scan is running. Progress shows under the page header. You can start another when it ends.
        </p>
      </Modal>
    );
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Scan projects"
      subtitle="Pick what to scan and which scanners to run."
      width={560}
      footer={
        <div className="flex flex-wrap justify-end gap-2">
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={scan.sending} onClick={() => void begin()}>
            {startLabel(projectCount, effective.length)}
          </Button>
        </div>
      }
    >
      <div className="space-y-5 text-[12.5px]" data-testid="scan-dialog">
        <section aria-labelledby="scan-dialog-projects" className="space-y-2">
          <h3 id="scan-dialog-projects" className="m-0 text-[12.5px] font-medium text-fg-1">
            Projects
          </h3>
          <label className="flex items-center gap-2 text-fg-1">
            <input
              type="radio"
              name="scan-dialog-mode"
              checked={mode === "all"}
              onChange={() => {
                setMode("all");
                setProblem("");
              }}
            />
            {`All active projects (${activeCount})`}
          </label>
          <label className="flex items-center gap-2 text-fg-1">
            <input
              type="radio"
              name="scan-dialog-mode"
              checked={mode === "choose"}
              onChange={() => {
                setMode("choose");
                setProblem("");
              }}
            />
            Choose projects
          </label>
          {mode === "choose" && (
            <EntityMultiPicker
              options={options}
              value={picked}
              onChange={(v) => {
                setPicked(v);
                setProblem("");
              }}
              placeholder="Search projects"
              ariaLabel="Projects to scan"
              hideIds
              emptyHint="No project matches."
            />
          )}
        </section>

        <section aria-labelledby="scan-dialog-scanners" className="space-y-2">
          <h3 id="scan-dialog-scanners" className="m-0 text-[12.5px] font-medium text-fg-1">
            Scanners
          </h3>
          {steps.length === 0 && <p className="m-0 text-fg-3">No scanner list yet.</p>}
          <ul className="m-0 list-none space-y-2 p-0">
            {steps.map((s) => {
              const info = stepInfo(s.id, s.label);
              const checked = s.ready && effective.includes(s.id);
              return (
                <li key={s.id} className="min-w-0">
                  <label className="flex items-start gap-2">
                    <input
                      type="checkbox"
                      className="mt-0.5"
                      checked={checked}
                      disabled={!s.ready}
                      onChange={(e) => toggle(s.id, e.target.checked)}
                      aria-describedby={`scan-step-${s.id}`}
                    />
                    <span className="min-w-0">
                      <span className={s.ready ? "text-fg-1" : "text-fg-3"}>{s.label}</span>
                      <span id={`scan-step-${s.id}`} className="block text-fg-3">
                        {info.description}
                        {!s.ready && ` · Not ready: ${scanStepReasonWords(s.reason) || "off"}`}
                      </span>
                    </span>
                  </label>
                  {!s.ready && onOpenScanners && (
                    <button
                      type="button"
                      className="ml-6 mt-0.5 text-accent hover:text-accent-strong hover:underline"
                      onClick={() => {
                        onClose();
                        onOpenScanners();
                      }}
                    >
                      Set up in Scanners
                    </button>
                  )}
                  {online.show && s.id === scan.view?.online?.step && (
                    <div className="ml-6 mt-1.5 space-y-1" data-testid="scan-dialog-online">
                      <label className="flex items-start gap-2">
                        <input
                          type="checkbox"
                          className="mt-0.5"
                          checked={online.checked}
                          disabled={!online.enabled}
                          onChange={(e) => {
                            setWantOnline(e.target.checked);
                            setProblem("");
                          }}
                          aria-describedby="scan-dialog-online-sends"
                        />
                        <span className="min-w-0">
                          <span className={online.enabled ? "text-fg-1" : "text-fg-3"}>Also check online</span>
                          <span id="scan-dialog-online-sends" className="block text-fg-3">
                            {online.sends}
                            {!online.enabled && ` Not available: ${online.blocked}.`}
                          </span>
                        </span>
                      </label>
                      {!online.enabled && onOpenScanners && onlineFixLabel(online.fix) && (
                        <button
                          type="button"
                          className="ml-6 text-accent hover:text-accent-strong hover:underline"
                          onClick={() => {
                            onClose();
                            onOpenScanners();
                          }}
                        >
                          {onlineFixLabel(online.fix)}
                        </button>
                      )}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        </section>

        {problem && (
          <p role="alert" className="m-0 text-danger" data-testid="scan-dialog-problem">
            {problem}
          </p>
        )}
      </div>
    </Modal>
  );
}
