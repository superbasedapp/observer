// The availability input editors: one dialog to add or change one staff input
// of the availability envelope (org_controls, components, release_flags) and
// one to remove it. Both go through ChangeDialog, so every write shows the
// value it replaces, asks for a reason and a tick, and checks the passkey.
// The value is built and checked by lib/envelope (the signed body's rules).

import { useEffect, useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import { Button } from "@shared/primitives/Button";
import { Input } from "@shared/primitives/Input";
import { Select } from "@shared/primitives/Select";
import { Textarea } from "@shared/primitives/Textarea";
import { deleteAvailability, setAvailability } from "../api";
import {
  INFERENCE_STATES,
  KEY_RE,
  PLATFORM_KEY,
  REACHES,
  buildOrgControl,
  buildReach,
  emptyOrgControlDraft,
  orgControlDraftFrom,
  reachDraftFrom,
  type InferenceState,
  type OrgControlDraft,
  type ReachDraft,
  type Section,
} from "../lib/envelope";
import { ChangeDialog } from "./ChangeDialog";

export const SECTION_LABEL: Record<Section, string> = {
  org_controls: "org control",
  components: "component reach",
  release_flags: "release flag",
};

/** OrgControlFields edits one org_controls draft. */
export function OrgControlFields({ draft, onChange }: { draft: OrgControlDraft; onChange: (d: OrgControlDraft) => void }) {
  const platform = draft.key === PLATFORM_KEY;
  const setRow = (i: number, patch: Partial<OrgControlDraft["inference"][number]>) =>
    onChange({ ...draft, inference: draft.inference.map((r, j) => (j === i ? { ...r, ...patch } : r)) });
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-end gap-3">
        <Select
          label="Ingest"
          value={draft.ingest}
          disabled={platform}
          onChange={(e) => onChange({ ...draft, ingest: e.target.value as OrgControlDraft["ingest"] })}
          options={[
            { value: "none", label: "No ingest control" },
            { value: "pause", label: "Pause ingest" },
            { value: "throttle", label: "Throttle ingest" },
          ]}
          help={platform ? "Ingest is controlled per org only." : undefined}
        />
        {draft.ingest === "throttle" && (
          <Input
            label="Pushes a minute"
            inputMode="numeric"
            value={draft.rateText}
            onChange={(e) => onChange({ ...draft, rateText: e.target.value })}
            className="w-32"
          />
        )}
      </div>
      <div className="flex flex-col gap-2">
        <span className="text-[11.5px] font-medium text-fg-2">Inference (admission: new jobs; dispatch: queued and running jobs)</span>
        {draft.inference.length === 0 && <span className="text-[11.5px] text-fg-3">No inference control.</span>}
        {draft.inference.map((r, i) => (
          <div key={i} className="flex flex-wrap items-end gap-2">
            <Input label="Route" placeholder="every route" value={r.route} onChange={(e) => setRow(i, { route: e.target.value })} className="w-44" mono />
            <Select
              label="Admission"
              value={r.admission}
              onChange={(e) => setRow(i, { admission: e.target.value as InferenceState })}
              options={[...INFERENCE_STATES]}
            />
            <Select
              label="Dispatch"
              value={r.dispatch}
              onChange={(e) => setRow(i, { dispatch: e.target.value as InferenceState })}
              options={[...INFERENCE_STATES]}
            />
            <Button
              type="button"
              size="sm"
              variant="ghost"
              iconLeft={Trash2}
              onClick={() => onChange({ ...draft, inference: draft.inference.filter((_, j) => j !== i) })}
            >
              Remove
            </Button>
          </div>
        ))}
        <div>
          <Button
            type="button"
            size="sm"
            variant="secondary"
            iconLeft={Plus}
            onClick={() => onChange({ ...draft, inference: [...draft.inference, { route: "", admission: "paused", dispatch: "on" }] })}
          >
            Add an inference control
          </Button>
        </div>
      </div>
    </div>
  );
}

/** ReachFields edits one components or release_flags draft. */
export function ReachFields({ draft, onChange }: { draft: ReachDraft; onChange: (d: ReachDraft) => void }) {
  return (
    <div className="flex flex-col gap-3">
      <Select
        label="Reach"
        value={draft.reach}
        onChange={(e) => onChange({ ...draft, reach: e.target.value as ReachDraft["reach"] })}
        options={REACHES.map((r) => ({ value: r, label: r }))}
      />
      {draft.reach === "named" && (
        <Textarea
          label="Org ids"
          help="One org id (UUID) per line."
          value={draft.orgsText}
          onChange={(e) => onChange({ ...draft, orgsText: e.target.value })}
          rows={3}
          mono
        />
      )}
      {draft.reach === "cohort" && <Input label="Cohort" value={draft.cohort} onChange={(e) => onChange({ ...draft, cohort: e.target.value })} mono />}
    </div>
  );
}

export interface InputEditorProps {
  open: boolean;
  section: Section;
  /** inputKey is the row's key; empty for a new row whose key is typed. */
  inputKey: string;
  /** before is the stored value (undefined for a new row). */
  before?: unknown;
  onClose: () => void;
  onDone: () => void;
}

/** InputEditorDialog adds or changes one availability input. */
export function InputEditorDialog(p: InputEditorProps) {
  const [key, setKey] = useState(p.inputKey);
  const [org, setOrg] = useState<OrgControlDraft>(() => orgControlDraftFrom(p.inputKey, p.before));
  const [reach, setReach] = useState<ReachDraft>(() => reachDraftFrom(p.before));
  useEffect(() => {
    if (!p.open) return;
    setKey(p.inputKey);
    setOrg(p.before === undefined ? emptyOrgControlDraft(p.inputKey) : orgControlDraftFrom(p.inputKey, p.before));
    setReach(reachDraftFrom(p.before));
  }, [p.open, p.inputKey, p.before]);

  const built = p.section === "org_controls" ? buildOrgControl({ ...org, key: key.trim() }) : buildReach(reach);
  const blocking = [...built.errors];
  if (p.section !== "org_controls" && !KEY_RE.test(key.trim())) {
    blocking.unshift(`The ${p.section === "components" ? "component" : "flag"} id is 1 to 128 letters, digits or . _ : -`);
  }
  const isNew = p.before === undefined;
  return (
    <ChangeDialog
      open={p.open}
      title={`${isNew ? "Add" : "Change"} ${SECTION_LABEL[p.section]}`}
      summary={
        <div className="flex flex-col gap-3">
          {p.inputKey === "" ? (
            <Input
              label={p.section === "org_controls" ? `Org id (or "${PLATFORM_KEY}" for every org)` : p.section === "components" ? "Component id" : "Flag id"}
              value={key}
              onChange={(e) => {
                setKey(e.target.value);
                setOrg({ ...org, key: e.target.value.trim() });
              }}
              mono
            />
          ) : (
            <p className="text-[12px] text-fg-2">
              {p.section === "org_controls" && key === PLATFORM_KEY ? "Every org (platform-wide)" : <span className="font-mono">{key}</span>}
            </p>
          )}
          {p.section === "org_controls" ? <OrgControlFields draft={org} onChange={setOrg} /> : <ReachFields draft={reach} onChange={setReach} />}
          <p className="text-[11.5px] text-fg-3">
            The next availability envelope the control plane signs carries this; hosts apply it when they take that envelope.
          </p>
        </div>
      }
      before={p.before}
      after={built.value}
      blocking={blocking}
      confirmLabel={isNew ? "Add" : "Apply"}
      run={(reason) => setAvailability(p.section, key.trim(), built.value, reason).then(() => undefined)}
      onClose={p.onClose}
      onDone={p.onDone}
    />
  );
}

/** RemoveInputDialog removes one availability input. */
export function RemoveInputDialog(p: { open: boolean; section: Section; inputKey: string; before: unknown; onClose: () => void; onDone: () => void }) {
  return (
    <ChangeDialog
      open={p.open}
      title={`Remove ${SECTION_LABEL[p.section]}`}
      summary={
        <span>
          Remove the <span className="font-mono">{p.inputKey}</span> {SECTION_LABEL[p.section]}. The next envelope no longer carries it
          {p.section === "org_controls" ? ", so the org runs without this control." : ", so the compiled stage default applies."}
        </span>
      }
      before={p.before}
      after={null}
      destructive
      confirmLabel="Remove"
      run={(reason) => deleteAvailability(p.section, p.inputKey, reason)}
      onClose={p.onClose}
      onDone={p.onDone}
    />
  );
}
