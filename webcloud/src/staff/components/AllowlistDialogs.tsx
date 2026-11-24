// The team allow-list's two writes, each through ChangeDialog (reason, "I
// have checked", passkey): add an entry (an email domain or an account id,
// checked with lib/allowlist's mirror of the server's validator, which stays
// the gate) and remove one (the row is kept, stamped removed). A refusal
// that means the list moved (the entry exists already, or is gone) re-reads
// the list and keeps the dialog open with the reason in words.

import { useEffect, useState } from "react";
import { Input } from "@shared/primitives/Input";
import { Select } from "@shared/primitives/Select";
import { StaffApiError, addTeamAllowlistEntry, needsPasskey, removeTeamAllowlistEntry, type AllowlistEntry } from "../api";
import { ALLOWLIST_KINDS, addBlocking, allowlistErrorText, kindLabel, validateAllowlistEntry, type AllowlistKind } from "../lib/allowlist";
import { invalidateStaff, staffKeys } from "../session";
import { ChangeDialog } from "./ChangeDialog";

/** refreshAllowlist re-reads both views of the list (active, all). */
export function refreshAllowlist(): void {
  invalidateStaff(staffKeys.teamAllowlist(false));
  invalidateStaff(staffKeys.teamAllowlist(true));
}

/** wordRefusal re-reads the list on a refusal that is not the passkey's and
 *  rethrows it in words. */
async function wordRefusal(p: Promise<unknown>): Promise<void> {
  try {
    await p;
  } catch (e) {
    if (e instanceof StaffApiError && !needsPasskey(e)) {
      refreshAllowlist();
      throw new StaffApiError(e.status, e.code, allowlistErrorText(e.code, e.message));
    }
    throw e;
  }
}

/** AllowlistFields edits the kind and value of a new entry (rendered by tests). */
export function AllowlistFields({
  kind,
  value,
  onKind,
  onValue,
}: {
  kind: AllowlistKind;
  value: string;
  onKind: (k: AllowlistKind) => void;
  onValue: (v: string) => void;
}) {
  const meta = ALLOWLIST_KINDS.find((k) => k.kind === kind) ?? ALLOWLIST_KINDS[0];
  const checked = validateAllowlistEntry(kind, value);
  const showStored = value.trim() !== "" && checked.error === null && checked.value !== value;
  return (
    <div className="flex flex-col gap-3">
      <Select
        label="Kind"
        value={kind}
        onChange={(e) => onKind(e.target.value as AllowlistKind)}
        options={ALLOWLIST_KINDS.map((k) => ({ value: k.kind, label: k.label }))}
        help={meta.help}
      />
      <Input
        label={meta.label}
        value={value}
        placeholder={meta.placeholder}
        onChange={(e) => onValue(e.target.value)}
        help={showStored ? `Stored as ${checked.value}` : undefined}
        mono
        autoComplete="off"
        spellCheck={false}
      />
    </div>
  );
}

/** AddAllowlistDialog adds one entry. */
export function AddAllowlistDialog({ open, entries, onClose, onDone }: { open: boolean; entries: AllowlistEntry[]; onClose: () => void; onDone: () => void }) {
  const [kind, setKind] = useState<AllowlistKind>("email_domain");
  const [value, setValue] = useState("");
  useEffect(() => {
    if (!open) return;
    setKind("email_domain");
    setValue("");
  }, [open]);
  const checked = validateAllowlistEntry(kind, value);
  return (
    <ChangeDialog
      open={open}
      title="Add to the team allow-list"
      summary={
        <div className="flex flex-col gap-3">
          <AllowlistFields kind={kind} value={value} onKind={setKind} onValue={setValue} />
          <p className="text-[11.5px] text-fg-3">
            {kind === "email_domain"
              ? "Anyone whose verified email is at this domain can create a team org while team creation is invitation-only."
              : "This account can create a team org while team creation is invitation-only."}
          </p>
        </div>
      }
      after={{ kind, value: checked.value }}
      blocking={addBlocking(entries, kind, value)}
      confirmLabel="Add"
      run={(reason) => wordRefusal(addTeamAllowlistEntry(kind, checked.value, reason))}
      onClose={onClose}
      onDone={onDone}
    />
  );
}

/** RemoveAllowlistDialog removes one active entry. */
export function RemoveAllowlistDialog({ entry, onClose, onDone }: { entry: AllowlistEntry; onClose: () => void; onDone: () => void }) {
  return (
    <ChangeDialog
      open
      title="Remove from the team allow-list"
      destructive
      summary={
        <span>
          Remove the {kindLabel(entry.kind).toLowerCase()} <span className="break-all font-mono">{entry.value}</span>.{" "}
          {entry.kind === "email_domain" ? "Accounts at this domain" : "This account"} can no longer create a team org unless another entry
          covers them. Team orgs already created are not affected.
        </span>
      }
      before={{ kind: entry.kind, value: entry.value }}
      after={null}
      confirmLabel="Remove"
      run={(reason) => wordRefusal(removeTeamAllowlistEntry(entry.entry_id, reason))}
      onClose={onClose}
      onDone={onDone}
    />
  );
}
