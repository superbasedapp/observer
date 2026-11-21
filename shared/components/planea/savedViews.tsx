import { useState } from "react";
import { Bookmark, Trash2 } from "lucide-react";
import { Button } from "../../primitives/Button";
import { ConfirmButton } from "../../primitives/ConfirmButton";
import { Input } from "../../primitives/Input";
import { Select } from "../../primitives/Select";
import type { PlaneASavedView, PlaneAViewScope } from "./explorerViewsModel";

// The Plane A explorer's saved views (W5-4, lane C9): a filter set, a
// grouping and a column set saved by name, on the org per member and shared
// with a team or the org (GET/POST /api/org/obs/views, PUT/DELETE
// .../views/{id}), on the machine private (/api/obs/explorer/views).
// Contract: docs/plans/plane-a-sdk-buildout/contracts/alerts.md "Saved
// views". Pure and presentational: the views come in through props and
// every action goes out through callbacks; each app fetches and saves.

const scopeLabels: Record<PlaneAViewScope, string> = { private: "Only me", team: "My team", org: "Everyone" };

// SavedViewsBar picks a saved view to apply, saves the current filters as a
// new one, and deletes one the viewer may delete. scopes lists the sharing
// choices this app offers (the machine offers "private" only); teams the
// viewer's teams for a team view. Drawn with the shared Select, Input,
// Button and ConfirmButton (design pass 2026-11-21: it used hand-rolled
// controls and deleted a view on one click).
export function SavedViewsBar({
  views,
  selectedId,
  onApply,
  onSave,
  onDelete,
  scopes = ["private"],
  teams = [],
  canDelete = (v) => v.mine,
  busy = false,
  error,
}: {
  views: PlaneASavedView[];
  selectedId?: string;
  onApply: (v: PlaneASavedView) => void;
  onSave: (name: string, scope: PlaneAViewScope, teamId: string) => void;
  onDelete: (v: PlaneASavedView) => void;
  scopes?: PlaneAViewScope[];
  teams?: { id: string; name: string }[];
  canDelete?: (v: PlaneASavedView) => boolean;
  busy?: boolean;
  error?: string;
}) {
  const [name, setName] = useState("");
  const [scope, setScope] = useState<PlaneAViewScope>(scopes[0] ?? "private");
  const [team, setTeam] = useState(teams[0]?.id ?? "");
  const selected = views.find((v) => v.id === selectedId);
  return (
    <div className="flex flex-wrap items-center gap-2 text-[12px]" aria-label="Saved views">
      <Select
        aria-label="Saved view"
        className="w-auto max-w-[220px]"
        value={selectedId ?? ""}
        onChange={(e) => {
          const v = views.find((x) => x.id === e.target.value);
          if (v) onApply(v);
        }}
        disabled={views.length === 0}
      >
        <option value="">{views.length ? "Saved views..." : "No saved views"}</option>
        {views.map((v) => (
          <option key={v.id} value={v.id}>
            {v.name}
            {v.scope !== "private" ? ` (${scopeLabels[v.scope]})` : ""}
            {v.redacted ? " - some filters hidden" : ""}
          </option>
        ))}
      </Select>
      {selected && canDelete(selected) && (
        <ConfirmButton
          size="sm"
          variant="ghost"
          iconLeft={Trash2}
          disabled={busy}
          confirmLabel="Delete it?"
          armedNote={`Deletes the saved view "${selected.name}".`}
          onConfirm={() => onDelete(selected)}
        >
          Delete view
        </ConfirmButton>
      )}
      <form
        className="flex flex-wrap items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (!name.trim()) return;
          onSave(name.trim(), scope, scope === "team" ? team : "");
          setName("");
        }}
      >
        <Input
          className="w-40"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Name this view"
          aria-label="View name"
          maxLength={120}
        />
        {scopes.length > 1 && (
          <Select
            aria-label="Share with"
            className="w-auto"
            value={scope}
            onChange={(e) => setScope(e.target.value as PlaneAViewScope)}
            options={scopes.map((s) => ({ value: s, label: scopeLabels[s], disabled: s === "team" && teams.length === 0 }))}
          />
        )}
        {scope === "team" && teams.length > 0 && (
          <Select
            aria-label="Team"
            className="w-auto"
            value={team}
            onChange={(e) => setTeam(e.target.value)}
            options={teams.map((t) => ({ value: t.id, label: t.name }))}
          />
        )}
        <Button type="submit" size="sm" variant="secondary" iconLeft={Bookmark} disabled={busy || !name.trim()} title={name.trim() ? undefined : "Name the view to save it."}>
          Save view
        </Button>
      </form>
      {selected?.redacted && (
        <span className="text-[11px] text-fg-3">This view also filters by values you cannot see, so it shows more than its author saw.</span>
      )}
      {error && (
        <span role="alert" className="text-[11px] text-danger">
          {error}
        </span>
      )}
    </div>
  );
}
