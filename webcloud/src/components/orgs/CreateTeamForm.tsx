import type { FormEvent } from "react";
import { Button } from "@shared/primitives/Button";
import { Callout } from "@shared/primitives/Callout";
import { Card } from "@shared/primitives/Card";
import { Input } from "@shared/primitives/Input";
import { InlineLoading } from "@shared/primitives/Spinner";
import { MANAGED_TEAM_NOTICE, SLUG_MAX, TEAM_NAME_MAX, type CreateFormView, type TeamCapView } from "../../lib/orgsModel";

// CreateTeamForm - the "Create a team" form (plan 07 M6.5): the team's name,
// its address (slug) with the live availability answer, and the host the
// address resolves to, as the SERVER answered it for this exact slug (the
// console never composes a tenant host). Presentational: the page owns the
// state and the requests; createFormView (lib/orgsModel.ts) decides what
// this renders. It always says, before the create, that a team is managed
// and captures full content (C2.front-door-2), and it shows the account's
// team cap (W15-D12): at the cap the submit is off and the note says the cap
// can be raised on request.

export interface CreateTeamFormProps {
  name: string;
  slugInput: string;
  view: CreateFormView;
  submitting: boolean;
  /** The create route's refusal, worded. */
  error: string | null;
  onName: (v: string) => void;
  onSlug: (v: string) => void;
  onSubmit: () => void;
  /** cap is the account's team cap (teamCapView); absent reads as no cap
   * known (the server still enforces it). */
  cap?: TeamCapView;
  /** price is the team plan's price from the catalogue (OrgsList.team_price);
   * absent when this deployment has none configured. */
  price?: { display: string; interval: string };
}

/** teamPriceLine words the team price shown before the create. */
export function teamPriceLine(price?: { display: string; interval: string }): string {
  if (!price || !price.display) return "You see the price on the team's page before you subscribe.";
  return price.interval ? `Price: ${price.display}, billed every ${price.interval}.` : `Price: ${price.display}.`;
}

const SLUG_TONE_CLASS: Record<CreateFormView["slugTone"], string> = {
  neutral: "text-fg-3",
  success: "text-success",
  danger: "text-danger",
};

export function CreateTeamForm(props: CreateTeamFormProps) {
  const { view } = props;
  const capBlocked = props.cap ? !props.cap.canCreate : false;
  const canSubmit = view.canSubmit && !capBlocked;
  function submit(e: FormEvent) {
    e.preventDefault();
    if (canSubmit) props.onSubmit();
  }
  return (
    <Card title="Create a team" sub="Your team gets its own dashboard at its own address. You can invite people once it is ready.">
      <form className="flex max-w-[520px] flex-col gap-4" onSubmit={submit} noValidate>
        <p className="text-[12.5px] font-medium text-fg-1">{teamPriceLine(props.price)}</p>
        <Callout tone="info" title={MANAGED_TEAM_NOTICE.title}>
          {MANAGED_TEAM_NOTICE.body}
        </Callout>
        {props.cap?.note && (
          <p id="team-cap" className={capBlocked ? "text-[12px] text-danger" : "text-[11px] text-fg-3"}>
            {props.cap.note}
          </p>
        )}
        <Input
          label="Team name"
          name="team-name"
          value={props.name}
          maxLength={TEAM_NAME_MAX + 20}
          autoComplete="organization"
          placeholder="Acme Engineering"
          error={view.nameError ?? undefined}
          onChange={(e) => props.onName(e.target.value)}
          disabled={props.submitting}
        />
        <div className="space-y-1">
          <Input
            label="Address"
            name="team-slug"
            mono
            value={props.slugInput}
            maxLength={SLUG_MAX + 10}
            autoComplete="off"
            spellCheck={false}
            placeholder="acme"
            onChange={(e) => props.onSlug(e.target.value)}
            disabled={props.submitting}
            aria-describedby="team-slug-status"
          />
          <div id="team-slug-status" aria-live="polite" className="text-[11px] leading-snug">
            {view.slugMessage === "Checking the address" ? (
              <InlineLoading label="Checking the address" />
            ) : (
              view.slugMessage && <span className={SLUG_TONE_CLASS[view.slugTone]}>{view.slugMessage}</span>
            )}
          </div>
          {view.host && (
            <p className="text-[11px] text-fg-3">
              Your team&apos;s dashboard will be at <span className="font-mono text-fg-1">https://{view.host}</span>
            </p>
          )}
        </div>
        {props.error && (
          <div role="alert" className="rounded-2 border border-danger/30 bg-danger-soft px-3 py-2 text-[11px] text-danger">
            {props.error}
          </div>
        )}
        <div>
          <Button type="submit" variant="primary" size="sm" disabled={!canSubmit} loading={props.submitting}>
            {props.submitting ? "Creating the team" : "Create team"}
          </Button>
        </div>
      </form>
    </Card>
  );
}
