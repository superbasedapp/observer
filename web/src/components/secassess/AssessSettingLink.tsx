import { GatedLink } from "@/components/GatedLink";
import { CODE_SECURITY_SETTINGS } from "@/lib/codeSecuritySettings";

// AssessSettingLink is a link from a sentence in an assessment dialog to the
// exact setting it names: Settings > Guard > Code security, opened on the row
// whose switch the sentence is about (the card scrolls to it and puts focus on
// it). A refusal that says "turn it on in the settings" is a dead end without
// it (N-10). The row's label is read from the settings table, never copied, so
// the link says what the row says. Settings > Guard is a section an
// organization may hide on a managed machine, so the link goes through the same
// gate every other link to a hidden-by-default place does (GatedLink): there it
// reads "Managed by your organization" instead of leading to a notice.

/** assessSettingHref is the address of the Code security setting row for a config key: the Settings section that holds the card, and the row as the fragment. */
export function assessSettingHref(key: string): string {
  return `/settings?section=guard#${key}`;
}

/** assessSettingLabel is the label the Settings row of a Code security key shows, or "" for a key the table does not hold. */
export function assessSettingLabel(key: string): string {
  return CODE_SECURITY_SETTINGS.find((r) => r.key === key)?.label ?? "";
}

/** AssessSettingLink renders the link, or nothing for a key the settings table does not hold. */
export function AssessSettingLink({ settingKey, className }: { settingKey: string; className?: string }) {
  const label = assessSettingLabel(settingKey);
  if (label === "") return null;
  return (
    <GatedLink to={assessSettingHref(settingKey)} className={className ?? "text-accent hover:underline"} data-testid="assess-setting-link" data-setting={settingKey}>
      {`Open the setting "${label}"`}
    </GatedLink>
  );
}
