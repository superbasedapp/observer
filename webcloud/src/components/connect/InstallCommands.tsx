import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { Button } from "@shared/primitives/Button";
import { SegmentedControl } from "@shared/primitives/SegmentedControl";
import { INSTALL_TABS, installCommand, type InstallTabId } from "../../lib/connectModel";

// InstallCommands - the account home's "Run this there" block (Getting
// started v2): one tab per way to install Observer (macOS / Linux, Windows,
// npm, pip), the tab the browser's own system suggests selected first, and
// the command with a Copy button. The commands are connectModel's
// INSTALL_TABS; this file only renders them.

export function InstallCommands({ initial }: { initial: InstallTabId }) {
  const [tab, setTab] = useState<InstallTabId>(initial);
  const [copied, setCopied] = useState(false);
  const command = installCommand(tab);

  async function onCopy() {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div className="flex flex-col gap-2">
      <SegmentedControl
        options={INSTALL_TABS.map((t) => ({ value: t.id, label: t.label }))}
        value={tab}
        onChange={(v) => {
          setTab(v);
          setCopied(false);
        }}
        size="sm"
      />
      <div className="flex items-center gap-2 rounded-2 border border-line-2 bg-bg-1 px-3 py-2">
        <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap font-mono text-[12px] text-fg-0">{command}</code>
        <Button
          variant="secondary"
          size="sm"
          iconLeft={copied ? Check : Copy}
          onClick={() => void onCopy()}
          aria-label={copied ? "Copied" : "Copy the command"}
        >
          {copied ? "Copied" : "Copy"}
        </Button>
      </div>
    </div>
  );
}
