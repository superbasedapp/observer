import { useState } from "react";
import { Copy } from "lucide-react";
import { Button } from "@/components/primitives";
import { writeClipboard } from "@/lib/clipboard";

// TaskPromptBlock is a task's prompt in a scrollable monospace block with a
// Copy button (task mode's paste step; the fix plan reuses it).
export function TaskPromptBlock({ text, testId }: { text: string; testId?: string }) {
  const [copied, setCopied] = useState<"" | "ok" | "failed">("");
  return (
    <div className="space-y-1.5" data-testid={testId}>
      <pre className="m-0 max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-2 border border-line-2 bg-bg-2 p-2 font-mono text-[11px] leading-relaxed text-fg-1">
        {text}
      </pre>
      <div className="flex items-center gap-2">
        <Button
          size="sm"
          variant="secondary"
          iconLeft={Copy}
          onClick={() => {
            void writeClipboard(text).then((w) => setCopied(w === "failed" ? "failed" : "ok"));
          }}
        >
          Copy the task
        </Button>
        {copied === "ok" && <span className="text-[11px] text-fg-3">Copied.</span>}
        {copied === "failed" && <span className="text-[11px] text-danger">Could not copy here: select the text and copy it.</span>}
      </div>
    </div>
  );
}
