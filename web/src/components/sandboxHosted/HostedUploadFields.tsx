// HostedUploadFields.tsx is the Hosted sandboxes panel's block for folders
// that are not git repositories (decision SBXD-8, audit item H8): whether a
// hosted row uploads such a folder at all, and the extra patterns that leave
// files out of it. The panel mounts it with one line and owns the save;
// the pure half is lib/sandboxHostedUpload.ts. The keys are
// [terminal.sandbox.hosted] upload_non_git and upload_ignore; an
// organization may keep the first off and add patterns to the second.

import { useEffect, useState } from "react";
import { HelpTooltip } from "@/components/primitives";
import { ignoreLines, ignoreProblem, uploadNonGitOn } from "@/lib/sandboxHostedUpload";

// PIN_PREFIX is how the organization's pins name these keys (the panel's).
const PIN_PREFIX = "hosted.";

const TECHNICAL =
  "[terminal.sandbox.hosted] upload_non_git (default true) and upload_ignore (gitignore patterns, written after the default set). " +
  "The folder is listed with git ls-files --others --exclude-standard through a temporary --git-dir outside it; it is never git init'ed or written. " +
  "Then the upload's credential-shaped, link and size exclusions and its caps apply, and the consent scope covers the listed paths.";

/** The two keys this block edits, on the panel's hosted block (the block
 *  does not import the panel, which owns the module gate's file name). */
export type HostedUploadValue = { upload_non_git?: boolean; upload_ignore?: string[] };

export function HostedUploadFields<T extends HostedUploadValue>({
  value,
  pinned,
  writable,
  onChange,
}: {
  value: T;
  pinned: Set<string>;
  writable: boolean;
  onChange: (next: T) => void;
}) {
  const on = uploadNonGitOn(value.upload_non_git);
  const saved = value.upload_ignore ?? [];
  // The textarea keeps its own text so a new empty line survives typing;
  // the saved list is the text's non-empty lines.
  const [text, setText] = useState(saved.join("\n"));
  const savedKey = saved.join("\n");
  useEffect(() => {
    setText((t) => (ignoreLines(t).join("\n") === savedKey ? t : savedKey));
  }, [savedKey]);
  const problem = ignoreProblem(ignoreLines(text));
  const nonGitPinned = pinned.has(PIN_PREFIX + "upload_non_git");
  const ignorePinned = pinned.has(PIN_PREFIX + "upload_ignore");
  return (
    <div className="space-y-2 rounded-2 border border-line-2 bg-bg-3 p-3 md:col-span-2" data-testid="sandbox-hosted-upload-non-git">
      <label className="flex items-start gap-2">
        <input
          type="checkbox"
          className="mt-0.5"
          checked={on}
          disabled={!writable || nonGitPinned}
          onChange={(e) => onChange({ ...value, upload_non_git: e.target.checked })}
        />
        <span>
          <span className="font-medium text-fg-1">Upload folders that are not git repositories</span>
          <HelpTooltip technical subject="uploading a folder that is not a git repository" content={TECHNICAL} className="ml-1 align-middle" />
          <span className="block text-[11px] text-fg-3">
            On by default. Observer lists the folder&apos;s files the way git would, without changing the folder: it follows the
            folder&apos;s own .gitignore and leaves out dependency, build and virtual-environment folders, version-control folders,
            .env files and operating-system clutter, then the usual secret-looking files. The consent screen lists the files before
            anything is sent, and the agent&apos;s changes come back as a diff file. Off: such a folder cannot be used with a hosted
            sandbox. A folder inside a git repository is never uploaded on its own; pick the repository.
          </span>
          {nonGitPinned && <span className="block text-[11px] text-fg-3">Set by your organization.</span>}
        </span>
      </label>
      <label className="block space-y-1">
        <span className="font-medium text-fg-2">More files to leave out</span>
        <textarea
          rows={Math.max(2, Math.min(5, saved.length + 1))}
          value={text}
          disabled={!writable || !on}
          placeholder={"*.log\ndata/raw/"}
          onChange={(e) => {
            setText(e.target.value);
            onChange({ ...value, upload_ignore: ignoreLines(e.target.value) });
          }}
          className="w-full rounded-2 border border-line-2 bg-bg-0 px-2 py-1 font-mono text-[11px] text-fg-1 disabled:opacity-50"
        />
        <span className="block text-[11px] text-fg-3">
          One pattern per line, written like a .gitignore line. Start a line with ! to send something the default list leaves out
          (for example !dist/). Used only for a folder that is not a git repository.
        </span>
        {problem && <span className="block text-[11px] text-warn">{problem}</span>}
        {ignorePinned && <span className="block text-[11px] text-fg-3">Your organization adds its patterns to yours.</span>}
      </label>
    </div>
  );
}
