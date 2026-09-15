// Human lines-of-code capture (plan §3.3 "Human capture v1").
//
// WHAT LEAVES THE EDITOR: line counts. Never file content, never a line
// of text, never an excerpt. The POST body's type
// (api/client.ts::EditorChangeRequest) has no field that can carry any.
// The counts go to the local observer daemon on loopback and nowhere
// else.
//
// EVENTS THIS RELIES ON, and why:
//
//   onDidOpenTextDocument   — seeds the clean baseline for a document
//                             the extension has not seen before.
//   onDidChangeTextDocument — safeguard (a). A change while the document
//                             is NOT dirty is VS Code reloading the file
//                             from disk, which is what happens when an
//                             agent writes it. Refreshing the baseline
//                             there is what stops the agent's lines from
//                             becoming the human's on the next save.
//                             A human edit always leaves the document
//                             dirty, so `!isDirty` is a sound
//                             discriminator and no timer is involved.
//   onWillSaveTextDocument  — safeguard (b), first half: the text as the
//                             human left it, BEFORE format-on-save runs.
//   onDidSaveTextDocument   — safeguard (b), second half: the text
//                             actually written. The difference between
//                             the two is the formatter's, reported as
//                             `system`.
//   onDidCloseTextDocument  — drops the snapshot.
//
// This is a SIBLING of the onDidSaveTextDocument listener in
// views/sessionsTree.ts, not an extension of it: that one belongs to a
// tree provider with its own lifetime and refreshes a view, this one
// owns a per-document snapshot map. Folding them together would couple
// two unrelated lifetimes for no gain.

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import type { DaemonManager } from '../daemon';
import { LocEndpointMissingError, type EditorChangeRequest } from '../api/client';
import { output } from '../output';
import { classifierVersion, hasGeneratedHeader, language } from './classify';
import {
  EditorTokenSource,
  SaveTracker,
  hasCounts,
  toForwardSlashes,
  type BufferChangeShape,
} from './tracker-internals';
import { dbDirDefault } from '../daemon-internals';

/**
 * bufferChangeShape reduces a VS Code change event to the numbers the
 * agent-shape classifier needs.
 *
 * It counts NEWLINES, never text: nothing derived here can carry a line
 * of the document, which keeps the "counts only" posture true all the way
 * up to the event listener.
 */
function bufferChangeShape(e: vscode.TextDocumentChangeEvent): BufferChangeShape {
  let insertedLength = 0;
  let insertedLines = 0;
  let replacedLines = 0;
  for (const c of e.contentChanges) {
    insertedLength += c.text.length;
    insertedLines += countNewlines(c.text);
    replacedLines += c.range.end.line - c.range.start.line;
  }
  return {
    ranges: e.contentChanges.length,
    insertedLength,
    insertedLines,
    replacedLines,
    reason: changeReason(e),
    dirty: e.document.isDirty,
  };
}

/**
 * firstLines returns up to n leading lines of a document, for the
 * generated-banner sniff. It uses lineAt rather than getText so the cost
 * does not scale with the file.
 */
function firstLines(doc: vscode.TextDocument, n: number): string[] {
  const out: string[] = [];
  for (let i = 0; i < Math.min(n, doc.lineCount); i++) {
    out.push(doc.lineAt(i).text);
  }
  return out;
}

/** countNewlines counts line breaks without allocating a split array. */
function countNewlines(text: string): number {
  let n = 0;
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10) {
      n++;
    }
  }
  return n;
}

/**
 * changeReason maps VS Code's TextDocumentChangeReason enum onto the
 * plain strings the pure classifier understands.
 *
 * `e.reason` is undefined on older VS Code versions, and an unknown value
 * degrades to undefined rather than being guessed at — which only ever
 * costs the change the undo/redo exemption.
 */
function changeReason(e: vscode.TextDocumentChangeEvent): 'undo' | 'redo' | undefined {
  switch (e.reason) {
    case vscode.TextDocumentChangeReason.Undo:
      return 'undo';
    case vscode.TextDocumentChangeReason.Redo:
      return 'redo';
    default:
      return undefined;
  }
}

const SETTING_ENABLED = 'loc.reportSaves';
// The LOC endpoint's own credential, distinct from observer.apiToken:
// apiToken is the general dashboard token, this one is the per-install
// secret the daemon generates for POST /api/loc/editor-change. Leaving it
// empty is the normal case - the token file is read instead.
const SETTING_TOKEN = 'loc.editorToken';

/**
 * LOC_TOKEN_FILENAME is the daemon's default [loc].editor_token_file
 * basename, resolved inside the observer home (OBSERVER_HOME, else
 * ~/.observer). An operator who moved the file with the config key sets
 * observer.loc.editorToken instead - the extension does not parse
 * config.toml.
 */
const LOC_TOKEN_FILENAME = 'loc-editor-token';

/**
 * registerLocTracker wires the human-LOC capture into the extension's
 * activation path. Everything it registers lands on ctx.subscriptions,
 * so deactivation tears it all down.
 */
export function registerLocTracker(ctx: vscode.ExtensionContext, daemon: DaemonManager): void {
  const tracker = new LocTracker(daemon);
  // The tracker owns its own listeners and disposes them; registering
  // the tracker itself is all ctx needs to hold.
  ctx.subscriptions.push(tracker);
  tracker.start();
}

class LocTracker implements vscode.Disposable {
  private readonly saves = new SaveTracker();
  private enabled: boolean;
  private readonly tokenSource: EditorTokenSource;
  /** Set once the daemon answers 404; stops posting for the session. */
  private endpointMissing = false;
  private readonly disposables: vscode.Disposable[] = [];

  constructor(private readonly daemon: DaemonManager) {
    const cfg = vscode.workspace.getConfiguration('observer');
    this.enabled = cfg.get<boolean>(SETTING_ENABLED) ?? true;
    this.tokenSource = new EditorTokenSource({
      setting: () => vscode.workspace.getConfiguration('observer').get<string>(SETTING_TOKEN) ?? '',
      tokenFile: () => path.join(dbDirDefault(), LOC_TOKEN_FILENAME),
      // A missing file is the ordinary case while the daemon has not
      // started yet, so this must never throw or log per save.
      readFile: (p) => {
        try {
          return fs.readFileSync(p, 'utf8');
        } catch {
          return undefined;
        }
      },
    });
  }

  start(): void {
    // Seed every already-open document. Without this, the first save of
    // a document that was open before activation has no baseline and is
    // (correctly, but uselessly) dropped.
    for (const doc of vscode.workspace.textDocuments) {
      if (this.eligible(doc)) {
        this.saves.seed(doc.uri.toString(), doc.getText());
      }
    }

    this.disposables.push(
      vscode.workspace.onDidOpenTextDocument((doc) => {
        if (this.eligible(doc)) {
          this.saves.seed(doc.uri.toString(), doc.getText());
        }
      }),
      vscode.workspace.onDidChangeTextDocument((e) => {
        if (!this.eligible(e.document)) {
          return;
        }
        // Safeguard (a): an external reload of a clean document.
        if (!e.document.isDirty) {
          this.saves.external(e.document.uri.toString(), e.document.getText());
          return;
        }
        // Safeguard (a2): an IN-EDITOR agent. Copilot Chat agent mode,
        // Cline/Kilo and Cursor apply edits through a WorkspaceEdit,
        // which dirties the buffer exactly like typing — so `!isDirty`
        // alone booked their lines as the developer's. Classify the
        // change's SHAPE instead and mark the document; the save that
        // follows reports possible_agent and the daemon books it as
        // unknown rather than human.
        this.saves.changed(e.document.uri.toString(), bufferChangeShape(e));
      }),
      vscode.workspace.onWillSaveTextDocument((e) => {
        if (this.eligible(e.document)) {
          this.saves.willSave(e.document.uri.toString(), e.document.getText());
        }
      }),
      vscode.workspace.onDidSaveTextDocument((doc) => {
        void this.onSaved(doc);
      }),
      vscode.workspace.onDidCloseTextDocument((doc) => {
        this.saves.forget(doc.uri.toString());
      }),
      vscode.workspace.onDidChangeConfiguration((e) => {
        if (
          e.affectsConfiguration('observer.loc.reportSaves') ||
          e.affectsConfiguration('observer.loc.editorToken')
        ) {
          const cfg = vscode.workspace.getConfiguration('observer');
          this.enabled = cfg.get<boolean>(SETTING_ENABLED) ?? true;
          // Drop the cached file token too: an operator who just cleared
          // the setting expects the next save to fall back to the file
          // without an editor reload.
          this.tokenSource.invalidate();
          output.appendLine(`LOC capture ${this.enabled ? 'enabled' : 'disabled'} by settings`);
        }
      }),
    );
  }

  /**
   * eligible gates a document on the two hard skips: a non-file scheme
   * (untitled buffers, diff views, git: revisions, notebook cells have
   * no path the daemon can resolve) and a generated or vendored path.
   * Both are checked BEFORE any text is snapshotted, so a node_modules
   * file never costs memory either.
   */
  private eligible(doc: vscode.TextDocument): boolean {
    if (doc.uri.scheme !== 'file') {
      return false;
    }
    const folder = vscode.workspace.getWorkspaceFolder(doc.uri);
    if (!folder) {
      return false;
    }
    const rel = toForwardSlashes(vscode.workspace.asRelativePath(doc.uri, false));
    const { category } = language(rel);
    if (category === 'generated' || category === 'vendored') {
      return false;
    }
    // The path is not always enough: a generator that names its output
    // `models.go` still stamps the canonical `// Code generated … DO NOT
    // EDIT.` banner on it. Only the first three lines are read, via
    // lineAt, so this costs nothing on a large file.
    return !hasGeneratedHeader(firstLines(doc, 3));
  }

  private async onSaved(doc: vscode.TextDocument): Promise<void> {
    const key = doc.uri.toString();
    if (!this.eligible(doc)) {
      this.saves.forget(key);
      return;
    }
    const folder = vscode.workspace.getWorkspaceFolder(doc.uri);
    if (!folder) {
      return;
    }
    const rel = toForwardSlashes(vscode.workspace.asRelativePath(doc.uri, false));
    const { lang, category } = language(rel);

    // Always advance the snapshot, even when reporting is off: leaving
    // a stale baseline behind would make the first save after the
    // setting is re-enabled include everything typed while it was off.
    const delta = this.saves.didSave(key, doc.getText(), lang);
    if (!this.enabled || this.endpointMissing || !hasCounts(delta)) {
      return;
    }
    if (this.daemon.getState().status === 'idle') {
      return;
    }

    const body: EditorChangeRequest = {
      path: rel,
      workspace_root: folder.uri.fsPath,
      language: lang,
      category,
      human: delta.human,
      system: delta.system,
      human_confidence: delta.humanConfidence,
      system_confidence: delta.systemConfidence,
      saved_at: new Date().toISOString(),
      classifier_version: classifierVersion,
      possible_agent: delta.possibleAgent,
    };

    try {
      await this.daemon.getClient().postEditorChange(body, this.tokenSource.get() || undefined);
    } catch (err) {
      if (err instanceof LocEndpointMissingError) {
        this.endpointMissing = true;
        output.appendLine(
          'LOC capture: daemon has no /api/loc/editor-change endpoint (older daemon); ' +
            'disabling editor line reporting for this session.',
        );
        return;
      }
      // Silent by design: a daemon that is not running must not produce
      // a notification on every save.
      output.appendLine(
        `LOC capture: post failed (${err instanceof Error ? err.message : String(err)})`,
      );
    }
  }

  dispose(): void {
    for (const d of this.disposables) {
      d.dispose();
    }
    this.disposables.length = 0;
  }
}
