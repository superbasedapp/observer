// launchPolicyStep: the pure state of the New Terminal dialog's inline
// launch-policy steps ("Allow this folder", "Turn on fresh-agent launch";
// LaunchPolicyInline.tsx). Windows 11 Pro run 4 (B4): the review of the
// config change used to open the shell's preview dialog, which sat BEHIND
// New terminal, so saving meant closing New terminal and opening it again.
// The step now owns the review: confirm runs the same dry run and save
// (saveConfigEdit through an injected prompt), the step shows the diff and a
// Save button in place, and the dialog never opens a second one. No imports,
// so node:test pins it directly.

/** Where one inline step is. Only "idle" leaves the dialog's Start free. */
export type StepPhase = "idle" | "confirming" | "checking" | "reviewing" | "saving";

/** One step's state; review is the preview request while reviewing or saving. */
export type StepState<R> = { phase: StepPhase; review: R | null; err: string | null };

/** The prompt the step hands the save: resolves true on Save, false on Cancel. */
export type ReviewPrompt<R> = (req: R) => Promise<boolean>;

/**
 * stepHoldsStart reports whether a step in this phase holds the dialog's
 * Start button: a change that is being confirmed, checked, reviewed or
 * written is not finished, so a launch now would race it.
 */
export function stepHoldsStart(phase: StepPhase): boolean {
  return phase !== "idle";
}

/** isCancelled: a cancelled preview is the user's own no, not an error. */
export function isCancelled(e: unknown): boolean {
  const name = e instanceof Error ? e.name : "";
  const msg = e instanceof Error ? e.message : String(e);
  return name === "ConfigSaveCancelled" || /cancel/i.test(name + " " + msg);
}

/**
 * PolicyStep runs one inline step: arm (the confirm question), confirm (the
 * dry run; the step's own review prompt then shows the diff), save or
 * cancel. run is the change itself, given the review prompt to pass to the
 * save; onState receives every new state.
 */
export class PolicyStep<R> {
  private s: StepState<R>;
  private resolve: ((ok: boolean) => void) | null = null;
  private disposed = false;
  private readonly run: (prompt: ReviewPrompt<R>) => Promise<void>;
  private readonly onState: (s: StepState<R>) => void;

  constructor(
    run: (prompt: ReviewPrompt<R>) => Promise<void>,
    onState: (s: StepState<R>) => void,
    initial: Partial<StepState<R>> = {},
  ) {
    this.run = run;
    this.onState = onState;
    this.s = { phase: "idle", review: null, err: null, ...initial };
  }

  /** The current state. */
  get state(): StepState<R> {
    return this.s;
  }

  private set(p: Partial<StepState<R>>) {
    this.s = { ...this.s, ...p };
    if (!this.disposed) this.onState(this.s);
  }

  /** arm shows the confirm question. */
  arm() {
    if (this.s.phase === "idle") this.set({ phase: "confirming", err: null });
  }

  /** disarm leaves the confirm question unanswered. */
  disarm() {
    if (this.s.phase === "confirming") this.set({ phase: "idle" });
  }

  /**
   * confirm runs the change. Its save asks this step's review prompt, which
   * puts the step in "reviewing" until save or cancelReview answers it. The
   * step ends idle: with no error after a save, a no-op or a cancel, with
   * the reason after a failure.
   */
  async confirm(): Promise<void> {
    if (this.s.phase !== "confirming") return;
    this.set({ phase: "checking", err: null });
    const prompt: ReviewPrompt<R> = (req) =>
      new Promise<boolean>((resolve) => {
        this.resolve = resolve;
        this.set({ phase: "reviewing", review: req });
      });
    try {
      await this.run(prompt);
      this.set({ phase: "idle", review: null });
    } catch (e) {
      this.set({ phase: "idle", review: null, err: isCancelled(e) ? null : e instanceof Error ? e.message : String(e) });
    } finally {
      this.resolve = null;
    }
  }

  /** save answers the review with Save: the change is written. */
  save() {
    const r = this.resolve;
    if (this.s.phase !== "reviewing" || !r) return;
    this.resolve = null;
    this.set({ phase: "saving" });
    r(true);
  }

  /** cancelReview answers the review with Cancel: nothing is written. */
  cancelReview() {
    const r = this.resolve;
    if (this.s.phase !== "reviewing" || !r) return;
    this.resolve = null;
    r(false);
  }

  /** dispose answers an open review with Cancel and stops reporting states. */
  dispose() {
    this.disposed = true;
    const r = this.resolve;
    this.resolve = null;
    if (r) r(false);
  }
}

/** absolutePath reports whether p is an absolute POSIX or drive-letter path. */
export function absolutePath(p: string): boolean {
  const s = p.trim();
  return s.startsWith("/") || /^[A-Za-z]:[\\/]/.test(s);
}

// isUnderOrEqual is a lexical containment check on the canonical form (the
// daemon canonicalizes allowed_project_roots to absolute, symlink-resolved,
// trailing-slash-stripped paths).
function isUnderOrEqual(child: string, parent: string): boolean {
  const c = child.replace(/\/+$/, "");
  const p = parent.replace(/\/+$/, "");
  return c === p || c.startsWith(p + "/");
}

/**
 * isPermittedRoot reports whether a project root would pass the server's
 * allowed_project_roots check, using the canonical allow-list verbatim. An
 * empty allow-list permits nothing but the agent's own default cwd.
 *
 * KNOWN COSMETIC MISMATCH (documented, not a gate): this check is LEXICAL
 * while the server canonicalizes the requested root through EvalSymlinks at
 * launch time (and, on a daemon in WSL, translates a Windows path to its
 * /mnt/c form). The server's canonical check remains the ONLY authority:
 * this is a UX hint and must never be mistaken for authorization.
 */
export function isPermittedRoot(path: string, allowedRoots: string[]): boolean {
  return allowedRoots.some((r) => isUnderOrEqual(path, r));
}

/**
 * folderNeedsAllow reports whether the typed custom folder still needs the
 * "Allow this folder" step: an absolute path the allow-list does not cover
 * and that the step has not saved in this dialog already. The saved list
 * matters where the server stores a different spelling (a daemon in WSL
 * stores C:\x as /mnt/c/x), so a folder just allowed never asks again.
 */
export function folderNeedsAllow(customRoot: string, allowedRoots: string[], savedRoots: string[]): boolean {
  const r = customRoot.trim();
  return absolutePath(r) && !isPermittedRoot(r, allowedRoots) && !savedRoots.includes(r);
}
