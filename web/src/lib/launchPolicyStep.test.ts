// Pins the New Terminal dialog's inline launch-policy step (Windows 11 Pro
// run 4, B4): the review of the change is the step's own, the full sequence
// (Allow, confirm, review, Save) writes once at the previewed etag, never
// asks a second dialog, and ends with nothing holding Start.
import { test } from "node:test";
import assert from "node:assert/strict";
import { runSectionSave, type SectionPreviewRequest } from "./configSectionSaveCore.ts";
import {
  PolicyStep,
  folderNeedsAllow,
  isCancelled,
  isPermittedRoot,
  stepHoldsStart,
  type StepPhase,
  type StepState,
} from "./launchPolicyStep.ts";

type Call = { params: Record<string, string>; body: string };

function fakeRoute(calls: Call[]) {
  return async (_section: string, params: Record<string, string>, body: string): Promise<unknown> => {
    calls.push({ params, body });
    if (params.dry_run === "1") {
      return {
        dry_run: true,
        would_write: true,
        changed_keys: ["terminal.launch.allowed_project_roots"],
        restart_required: false,
        restart_required_keys: [],
        applied_live_keys: ["terminal.launch.allowed_project_roots"],
        next_spawn_keys: [],
        comments_preserved: true,
        write_mode: "surgical",
        config_path: "C:\\Users\\u\\.observer\\config.toml",
        config_etag: "etag-1",
        diff: "-allowed_project_roots = ['C:\\\\w']\n+allowed_project_roots = ['C:\\\\w', 'C:\\\\w2']\n",
        diff_stats: { added: 1, removed: 1 },
        needs_confirm: false,
        secret_warnings: [],
      };
    }
    return { saved: true, section: "terminal.launch", restart_required: false };
  };
}

async function until(f: () => boolean) {
  for (let i = 0; i < 100 && !f(); i++) await new Promise((r) => setTimeout(r, 1));
  assert.ok(f(), "condition not reached");
}

test("the full Allow, confirm, review, Save sequence stays in the step and frees Start", async () => {
  const calls: Call[] = [];
  let shellDialogAsked = 0;
  const phases: StepPhase[] = [];
  const step = new PolicyStep<SectionPreviewRequest>(
    async (review) => {
      // The shell dialog would be the fallback; the step's review must answer instead.
      const shellDialog = async () => {
        shellDialogAsked++;
        return true;
      };
      await runSectionSave("terminal.launch", { allowed_project_roots: ["C:\\w", "C:\\w2"] }, { put: fakeRoute(calls), prompt: review ?? shellDialog });
    },
    (s: StepState<SectionPreviewRequest>) => phases.push(s.phase),
  );
  assert.equal(stepHoldsStart(step.state.phase), false);
  step.arm();
  assert.equal(step.state.phase, "confirming");
  assert.equal(stepHoldsStart(step.state.phase), true);
  const done = step.confirm();
  await until(() => step.state.phase === "reviewing");
  assert.match(step.state.review?.dryRun.diff ?? "", /C:\\\\w2/);
  assert.equal(calls.length, 1, "only the dry run so far: nothing written before Save");
  step.save();
  await done;
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[1].params, { base_etag: "etag-1" }, "the save is at the previewed etag");
  assert.equal(shellDialogAsked, 0, "no second dialog is opened");
  assert.deepEqual(phases, ["confirming", "checking", "reviewing", "saving", "idle"]);
  assert.equal(step.state.err, null);
  assert.equal(stepHoldsStart(step.state.phase), false, "Start is free once the change is saved");
});

test("Cancel in the review writes nothing and is not an error", async () => {
  const calls: Call[] = [];
  const step = new PolicyStep<SectionPreviewRequest>(
    (review) => runSectionSave("terminal.launch", {}, { put: fakeRoute(calls), prompt: review }).then(() => undefined),
    () => {},
  );
  step.arm();
  const done = step.confirm();
  await until(() => step.state.phase === "reviewing");
  step.cancelReview();
  await done;
  assert.equal(calls.length, 1, "the dry run only");
  assert.equal(step.state.phase, "idle");
  assert.equal(step.state.err, null);
});

test("a failed save shows its reason; a step that goes away cancels its open review", async () => {
  const failing = new PolicyStep<SectionPreviewRequest>(async () => {
    throw new Error("409 the config file changed");
  }, () => {});
  failing.arm();
  await failing.confirm();
  assert.equal(failing.state.err, "409 the config file changed");
  assert.equal(failing.state.phase, "idle");

  const calls: Call[] = [];
  const gone = new PolicyStep<SectionPreviewRequest>(
    (review) => runSectionSave("terminal.launch", {}, { put: fakeRoute(calls), prompt: review }).then(() => undefined),
    () => {},
  );
  gone.arm();
  const done = gone.confirm();
  await until(() => gone.state.phase === "reviewing");
  gone.dispose();
  await done;
  assert.equal(calls.length, 1, "nothing written after the step went away");
  assert.equal(isCancelled(new Error("Save cancelled; nothing was written.")), true);
});

test("a folder the step saved needs no second Allow, whatever spelling the server keeps", () => {
  assert.equal(folderNeedsAllow("C:\\Users\\u\\work2", ["C:\\Users\\u\\work"], []), true);
  // A daemon in WSL stores the translated path, so only the saved list says it is done.
  assert.equal(folderNeedsAllow("C:\\Users\\u\\work2", ["/mnt/c/Users/u/work2"], ["C:\\Users\\u\\work2"]), false);
  assert.equal(folderNeedsAllow(" C:\\Users\\u\\work2 ", ["C:\\Users\\u\\work2"], []), false);
  assert.equal(folderNeedsAllow("work2", [], []), false, "a relative path gets no step");
  assert.equal(isPermittedRoot("/srv/a/b", ["/srv/a/"]), true);
  assert.equal(isPermittedRoot("/srv/ab", ["/srv/a"]), false);
});
