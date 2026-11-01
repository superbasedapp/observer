import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  diagMessage,
  diagSeverity,
  normalizeRel,
  planDiagnostics,
  quickPickLabel,
  relativeTo,
  statusLabel,
  type SecurityEditorFinding,
} from '../../src/security-internals';
import { contextValues, GATED_SURFACES } from '../../src/components-internals';

function finding(over: Partial<SecurityEditorFinding> = {}): SecurityEditorFinding {
  return {
    id: 'F1',
    rule_id: 'S-721',
    category: 'secret',
    severity: 'high',
    confidence: 'high',
    baseline: 'new',
    rel_path: 'src/a.py',
    start_line: 3,
    message: 'S-721: an AWS secret access key in the code',
    fix_hint: 'Move the value to an environment variable.',
    ...over,
  };
}

test('severity table: high is a warning, medium information, low a hint', () => {
  assert.equal(diagSeverity('critical'), 'warning');
  assert.equal(diagSeverity('high'), 'warning');
  assert.equal(diagSeverity('medium'), 'information');
  assert.equal(diagSeverity('low'), 'hint');
  assert.equal(diagSeverity('info'), 'hint');
  assert.equal(diagSeverity('whatever'), 'information');
});

test('the message carries the fix hint, marks pre-existing, strips control characters and is capped', () => {
  assert.equal(
    diagMessage(finding()),
    'S-721: an AWS secret access key in the code Fix: Move the value to an environment variable.',
  );
  assert.match(diagMessage(finding({ baseline: 'pre_existing', fix_hint: '' })), /pre-existing at the baseline\)$/);
  assert.equal(diagMessage(finding({ message: 'a\u001b[31mb', fix_hint: '' })), 'a [31mb');
  assert.equal(diagMessage(finding({ message: 'x'.repeat(1000), fix_hint: '' })).length, 400);
});

test('planDiagnostics groups by file, 0-based lines, ordered, unsafe paths dropped', () => {
  const plan = planDiagnostics([
    finding({ id: 'b', start_line: 9 }),
    finding({ id: 'a', start_line: 2 }),
    finding({ id: 'c', rel_path: '../etc/passwd' }),
    finding({ id: 'd', rel_path: '/abs/x' }),
    finding({ id: 'e', rel_path: 'C:/x' }),
    finding({ id: 'f', rel_path: 'win\\style.py', start_line: 0 }),
  ]);
  assert.deepEqual([...plan.keys()].sort(), ['src/a.py', 'win/style.py']);
  assert.deepEqual(plan.get('src/a.py')!.map((p) => [p.findingId, p.line]), [['a', 1], ['b', 8]]);
  assert.equal(plan.get('win/style.py')![0].line, 0);
  assert.equal(planDiagnostics(null).size, 0);
});

test('relativeTo and normalizeRel', () => {
  assert.equal(relativeTo('/w/repo', '/w/repo/src/a.py'), 'src/a.py');
  assert.equal(relativeTo('/w/repo/', '/w/repo2/a.py'), '');
  assert.equal(relativeTo('C:\\W\\Repo', 'c:\\w\\repo\\a.py'), 'a.py');
  assert.equal(normalizeRel('./a/b'), 'a/b');
  assert.equal(normalizeRel('a/../b'), '');
});

test('status and quick pick labels', () => {
  assert.equal(statusLabel(1), '$(shield) 1 finding');
  assert.equal(statusLabel(3), '$(shield) 3 findings');
  assert.deepEqual(quickPickLabel(finding()).description, 'src/a.py:3');
});

test('the surface is gated on the security component', () => {
  assert.ok(GATED_SURFACES.some((g) => g.contextKey === 'observer.securityInactive' && g.component === 'security'));
  const inactive = contextValues({ view: { components: [{ id: 'security', state: 'inactive' }] } });
  assert.equal(inactive['observer.securityInactive'], true);
  const active = contextValues({ view: { components: [{ id: 'security', state: 'active' }] } });
  assert.equal(active['observer.securityInactive'], false);
  // No state read (an older daemon): fail open, like every other surface.
  assert.equal(contextValues(undefined)['observer.securityInactive'], false);
});
