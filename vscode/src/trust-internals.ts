// Pure helpers for the workspace-trust gate (P1-5: a cloned repo's
// .vscode/settings.json must not be able to choose the daemon binary this
// extension spawns). Kept vscode-free, mirroring the binary-internals.ts
// split, so the decision logic is unit-testable without the Extension
// Development Host.

// Settings that name an executable/path this extension resolves and spawns.
// Kept as the single source of truth for the warning text; package.json's
// capabilities.untrustedWorkspaces.restrictedConfigurations list (and each
// setting's own "scope": "machine") is the actual VS Code-enforced
// restriction — this constant only has to stay in sync for the message to
// be accurate.
export const RESTRICTED_TRUST_SETTINGS = [
  'observer.binary.path',
  'observer.binary.preferPathBinary',
] as const;

// shouldDeferActivation reports whether activate() must refuse to resolve or
// spawn the observer binary and defer the rest of activation until workspace
// trust is granted.
export function shouldDeferActivation(isTrusted: boolean): boolean {
  return !isTrusted;
}

// untrustedWorkspaceWarning is the single line surfaced to both the output
// channel and a notification when activation is deferred for trust.
export function untrustedWorkspaceWarning(): string {
  return (
    'SuperBased: this workspace is not trusted, so the observer daemon ' +
    'binary will not be resolved or spawned. ' +
    `${RESTRICTED_TRUST_SETTINGS.join(' and ')} are restricted (machine-scoped) ` +
    'settings and are ignored from workspace/folder configuration until you ' +
    'grant workspace trust.'
  );
}
