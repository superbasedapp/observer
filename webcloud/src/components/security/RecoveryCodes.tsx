import { OneTimeSecret } from "@shared/primitives/OneTimeSecret";

// RecoveryCodes shows a fresh batch of one-time recovery codes exactly once
// (the server keeps only their hashes). Purely presentational.
export function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  return (
    <OneTimeSecret
      title="Save your recovery codes"
      value={codes.join("\n")}
      description="Each code signs you in once if you lose your passkey. Keep them somewhere safe, like a password manager."
      warning="You will not see these codes again."
      dismissLabel="I saved them"
      copyLabel="Copy codes"
      onDismiss={onDone}
    />
  );
}
