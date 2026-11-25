// admissionMark moved to shared/lib/admissionMark.ts (the org dashboard
// had the same helper); re-exported here so existing importers keep
// compiling. A relative .ts path, so the node test runner resolves it.
export * from "../../../shared/lib/admissionMark.ts";
