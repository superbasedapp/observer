// What `setup` prints for a Next.js project (plan 3.3), as Next's
// instrumentation.ts: the nodejs runtime loads the register entry; the edge
// runtime does not.
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    await import("@superbased/sdk/register");
  }
}
