// Stands in for `next start` on the nodejs runtime: Next calls the
// instrumentation hook's register() once, before it loads any route module,
// then loads routes with a dynamic import (an externalised package, here
// openai, is then loaded by Node itself; see the setup next steps on
// serverExternalPackages). The real Next.js build is the live e2e's (L8).
const instrumentation = await import("./instrumentation.mjs");
await instrumentation.register();
const route = await import("./app/api/chat/route.mjs");
const answer = await route.POST();

const sb = await import("@superbased/sdk");
await sb.flush(5000);
const d = sb.diagnostics();
console.log(JSON.stringify({ answer, runtime: process.env.NEXT_RUNTIME ?? "", initialized: d.initialized, instrumented: sb.instrumented(), service: d.serviceName }));
