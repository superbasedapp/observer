# Trace the AI apps you build

**AI Apps** is the part of SuperBased for the LLM apps and agents you
build yourself: traces, cost and evals, sent by the superbased SDKs (or
any OpenTelemetry exporter) to this machine. Your AI coding agents keep
being tracked whether it is on or off.

`SuperBased: Turn on AI Apps` asks once, then turns it on in the running
daemon, with no restart:

- adds the AI Apps component;
- starts listening for your app's traces on `127.0.0.1:4318`, for this
  machine only.

The confirmation names where the data goes. On a machine that is not
connected to an organization it stays on this machine; on one whose
organization turned an AI Apps share on, the confirmation says which.

### If it cannot turn on

- **The port is taken.** Another program (a collector, Jaeger) holds
  4318 or 4317. Stop it, or move the receiver with `[ingest.otel]
  http_addr` / `grpc_addr`, and turn AI Apps on again.
- **This edition does not include AI Apps.** The developer and full
  editions have it; reinstall with `install.sh --edition developer`
  (Windows: `install.ps1 -Edition developer`).
- **An older daemon.** It cannot turn AI Apps on while it runs: restart
  `observer start` (with the proxy route off first if an AI session uses
  it).

### Send a trace

Open the dashboard's **AI apps** page: it waits for your first trace
and shows the SDK install line and a snippet for Python, TypeScript, Go
and Java.

From a terminal the same thing is `observer apps on`; `observer apps
status` shows the receiver and the latest trace, and `observer apps off`
turns it off at the next start.
