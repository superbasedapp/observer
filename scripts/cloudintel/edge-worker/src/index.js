const EDGE_AUTH_HEADER = "X-SBCI-Edge-Auth";
const EDGE_HOST_HEADER = "X-SBCI-Edge-Host";
const EDGE_CLIENT_IP_HEADER = "X-SBCI-Client-IP";

const STRIPPED_HEADERS = [
  "x-sbci-edge-auth",
  "x-sbci-edge-host",
  "x-sbci-client-ip",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-real-ip",
];

// Fallback accepted public hosts when SBCI_PUBLIC_HOSTS is unset (the shape
// every deployment before the 2026-09-14 hostname move ran with).
const DEFAULT_PUBLIC_HOSTS = [
  "cloud.superbased.app",
  "app.superbased.app",
];

// publicHostsFor returns the set of public hostnames this Worker will proxy.
// SBCI_PUBLIC_HOSTS (a comma-separated [vars] entry, per Wrangler environment)
// overrides the default so staging and production can each fence exactly the
// hostname their Cloudflare route carries; the Worker route is the first
// filter, this set is the second. Blank entries are ignored.
export function publicHostsFor(env) {
  const raw = typeof env.SBCI_PUBLIC_HOSTS === "string" ? env.SBCI_PUBLIC_HOSTS : "";
  const hosts = raw
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter((h) => h.length > 0);
  return new Set(hosts.length > 0 ? hosts : DEFAULT_PUBLIC_HOSTS);
}

export default {
  async fetch(request, env) {
    if (!env.SBCI_EDGE_SHARED_SECRET || !env.SBCI_ORIGIN_BASE_URL) {
      return new Response("edge proxy is not configured", { status: 503 });
    }

    const incoming = new URL(request.url);
    const publicHost = incoming.hostname.toLowerCase();
    if (!publicHostsFor(env).has(publicHost)) {
      return new Response("unknown public edge host", { status: 421 });
    }

    let origin;
    try {
      origin = new URL(env.SBCI_ORIGIN_BASE_URL);
    } catch (_) {
      return new Response("edge proxy origin is invalid", { status: 503 });
    }
    if (origin.protocol !== "https:") {
      return new Response("edge proxy origin must use HTTPS", { status: 503 });
    }

    // Cloudflare supplies this header at the edge. Reject a missing or
    // comma-separated value so the API receives one candidate address only.
    const clientIP = request.headers.get("CF-Connecting-IP");
    if (!clientIP || clientIP.includes(",")) {
      return new Response("missing or ambiguous client address", { status: 400 });
    }

    origin.pathname = incoming.pathname;
    origin.search = incoming.search;

    const headers = new Headers(request.headers);
    for (const name of STRIPPED_HEADERS) headers.delete(name);
    headers.delete("cf-connecting-ip");
    // CF-Connecting-IP is reserved and can be rewritten by the runtime when
    // this fetch crosses from the superbased.app zone to Azure. Preserve the
    // value in a private header instead; the API accepts it only after the
    // authenticated edge proof succeeds.
    headers.set(EDGE_CLIENT_IP_HEADER, clientIP.trim());
    headers.set(EDGE_AUTH_HEADER, env.SBCI_EDGE_SHARED_SECRET);
    // The ACA fetch necessarily changes Host to the fixed origin FQDN. Pass
    // the validated public hostname in a separate private header so the API's
    // canonical-host fence can still distinguish its /v1 and /portal names.
    headers.set(EDGE_HOST_HEADER, publicHost);

    const init = {
      method: request.method,
      headers,
      redirect: "manual",
    };
    if (request.method !== "GET" && request.method !== "HEAD") {
      init.body = request.body;
    }
    // The URL host is the fixed ACA origin host. Do not derive it from the
    // incoming URL; otherwise this becomes an SSRF-capable open proxy.
    return fetch(new Request(origin, init));
  },
};
