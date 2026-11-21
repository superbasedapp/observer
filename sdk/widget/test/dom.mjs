// A browser-like global environment for node --test (happy-dom, dev only).
import { Window } from "happy-dom";

export function installDom(url = "https://app.example/chat") {
  const window = new Window({ url });
  for (const k of ["window", "document", "customElements", "HTMLElement", "HTMLFormElement", "CustomEvent", "Event", "KeyboardEvent", "Node", "location", "navigator", "MutationObserver", "getComputedStyle"]) {
    Object.defineProperty(globalThis, k, { value: k === "window" ? window : window[k], configurable: true, writable: true });
  }
  globalThis.requestAnimationFrame = (cb) => setTimeout(cb, 0);
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  return window;
}

/** A recording fetch: answers `status` (default 200) and keeps every call. */
export function fakeFetch(status = 200) {
  const calls = [];
  const f = async (url, init) => {
    calls.push({ url, init, body: JSON.parse(init.body) });
    if (status === "throw") throw new Error("network down");
    return { ok: status >= 200 && status < 300, status };
  };
  f.calls = calls;
  return f;
}

export const TRACE = "4bf92f3577b34da6a3ce929d0e0e4736";
export const SPAN = "00f067aa0ba902b7";
export const tick = () => new Promise((r) => setTimeout(r, 0));
