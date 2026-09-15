import React from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { App } from "./App";
import { initTheme } from "./theme";
import "./styles.css";

// Apply the stored (or default-dark) theme before first paint.
initTheme();

function render() {
  const container = document.getElementById("root");
  if (!container) {
    throw new Error("root element missing");
  }
  createRoot(container).render(
    <React.StrictMode>
      <BrowserRouter basename="/portal">
        <App />
      </BrowserRouter>
    </React.StrictMode>,
  );
}

// DEV-only: mock the /portal/* API so the redesign renders with data under a
// bare `vite` dev server. Dynamically imported behind import.meta.env.DEV so
// it is never included in the production build (the branch is dead-code
// eliminated and the dynamic import dropped when DEV is false). The mock's
// fetch patch MUST be installed before React mounts — App fires getSession()
// on mount — so the render is awaited behind it. See src/devmock.ts.
if (import.meta.env.DEV) {
  void import("./devmock").then((m) => {
    m.installDevMock();
    render();
  });
} else {
  render();
}
