// The staff console's entry (staff.html; built by vite.staff.config.ts into
// dist-staff/, embedded by webcloud.StaffHandler and served ONLY by
// `observer-cloud staff serve` under /staff/ on the staff host). It shares
// the portal's design system and stylesheet, never its code paths: no portal
// API, cookie or route is reachable from here.

import React from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { ThemeProvider } from "@shared/lib/useTheme";
import { initTheme } from "../theme";
import { StaffApp } from "./StaffApp";
import "../styles.css";

initTheme();

function render() {
  const container = document.getElementById("root");
  if (!container) throw new Error("root element missing");
  createRoot(container).render(
    <React.StrictMode>
      <ThemeProvider app="webcloud">
        <BrowserRouter basename="/staff">
          <StaffApp />
        </BrowserRouter>
      </ThemeProvider>
    </React.StrictMode>,
  );
}

// DEV-only: mock /staff/* under a bare `vite --config vite.staff.config.ts`
// so the screens render with data; dead-code eliminated from the build.
if (import.meta.env.DEV) {
  void import("./devmock").then((m) => {
    m.installStaffDevMock();
    render();
  });
} else {
  render();
}
