const express = require("express");
const cors = require("cors");
const app = express();

// ruleid: js.cors-credentials-any-origin
app.use(cors({ origin: true, credentials: true }));
// ruleid: js.cors-credentials-any-origin
app.use(cors({ credentials: true, origin: "*" }));
// ruleid: js.cors-credentials-any-origin
app.use(cors({ origin: (origin, cb) => cb(null, true), credentials: true }));
// ok: js.cors-credentials-any-origin
app.use(cors({ origin: "https://app.example.com", credentials: true }));
// ok: js.cors-credentials-any-origin
app.use(cors({ origin: "*" }));
// ok: js.cors-credentials-any-origin
app.use(cors({ origin: ["https://a.example.com"], credentials: true }));
