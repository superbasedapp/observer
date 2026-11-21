// Two hand-built answers of GET /api/security/assessments/model, in the exact
// shape the server sends (see AssessModelResponse): a small threat model and a
// small penetration test. They are test and e2e data, not product code: the
// lib tests (secAssessModel.test.ts), the component tests and the Playwright
// spec (e2e/security-assessments.spec.ts) all read these, so the views are
// pinned against one realistic set of values.
//
// The threat model has: every reference state, waived and empty matrix cells,
// a weak crossing flow, an AI-framework threat, an abuse case and an attack
// tree. The pen test has: a target that started, coverage rows in each state
// (claimed, skipped, not applicable, tool unavailable), findings with the
// agent's claim and no log, and one finding without a located reference.
// FIXTURE_PT_EVIDENCE is the same application's pen test with the request
// helper on: one finding per evidence state a started target can have, the
// log records the findings cite, and the run's evidence report;
// FIXTURE_PT_NOT_STARTED is one whose target never started. The retest
// (FIXTURE_PT_RETESTABLE, FIXTURE_PT_RETESTED, FIXTURE_RETEST) and the red
// team's exercise (FIXTURE_RED_TEAM, FIXTURE_RED_TEAM_AGENT) follow the
// evidence fixtures, before the big answers.
// Names are invented (an application called "Ledger"); no path, host or text
// here comes from a real project.

import type { AssessModelResponse, CoverageRow, ModelBand, ModelIssue, ModelThreat, ModelVocab, ProbeRecord, PTChainStep, PTFinding, RetestView, TMCoverage } from "./secAssessModel.ts";

export const FIXTURE_VOCAB: ModelVocab = {
  stride: [
    { id: "spoofing", letter: "S", name: "Spoofing", question: "Can something pretend to be this element, or to be a caller of it?" },
    { id: "tampering", letter: "T", name: "Tampering", question: "Can data or code here be changed without the owner knowing?" },
    { id: "repudiation", letter: "R", name: "Repudiation", question: "Can someone do something here and later deny it, because nothing records it?" },
    { id: "information_disclosure", letter: "I", name: "Information disclosure", question: "Can data reach someone who should not see it?" },
    { id: "denial_of_service", letter: "D", name: "Denial of service", question: "Can someone make this element unavailable or exhaust it?" },
    { id: "elevation_of_privilege", letter: "E", name: "Elevation of privilege", question: "Can someone do more here than they are allowed to?" },
  ],
  linddun: [
    { id: "linkability", name: "Linkability", question: "Can two records or actions be tied to the same person?" },
    { id: "identifiability", name: "Identifiability", question: "Can a person be singled out from this data?" },
    { id: "non_repudiation", name: "Non-repudiation", question: "Is a person unable to deny something they would want to deny?" },
    { id: "detectability", name: "Detectability", question: "Can someone tell that a record about a person exists?" },
    { id: "disclosure_of_information", name: "Disclosure of information", question: "Can personal data reach someone who should not have it?" },
    { id: "unawareness", name: "Unawareness", question: "Is the person unaware of what is collected or why?" },
    { id: "non_compliance", name: "Non-compliance", question: "Does the handling miss a rule, policy or consent it should follow?" },
  ],
  component_types: [
    { id: "service", class: "process", name: "Service or process" },
    { id: "ui", class: "process", name: "User interface" },
    { id: "datastore", class: "data_store", name: "Data store" },
    { id: "log_store", class: "data_store", holds_logs: true, name: "Log or audit store" },
    { id: "external", class: "external_entity", name: "External service" },
  ],
  wstg: [
    { id: "INFO", title: "Information gathering", intent: "What the target reveals about itself: versions, routes, files and metadata a visitor can read.", applies_when: "always" },
    { id: "CONF", title: "Configuration and deployment", intent: "Default settings, exposed admin or debug interfaces, missing security headers and risky methods.", applies_when: "always" },
    { id: "ATHN", title: "Authentication", intent: "Whether signing in can be bypassed, guessed or worn down, and how credentials are reset.", applies_when: "login" },
    { id: "ATHZ", title: "Authorization", intent: "Whether one user can reach another user's data or a higher role's functions.", applies_when: "login" },
    { id: "SESS", title: "Session management", intent: "How session tokens are made, kept, expired and protected, and whether cross-site requests are stopped.", applies_when: "sessions" },
    { id: "INPV", title: "Input validation", intent: "Whether data the caller controls can change a query, a command, a file path, a template or an outbound request.", applies_when: "always" },
    { id: "CLNT", title: "Client side", intent: "Script injection, unsafe redirects, framing and cross-origin settings in what the browser receives.", applies_when: "browser_client" },
    { id: "APIT", title: "API", intent: "Object and function level access, mass assignment, rate limits and schema handling on the API routes.", applies_when: "http_api" },
  ],
  ai_frameworks: [
    { id: "owasp_llm", name: "OWASP Top 10 for LLM applications" },
    { id: "owasp_agentic", name: "OWASP Top 10 for agentic applications" },
  ],
  bands: ["low", "medium", "high", "critical"],
};

const ZERO_REFS = { found: 0, exists: 0, claimed_not_found: 0, missing: 0, invalid: 0, unchecked: 0 };

/** A threat model of "Ledger", validated: partial (one reference could not be looked at). */
export const FIXTURE_TM: AssessModelResponse = {
  record: {
    schema: 1,
    run_id: "00000000000000b2",
    validated_at: "2026-11-14T08:45:00Z",
    contract: "threatmodel.v1",
    source_sha: "a1b2c3d4e5f60718",
    source_bytes: 18234,
    files: [{ path: "src/api/db.ts", sha: "0011223344556677", lines: 120 }],
    ref_budget: { files: 500, mib: 128, seconds: 10 },
    result: {
      report: {
        state: "partial",
        contract: "threatmodel.v1",
        ref_check: { window_lines: 5, text_hidden: 1 },
        issues: [
          { row: "V8", code: "ref_needle_not_found", severity: "warn", path: "refs", message: "1 references name a text that is not in the cited lines; they earn no credit." },
          { row: "V11", code: "coverage_empty_cells", severity: "warn", path: "coverage", message: "9 element and category pairs have neither a threat nor a reason that none applies." },
        ],
        counts: { components: { read: 5, kept: 5 }, flows: { read: 5, kept: 5 }, threats: { read: 5, kept: 5 } },
        refs: { ...ZERO_REFS, found: 2, exists: 1, claimed_not_found: 1, missing: 1, unchecked: 1 },
        tm: {
          "analysed": 4,
          "waived": 2,
          "empty": 41,
          "by_framework": [
            {
              "framework": "stride",
              "analysed": 3,
              "waived": 2,
              "empty": 35
            },
            {
              "framework": "linddun",
              "analysed": 1,
              "waived": 0,
              "empty": 6
            }
          ],
          "rows": [
            {
              "kind": "component",
              "id": "web",
              "name": "Web client",
              "class": "process",
              "cells": [
                {
                  "category": "spoofing",
                  "state": "empty"
                },
                {
                  "category": "tampering",
                  "state": "empty"
                },
                {
                  "category": "repudiation",
                  "state": "empty"
                },
                {
                  "category": "information_disclosure",
                  "state": "empty"
                },
                {
                  "category": "denial_of_service",
                  "state": "empty"
                },
                {
                  "category": "elevation_of_privilege",
                  "state": "empty"
                }
              ]
            },
            {
              "kind": "component",
              "id": "api",
              "name": "Ledger API",
              "class": "process",
              "cells": [
                {
                  "category": "spoofing",
                  "state": "analysed"
                },
                {
                  "category": "tampering",
                  "state": "empty"
                },
                {
                  "category": "repudiation",
                  "state": "empty"
                },
                {
                  "category": "information_disclosure",
                  "state": "empty"
                },
                {
                  "category": "denial_of_service",
                  "state": "empty"
                },
                {
                  "category": "elevation_of_privilege",
                  "state": "empty"
                }
              ]
            },
            {
              "kind": "component",
              "id": "db",
              "name": "Ledger database",
              "class": "data_store",
              "cells": [
                {
                  "category": "tampering",
                  "state": "empty"
                },
                {
                  "category": "information_disclosure",
                  "state": "empty"
                },
                {
                  "category": "denial_of_service",
                  "state": "empty"
                }
              ]
            },
            {
              "kind": "component",
              "id": "audit",
              "name": "Audit log",
              "class": "data_store",
              "cells": [
                {
                  "category": "tampering",
                  "state": "empty"
                },
                {
                  "category": "repudiation",
                  "state": "waived"
                },
                {
                  "category": "information_disclosure",
                  "state": "empty"
                },
                {
                  "category": "denial_of_service",
                  "state": "empty"
                }
              ]
            },
            {
              "kind": "component",
              "id": "idp",
              "name": "Identity provider",
              "class": "external_entity",
              "cells": [
                {
                  "category": "spoofing",
                  "state": "empty"
                },
                {
                  "category": "repudiation",
                  "state": "empty"
                }
              ]
            },
            {
              "kind": "actor",
              "id": "anon",
              "name": "Anonymous visitor",
              "class": "external_entity",
              "cells": [
                {
                  "category": "spoofing",
                  "state": "waived"
                },
                {
                  "category": "repudiation",
                  "state": "empty"
                }
              ]
            },
            {
              "kind": "actor",
              "id": "user",
              "name": "Signed-in user",
              "class": "external_entity",
              "cells": [
                {
                  "category": "spoofing",
                  "state": "empty"
                },
                {
                  "category": "repudiation",
                  "state": "empty"
                }
              ]
            },
            {
              "kind": "flow",
              "id": "f-user-web",
              "name": "user to web",
              "class": "data_flow",
              "cells": [
                {
                  "category": "tampering",
                  "state": "empty"
                },
                {
                  "category": "information_disclosure",
                  "state": "empty"
                },
                {
                  "category": "denial_of_service",
                  "state": "empty"
                }
              ]
            },
            {
              "kind": "flow",
              "id": "f-web-api",
              "name": "web to api",
              "class": "data_flow",
              "cells": [
                {
                  "category": "tampering",
                  "state": "empty"
                },
                {
                  "category": "information_disclosure",
                  "state": "empty"
                },
                {
                  "category": "denial_of_service",
                  "state": "empty"
                }
              ]
            },
            {
              "kind": "flow",
              "id": "f-anon-api",
              "name": "anon to api",
              "class": "data_flow",
              "cells": [
                {
                  "category": "tampering",
                  "state": "empty"
                },
                {
                  "category": "information_disclosure",
                  "state": "empty"
                },
                {
                  "category": "denial_of_service",
                  "state": "empty"
                }
              ]
            },
            {
              "kind": "flow",
              "id": "f-api-db",
              "name": "api to db",
              "class": "data_flow",
              "cells": [
                {
                  "category": "tampering",
                  "state": "analysed"
                },
                {
                  "category": "information_disclosure",
                  "state": "analysed"
                },
                {
                  "category": "denial_of_service",
                  "state": "empty"
                },
                {
                  "category": "linkability",
                  "state": "analysed"
                },
                {
                  "category": "identifiability",
                  "state": "empty"
                },
                {
                  "category": "non_repudiation",
                  "state": "empty"
                },
                {
                  "category": "detectability",
                  "state": "empty"
                },
                {
                  "category": "disclosure_of_information",
                  "state": "empty"
                },
                {
                  "category": "unawareness",
                  "state": "empty"
                },
                {
                  "category": "non_compliance",
                  "state": "empty"
                }
              ]
            },
            {
              "kind": "flow",
              "id": "f-api-idp",
              "name": "api to idp",
              "class": "data_flow",
              "cells": [
                {
                  "category": "tampering",
                  "state": "empty"
                },
                {
                  "category": "information_disclosure",
                  "state": "empty"
                },
                {
                  "category": "denial_of_service",
                  "state": "empty"
                }
              ]
            }
          ],
          "ai_threats": {
            "owasp_llm": 1
          }
        },
        sets: { frameworks: ["linddun", "owasp_agentic", "owasp_llm", "stride"], method_extras: ["abuse_cases", "attack_trees"], ai_app: true },
      },
      tm: {
        schema: "observer.threatmodel.v1",
        run_id: "00000000000000b2",
        prompt_version: "tm.2",
        generator: { tool: "claude-code", model: "model-x" },
        summary: "Ledger is a small bookkeeping service: a browser client, an API and a database. The agent read the repository and modelled five components and five flows.",
        scope: { in_scope: ["src"], out_of_scope: ["docs"], assumptions: ["The API runs behind a reverse proxy that ends TLS."] },
        system: {
          zones: [
            { id: "z-net", name: "Internet" },
            { id: "z-app", name: "Application" },
            { id: "z-data", name: "Data" },
          ],
          components: [
            { id: "web", name: "Web client", type: "ui", zone: "z-net", tech: ["react"], paths: [{ path: "web/src/main.tsx", line: 1, state: "exists" }] },
            {
              id: "api",
              name: "Ledger API",
              type: "service",
              zone: "z-app",
              description: "The HTTP API: sessions, entries and exports.",
              tech: ["node", "express"],
              paths: [{ path: "src/api/server.ts", line: 10, end_line: 40, needle: "app.use(session(", state: "found", match_line: 12 }],
            },
            { id: "db", name: "Ledger database", type: "datastore", zone: "z-data", tech: ["postgres"] },
            { id: "audit", name: "Audit log", type: "log_store", zone: "z-data" },
            { id: "idp", name: "Identity provider", type: "external", zone: "z-net" },
          ],
          actors: [
            { id: "anon", name: "Anonymous visitor", kind: "anonymous" },
            { id: "user", name: "Signed-in user", kind: "end_user" },
          ],
          assets: [
            { id: "entries", name: "Ledger entries", sensitivity: "confidential", data_classes: ["financial"], stored_in: ["db"] },
            { id: "sessions", name: "Session tokens", sensitivity: "restricted", stored_in: ["api"] },
          ],
          entry_points: [
            { id: "ep-login", component: "api", kind: "http_route", authn: "none", exposure: "internet", ref: { path: "src/api/login.ts", line: 8, state: "found", match_line: 8, needle: "router.post('/login'" } },
            { id: "ep-export", component: "api", kind: "http_route", authn: "session", exposure: "internet" },
          ],
          flows: [
            { id: "f-user-web", from: "user", to: "web", protocol: "https", authn: "session", encrypted: "yes", crosses: ["z-net"], data: ["sessions"] },
            { id: "f-web-api", from: "web", to: "api", protocol: "https", authn: "session", encrypted: "yes", crosses: ["z-net", "z-app"], data: ["entries"] },
            { id: "f-anon-api", from: "anon", to: "api", protocol: "https", authn: "none", encrypted: "unknown", crosses: ["z-net", "z-app"] },
            { id: "f-api-db", from: "api", to: "db", protocol: "postgres", authn: "basic", encrypted: "no", crosses: ["z-app", "z-data"], data: ["entries"], personal_data: true },
            { id: "f-api-idp", from: "api", to: "idp", protocol: "https", authn: "token", encrypted: "yes", crosses: ["z-app", "z-net"] },
          ],
        },
        threats: [
          {
            id: "T-1",
            title: "SQL injection through the entry search",
            framework: "stride",
            category: "tampering",
            element: { kind: "flow", id: "f-api-db" },
            actor: "anon",
            description: "The search route builds its query by joining the request text, so a caller can change the query.",
            rating: { likelihood: 4, impact: 5 },
            existing: [{ text: "Entries are written through a parameterised helper.", refs: [{ path: "src/api/db.ts", line: 30, end_line: 34, needle: "db.query($1, [id])", state: "found", match_line: 31 }] }],
            missing: [{ text: "Use the parameterised helper in the search route.", control: "parameterised queries", effort: "s", refs: [{ path: "src/api/search.ts", line: 22, state: "exists" }] }],
            cwe: ["CWE-89"],
            asvs: ["V5.3.4"],
            status: "identified",
            abuse_case: { actor: "anon", goal: "Read every account's entries.", steps: ["Send a search term that closes the quote.", "Add a union query for the entries table."] },
            band: "critical",
            score: 20,
          },
          {
            id: "T-2",
            title: "Session token theft from a script injected into the client",
            framework: "stride",
            category: "spoofing",
            element: { kind: "component", id: "api" },
            description: "A stolen session token lets an attacker act as the user.",
            rating: { likelihood: 3, impact: 4 },
            existing: [{ text: "Sessions are set with the HttpOnly flag.", refs: [{ path: "src/api/server.ts", line: 12, state: "exists" }] }],
            missing: [{ text: "Bind the session to a second factor of the client.", effort: "m", refs: [{ path: "src/api/missing.ts", line: 3, state: "missing" }] }],
            cwe: ["CWE-384"],
            status: "partial",
            band: "medium",
            score: 12,
          },
          {
            id: "T-3",
            title: "Entries travel to the database without transport encryption",
            framework: "stride",
            category: "information_disclosure",
            element: { kind: "flow", id: "f-api-db" },
            description: "The connection string disables TLS, so a host on the network path can read entries.",
            rating: { likelihood: 3, impact: 5 },
            missing: [{ text: "Require TLS in the connection string.", effort: "s", refs: [{ path: "src/api/db.ts", line: 6, needle: "ssl: false", state: "found", match_line: 6 }] }],
            cwe: ["CWE-319"],
            status: "identified",
            band: "high",
            score: 15,
          },
          {
            id: "T-4",
            title: "Entries can be linked to one person across exports",
            framework: "linddun",
            category: "linkability",
            element: { kind: "flow", id: "f-api-db" },
            rating: { likelihood: 2, impact: 3 },
            existing: [{ text: "Exports use a per-export pseudonym.", refs: [{ path: "src/api/export.ts", line: 51, needle: "pseudonymise(user)", state: "claimed_not_found" }] }],
            status: "accepted_by_design",
            band: "low",
            score: 6,
          },
          {
            id: "T-5",
            title: "Prompt text in an entry note steers the summary assistant",
            framework: "owasp_llm",
            category: "LLM01",
            element: { kind: "component", id: "api" },
            rating: { likelihood: 3, impact: 3 },
            existing: [{ text: "The assistant call has no tools.", refs: [{ path: "src/api/assist.ts", line: 9, state: "unchecked" }] }],
            status: "partial",
            band: "medium",
            score: 9,
          },
        ],
        no_threat: [
          { element: { kind: "actor", id: "anon" }, category: "spoofing", reason: "An anonymous visitor claims no identity, so there is nothing to spoof." },
          { element: { kind: "component", id: "audit" }, category: "repudiation", reason: "The audit log is append-only and written by the API only." },
        ],
        attack_trees: [
          {
            root: "Read another user's entries",
            nodes: [
              { id: "n1", label: "Inject into the search query", op: "or" },
              { id: "n2", parent: "n1", label: "Close the quote in the term", leaf: true },
              { id: "n3", parent: "n1", label: "Use a union query", leaf: true },
              { id: "n4", label: "Steal a session token", op: "and" },
              { id: "n5", parent: "n4", label: "Inject a script into the client", leaf: true },
              { id: "n6", parent: "n4", label: "Send the token to a host the attacker controls", leaf: true },
            ],
          },
        ],
        open_questions: ["Is the export route reachable without a session?"],
        limits: ["The agent did not read the deployment files."],
      },
    },
  },
  stale: false,
  coverage_line: "Covered by the agent: 4 element and category pairs analysed, 2 waived with a reason and 41 with neither.",
  mermaid: {
    source: [
      "flowchart LR",
      "  subgraph z1[\"Internet\"]",
      "    c1[\"Web client\"]",
      "    c5[[\"Identity provider\"]]",
      "  end",
      "  subgraph z2[\"Application\"]",
      "    c2[\"Ledger API\"]",
      "  end",
      "  subgraph z3[\"Data\"]",
      "    c3[(\"Ledger database\")]",
      "    c4[(\"Audit log\")]",
      "  end",
      "  a1([\"Anonymous visitor\"])",
      "  a2([\"Signed-in user\"])",
      "  a2 -.->|\"https\"| c1",
      "  c1 -.->|\"https\"| c2",
      "  a1 -.->|\"https, no authentication\"| c2",
      "  c2 -.->|\"postgres, not encrypted\"| c3",
      "  c2 -.->|\"https\"| c5",
      "  linkStyle 2,3 stroke:#d33,stroke-width:2px"
    ].join("\n"),
    nodes: 7,
    total_nodes: 7,
    omitted_nodes: 0,
    edges: 5,
    omitted_edges: 0,
    max_nodes: 60,
    label_chars: 40,
    labels_cut: 0,
  },
  vocab: FIXTURE_VOCAB,
  redaction: { on: true, hidden: 0 },
};

/** A pen test of "Ledger": the target started; findings carry the agent's claim and no log. */
export const FIXTURE_PT: AssessModelResponse = {
  record: {
    schema: 1,
    run_id: "00000000000000a1",
    validated_at: "2026-11-14T10:50:00Z",
    contract: "pentest.v1",
    source_sha: "f0e1d2c3b4a59687",
    source_bytes: 9120,
    result: {
      report: {
        state: "valid",
        contract: "pentest.v1",
        counts: { findings: { read: 3, kept: 3 } },
        refs: { ...ZERO_REFS, found: 2, exists: 1 },
        pt: {
          started: true,
          rows: [
            { category: "INFO", title: "Information gathering", agent: "tested", effective: "tested_claimed" },
            { category: "CONF", title: "Configuration and deployment", agent: "tested", effective: "tested_claimed" },
            { category: "ATHN", title: "Authentication", agent: "tested", effective: "tested_claimed" },
            { category: "ATHZ", title: "Authorization", agent: "tested", effective: "tested_claimed" },
            { category: "SESS", title: "Session management", agent: "skipped", effective: "skipped", reason: "No second account could be created in the box." },
            { category: "INPV", title: "Input validation", agent: "tested", effective: "tested_claimed" },
            { category: "CLNT", title: "Client side", agent: "not_applicable", effective: "not_applicable", reason: "The target serves no pages, only JSON." },
            { category: "APIT", title: "API", agent: "tool_unavailable", effective: "tool_unavailable", reason: "No HTTP client other than curl was on the box." },
          ],
          counts: { tested_claimed: 5, skipped: 1, not_applicable: 1, tool_unavailable: 1 },
        },
        sets: { categories: ["INFO", "CONF", "ATHN", "ATHZ", "SESS", "INPV", "CLNT", "APIT"] },
      },
      pt: {
        schema: "observer.pentest.v1",
        run_id: "00000000000000a1",
        prompt_version: "pt.2",
        generator: { tool: "claude-code", model: "model-x" },
        summary: "The agent started the development server and tested five of eight categories.",
        target: {
          url: "http://localhost:3000/",
          start: { argv: ["npm", "run", "dev"], source: ".claude/launch.json", started: true, startup_seconds: 6, health: { path: "/health", status: 200 } },
          accounts: [{ label: "user-a", role: "user" }, { label: "admin", role: "admin" }],
        },
        method: { standard: "wstg+ptes" },
        coverage: [
          { category: "INFO", status: "tested", probes: ["p1"] },
          { category: "CONF", status: "tested" },
          { category: "ATHN", status: "tested" },
          { category: "ATHZ", status: "tested" },
          { category: "SESS", status: "skipped", reason: "No second account could be created in the box." },
          { category: "INPV", status: "tested", probes: ["p3", "p4"] },
          { category: "CLNT", status: "not_applicable", reason: "The target serves no pages, only JSON." },
          { category: "APIT", status: "tool_unavailable", reason: "No HTTP client other than curl was on the box." },
        ],
        findings: [
          {
            id: "F-1",
            title: "Entry search is injectable",
            category: "INPV",
            cwe: ["CWE-89"],
            rating: { likelihood: 4, impact: 5 },
            basis: "observed",
            where: { refs: [{ path: "src/api/search.ts", line: 22, end_line: 26, needle: "db.query(`SELECT", state: "found", match_line: 22 }] },
            route: "GET /api/search",
            indicator: { control: "p4", attack: "p3" },
            evidence: ["p3", "p4"],
            reproduction: [
              { step: "Request a normal search term", request: { method: "GET", path: "/api/search?q=rent" } },
              { step: "Request a term that closes the quote", request: { method: "GET", path: "/api/search?q=rent'--", headers: [{ name: "Accept", value: "application/json" }] } },
            ],
            impact: "A caller can read entries that are not theirs.",
            fix: "Use the parameterised helper in the search route.",
            status: "open",
            band: "critical",
            score: 20,
          },
          {
            id: "F-2",
            title: "The login route does not slow repeated failures",
            category: "ATHN",
            cwe: ["CWE-307"],
            rating: { likelihood: 3, impact: 3 },
            basis: "inferred",
            where: { refs: [{ path: "src/api/login.ts", line: 8, state: "exists" }] },
            reproduction: [],
            impact: "A password can be guessed at the rate the server answers.",
            fix: "Count failures per account and slow the answers.",
            status: "open",
            band: "medium",
            score: 9,
          },
          {
            id: "F-3",
            title: "Error pages name the framework and version",
            category: "INFO",
            rating: { likelihood: 2, impact: 2 },
            basis: "observed",
            where: {},
            evidence: ["p1"],
            impact: "A visitor learns which version to look up.",
            status: "open",
            band: "low",
            score: 4,
          },
        ],
        limits: ["Only one origin was tested."],
      },
    },
  },
  stale: false,
  coverage_line: "Covered by the agent: 5 of 8 categories claimed, 0 with a logged request, 1 skipped, 1 not applicable, 1 with a tool unavailable.",
  vocab: FIXTURE_VOCAB,
  redaction: { on: true, hidden: 2 },
};

/** A pen test whose target never started and which reported nothing: the reading says what it is not. */
export const FIXTURE_PT_EMPTY: AssessModelResponse = {
  record: {
    schema: 1,
    run_id: "00000000000000c3",
    validated_at: "2026-11-14T11:30:00Z",
    contract: "pentest.v1",
    source_sha: "0102030405060708",
    source_bytes: 1400,
    result: {
      report: {
        state: "partial",
        contract: "pentest.v1",
        refs: ZERO_REFS,
        pt: {
          started: false,
          rows: [
            { category: "INFO", title: "Information gathering", agent: "tested", effective: "skipped_not_started" },
            { category: "ATHN", title: "Authentication", effective: "skipped_not_started" },
          ],
          counts: { skipped_not_started: 2 },
        },
        sets: { categories: ["INFO", "ATHN"] },
      },
      pt: {
        schema: "observer.pentest.v1",
        run_id: "00000000000000c3",
        generator: { tool: "claude-code" },
        target: { url: "http://localhost:3000/", start: { started: false, health: {} } },
        method: { standard: "wstg+ptes" },
        coverage: [{ category: "INFO", status: "tested" }],
        findings: [],
      },
    },
  },
  stale: false,
  reading:
    "The target was not started, so nothing was tested in a running application: all 2 categories read as skipped. No weakness was reported; this is not proof that none exists.",
  coverage_line: "Covered by the agent: 0 of 2 categories claimed, 0 with a logged request, 2 skipped (target not started).",
  vocab: FIXTURE_VOCAB,
  redaction: { on: true, hidden: 0 },
};

/** The earlier run FIXTURE_TM is compared with in FIXTURE_TM_SINCE. */
export const FIXTURE_SINCE_RUN = "00000000000000a0";

/** What changed since an earlier run: one threat added, one removed, one changed (band raised), the system names that differ, and the sentence that always comes with it. */
export const FIXTURE_SINCE: NonNullable<AssessModelResponse["since"]> = {
  prev_run: FIXTURE_SINCE_RUN,
  added: [{ id: "T-5", title: "Prompt text in an entry note steers the summary assistant", element: { kind: "component", id: "api" }, category: "LLM01", band: "medium", score: 9 }],
  removed: [{ id: "T-9", title: "Export route answers without a session", element: { kind: "component", id: "api" }, category: "spoofing", band: "high", score: 15 }],
  changed: [
    {
      id: "T-1",
      prev_id: "T-1",
      title: "SQL injection through the entry search",
      element: { kind: "flow", id: "f-api-db" },
      category: "tampering",
      match: "id",
      from_band: "high",
      to_band: "critical",
      from_score: 15,
      to_score: 20,
      from_status: "partial",
      to_status: "identified",
      missing_from: 2,
      missing_to: 1,
    },
  ],
  unchanged: 2,
  matched_by_id: 3,
  matched_by_title: 0,
  system: { components: { added: ["Audit log"] }, zones: {}, flows: { removed: ["web to cache"] } },
  note: "Threats are matched by element, category and title first (an element by its name, so a renumbered component is the same element). What is left is paired when the two threats cite nearly the same place in the code and agree on other signs (the same weakness id, category or words in the title); those pairs are listed as probably the same, with what they have in common, and are never counted as unchanged. Last, a threat with the same id as one in the other run is paired when its element and category agree. A threat the agent renamed and renumbered, with nothing else in common, shows as one removed and one added. This compares what two runs reported; it does not say which is right.",
};

/** FIXTURE_TM as the server answers when the request names `since`. */
export const FIXTURE_TM_SINCE: AssessModelResponse = { ...FIXTURE_TM, since: FIXTURE_SINCE };

/** Two independent runs of one project: the same flaws in other words. The exact passes paired nothing; three threats pair by the place they cite, one of them under another category, and the rest stay added and removed. 15 threats in the earlier run, 5 in this one, 3 paired: the "few could be paired" note applies. */
export const FIXTURE_SINCE_SIMILAR: NonNullable<AssessModelResponse["since"]> = {
  prev_run: FIXTURE_SINCE_RUN,
  added: [
    { id: "T-5", title: "Prompt text in an entry note steers the summary assistant", element: { kind: "component", id: "api" }, category: "LLM01", band: "medium", score: 9 },
    { id: "T-4", title: "Export route answers without a session", element: { kind: "component", id: "api" }, category: "spoofing", band: "high", score: 15 },
  ],
  removed: Array.from({ length: 12 }, (_, i) => ({ id: `E-${i + 1}`, title: `Earlier threat ${i + 1}`, element: { kind: "component", id: "api" }, category: "tampering", band: "low" as const, score: 4 })),
  similar: [
    {
      id: "T-1",
      prev_id: "E-40",
      title: "SQL injection through the entry search",
      prev_title: "The search term is concatenated into the notes query",
      element: { kind: "flow", id: "f-api-db" },
      category: "tampering",
      prev_category: "information_disclosure",
      from_band: "high",
      to_band: "critical",
      from_score: 15,
      to_score: 20,
      basis: ["location", "cwe", "words", "element"],
      points: 11,
    },
    {
      id: "T-2",
      prev_id: "E-41",
      title: "Session token is never rotated",
      prev_title: "Tokens stay valid for ever",
      element: { kind: "component", id: "api" },
      category: "spoofing",
      from_band: "medium",
      to_band: "medium",
      from_score: 9,
      to_score: 9,
      basis: ["location", "category"],
      points: 6,
    },
    {
      id: "T-3",
      prev_id: "E-42",
      title: "Verbose errors leak the stack",
      prev_title: "Tracebacks are returned to the caller",
      element: { kind: "component", id: "api" },
      category: "information_disclosure",
      basis: ["cwe", "words", "category"],
      points: 9,
    },
  ],
  unchanged: 0,
  matched_by_id: 0,
  matched_by_title: 0,
  system: { components: {}, zones: {}, flows: {} },
  note: "Threats are matched by element, category and title first (an element by its name, so a renumbered component is the same element). What is left is paired when the two threats cite nearly the same place in the code and agree on other signs (the same weakness id, category or words in the title); those pairs are listed as probably the same, with what they have in common, and are never counted as unchanged. Last, a threat with the same id as one in the other run is paired when its element and category agree. A threat the agent renamed and renumbered, with nothing else in common, shows as one removed and one added. This compares what two runs reported; it does not say which is right.",
};

// ---- results the check only partly kept, and refused whole ----
//
// The agent wrote more than the check kept: what was refused is counted in the
// report (counts[list].read, .refused, .kept), the issues say why, and the
// server's own reading says what became of the items when none is left to show.
// A view must not read that as "the agent found nothing".

/** A refused-item issue as the validator words it (row V5, bad_rating). */
function refusedIssue(list: string, i: number): ModelIssue {
  return { row: "V5", code: "bad_rating", severity: "refused", path: `${list}[${i}]`, message: "Likelihood and impact must each be a whole number from 1 to 5." };
}

/** retally recounts the matrix totals and the per-framework counts from the rows, after a cell changed. */
function retally(rows: CoverageRow[]): Pick<TMCoverage, "analysed" | "waived" | "empty" | "by_framework"> {
  const linddun = new Set(FIXTURE_VOCAB.linddun.map((c) => c.id));
  const fw = new Map<string, { framework: string; analysed: number; waived: number; empty: number }>();
  const total = { analysed: 0, waived: 0, empty: 0 };
  for (const r of rows) {
    for (const c of r.cells) {
      const key = linddun.has(c.category) ? "linddun" : "stride";
      const f = fw.get(key) ?? { framework: key, analysed: 0, waived: 0, empty: 0 };
      f[c.state]++;
      total[c.state]++;
      fw.set(key, f);
    }
  }
  return { ...total, by_framework: [...fw.values()] };
}

const TM_REPORT = FIXTURE_TM.record.result.report;
const TM_DOC = FIXTURE_TM.record.result.tm!;
const PT_REPORT = FIXTURE_PT.record.result.report;
const PT_DOC = FIXTURE_PT.record.result.pt!;

/** A threat model of which the agent wrote 6 threats and the check kept 5: the table is shown and the check says one was refused. */
export const FIXTURE_TM_PARTIAL: AssessModelResponse = {
  ...FIXTURE_TM,
  record: {
    ...FIXTURE_TM.record,
    result: {
      ...FIXTURE_TM.record.result,
      report: {
        ...TM_REPORT,
        issues: [refusedIssue("threats", 5), ...(TM_REPORT.issues ?? [])],
        counts: { ...TM_REPORT.counts, threats: { read: 6, refused: 1, kept: 5 } },
      },
    },
  },
};

/** A threat model of which the agent wrote 3 threats and the check refused all 3: no threat is left to show. */
export const FIXTURE_TM_REFUSED_ALL: AssessModelResponse = (() => {
  const rows = (TM_REPORT.tm?.rows ?? []).map((r) => ({ ...r, cells: r.cells.map((c) => (c.state === "analysed" ? { ...c, state: "empty" as const } : c)) }));
  return {
    ...FIXTURE_TM,
    record: {
      ...FIXTURE_TM.record,
      run_id: "00000000000000d1",
      result: {
        ...FIXTURE_TM.record.result,
        report: {
          ...TM_REPORT,
          issues: [0, 1, 2].map((i) => refusedIssue("threats", i)),
          counts: { ...TM_REPORT.counts, threats: { read: 3, refused: 3, kept: 0 } },
          tm: { ...TM_REPORT.tm, ...retally(rows), rows, ai_threats: undefined },
        },
        tm: { ...TM_DOC, threats: [] },
      },
    },
    reading:
      "The agent wrote 3 threats, and none is shown here: the check refused 3. This says nothing about whether a threat exists; the issues say why.",
    coverage_line: "Covered by the agent: 0 element and category pairs analysed, 2 waived with a reason and 45 with neither.",
  };
})();

/** A pen test of which the agent wrote 4 findings and the check kept 3: the list is shown and the check says one was refused. */
export const FIXTURE_PT_PARTIAL: AssessModelResponse = {
  ...FIXTURE_PT,
  record: {
    ...FIXTURE_PT.record,
    result: {
      ...FIXTURE_PT.record.result,
      report: {
        ...PT_REPORT,
        state: "partial",
        issues: [refusedIssue("findings", 3)],
        counts: { findings: { read: 4, refused: 1, kept: 3 } },
      },
    },
  },
};

/** A pen test of which the agent wrote 2 findings and the check refused both: no finding is left to show. */
export const FIXTURE_PT_REFUSED_ALL: AssessModelResponse = {
  ...FIXTURE_PT,
  record: {
    ...FIXTURE_PT.record,
    run_id: "00000000000000d2",
    result: {
      ...FIXTURE_PT.record.result,
      report: {
        ...PT_REPORT,
        state: "partial",
        issues: [0, 1].map((i) => refusedIssue("findings", i)),
        counts: { findings: { read: 2, refused: 2, kept: 0 } },
        refs: ZERO_REFS,
      },
      pt: { ...PT_DOC, findings: [] },
    },
  },
  reading:
    "The agent wrote 2 findings, and none is shown here: the check refused 2. This says nothing about whether a weakness exists; the issues say why.",
};

// ---- the request helper's log: evidence states and the records findings cite ----

/** A request in the helper's log, as the server sends it: redacted, every field present. Obviously fake values. */
function probe(over: Partial<ProbeRecord> & Pick<ProbeRecord, "id">): ProbeRecord {
  return {
    ts: "2026-11-14T10:20:00Z",
    role: "",
    wstg: "",
    account: "",
    note: "",
    method: "GET",
    path: "/",
    req_headers: [],
    req_body_bytes: 0,
    req_body_excerpt: "",
    sent: true,
    refused: "",
    error: "",
    status: 200,
    resp_headers: [],
    body_bytes: 0,
    body_truncated: false,
    body_excerpt: "",
    ms: 12,
    hops: 0,
    redirect_to: "",
    redirect_blocked: false,
    cost: 1,
    ...over,
  };
}

/** The log records FIXTURE_PT_EVIDENCE's findings and coverage rows cite: a plain request, a control and its attack, and one the helper refused. */
const EVIDENCE_PROBES: ProbeRecord[] = [
  probe({
    id: "p1",
    ts: "2026-11-14T10:12:03Z",
    wstg: "INFO",
    note: "front page",
    path: "/",
    resp_headers: [
      { n: "Content-Type", v: "text/html" },
      { n: "X-Powered-By", v: "LedgerKit 2.3" },
    ],
    body_bytes: 640,
    body_excerpt: "<!doctype html><title>Ledger</title>",
    ms: 18,
  }),
  probe({
    id: "p3",
    ts: "2026-11-14T10:31:44Z",
    role: "attack",
    wstg: "INPV",
    account: "user-a",
    note: "term that closes the quote",
    path: "/api/search?q=rent'--",
    req_headers: [
      { n: "Accept", v: "application/json" },
      { n: "Authorization", v: "[REDACTED]" },
    ],
    resp_headers: [{ n: "Content-Type", v: "application/json" }],
    body_bytes: 65536,
    body_truncated: true,
    body_excerpt: '{"total":412,"items":[{"id":1,"title":"Rent, March"},{"id":2,"title":"An entry of another account"}]}',
    ms: 63,
  }),
  probe({
    id: "p4",
    ts: "2026-11-14T10:31:41Z",
    role: "control",
    wstg: "INPV",
    account: "user-a",
    note: "normal search term",
    path: "/api/search?q=rent",
    req_headers: [
      { n: "Accept", v: "application/json" },
      { n: "Authorization", v: "[REDACTED]" },
    ],
    resp_headers: [{ n: "Content-Type", v: "application/json" }],
    body_bytes: 96,
    body_excerpt: '{"total":3,"items":[{"id":1,"title":"Rent, March"}]}',
    ms: 41,
  }),
  probe({
    id: "p5",
    ts: "2026-11-14T10:40:10Z",
    role: "attack",
    wstg: "ATHN",
    note: "address of another host",
    path: "http://other.invalid/api/login",
    sent: false,
    refused: "off_target",
    status: 0,
    ms: 0,
    cost: 0,
  }),
];

/** The pen test of "Ledger" with the request helper on. F-1 cites an attack request and its control and the log holds both (Helper log matches); F-2 cites nothing logged; F-3 cites a request that is not in the log; F-4 cites one the helper refused. */
export const FIXTURE_PT_EVIDENCE: AssessModelResponse = (() => {
  const doc = FIXTURE_PT.record.result.pt!;
  const f = doc.findings!;
  return {
    ...FIXTURE_PT,
    record: {
      ...FIXTURE_PT.record,
      run_id: "00000000000000f1",
      result: {
        report: {
          ...PT_REPORT,
          counts: { findings: { read: 4, kept: 4 } },
          pt: {
            started: true,
            rows: PT_REPORT.pt!.rows.map((r) => (r.category === "INPV" ? { ...r, effective: "tested_logged" } : r)),
            counts: { tested_claimed: 4, tested_logged: 1, skipped: 1, not_applicable: 1, tool_unavailable: 1 },
          },
          evidence: {
            mode: "on",
            helper: "intact",
            log: "ok",
            records: 5,
            sent: 4,
            refused: 1,
            requests: 4,
            logged: 1,
            unlogged: 3,
            not_started: 0,
            by_reason: { no_probe: 1, probe_not_in_log: 1, probe_not_sent: 1 },
          },
        },
        pt: {
          ...doc,
          run_id: "00000000000000f1",
          findings: [
            {
              ...f[0],
              indicator: { control: "p4", attack: "p3", when: { status: 200, body_contains: ["412"], header_absent: ["X-Request-Id"] } },
              evidence_state: "logged",
              evidence: ["p3", "p4"],
              reproduction: [
                { step: "Request a normal search term", request: { method: "GET", path: "/api/search?q=rent", headers: [{ name: "Accept", value: "application/json" }] } },
                { step: "Request a term that closes the quote", request: { method: "GET", path: "/api/search?q=rent'--", headers: [{ name: "Accept", value: "application/json" }] } },
                { step: "Send a body to the export route", request: { method: "POST", path: "/api/export", body: '{"format":"csv"}' } },
              ],
            },
            { ...f[1], evidence_state: "unlogged", evidence_reason: "no_probe" },
            { ...f[2], evidence_state: "unlogged", evidence_reason: "probe_not_in_log", evidence: ["p9"] },
            {
              id: "F-4",
              title: "The login route answers differently for an unknown account",
              category: "ATHN",
              cwe: ["CWE-204"],
              rating: { likelihood: 3, impact: 2 },
              basis: "observed",
              where: {},
              indicator: { control: "p4", attack: "p5" },
              evidence: ["p5"],
              evidence_state: "unlogged",
              evidence_reason: "probe_not_sent",
              impact: "A visitor can tell which accounts exist.",
              status: "open",
              band: "low",
              score: 6,
            },
          ],
        },
      },
    },
    coverage_line: "Covered by the agent: 5 of 8 categories claimed, 1 with a logged request, 1 skipped, 1 not applicable, 1 with a tool unavailable.",
    probes: EVIDENCE_PROBES,
    probe_log: { records: 5, shown: EVIDENCE_PROBES.length, truncated: false },
  };
})();

/** A pen test whose target never started: its one finding was read from code, and its evidence reads Not started. */
export const FIXTURE_PT_NOT_STARTED: AssessModelResponse = (() => {
  const base = FIXTURE_PT_EMPTY.record.result;
  const doc = base.pt!;
  return {
    ...FIXTURE_PT_EMPTY,
    record: {
      ...FIXTURE_PT_EMPTY.record,
      run_id: "00000000000000f2",
      result: {
        report: {
          ...base.report,
          counts: { findings: { read: 1, kept: 1 } },
          evidence: { mode: "on", helper: "intact", log: "absent", records: 0, sent: 0, refused: 0, requests: 0, logged: 0, unlogged: 0, not_started: 1, by_reason: { target_not_started: 1 } },
        },
        pt: {
          ...doc,
          run_id: "00000000000000f2",
          findings: [
            {
              id: "F-1",
              title: "The password reset link does not expire",
              category: "ATHN",
              rating: { likelihood: 3, impact: 4 },
              basis: "inferred",
              where: { refs: [{ path: "src/api/reset.ts", line: 31, needle: "createToken(", state: "found", match_line: 31 }] },
              evidence_state: "not_started",
              evidence_reason: "target_not_started",
              impact: "An old link can still be used.",
              status: "open",
              band: "medium",
              score: 12,
            },
          ],
        },
      },
    },
    reading: undefined,
    coverage_line: "Covered by the agent: 0 of 2 categories claimed, 0 with a logged request, 2 skipped (target not started).",
  };
})();

// ---- the retest (W7.2) and the red team's exercise (W7.3) ----
//
// FIXTURE_PT_RETESTABLE is a pen test of "Ledger" whose findings differ in what a
// retest can do with them: F-1 has two stored requests and a stored condition,
// F-2 has a request with a hidden value (the Authorization header) and a
// condition, F-3 has a request and no condition, F-4 has only text steps (no
// request, so a retest cannot replay it), F-5 and F-6 have a request and a
// condition. FIXTURE_PT_RETESTED is the same run with two retests listed, the
// newer one first; FIXTURE_RETEST is the newer retest's own view. All names
// and values are invented.

/** The pen test run the two retests replayed. */
export const FIXTURE_RETEST_OF_RUN = "00000000000000f4";
/** The newer and the older retest of it. */
export const FIXTURE_RETEST_RUN_NEW = "00000000000000f6";
export const FIXTURE_RETEST_RUN_OLD = "00000000000000f5";
/** The red team runs of the exercise fixtures. */
export const FIXTURE_RED_TEAM_RUN = "00000000000000f7";
export const FIXTURE_RED_TEAM_AGENT_RUN = "00000000000000f8";

const RETEST_FINDINGS: PTFinding[] = [
  {
    id: "F-1",
    title: "Entry search is injectable",
    category: "INPV",
    cwe: ["CWE-89"],
    rating: { likelihood: 4, impact: 5 },
    basis: "observed",
    where: {},
    route: "GET /api/search",
    indicator: { when: { status: 200, body_contains: ["412"] } },
    reproduction: [
      { step: "Request a normal search term", request: { method: "GET", path: "/api/search?q=rent" } },
      { step: "Request a term that closes the quote", request: { method: "GET", path: "/api/search?q=rent'--", headers: [{ name: "Accept", value: "application/json" }] } },
    ],
    impact: "A caller can read entries that are not theirs.",
    fix: "Use the parameterised helper in the search route.",
    status: "open",
    band: "critical",
    score: 20,
  },
  {
    id: "F-2",
    title: "An export can be read with another account's session",
    category: "ATHZ",
    rating: { likelihood: 4, impact: 4 },
    basis: "observed",
    where: {},
    route: "GET /api/export/1",
    indicator: { when: { status: 200, header_absent: ["X-Owner-Check"] } },
    reproduction: [{ step: "Ask for the export as the second account", request: { method: "GET", path: "/api/export/1", headers: [{ name: "Authorization", value: "[REDACTED]" }] } }],
    impact: "One account can download another account's export.",
    status: "open",
    band: "high",
    score: 16,
  },
  {
    id: "F-3",
    title: "Error pages name the framework and version",
    category: "INFO",
    rating: { likelihood: 2, impact: 2 },
    basis: "observed",
    where: {},
    reproduction: [{ step: "Open a page that does not exist", request: { method: "GET", path: "/no-such-page" } }],
    impact: "A visitor learns which version to look up.",
    status: "open",
    band: "low",
    score: 4,
  },
  {
    id: "F-4",
    title: "The login route does not slow repeated failures",
    category: "ATHN",
    rating: { likelihood: 3, impact: 3 },
    basis: "inferred",
    where: {},
    reproduction: [{ step: "Send fifty wrong passwords in a row and watch the answer time" }],
    impact: "A password can be guessed at the rate the server answers.",
    status: "open",
    band: "medium",
    score: 9,
  },
  {
    id: "F-5",
    title: "The health route lists the database address",
    category: "CONF",
    rating: { likelihood: 3, impact: 3 },
    basis: "observed",
    where: {},
    indicator: { when: { status: 200, body_contains: ["db.internal"] } },
    reproduction: [{ step: "Open the health route", request: { method: "GET", path: "/health" } }],
    impact: "A visitor learns where the database is.",
    status: "open",
    band: "medium",
    score: 9,
  },
  {
    id: "F-6",
    title: "The admin list answers without a session",
    category: "ATHN",
    rating: { likelihood: 3, impact: 4 },
    basis: "observed",
    where: {},
    indicator: { when: { status: 200, body_contains: ["users"] } },
    reproduction: [{ step: "Ask for the admin list with no session", request: { method: "GET", path: "/api/admin/users" } }],
    impact: "The list of accounts can be read by anyone.",
    status: "open",
    band: "high",
    score: 12,
  },
];

/** A pen test run with findings a retest can replay (and one it cannot), with no retest yet. */
export const FIXTURE_PT_RETESTABLE: AssessModelResponse = {
  ...FIXTURE_PT,
  record: {
    ...FIXTURE_PT.record,
    run_id: FIXTURE_RETEST_OF_RUN,
    result: {
      report: { ...PT_REPORT, counts: { findings: { read: RETEST_FINDINGS.length, kept: RETEST_FINDINGS.length } }, refs: ZERO_REFS },
      pt: { ...PT_DOC, run_id: FIXTURE_RETEST_OF_RUN, findings: RETEST_FINDINGS },
    },
  },
};

/** What the newer retest gave: all three labels, one of them with a log that does not back it (the stored request had a hidden value). */
const RETEST_NEWER: RetestView = {
  run: FIXTURE_RETEST_RUN_NEW,
  launched_at: "2026-11-16T09:10:00Z",
  at: "2026-11-16T09:30:00Z",
  state: "valid",
  started: true,
  asked: ["F-1", "F-2", "F-3", "F-5", "F-6"],
  summary: { replayed: 5, reproduced: 1, not_reproduced: 2, inconclusive: 1, missing: 1 },
  results: [
    { finding: "F-1", result: "reproduced", evidence_state: "logged", attack: "p1", control: "p2", note: "The same search term returned every entry again." },
    { finding: "F-2", result: "not_reproduced", evidence_state: "unlogged", evidence_reason: "replay_incomplete", attack: "p3", note: "The export answered 403 for the second account." },
    { finding: "F-3", result: "inconclusive", note: "The error page changed, so the stored condition could not be compared." },
    { finding: "F-5", result: "not_reproduced", evidence_state: "logged", attack: "p4", control: "p5", note: "The health route no longer lists the address." },
  ],
};

/** What the older retest gave two of the same findings: it disagrees with the newer one, which is why the newest label wins and the older ones are listed. */
const RETEST_OLDER: RetestView = {
  run: FIXTURE_RETEST_RUN_OLD,
  launched_at: "2026-11-15T15:50:00Z",
  at: "2026-11-15T16:10:00Z",
  state: "valid",
  started: true,
  asked: ["F-1", "F-2"],
  summary: { replayed: 2, reproduced: 1, not_reproduced: 1, inconclusive: 0, missing: 0 },
  results: [
    { finding: "F-1", result: "not_reproduced", evidence_state: "logged", attack: "p1", control: "p2", note: "The search answered with the ordinary list." },
    { finding: "F-2", result: "reproduced", evidence_state: "unlogged", evidence_reason: "not_replayed", attack: "p3" },
  ],
};

/** The pen test with two retests listed, the newer first. */
export const FIXTURE_PT_RETESTED: AssessModelResponse = { ...FIXTURE_PT_RETESTABLE, retests: [RETEST_NEWER, RETEST_OLDER] };

/** The helper's log of the newer retest: each replay is tagged with the finding it replayed. */
const RETEST_PROBES: ProbeRecord[] = [
  probe({ id: "p1", ts: "2026-11-16T09:12:01Z", role: "attack", wstg: "INPV", note: "replay of the stored search request", path: "/api/search?q=rent'--", req_headers: [{ n: "Accept", v: "application/json" }], body_bytes: 65536, body_excerpt: '{"total":412,"items":[{"id":1,"title":"Rent, March"}]}', replay: "F-1", ms: 58 }),
  probe({ id: "p2", ts: "2026-11-16T09:12:03Z", role: "control", wstg: "INPV", note: "an ordinary search through the helper", path: "/api/search?q=rent", body_bytes: 96, body_excerpt: '{"total":3,"items":[{"id":1,"title":"Rent, March"}]}', ms: 39 }),
  probe({ id: "p3", ts: "2026-11-16T09:13:20Z", role: "attack", wstg: "ATHZ", note: "replay of the stored export request", path: "/api/export/1", req_headers: [{ n: "Authorization", v: "[REDACTED]" }], status: 403, body_bytes: 24, body_excerpt: '{"error":"forbidden"}', replay: "F-2", ms: 21 }),
  probe({ id: "p4", ts: "2026-11-16T09:14:02Z", role: "attack", wstg: "CONF", note: "replay of the stored health request", path: "/health", body_bytes: 15, body_excerpt: '{"status":"ok"}', replay: "F-5", ms: 9 }),
  probe({ id: "p5", ts: "2026-11-16T09:14:05Z", role: "control", wstg: "CONF", note: "the home page through the helper", path: "/", body_bytes: 640, body_excerpt: "<!doctype html><title>Ledger</title>", ms: 17 }),
];

/** The newer retest's own view: a retest run, its results (the earlier finding's title and category on each), the helper's log of the replays and the counts. */
export const FIXTURE_RETEST: AssessModelResponse = {
  record: {
    schema: 1,
    run_id: FIXTURE_RETEST_RUN_NEW,
    validated_at: "2026-11-16T09:30:00Z",
    contract: "retest.v1",
    source_sha: "a0b1c2d3e4f50617",
    source_bytes: 2310,
    result: {
      report: {
        state: "valid",
        contract: "retest.v1",
        counts: { results: { read: 4, kept: 4 } },
        refs: ZERO_REFS,
        rt: { replayed: 5, reproduced: 1, not_reproduced: 2, inconclusive: 1, missing: 1 },
        evidence: {
          mode: "on",
          helper: "intact",
          log: "ok",
          records: 5,
          sent: 5,
          refused: 0,
          requests: 5,
          logged: 2,
          unlogged: 1,
          not_started: 0,
          by_reason: { replay_incomplete: 1 },
        },
        issues: [{ row: "RT6", code: "finding_not_covered", severity: "warn", path: "results", message: "1 of the findings this retest replayed have no result." }],
        sets: {},
      },
      rt: {
        schema: "observer.retest.v1",
        run_id: FIXTURE_RETEST_RUN_NEW,
        prompt_version: "re.1",
        generator: { tool: "claude-code", model: "model-x" },
        summary: "The agent started the development server and replayed the stored requests of five findings.",
        started: true,
        results: [
          { finding: "F-1", result: "reproduced", attack: "p1", control: "p2", evidence: ["p1", "p2"], note: "The same search term returned every entry again.", title: "Entry search is injectable", category: "INPV", evidence_state: "logged" },
          {
            finding: "F-2",
            result: "not_reproduced",
            attack: "p3",
            note: "The export answered 403 for the second account.",
            title: "An export can be read with another account's session",
            category: "ATHZ",
            evidence_state: "unlogged",
            evidence_reason: "replay_incomplete",
          },
          { finding: "F-3", result: "inconclusive", note: "The error page changed, so the stored condition could not be compared.", title: "Error pages name the framework and version", category: "INFO" },
          { finding: "F-5", result: "not_reproduced", attack: "p4", control: "p5", note: "The health route no longer lists the address.", title: "The health route lists the database address", category: "CONF", evidence_state: "logged" },
        ],
        limits: ["Only the stored requests were sent."],
        of: FIXTURE_RETEST_OF_RUN,
      },
    },
  },
  stale: false,
  vocab: FIXTURE_VOCAB,
  redaction: { on: true, hidden: 1 },
  probes: RETEST_PROBES,
  probe_log: { records: 5, shown: RETEST_PROBES.length, truncated: false },
};

/** The chain of FIXTURE_RED_TEAM: five steps, one with no finding that ended blocked and gave no opinion, one that used no finding but did get one. */
const EXERCISE_CHAIN: PTChainStep[] = [
  { step: "Read the front page and the error pages to learn what the app is built with.", result: "achieved", stop: "Plainer error pages would have given less to read." },
  { step: "Looked up the framework version the error page names.", finding: "F-3", result: "achieved", stop: "A response header that hides the framework would have removed this clue." },
  { step: "Searched with a term that closes the quote and read entries of another account.", finding: "F-1", result: "achieved", stop: "A parameterised query, or an alert on a search that returns every entry, would have stopped it." },
  { step: "Tried the login route for an unknown account to learn which accounts exist.", finding: "F-4", result: "partly", stop: "Answering the same way for every account would have stopped it." },
  { step: "Tried the admin pages with the session of another account.", result: "blocked" },
];

/** A red team run with the developer's own objective and a five-step chain; its findings are the evidence fixture's. */
export const FIXTURE_RED_TEAM: AssessModelResponse = (() => {
  const base = FIXTURE_PT_EVIDENCE;
  return {
    ...base,
    record: {
      ...base.record,
      run_id: FIXTURE_RED_TEAM_RUN,
      result: {
        report: { ...base.record.result.report, counts: { findings: { read: 4, kept: 4 }, chain: { read: EXERCISE_CHAIN.length, kept: EXERCISE_CHAIN.length } } },
        pt: {
          ...base.record.result.pt!,
          run_id: FIXTURE_RED_TEAM_RUN,
          exercise: { objective: "Read another user's entries without signing in as them.", objective_by: "developer", chain: EXERCISE_CHAIN },
        },
      },
    },
  };
})();

/** A red team run that was given no objective: the agent stated one, and recorded no steps. */
export const FIXTURE_RED_TEAM_AGENT: AssessModelResponse = {
  ...FIXTURE_RED_TEAM,
  record: {
    ...FIXTURE_RED_TEAM.record,
    run_id: FIXTURE_RED_TEAM_AGENT_RUN,
    result: {
      report: { ...FIXTURE_RED_TEAM.record.result.report, counts: { findings: { read: 4, kept: 4 } } },
      pt: {
        ...FIXTURE_RED_TEAM.record.result.pt!,
        run_id: FIXTURE_RED_TEAM_AGENT_RUN,
        exercise: { objective: "Reach the entries of another account through the search route.", objective_by: "agent" },
      },
    },
  },
};

// ---- big answers, for the pins that nothing is capped ----

const BANDS_BY_INDEX: readonly { band: ModelBand; likelihood: number; impact: number }[] = [
  { band: "low", likelihood: 2, impact: 3 },
  { band: "medium", likelihood: 3, impact: 3 },
  { band: "high", likelihood: 4, impact: 4 },
  { band: "critical", likelihood: 5, impact: 4 },
];

/** fixtureThreats makes n generated threats with every state a row can have: bands cycle, frameworks cycle, mitigations carry references that are found, only existing, or not found. */
export function fixtureThreats(n: number): ModelThreat[] {
  return Array.from({ length: n }, (_, i): ModelThreat => {
    const b = BANDS_BY_INDEX[i % 4];
    const ref = (state: "found" | "exists" | "claimed_not_found") => ({ path: `src/generated/file${i % 40}.ts`, line: 10 + (i % 90), needle: "guard(request)", state, ...(state === "found" ? { match_line: 10 + (i % 90) } : {}) });
    return {
      id: `T-${i + 1}`,
      title: `Generated threat ${i + 1}`,
      framework: "stride",
      category: ["spoofing", "tampering", "repudiation", "information_disclosure", "denial_of_service", "elevation_of_privilege"][i % 6],
      element: { kind: "component", id: ["web", "api", "db", "audit", "idp"][i % 5] },
      description: `The agent's description of generated threat ${i + 1}.`,
      rating: { likelihood: b.likelihood, impact: b.impact },
      band: b.band,
      score: b.likelihood * b.impact,
      status: ["identified", "mitigated", "partial", "accepted_by_design"][i % 4],
      existing: [{ text: `Existing mitigation of threat ${i + 1}.`, refs: [ref(i % 3 === 0 ? "found" : i % 3 === 1 ? "exists" : "claimed_not_found"), ref("claimed_not_found")] }],
      missing: [{ text: `Missing mitigation of threat ${i + 1}.`, effort: "m", refs: [ref("exists")] }],
    };
  });
}

/** fixtureFindings makes n generated findings: bands cycle, categories cycle, every finding cites a place and has reproduction steps. */
export function fixtureFindings(n: number): PTFinding[] {
  const cats = FIXTURE_VOCAB.wstg.map((w) => w.id);
  return Array.from({ length: n }, (_, i): PTFinding => {
    const b = BANDS_BY_INDEX[i % 4];
    return {
      id: `F-${i + 1}`,
      title: `Generated finding ${i + 1}`,
      category: cats[i % cats.length],
      cwe: [`CWE-${100 + (i % 50)}`],
      rating: { likelihood: b.likelihood, impact: b.impact },
      basis: i % 2 === 0 ? "observed" : "inferred",
      where: { refs: [{ path: `src/generated/route${i % 40}.ts`, line: 5 + (i % 60), needle: "db.query(", state: i % 3 === 0 ? "found" : "exists", ...(i % 3 === 0 ? { match_line: 5 + (i % 60) } : {}) }] },
      route: `GET /api/generated/${i + 1}`,
      reproduction: [{ step: "Send the request", request: { method: "GET", path: `/api/generated/${i + 1}` } }],
      impact: `The impact of generated finding ${i + 1}.`,
      fix: `The fix of generated finding ${i + 1}.`,
      status: "open",
      band: b.band,
      score: b.likelihood * b.impact,
    };
  });
}

/** The run id the generated threat model answer carries. */
export const FIXTURE_BIG_TM_RUN = "00000000000000e1";
/** The run id the generated pen test answer carries. */
export const FIXTURE_BIG_PT_RUN = "00000000000000e2";

/** fixtureBigThreatModel is FIXTURE_TM with n generated threats in place of its own (the matrix and the counts stay the small model's). */
export function fixtureBigThreatModel(n: number): AssessModelResponse {
  return {
    ...FIXTURE_TM,
    record: {
      ...FIXTURE_TM.record,
      run_id: FIXTURE_BIG_TM_RUN,
      result: {
        ...FIXTURE_TM.record.result,
        report: { ...TM_REPORT, counts: { ...TM_REPORT.counts, threats: { read: n, kept: n } } },
        tm: { ...TM_DOC, run_id: FIXTURE_BIG_TM_RUN, threats: fixtureThreats(n) },
      },
    },
  };
}

/** fixtureBigPentest is FIXTURE_PT with n generated findings in place of its own. */
export function fixtureBigPentest(n: number): AssessModelResponse {
  return {
    ...FIXTURE_PT,
    record: {
      ...FIXTURE_PT.record,
      run_id: FIXTURE_BIG_PT_RUN,
      result: {
        ...FIXTURE_PT.record.result,
        report: { ...PT_REPORT, counts: { findings: { read: n, kept: n } } },
        pt: { ...PT_DOC, run_id: FIXTURE_BIG_PT_RUN, findings: fixtureFindings(n) },
      },
    },
  };
}

/** ANSWER_FIXTURES is every fixed answer, by name, in the order internal/secassess/testdata/model_answer_fixtures.json holds them: the file the Go tests decode into the real response struct. */
export const ANSWER_FIXTURES: Readonly<Record<string, AssessModelResponse>> = {
  threat_model: FIXTURE_TM,
  threat_model_since: FIXTURE_TM_SINCE,
  threat_model_partial: FIXTURE_TM_PARTIAL,
  threat_model_refused_all: FIXTURE_TM_REFUSED_ALL,
  pentest: FIXTURE_PT,
  pentest_partial: FIXTURE_PT_PARTIAL,
  pentest_empty: FIXTURE_PT_EMPTY,
  pentest_refused_all: FIXTURE_PT_REFUSED_ALL,
  pentest_evidence: FIXTURE_PT_EVIDENCE,
  pentest_not_started: FIXTURE_PT_NOT_STARTED,
  pentest_retestable: FIXTURE_PT_RETESTABLE,
  pentest_retested: FIXTURE_PT_RETESTED,
  retest: FIXTURE_RETEST,
  red_team: FIXTURE_RED_TEAM,
  red_team_agent_objective: FIXTURE_RED_TEAM_AGENT,
};
