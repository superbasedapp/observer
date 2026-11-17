import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Stagger } from "@shared/primitives/Motion";
import { PageHeader } from "@shared/primitives/PageHeader";
import { ApiError, checkSlug, createTeam, listOrgs } from "../api";
import type { OrgsList } from "../api";
import { CreateTeamForm } from "../components/orgs/CreateTeamForm";
import { routeIcon } from "../lib/nav";
import {
  CREATE_ERROR_TEXT,
  createFormView,
  normalizeSlug,
  slugShapeProblem,
  suggestSlug,
  teamCapView,
  type AvailabilityState,
} from "../lib/orgsModel";
import { invalidatePortal, usePortalQuery } from "../lib/query";

// CreateTeam - "Create a team" (plan 07 M6.5). The address follows the name
// until the user edits it; each well-shaped address is checked with the
// server (debounced), which answers taken / reserved and the host. Submitting
// creates the team and enqueues its setup; the page then opens the team,
// which shows the setup's progress (including a capacity waitlist). The form
// says a team is managed (full content) before the create, and the account's
// team cap comes from the orgs list (W15-D12; the create route enforces it).

const CHECK_DEBOUNCE_MS = 350;

export function CreateTeam() {
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [slugInput, setSlugInput] = useState("");
  const [slugEdited, setSlugEdited] = useState(false);
  const [availability, setAvailability] = useState<AvailabilityState>({ kind: "idle" });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const seq = useRef(0);
  const orgs = usePortalQuery<OrgsList>("orgs", listOrgs, []);
  const cap = teamCapView(orgs.data?.team_orgs);

  const slug = normalizeSlug(slugInput);
  useEffect(() => {
    if (slugShapeProblem(slug)) {
      setAvailability({ kind: "idle" });
      return;
    }
    const mine = ++seq.current;
    setAvailability({ kind: "checking", slug });
    const t = window.setTimeout(() => {
      checkSlug(slug)
        .then((answer) => {
          if (seq.current === mine) setAvailability({ kind: "answered", answer });
        })
        .catch((e: unknown) => {
          if (seq.current === mine) {
            setAvailability({ kind: "error", slug, message: e instanceof Error ? e.message : "failed" });
          }
        });
    }, CHECK_DEBOUNCE_MS);
    return () => window.clearTimeout(t);
  }, [slug]);

  const view = createFormView({ name, slug: slugInput, availability, submitting });

  function onName(v: string) {
    setName(v);
    if (!slugEdited) setSlugInput(suggestSlug(v));
  }
  function onSlug(v: string) {
    setSlugEdited(true);
    setSlugInput(v);
  }
  async function onSubmit() {
    setSubmitting(true);
    setError(null);
    try {
      const d = await createTeam(name.trim(), view.slug);
      invalidatePortal("orgs");
      navigate("/orgs/" + encodeURIComponent(d.org.org_id));
    } catch (e) {
      const code = e instanceof ApiError ? e.code : "";
      setError(CREATE_ERROR_TEXT[code] ?? (e instanceof Error ? e.message : "could not create the team"));
      if (code === "team_org_limit" || code === "team_create_invite_only") invalidatePortal("orgs");
      if (code === "slug_taken") setAvailability({ kind: "answered", answer: { slug: view.slug, available: false, reason: "taken" } });
      setSubmitting(false);
    }
  }

  return (
    <Stagger className="flex flex-col gap-6">
      <PageHeader title="Create a team" icon={routeIcon("/home")} sub="A team gets its own dashboard, members and billing. Machines you connect to it send full detail." />
      <CreateTeamForm
        name={name}
        slugInput={slugInput}
        view={view}
        submitting={submitting}
        error={error}
        onName={onName}
        onSlug={onSlug}
        onSubmit={onSubmit}
        cap={cap}
        price={orgs.data?.team_price}
      />
    </Stagger>
  );
}
