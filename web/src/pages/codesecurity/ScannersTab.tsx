import { useState, type ReactNode } from "react";
import { CustomScannersCard } from "@/components/security/CustomScannersCard";
import { IaCInstallCard } from "@/components/security/IaCInstallCard";
import { OpengrepScannerCard } from "@/components/security/OpengrepScannerCard";
import { SARIFImportCard } from "@/components/security/SARIFImportCard";
import { ScannersCard, type SecurityScanners } from "@/components/security/ScannersCard";
import { projectLabel, sortProjects, type SecurityStatus } from "@/lib/codeSecurity";
import { useApi, type ApiState } from "@/lib/useApi";
import { useComponentCatalog, useComponentState } from "@/lib/useComponents";
import { DastCard } from "./DastCard";
import { PackageChecksCard } from "./PackageChecksCard";
import { ScannerSwitches } from "./ScannerSwitches";

// ScannersTab: the Code security page's Scanners tab (redesign plan section
// 4.6). First the on/off switch of every scanner (ScannerSwitches: preview,
// confirm, apply through the owner-local components routes), then the setup
// that used to sit under the findings, moved here with the same behaviour
// and grouped under plain headings: Scanners (custom scanners), Package
// checks, Databases and images (the dependency Scanners card), Code rules,
// IaC scanners (Trivy and KICS: the guided install the CLI's `observer
// security iac install` does, dashboard CLI parity plan B-CS2), Web checks
// (the passive DAST card, shown only while security.dast is selected), Import
// results.
//
// The custom scanners card shows only while /api/security/scanners/custom
// answers templates, and the dependency Scanners card only while
// /api/security/scanners answers drivers, as before. After a switch is
// applied the cards that read component state are re-read (a bumped key),
// so a scanner that just turned on shows its setup at once.
//
// Working surface: calm register, zero delight elements.

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    // A section whose cards all render nothing (their component is off) hides
    // its heading too, so no heading stands over an empty space.
    <section className="space-y-3 has-[[data-section-body]:empty]:hidden" aria-label={title}>
      <h2 className="m-0 text-[15px] font-medium text-fg-1">{title}</h2>
      <div className="space-y-3" data-section-body>
        {children}
      </div>
    </section>
  );
}

export function ScannersTab({ status, onChanged }: { status: ApiState<SecurityStatus>; onChanged: () => void }) {
  const catalog = useComponentCatalog();
  const compState = useComponentState();
  // The custom scanners card shows only while its component answers.
  const customProbe = useApi<{ templates: unknown[] }>("/api/security/scanners/custom");
  const customScannersActive = Boolean(customProbe.data?.templates);
  // The dependency Scanners card shows only while a driver is selected (the
  // route answers 404 otherwise).
  const scanners = useApi<SecurityScanners>("/api/security/scanners");
  const scannersActive = Boolean(scanners.data?.drivers);
  // Bumped after a switch is applied so the cards below re-read themselves.
  const [epoch, setEpoch] = useState(0);

  const projects = sortProjects(status.data?.projects ?? []).map((p) => ({
    project_root_hash: p.project_root_hash,
    label: projectLabel(p),
    active: p.active,
  }));

  const changed = () => {
    scanners.reload();
    customProbe.reload();
    setEpoch((n) => n + 1);
    onChanged();
  };

  return (
    <div className="space-y-8" data-testid="scanners-tab">
      <Section title="Scanners">
        <ScannerSwitches catalog={catalog} state={compState} drivers={scanners.data?.drivers} onChanged={changed} />
        {customScannersActive ? <CustomScannersCard key={`custom-${epoch}`} /> : null}
      </Section>
      <Section title="Package checks">
        <PackageChecksCard key={`deps-${epoch}`} />
      </Section>
      {scannersActive && scanners.data ? (
        <Section title="Databases and images">
          <ScannersCard data={scanners.data} onChanged={scanners.reload} projects={projects} />
        </Section>
      ) : null}
      <Section title="Code rules">
        <OpengrepScannerCard key={`opengrep-${epoch}`} />
      </Section>
      <Section title="IaC scanners">
        <IaCInstallCard key={`iac-${epoch}`} onChanged={scanners.reload} />
      </Section>
      <Section title="Web checks">
        <DastCard key={`dast-${epoch}`} projects={projects} />
      </Section>
      <Section title="Import results">
        <SARIFImportCard key={`sarif-${epoch}`} projects={projects} onImported={onChanged} />
      </Section>
    </div>
  );
}
