// The packages every app's Vite config dedupes (resolve.dedupe). shared/
// imports these; dedupe pins one copy of each, so a hooks-bearing shared
// component never gets a second React ("invalid hook call") when its
// dependency resolves from the root workspace node_modules. One list for
// web, web2 and webcloud (docs/app-design-system.md).
export const SHARED_DEDUPE: string[] = [
  "react",
  "react-dom",
  "react-router-dom",
  "recharts",
  "clsx",
  "@floating-ui/react",
  "framer-motion",
  "lucide-react",
  "@tanstack/react-table",
];
