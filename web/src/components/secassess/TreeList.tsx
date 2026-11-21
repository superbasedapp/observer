import { useMemo, useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { EmptyState, Icon, Pill } from "@/components/primitives";
import { plural, treeItems, type ModelTree, type TreeItem } from "@/lib/secAssessModel";
import { SubHeading } from "./modelParts";

// TreeList shows each attack tree as a nested list: the root as the heading,
// every node under its parent, "and" or "or" on a node that combines its
// children, and a marker on a leaf. Every node is shown; a branch can be
// folded by the reader, and none is folded at first. The labels are the
// agent's text, shown as text. Observer checked the tree's links (a node whose
// parent is missing hangs from the root, a cycle is cut), not that the tree is
// a sound argument.

const OP_WORDS: Readonly<Record<string, string>> = {
  and: "All of the nodes below are needed",
  or: "Any one of the nodes below is enough",
};

function opWords(op: string): string {
  return Object.prototype.hasOwnProperty.call(OP_WORDS, op) ? OP_WORDS[op] : `Combined by ${op}`;
}

function TreeNode({ item }: { item: TreeItem }) {
  const [open, setOpen] = useState(true);
  const branch = item.children.length > 0;
  return (
    <li data-testid="assess-tree-node" data-node-id={item.id} data-leaf={item.leaf ? "true" : "false"} className="min-w-0">
      <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-0.5 py-0.5 text-[12px]">
        {branch ? (
          <button
            type="button"
            aria-expanded={open}
            aria-label={`${open ? "Fold" : "Unfold"} ${item.label}`}
            onClick={() => setOpen((v) => !v)}
            className="inline-flex shrink-0 items-center rounded-1 text-fg-3 hover:text-fg-1 focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]"
          >
            <Icon icon={open ? ChevronDown : ChevronRight} size="xs" />
          </button>
        ) : (
          <span className="inline-block w-3 shrink-0" aria-hidden />
        )}
        <span className="min-w-0 break-words text-fg-1">{item.label}</span>
        {item.op && (
          <Pill variant="info" case="none" title={opWords(item.op)}>
            {item.op}
          </Pill>
        )}
        {item.leaf && (
          <Pill variant="neutral" case="none">
            leaf
          </Pill>
        )}
      </div>
      {branch && open && (
        <ul className="m-0 ml-1.5 list-none space-y-0 border-l border-line-2 p-0 pl-3">
          {item.children.map((c, i) => (
            <TreeNode key={`${c.id}#${i}`} item={c} />
          ))}
        </ul>
      )}
    </li>
  );
}

function countNodes(items: TreeItem[]): number {
  let n = 0;
  const stack = [...items];
  while (stack.length > 0) {
    const it = stack.pop()!;
    n++;
    for (const c of it.children) stack.push(c);
  }
  return n;
}

function Tree({ tree }: { tree: ModelTree }) {
  const items = useMemo(() => treeItems(tree), [tree]);
  const nodes = useMemo(() => countNodes(items), [items]);
  return (
    <section data-testid="assess-tree" className="space-y-1.5 rounded-2 border border-line-2 bg-bg-2 p-3">
      <h4 className="m-0 break-words text-[12.5px] font-semibold text-fg-1">{tree.root}</h4>
      <p className="m-0 text-[11px] text-fg-3">{`${nodes} ${plural(nodes, "node", "nodes")}`}</p>
      {items.length === 0 ? (
        <p className="m-0 text-[11.5px] text-fg-3">The tree has no nodes under its root.</p>
      ) : (
        <ul className="m-0 list-none space-y-0 p-0" aria-label={`Attack tree: ${tree.root}`}>
          {items.map((it, i) => (
            <TreeNode key={`${it.id}#${i}`} item={it} />
          ))}
        </ul>
      )}
    </section>
  );
}

export function TreeList({ trees }: { trees: ModelTree[] | undefined }) {
  const list = trees ?? [];
  if (list.length === 0) {
    return (
      <div data-testid="assess-trees">
        <EmptyState
          variant="inline"
          title="The model has no attack trees"
          body="Attack trees are an optional part of a threat model. Whether the agent is asked for them is the setting Threat model abuse cases and attack trees (Code security, Settings, Security assessments). This model has none."
        />
      </div>
    );
  }
  return (
    <div className="min-w-0 space-y-3" data-testid="assess-trees">
      <SubHeading agent>{`Attack trees (${list.length})`}</SubHeading>
      {list.map((t, i) => (
        <Tree key={`${t.root}#${i}`} tree={t} />
      ))}
    </div>
  );
}
