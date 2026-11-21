import { Wrench } from "lucide-react";
import { Button } from "@/components/primitives";

// FixButton is the Findings tab's "Fix with an agent" action, the same on a
// finding row, a group row, the drawer and the list header. In a row it is
// icon-only and stops the click so the row's own click (open the drawer,
// list the group) does not also fire.
export function FixButton({
  onClick,
  label = "Fix with an agent",
  iconOnly = false,
  testId,
}: {
  onClick: () => void;
  label?: string;
  iconOnly?: boolean;
  testId?: string;
}) {
  return (
    <Button
      size="sm"
      variant={iconOnly ? "ghost" : "secondary"}
      iconLeft={Wrench}
      aria-label={label}
      title={label}
      data-testid={testId}
      onClick={(e) => {
        e.stopPropagation();
        onClick();
      }}
    >
      {iconOnly ? undefined : label}
    </Button>
  );
}
