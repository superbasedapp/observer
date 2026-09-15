import type { ComponentProps } from "react";
import { MessagesTable as SharedMessagesTable } from "@shared/components/sessiondetail/MessagesTable";
import { fetchJSON } from "@/lib/api";
import type { ActionFullText } from "@/lib/types";

// Compatibility wrapper: MessagesTable was promoted into the shared design
// system so the node and org session-detail Messages tables share one
// implementation. The shared component takes an injected `fetchFullText`; this
// wrapper passes the node's fetchJSON-backed /api/action/<id>/full_text fetch
// and leaves the cost columns on their default (fmtUSD), so the node behaviour
// is byte-for-byte unchanged. Existing @/...MessagesTable importers are
// untouched.

type SharedProps = ComponentProps<typeof SharedMessagesTable>;

export function MessagesTable(props: Omit<SharedProps, "fetchFullText">) {
  return (
    <SharedMessagesTable
      {...props}
      fetchFullText={(id) =>
        fetchJSON<ActionFullText>(`/api/action/${id}/full_text`)
      }
    />
  );
}
