import React from "react";

export function Message() {
  const text = new URLSearchParams(location.search).get("text");
  const raw = (
    // ruleid: js.xss-request-input
    <p dangerouslySetInnerHTML={{ __html: text }} />
  );
  const cleaned = (
    // ok: js.xss-request-input
    <p dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(text) }} />
  );
  return <div>{raw}{cleaned}<p>{text}</p></div>;
}

export function Article({ body }) {
  // ok: js.xss-request-input
  return <article dangerouslySetInnerHTML={{ __html: body }} />;
}
