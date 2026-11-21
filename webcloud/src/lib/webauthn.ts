// webauthn.ts - the browser half of the portal's passkey second factor (C2;
// internal/cloudserver/api/portalmfa.go). The server sends the creation and
// request options in their JSON form (base64url strings for every binary
// field) and expects a credential back in the same JSON form
// (PublicKeyCredential.toJSON()). This file converts between that and the
// ArrayBuffers navigator.credentials takes, by hand, so it works in browsers
// without parseCreationOptionsFromJSON / toJSON. It holds no state.

/** b64urlToBytes decodes base64url (no padding needed). */
export function b64urlToBytes(s: string): Uint8Array<ArrayBuffer> {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** bytesToB64url encodes bytes as base64url without padding. */
export function bytesToB64url(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** safeNext keeps a post-sign-in destination same-origin: the platform
 * sign-in resume (/oauth2/authorize?...) or a portal page; anything else is
 * the portal root. The server validates the same before answering "next";
 * this guards the one path the SPA computes itself (after a first enrol). */
export function safeNext(raw: string | null | undefined): string {
  const v = (raw ?? "").trim();
  if (v === "" || v.startsWith("//") || /[\\\s#]/.test(v) || /^[a-z][a-z0-9+.-]*:/i.test(v)) return "/portal/";
  if (v.startsWith("/oauth2/authorize?") || v === "/oauth2/authorize") return v;
  if (v.startsWith("/portal/") && !v.includes("..")) return v;
  return "/portal/";
}

/** passkeysSupported reports whether this browser can run a ceremony. */
export function passkeysSupported(): boolean {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential === "function" && !!navigator.credentials;
}

type Json = Record<string, unknown>;

function descriptors(list: unknown): PublicKeyCredentialDescriptor[] {
  if (!Array.isArray(list)) return [];
  return list.map((d) => {
    const o = d as { type: string; id: string };
    return { type: "public-key", id: b64urlToBytes(o.id) };
  });
}

/** createPasskey runs navigator.credentials.create for the server's options
 * and returns the credential in its JSON form. */
export async function createPasskey(options: Json): Promise<Json> {
  const o = options as {
    rp: PublicKeyCredentialRpEntity;
    user: { id: string; name: string; displayName: string };
    challenge: string;
    pubKeyCredParams: PublicKeyCredentialParameters[];
    timeout?: number;
    excludeCredentials?: unknown;
    authenticatorSelection?: AuthenticatorSelectionCriteria;
    attestation?: AttestationConveyancePreference;
  };
  const cred = (await navigator.credentials.create({
    publicKey: {
      rp: o.rp,
      user: { id: b64urlToBytes(o.user.id), name: o.user.name, displayName: o.user.displayName },
      challenge: b64urlToBytes(o.challenge),
      pubKeyCredParams: o.pubKeyCredParams,
      timeout: o.timeout,
      excludeCredentials: descriptors(o.excludeCredentials),
      authenticatorSelection: o.authenticatorSelection,
      attestation: o.attestation,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("no passkey was created");
  const r = cred.response as AuthenticatorAttestationResponse;
  const transports = typeof r.getTransports === "function" ? r.getTransports() : [];
  return {
    id: cred.id,
    rawId: bytesToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bytesToB64url(r.clientDataJSON),
      attestationObject: bytesToB64url(r.attestationObject),
      transports,
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

/** usePasskey runs navigator.credentials.get for the server's options and
 * returns the assertion in its JSON form. */
export async function usePasskey(options: Json): Promise<Json> {
  const o = options as {
    challenge: string;
    rpId: string;
    timeout?: number;
    userVerification?: UserVerificationRequirement;
    allowCredentials?: unknown;
  };
  const cred = (await navigator.credentials.get({
    publicKey: {
      challenge: b64urlToBytes(o.challenge),
      rpId: o.rpId,
      timeout: o.timeout,
      userVerification: o.userVerification,
      allowCredentials: descriptors(o.allowCredentials),
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("no passkey was used");
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: bytesToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bytesToB64url(r.clientDataJSON),
      authenticatorData: bytesToB64url(r.authenticatorData),
      signature: bytesToB64url(r.signature),
      userHandle: r.userHandle ? bytesToB64url(r.userHandle) : undefined,
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

/** passkeyErrorText words a browser-side failure (the person cancelled, or
 * the authenticator refused) in plain language. */
export function passkeyErrorText(e: unknown): string {
  const name = e instanceof Error ? e.name : "";
  if (name === "NotAllowedError" || name === "AbortError") return "The passkey prompt was closed or timed out. Try again.";
  if (name === "InvalidStateError") return "That passkey is already registered on this account.";
  if (name === "SecurityError") return "This browser refused the passkey for this site.";
  return e instanceof Error && e.message ? e.message : "The passkey did not work. Try again.";
}
