// WebAuthn encoding for the staff console's passkey sign-in (managed-SaaS
// M6.8; the server half is internal/cloudserver/staffauth/webauthn.go and
// staffwebauthn.go). The server sends the options with every binary field as
// unpadded base64url (staffauth.CreationOptions / RequestOptions); the browser
// API wants ArrayBuffers; the server reads the credential back in the
// standard JSON form (PublicKeyCredential.toJSON: base64url fields). Pure: no
// fetch, no navigator; the page passes navigator.credentials in.

/** b64urlToBytes decodes unpadded (or padded) base64url. */
export function b64urlToBytes(s: string): Uint8Array<ArrayBuffer> {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "===".slice((b64.length + 3) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** bytesToB64url encodes bytes as unpadded base64url. */
export function bytesToB64url(buf: ArrayBuffer | ArrayBufferView): string {
  const bytes =
    buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export interface CredentialDescriptorJSON {
  type: "public-key";
  id: string;
}

/** RequestOptionsJSON is staffauth.RequestOptions on the wire. */
export interface RequestOptionsJSON {
  challenge: string;
  rpId: string;
  timeout: number;
  userVerification: UserVerificationRequirement;
  allowCredentials: CredentialDescriptorJSON[];
}

/** CreationOptionsJSON is staffauth.CreationOptions on the wire. */
export interface CreationOptionsJSON {
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: { type: "public-key"; alg: number }[];
  timeout: number;
  excludeCredentials: CredentialDescriptorJSON[];
  authenticatorSelection: {
    residentKey: ResidentKeyRequirement;
    requireResidentKey: boolean;
    userVerification: UserVerificationRequirement;
  };
  attestation: AttestationConveyancePreference;
}

function descriptor(d: CredentialDescriptorJSON): PublicKeyCredentialDescriptor {
  return { type: "public-key", id: b64urlToBytes(d.id) };
}

/** toRequestOptions turns the server's assertion options into the browser's. */
export function toRequestOptions(o: RequestOptionsJSON): PublicKeyCredentialRequestOptions {
  return {
    challenge: b64urlToBytes(o.challenge),
    rpId: o.rpId,
    timeout: o.timeout,
    userVerification: o.userVerification,
    allowCredentials: (o.allowCredentials ?? []).map(descriptor),
  };
}

/** toCreationOptions turns the server's registration options into the
 *  browser's. */
export function toCreationOptions(o: CreationOptionsJSON): PublicKeyCredentialCreationOptions {
  return {
    rp: o.rp,
    user: { id: b64urlToBytes(o.user.id), name: o.user.name, displayName: o.user.displayName },
    challenge: b64urlToBytes(o.challenge),
    pubKeyCredParams: o.pubKeyCredParams,
    timeout: o.timeout,
    excludeCredentials: (o.excludeCredentials ?? []).map(descriptor),
    authenticatorSelection: o.authenticatorSelection,
    attestation: o.attestation,
  };
}

/** The slice of a PublicKeyCredential this module reads (a test builds one
 *  without a browser). */
export interface CredentialLike {
  id: string;
  rawId: ArrayBuffer;
  type: string;
  authenticatorAttachment?: string | null;
  response: {
    clientDataJSON: ArrayBuffer;
    authenticatorData?: ArrayBuffer;
    signature?: ArrayBuffer;
    userHandle?: ArrayBuffer | null;
    attestationObject?: ArrayBuffer;
    getTransports?: () => string[];
  };
  getClientExtensionResults?: () => AuthenticationExtensionsClientOutputs;
}

/** credentialToJSON serializes an assertion or an attestation the way
 *  PublicKeyCredential.toJSON does (the server parses that form). */
export function credentialToJSON(c: CredentialLike): Record<string, unknown> {
  const r = c.response;
  const response: Record<string, unknown> = { clientDataJSON: bytesToB64url(r.clientDataJSON) };
  if (r.attestationObject) {
    response.attestationObject = bytesToB64url(r.attestationObject);
    response.transports = r.getTransports ? r.getTransports() : [];
  }
  if (r.authenticatorData) response.authenticatorData = bytesToB64url(r.authenticatorData);
  if (r.signature) response.signature = bytesToB64url(r.signature);
  if (r.userHandle) response.userHandle = bytesToB64url(r.userHandle);
  return {
    id: c.id,
    rawId: bytesToB64url(c.rawId),
    type: c.type,
    authenticatorAttachment: c.authenticatorAttachment ?? undefined,
    response,
    clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
  };
}

/** passkeyErrorText turns a browser WebAuthn rejection into one plain line. */
export function passkeyErrorText(err: unknown): string {
  const name = err instanceof Error ? err.name : "";
  switch (name) {
    case "NotAllowedError":
      return "The passkey prompt was cancelled or timed out.";
    case "InvalidStateError":
      return "This passkey is already registered.";
    case "SecurityError":
      return "This page's address does not match the staff console's passkey domain.";
    case "NotSupportedError":
      return "This browser or device cannot use a passkey here.";
    default:
      return err instanceof Error && err.message ? err.message : "The passkey step failed.";
  }
}
