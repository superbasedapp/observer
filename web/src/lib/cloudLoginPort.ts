// cloudLoginPort: the rule for Settings > Cloud Intelligence > Advanced's
// "Login callback port" field ([cloud].login_port). The server enforces the
// same range (internal/intelligence/dashboard/settings.go
// validCloudLoginPort); this copy only lets the form say what is wrong
// before Save. Pure, so the node test runner covers it.

/** The port `observer cloud login` listens on when the key is unset (0). */
export const CLOUD_LOGIN_PORT_DEFAULT = 9797;

/**
 * cloudLoginPortError returns why a login port cannot be saved, or null when
 * it can: 0 (use the built-in default) or a whole number from 1024 to 65535.
 * Privileged ports are refused because the callback listener runs as you.
 */
export function cloudLoginPortError(port: number): string | null {
  if (!Number.isFinite(port) || !Number.isInteger(port)) return "Enter a whole number.";
  if (port === 0) return null;
  if (port < 1024 || port > 65535) return "Use a port from 1024 to 65535, or 0 for the default.";
  return null;
}

/** cloudLoginPortShown is the port a sign-in will actually use. */
export function cloudLoginPortShown(port: number): number {
  return port > 0 ? port : CLOUD_LOGIN_PORT_DEFAULT;
}
