/**
 * setup's output: plain lines for people, or (`--json`) one JSON object per
 * phase on stdout for agents, with the people's lines on stderr.
 *
 * Secrecy (plan 3.5, ledger SDKQS-4): the key, its secret half, the device
 * code, the redeem secret and the key grant are registered here as soon as
 * setup holds them, and every byte setup writes passes through `redact()`.
 * The phases never put them in a message in the first place; the reporter
 * counts any it had to take out (`redactions`), and the contract test
 * asserts that count stays 0 as well as that no output carries them.
 */

export interface Sink {
  write(s: string): void;
}

export const REDACTED = "[redacted]";

export class Reporter {
  /** How many times a secret had to be taken out of a line (0 when the phases behaved). */
  redactions = 0;
  private readonly secrets = new Set<string>();

  constructor(
    readonly json: boolean,
    private readonly stdout: Sink,
    private readonly stderr: Sink,
  ) {}

  /** Register a value that must never be written (its secret half too, for a `<id>.<secret>` key). */
  secret(v: string): void {
    if (!v || v.length < 8) return;
    this.secrets.add(v);
    const dot = v.indexOf(".");
    if (dot > 0 && v.length - dot - 1 >= 8) this.secrets.add(v.slice(dot + 1));
  }

  /** The text with every registered secret replaced. */
  redact(text: string): string {
    let out = text;
    for (const s of [...this.secrets].sort((a, b) => b.length - a.length)) {
      if (out.includes(s)) {
        this.redactions += 1;
        out = out.split(s).join(REDACTED);
      }
    }
    return out;
  }

  /** A line for people (stdout; stderr under --json). */
  say(line = ""): void {
    const text = this.redact(line) + "\n";
    if (this.json) this.stderr.write(text);
    else this.stdout.write(text);
  }

  /** A warning for people (stderr). */
  warn(line: string): void {
    this.stderr.write(this.redact(line) + "\n");
  }

  /** One phase's object (stdout under --json; nothing otherwise). */
  event(phase: string, fields: Record<string, unknown> = {}): void {
    if (!this.json) return;
    this.stdout.write(this.redact(JSON.stringify({ phase, ...fields })) + "\n");
  }
}
