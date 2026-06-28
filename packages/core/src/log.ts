/** Emit a warning to stderr. Used so degraded/fallback paths announce themselves instead
 * of failing silently — a swallowed error makes the very outage it hides undetectable. */
export function warn(message: string): void {
  console.warn(`preflight: ${message}`);
}
