/** Shared env string cleanup (safe for client + server bundles). */
export function cleanEnvValue(value: string | undefined) {
  if (!value) return "";
  return value.trim().replace(/^['"]|['"]$/g, "");
}
