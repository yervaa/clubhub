const INLINE_WHITESPACE = /\s+/g;
const CONTROL_CHARS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;

function stripUnsafeCharacters(value: string) {
  return value.replace(CONTROL_CHARS, "").replace(/[<>]/g, "");
}

export function sanitizeInlineText(value: string) {
  return stripUnsafeCharacters(value).trim().replace(INLINE_WHITESPACE, " ");
}

export function sanitizeMultilineText(value: string) {
  return stripUnsafeCharacters(value)
    .replace(/\r\n/g, "\n")
    .split("\n")
    .map((line) => line.trim())
    .join("\n")
    .trim();
}

export function sanitizeEmail(value: string) {
  return sanitizeInlineText(value).toLowerCase();
}

export function sanitizeCode(value: string) {
  return sanitizeInlineText(value).toUpperCase();
}
