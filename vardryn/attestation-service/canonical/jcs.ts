/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) — reference implementation.
 *
 * Mirrors canonical/jcs.py byte-for-byte for the
 * vardryn.attestation.payload/1.0 schema (objects, arrays, strings,
 * booleans, null, and non-negative integers — no float fields).
 *
 * JS strings are sequences of UTF-16 code units, so the native `<`/`>`
 * operators on strings already implement the RFC 8785 §3.2.3 object-key
 * ordering — no special handling needed (unlike the Python port, which
 * must re-encode to UTF-16BE to get the same result).
 *
 * JSON.stringify() on a string escapes exactly the RFC 8785 set: '"',
 * '\\', and U+0000-U+001F via short forms or \u00XX, with all other code
 * points emitted literally — matching json.dumps(ensure_ascii=False).
 */

export function canonicalize(value: unknown): Buffer {
  return Buffer.from(encode(value), "utf-8");
}

function encode(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") return encodeNumber(value);
  if (Array.isArray(value)) return "[" + value.map(encode).join(",") + "]";
  if (typeof value === "object") return encodeObject(value as Record<string, unknown>);
  throw new TypeError(`Unsupported type for JCS canonicalization: ${typeof value}`);
}

function encodeNumber(n: number): string {
  if (!Number.isFinite(n)) {
    throw new Error("NaN and Infinity are not representable in JSON");
  }
  if (Number.isSafeInteger(n)) {
    return String(n);
  }
  throw new Error(
    `Non-integer number ${n} is outside this implementation's ` +
      "guaranteed-correct range for ECMA-262 Number::toString parity. " +
      "The attestation payload schema does not use float fields."
  );
}

function encodeObject(obj: Record<string, unknown>): string {
  const keys = Object.keys(obj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return (
    "{" +
    keys.map((k) => `${JSON.stringify(k)}:${encode(obj[k])}`).join(",") +
    "}"
  );
}
