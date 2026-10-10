// @effect-diagnostics-next-line nodeBuiltinImport:off -- Effect's Crypto has no createHmac or timingSafeEqual.
import * as NodeCrypto from "node:crypto";

import type { ScheduledTaskWebhookSignature } from "@t3tools/contracts";

/** Constant-time string comparison that does not leak length through timing. */
export function constantTimeEquals(a: string, b: string): boolean {
  const digestA = NodeCrypto.createHash("sha256").update(a).digest();
  const digestB = NodeCrypto.createHash("sha256").update(b).digest();
  return NodeCrypto.timingSafeEqual(digestA, digestB);
}

type SignatureInput = {
  readonly signature: ScheduledTaskWebhookSignature;
  readonly secret: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Uint8Array;
};

/**
 * A verified request, and for a signed timestamp the key it runs once under:
 * its timestamp and digest, so the same signed request sent again (a retry, or
 * a replay inside the tolerance) is recognised. A body-only signature has no
 * such key: identical bodies may legitimately be sent twice.
 */
export type WebhookSignatureVerdict =
  | { readonly _tag: "verified"; readonly replayKey: string | undefined }
  | { readonly _tag: "rejected" };

const encode = (signature: ScheduledTaskWebhookSignature, digest: Buffer) =>
  signature.encoding === "hex" ? digest.toString("hex") : digest.toString("base64");

const normalize = (signature: ScheduledTaskWebhookSignature, candidate: string) =>
  signature.encoding === "hex" ? candidate.toLowerCase() : candidate;

/** The header value with its configured prefix removed, or undefined. */
const headerValue = (input: SignatureInput): string | undefined => {
  const received = input.headers[input.signature.header.toLowerCase()];
  if (received === undefined) return undefined;
  const value = received.trim();
  const prefix = input.signature.prefix;
  if (prefix !== "" && !value.toLowerCase().startsWith(prefix.toLowerCase())) return undefined;
  return value.slice(prefix.length);
};

/**
 * Checks an HMAC-SHA256 signature over the raw body bytes, as GitHub, Linear,
 * Shopify and most other signing senders do. The header value is
 * `<prefix><digest>`, with the digest hex- or base64-encoded.
 */
export function verifyWebhookSignature(input: SignatureInput): boolean {
  const candidate = headerValue(input);
  if (candidate === undefined) return false;
  const digest = NodeCrypto.createHmac("sha256", input.secret).update(input.body).digest();
  return constantTimeEquals(normalize(input.signature, candidate), encode(input.signature, digest));
}

const TIMESTAMP = /^\d{1,12}$/;

/**
 * Checks a Stripe-style signed timestamp: the header value (after the prefix)
 * is `t=<unix seconds>,v1=<digest>[,v1=<digest>…]`, each digest an
 * HMAC-SHA256 of `<t>.` followed by the raw body. Any matching `v1` passes, so
 * a sender can sign with two secrets while rotating. `t` must lie within the
 * tolerance of `nowMs`, in either direction.
 */
export function verifyTimestampedWebhookSignature(
  input: SignatureInput & { readonly toleranceSeconds: number; readonly nowMs: number },
): { readonly timestamp: string; readonly digest: string } | undefined {
  const value = headerValue(input);
  if (value === undefined) return undefined;
  let timestamp: string | undefined;
  const candidates: Array<string> = [];
  for (const part of value.split(",")) {
    const separator = part.indexOf("=");
    if (separator === -1) continue;
    const key = part.slice(0, separator).trim();
    const item = part.slice(separator + 1).trim();
    // A second t is ambiguous: refuse rather than pick one.
    if (key === "t") {
      if (timestamp !== undefined) return undefined;
      timestamp = item;
    } else if (key === "v1" && item !== "") candidates.push(item);
  }
  if (timestamp === undefined || !TIMESTAMP.test(timestamp) || candidates.length === 0) {
    return undefined;
  }
  if (Math.abs(input.nowMs - Number(timestamp) * 1000) > input.toleranceSeconds * 1000) {
    return undefined;
  }
  const digest = encode(
    input.signature,
    NodeCrypto.createHmac("sha256", input.secret)
      .update(`${timestamp}.`)
      .update(input.body)
      .digest(),
  );
  const matched = candidates.some((candidate) =>
    constantTimeEquals(normalize(input.signature, candidate), digest),
  );
  return matched ? { timestamp, digest } : undefined;
}

/** Verifies a request against the task's signature settings. */
export function checkWebhookSignature(
  input: SignatureInput & { readonly nowMs: number },
): WebhookSignatureVerdict {
  const tolerance = input.signature.timestampToleranceSeconds ?? null;
  if (tolerance === null) {
    return verifyWebhookSignature(input)
      ? { _tag: "verified", replayKey: undefined }
      : { _tag: "rejected" };
  }
  const verified = verifyTimestampedWebhookSignature({ ...input, toleranceSeconds: tolerance });
  return verified === undefined
    ? { _tag: "rejected" }
    : { _tag: "verified", replayKey: `${verified.timestamp}.${verified.digest}` };
}
