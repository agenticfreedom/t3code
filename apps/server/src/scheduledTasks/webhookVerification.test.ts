// @effect-diagnostics-next-line nodeBuiltinImport:off -- Effect's Crypto has no createHmac.
import * as NodeCrypto from "node:crypto";

import { assert, describe, it } from "@effect/vitest";

import { checkWebhookSignature, verifyWebhookSignature } from "./webhookVerification.ts";

const body = new TextEncoder().encode('{"action":"opened"}');
const secret = "shared-secret";
const hmac = () => NodeCrypto.createHmac("sha256", secret).update(body);

describe("verifyWebhookSignature", () => {
  const github = { header: "x-hub-signature-256", encoding: "hex", prefix: "sha256=" } as const;

  it("accepts a GitHub-style hex signature with prefix", () => {
    const headers = { "x-hub-signature-256": `sha256=${hmac().digest("hex")}` };
    assert.isTrue(verifyWebhookSignature({ signature: github, secret, headers, body }));
  });

  it("rejects a tampered body, a wrong secret, a missing header and a missing prefix", () => {
    const valid = `sha256=${hmac().digest("hex")}`;
    const tampered = new TextEncoder().encode('{"action":"closed"}');
    assert.isFalse(
      verifyWebhookSignature({
        signature: github,
        secret,
        headers: { "x-hub-signature-256": valid },
        body: tampered,
      }),
    );
    assert.isFalse(
      verifyWebhookSignature({
        signature: github,
        secret: "other",
        headers: { "x-hub-signature-256": valid },
        body,
      }),
    );
    assert.isFalse(verifyWebhookSignature({ signature: github, secret, headers: {}, body }));
    assert.isFalse(
      verifyWebhookSignature({
        signature: github,
        secret,
        headers: { "x-hub-signature-256": hmac().digest("hex") },
        body,
      }),
    );
  });

  it("accepts a base64 signature without prefix", () => {
    assert.isTrue(
      verifyWebhookSignature({
        signature: { header: "X-Signature", encoding: "base64", prefix: "" },
        secret,
        headers: { "x-signature": hmac().digest("base64") },
        body,
      }),
    );
  });
});

describe("checkWebhookSignature with a signed timestamp", () => {
  const stripe = {
    header: "x-signature",
    encoding: "hex",
    prefix: "",
    timestampToleranceSeconds: 300,
    deliveryIdHeader: "webhook-id",
  } as const;
  const nowMs = 1_800_000_000_000;
  const t = String(nowMs / 1000);
  const sign = (timestamp: string, key = secret, payload = body) =>
    NodeCrypto.createHmac("sha256", key).update(`${timestamp}.`).update(payload).digest("hex");
  const check = (headers: Record<string, string>, at = nowMs) =>
    checkWebhookSignature({ signature: stripe, secret, headers, body, nowMs: at });

  it("accepts t and v1 over the timestamp and body, and keys it by both and by the delivery id", () => {
    const digest = sign(t);
    assert.deepStrictEqual(check({ "x-signature": `t=${t},v1=${digest}`, "webhook-id": "evt_1" }), {
      _tag: "verified",
      replayKeys: [`signature:${t}.${digest}`, "delivery:evt_1"],
    });
  });

  it("accepts any matching v1, so a sender can sign with two secrets while rotating", () => {
    const header = `t=${t},v1=${sign(t, "old-secret")},v1=${sign(t)}`;
    assert.equal(check({ "x-signature": header })._tag, "verified");
  });

  it("refuses a timestamp outside the tolerance in either direction", () => {
    const header = { "x-signature": `t=${t},v1=${sign(t)}` };
    assert.equal(check(header, nowMs + 300_000)._tag, "verified");
    assert.equal(check(header, nowMs + 300_001)._tag, "rejected");
    assert.equal(check(header, nowMs - 300_001)._tag, "rejected");
  });

  it("refuses a body-only digest, a changed timestamp, a second t and malformed values", () => {
    const bodyOnly = hmac().digest("hex");
    const later = String(Number(t) + 1);
    for (const header of [
      `t=${t},v1=${bodyOnly}`,
      `t=${later},v1=${sign(t)}`,
      `t=${t},t=${later},v1=${sign(t)}`,
      `v1=${sign(t)}`,
      `t=${t}`,
      `t=-1,v1=${sign("-1")}`,
      `t=1.5,v1=${sign("1.5")}`,
    ]) {
      assert.equal(check({ "x-signature": header })._tag, "rejected", header);
    }
  });

  it("names the delivery id only for a body-only signature that verified", () => {
    const signature = { ...stripe, timestampToleranceSeconds: null };
    const valid = { "x-signature": hmac().digest("hex"), "webhook-id": "evt_2" };
    assert.deepStrictEqual(
      checkWebhookSignature({ signature, secret, headers: valid, body, nowMs }),
      { _tag: "verified", replayKeys: ["delivery:evt_2"] },
    );
    assert.deepStrictEqual(
      checkWebhookSignature({
        signature,
        secret: "other",
        headers: valid,
        body,
        nowMs,
      }),
      { _tag: "rejected" },
    );
  });
});
