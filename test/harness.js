"use strict";
/**
 * Local test harness for the diracloud9 Proof Gatekeeper agent.
 *
 * Boots the real HTTP server on an ephemeral port with a throwaway HMAC
 * secret and a temp seen-store, then replays signed envelopes built from the
 * /build + /events/proof-gatekeeper samples:
 *   - preflight handshake shape + response signature
 *   - HMAC sign/verify roundtrip (hex + base64), tamper + wrong-secret rejects
 *   - one VALID_CONDITION approve, with the returned Groth16 proof verified
 *     locally against the circuit verification key
 *   - every documented trap: VK_SUBSTITUTION, PROOF_REUSED,
 *     THRESHOLD_MISMATCH, EXPIRED_CONDITION, RECIPIENT_MISMATCH,
 *     AMOUNT_OVERFLOW (each with decision + reason_code asserted, and the
 *     proof verified where the spec requires one)
 *   - idempotent redelivery of the same task_id
 *   - Kurier key absent -> submission skipped, answer unaffected
 *
 * Run: npm test
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const TEST_SECRET = "test-secret-for-local-harness-only";
process.env.AGENT_GAMES_HMAC_SECRET = TEST_SECRET;
process.env.SEEN_STORE_PATH = path.join(
  fs.mkdtempSync(path.join(os.tmpdir(), "gk-seen-")),
  "seen.json",
);
delete process.env.KURIER_API_KEY;

const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const RECIPIENT = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
const OTHER_RECIPIENT = "0x742d35Cc6634C0532925a3b844Bc454e4438f44f";

let passed = 0;
let failed = 0;
function check(name, cond, extra) {
  if (cond) {
    passed++;
    console.log(`  ok    ${name}`);
  } else {
    failed++;
    console.log(`  FAIL  ${name}${extra ? ` — ${extra}` : ""}`);
  }
}

function tx(seed) {
  return "0x" + crypto.createHash("sha256").update(seed).digest("hex");
}

function makeTask(taskId, overrides) {
  const now = Date.now();
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "competition",
    issued_at: new Date(now).toISOString(),
    deadline_at: new Date(now + 55_000).toISOString(),
    input: {
      registered_vk: VK_HASH,
      proof_vk: VK_HASH,
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: RECIPIENT,
      condition_recipient: RECIPIENT,
      amount: "500",
      max_transfer: "1000",
      proof_tx: tx("proof-" + taskId),
      ...(overrides || {}),
    },
  };
}

async function main() {
  const { createAgentServer } = require("../src/server");
  const { signBody, verifyBodySignature } = require("../src/hmac");
  const snarkjs = require("snarkjs");
  const verificationKey = JSON.parse(
    fs.readFileSync(path.resolve(__dirname, "..", "circuits", "vk.json"), "utf8"),
  );

  const server = createAgentServer();
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;

  async function post(body, opts) {
    const o = opts || {};
    const headers = { "content-type": "application/json" };
    if (o.sign !== false) {
      headers["x-agent-games-signature"] = o.signature || signBody(o.secret || TEST_SECRET, body);
    }
    const res = await fetch(`${base}/agent`, { method: "POST", headers, body });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* keep null */ }
    return { status: res.status, json, sig: res.headers.get("x-agent-games-signature") };
  }

  console.log("== HMAC unit checks ==");
  {
    const body = JSON.stringify({ hello: "world" });
    const hexSig = signBody(TEST_SECRET, body);
    check("hex signature verifies", verifyBodySignature(TEST_SECRET, body, hexSig));
    const b64Sig = crypto.createHmac("sha256", TEST_SECRET).update(body).digest("base64");
    check("base64 signature verifies", verifyBodySignature(TEST_SECRET, body, b64Sig));
    check("prefixed signature verifies", verifyBodySignature(TEST_SECRET, body, "sha256=" + hexSig));
    check("tampered body rejected", !verifyBodySignature(TEST_SECRET, body + " ", hexSig));
    check("wrong secret rejected", !verifyBodySignature("other-secret", body, hexSig));
    check("missing header rejected", !verifyBodySignature(TEST_SECRET, body, undefined));
  }

  console.log("== Preflight ==");
  {
    const body = JSON.stringify({
      type: "agent-games.preflight.v1",
      agent_id: "agt_test",
      issued_at: new Date().toISOString(),
      nonce: "abc123",
    });
    const r = await post(body);
    check("preflight status 200", r.status === 200, `got ${r.status}`);
    check("preflight body shape", r.json && r.json.ok === true && r.json.protocolVersion === "v1", JSON.stringify(r.json));
    check(
      "preflight response signed",
      r.sig !== null && verifyBodySignature(TEST_SECRET, JSON.stringify(r.json), r.sig),
    );
    const bad = await post(body, { secret: "wrong-secret" });
    check("preflight with bad HMAC -> 401", bad.status === 401, `got ${bad.status}`);
  }

  console.log("== Health ==");
  {
    const res = await fetch(`${base}/agent`);
    const json = await res.json();
    check("GET /agent health", res.status === 200 && json.ok === true && json.protocolVersion === "v1");
    const res2 = await fetch(`${base}/health`);
    const json2 = await res2.json();
    check("GET /health -> {status:ok}", res2.status === 200 && json2.status === "ok");
  }

  async function expectTask(label, task, decision, reason, withProof) {
    const t0 = Date.now();
    const r = await post(JSON.stringify(task));
    const elapsed = Date.now() - t0;
    check(`${label}: status 200`, r.status === 200, `got ${r.status}`);
    check(`${label}: decision ${decision}`, r.json && r.json.decision === decision, JSON.stringify(r.json));
    check(`${label}: reason ${reason}`, r.json && r.json.reason_code === reason, JSON.stringify(r.json));
    check(
      `${label}: response signed`,
      r.sig !== null && verifyBodySignature(TEST_SECRET, JSON.stringify(r.json), r.sig),
    );
    check(`${label}: answered in ${elapsed}ms (< 60s deadline)`, elapsed < 60_000);
    if (withProof) {
      check(`${label}: proof present`, !!(r.json && r.json.proof) && Array.isArray(r.json.public_signals));
      check(
        `${label}: 13 public signals`,
        Array.isArray(r.json && r.json.public_signals) && r.json.public_signals.length === 13,
        `got ${r.json && r.json.public_signals && r.json.public_signals.length}`,
      );
      if (r.json && r.json.proof && r.json.public_signals) {
        const ok = await snarkjs.groth16.verify(verificationKey, r.json.public_signals, r.json.proof);
        check(`${label}: proof verifies locally against circuit VK`, ok === true);
        const expectedDecisionSignal = decision === "APPROVE" ? "1" : "0";
        check(
          `${label}: decision signal = ${expectedDecisionSignal}`,
          r.json.public_signals[11] === expectedDecisionSignal,
          `got ${r.json.public_signals[11]}`,
        );
      }
    } else {
      check(`${label}: no proof attached (documented for PROOF_REUSED)`, !(r.json && r.json.proof));
    }
    return r.json;
  }

  console.log("== Valid condition ==");
  const validTask = makeTask("gk_test_valid");
  await expectTask("valid", validTask, "APPROVE", "VALID_CONDITION", true);

  console.log("== Idempotent redelivery ==");
  {
    const r = await post(JSON.stringify(validTask));
    check("redelivery still APPROVE (not PROOF_REUSED)", r.json && r.json.decision === "APPROVE" && r.json.reason_code === "VALID_CONDITION", JSON.stringify(r.json));
  }

  console.log("== Traps ==");
  await expectTask(
    "vk-substitution",
    makeTask("gk_test_vk", { proof_vk: "0x13ab00000000000000000000000000000000000000000000000000000000aa" }),
    "REJECT", "VK_SUBSTITUTION", true,
  );

  const reusedTx = tx("proof-gk_test_reuse_source");
  await expectTask("reuse-source", makeTask("gk_test_reuse_source", { proof_tx: reusedTx }), "APPROVE", "VALID_CONDITION", true);
  await expectTask(
    "proof-reused",
    makeTask("gk_test_reuse", { proof_tx: reusedTx }),
    "REJECT", "PROOF_REUSED", false,
  );

  await expectTask(
    "threshold-mismatch",
    makeTask("gk_test_threshold", { public_balance: "999" }),
    "REJECT", "THRESHOLD_MISMATCH", true,
  );
  await expectTask(
    "expired-condition",
    makeTask("gk_test_expired", { current_block: 8430000 }),
    "REJECT", "EXPIRED_CONDITION", true,
  );
  await expectTask(
    "recipient-mismatch",
    makeTask("gk_test_recipient", { recipient: OTHER_RECIPIENT }),
    "REJECT", "RECIPIENT_MISMATCH", true,
  );
  await expectTask(
    "amount-overflow",
    makeTask("gk_test_amount", { amount: "1001" }),
    "REJECT", "AMOUNT_OVERFLOW", true,
  );

  console.log("== Fail-closed behaviour ==");
  {
    const r = await post(JSON.stringify(makeTask("gk_test_tampered")), { sign: false, signature: "deadbeef" });
    check("bad signature -> 401", r.status === 401, `got ${r.status}`);
    const malformed = await post(JSON.stringify({ type: "agent-games.proof-gatekeeper.v1", task_id: "gk_test_bad", input: { minimum: "x" } }));
    check("malformed input -> REJECT/INVALID_TASK", malformed.json && malformed.json.decision === "REJECT" && malformed.json.reason_code === "INVALID_TASK", JSON.stringify(malformed.json));
    const pastDeadline = makeTask("gk_test_late");
    pastDeadline.deadline_at = new Date(Date.now() - 1000).toISOString();
    const late = await post(JSON.stringify(pastDeadline));
    check("past deadline -> REJECT/INVALID_TASK", late.json && late.json.decision === "REJECT" && late.json.reason_code === "INVALID_TASK", JSON.stringify(late.json));
  }

  server.close();
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error("harness crashed:", err);
  process.exit(1);
});
