// Dev verification: prove a valid scenario, map public-signal positions by
// varying one input at a time, and confirm the circuit refuses wrong
// decisions (decision=1 on a trap, decision=0 on a valid statement).
// Logs each step to verify-circuit.log (unbuffered) as well as stdout.
// Run: node scripts/verify-circuit.js
const crypto = require("crypto");
const fs = require("fs");
const snarkjs = require("snarkjs");
const path = require("path");

const LOG = path.resolve(__dirname, "verify-circuit.log");
function logLine(s) {
  fs.appendFileSync(LOG, s + "\n");
  console.log(s);
}

const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const WASM = path.resolve(__dirname, "..", "circuits", "gatekeeper.wasm");
const ZKEY = path.resolve(__dirname, "..", "circuits", "gatekeeper_final.zkey");
const VK = path.resolve(__dirname, "..", "circuits", "vk.json");

const REG_VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const ADDR = "0xDe42f1a2b3c4d5e6f708192a3b4c5d6e7f809f01";

function toField(v) {
  let n;
  if (typeof v === "bigint") n = v;
  else if (/^0x[0-9a-fA-F]+$/.test(v.trim())) n = BigInt(v.trim());
  else if (/^[0-9]+$/.test(v.trim())) n = BigInt(v.trim());
  else n = BigInt("0x" + crypto.createHash("sha256").update(v).digest("hex"));
  return (((n % BN128_PRIME) + BN128_PRIME) % BN128_PRIME).toString(10);
}

function baseInputs(overrides) {
  return {
    taskId: toField("gk_24_9d1"),
    registeredVkHash: toField(REG_VK),
    proofVkHash: toField(REG_VK),
    minimum: "1000",
    publicBalance: "1460",
    expiryBlock: "8430000",
    currentBlock: "8420000",
    recipient: toField(ADDR),
    conditionRecipient: toField(ADDR),
    amount: "500",
    maxTransfer: "1000",
    decision: "1",
    salt: "12345",
    ...(overrides || {}),
  };
}

async function proveAndVerify(inputs, label) {
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, WASM, ZKEY);
  const ms = Date.now() - t0;
  const vk = JSON.parse(fs.readFileSync(VK, "utf8"));
  const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
  logLine(`${label}: prove+verify ${ok ? "OK" : "FAIL"} in ${ms}ms, publicSignals=${publicSignals.length}`);
  return { proof, publicSignals, ok, ms };
}

(async () => {
  fs.writeFileSync(LOG, `verify-circuit run ${new Date().toISOString()}\n`);
  logLine("step 1: valid decision=1");
  const valid = await proveAndVerify(baseInputs(), "valid decision=1");
  logLine("  publicSignals: " + JSON.stringify(valid.publicSignals));

  const ref = valid.publicSignals;
  const probes = [
    ["taskId", { taskId: toField("gk_24_9d2") }],
    ["registeredVkHash+proofVkHash", { registeredVkHash: toField("0x1111111111111111111111111111111111111111111111111111111111111111"), proofVkHash: toField("0x1111111111111111111111111111111111111111111111111111111111111111") }],
    ["minimum", { minimum: "999" }],
    ["publicBalance", { publicBalance: "1461" }],
    ["expiryBlock", { expiryBlock: "8430001" }],
    ["currentBlock", { currentBlock: "8420001" }],
    ["recipient+conditionRecipient", { recipient: toField("0xDe42f1a2b3c4d5e6f708192a3b4c5d6e7f809f02"), conditionRecipient: toField("0xDe42f1a2b3c4d5e6f708192a3b4c5d6e7f809f02") }],
    ["amount", { amount: "501" }],
    ["maxTransfer", { maxTransfer: "1001" }],
    ["salt", { salt: "54321" }],
  ];
  for (const [name, over] of probes) {
    logLine(`step probe: vary ${name}`);
    const r = await proveAndVerify(baseInputs(over), `vary ${name}`);
    const changed = r.publicSignals.map((s, i) => (s !== ref[i] ? i : -1)).filter((i) => i >= 0);
    logLine(`  -> ${name} changes publicSignals[${changed.join(",")}]`);
  }

  logLine("step negative: trap + decision=1 (must fail)");
  try {
    await snarkjs.groth16.fullProve(
      baseInputs({ proofVkHash: toField("0xa4c1b8ff00000000000000000000000000000000000000000000000000000000") }),
      WASM, ZKEY);
    logLine("NEGATIVE trap+decision=1: UNEXPECTEDLY PROVED (circuit does NOT enforce!)");
  } catch (e) {
    logLine("NEGATIVE trap+decision=1: correctly failed: " + String(e.message).slice(0, 120));
  }

  logLine("step negative: valid + decision=0 (must fail)");
  try {
    await snarkjs.groth16.fullProve(baseInputs({ decision: "0" }), WASM, ZKEY);
    logLine("NEGATIVE valid+decision=0: UNEXPECTEDLY PROVED (circuit does NOT enforce!)");
  } catch (e) {
    logLine("NEGATIVE valid+decision=0: correctly failed: " + String(e.message).slice(0, 120));
  }

  logLine("step: trap(VK mismatch) + decision=0 (must prove + verify)");
  const trap = await proveAndVerify(
    baseInputs({ proofVkHash: toField("0xa4c1b8ff00000000000000000000000000000000000000000000000000000000"), decision: "0" }),
    "trap(VK mismatch) decision=0");
  logLine("  trap publicSignals[11] (decision) = " + trap.publicSignals[11]);
  logLine("ALL DONE");
  // snarkjs leaves worker threads behind; exit explicitly.
  process.exit(0);
})();
