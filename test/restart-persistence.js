// Restart-persistence check: sends a valid task, restarts the server
// (new process), then sends a DIFFERENT task_id reusing the same proof_tx.
// The second task must be PROOF_REUSED, proving the seen-set survives restarts.
// Usage: node test/restart-persistence.js  (server must NOT already run on 8931)
const crypto = require("crypto");
const { spawn } = require("child_process");
const path = require("path");

const SECRET = "test-persist-secret";
const SEEN = "/tmp/persist-test/seen.json";
const PORT = 8931;
const TX = "0x" + crypto.createHash("sha256").update("persist-proof-1").digest("hex");

function makeTask(taskId) {
  const now = Date.now();
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "competition",
    issued_at: new Date(now).toISOString(),
    deadline_at: new Date(now + 55000).toISOString(),
    input: {
      registered_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
      proof_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
      condition_recipient: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
      amount: "500",
      max_transfer: "1000",
      proof_tx: TX,
    },
  };
}

async function post(task) {
  const body = JSON.stringify(task);
  const sig = crypto.createHmac("sha256", SECRET).update(body).digest("hex");
  const res = await fetch(`http://127.0.0.1:${PORT}/agent`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": sig },
    body,
  });
  return res.json();
}

function startServer() {
  return new Promise((resolve, reject) => {
    const child = spawn("node", [path.resolve(__dirname, "..", "src", "server.js")], {
      env: { ...process.env, AGENT_GAMES_HMAC_SECRET: SECRET, SEEN_STORE_PATH: SEEN, PORT: String(PORT) },
      stdio: "ignore",
    });
    child.on("error", reject);
    setTimeout(() => resolve(child), 1500);
  });
}

function stopServer(child) {
  return new Promise((resolve) => {
    child.on("exit", resolve);
    child.kill("SIGTERM");
    setTimeout(resolve, 2000);
  });
}

(async () => {
  const fs = require("fs");
  try { fs.unlinkSync(SEEN); } catch { /* fresh start */ }

  const s1 = await startServer();
  const r1 = await post(makeTask("gk_persist_1"));
  console.log("before restart:", r1.decision, r1.reason_code);
  await stopServer(s1);

  const s2 = await startServer();
  const r2 = await post(makeTask("gk_persist_2"));
  console.log("after restart, same proof_tx:", r2.decision, r2.reason_code);
  await stopServer(s2);

  const ok = r1.decision === "APPROVE" && r2.decision === "REJECT" && r2.reason_code === "PROOF_REUSED";
  console.log(ok ? "PERSISTENCE OK" : "PERSISTENCE FAILED");
  process.exit(ok ? 0 : 1);
})();
