"use strict";
/**
 * Vercel serverless entrypoint for the diracloud9 Proof Gatekeeper agent.
 * Wraps the same AgentHandler as the long-running server (src/server.js).
 *
 * bodyParser is disabled so the raw request body survives for HMAC
 * verification (the platform signs the raw bytes).
 *
 * Route: POST /api/agent  (register https://<vercel-host>/api/agent as the
 * agent endpoint — the full handler path, not just the root domain).
 *        GET  /api/agent  -> health check { ok: true, protocolVersion: "v1" }
 */
const { loadConfig } = require("../src/config");
const { AgentHandler } = require("../src/handler");
const { SeenStore } = require("../src/seenStore");

const SIGNATURE_HEADER = "x-agent-games-signature";
const MAX_BODY_BYTES = 1048576;

let cached = null;
function getHandler() {
  if (cached) return cached;
  const cfg = loadConfig();
  // On Vercel the seen-store lives in /tmp (see src/config.js): state can
  // reset on cold start. Within a round, warm instances retain it.
  cached = new AgentHandler(cfg, new SeenStore(cfg.seenStorePath));
  return cached;
}

async function readRawBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      const err = new Error("payload_too_large");
      err.status = 413;
      throw err;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

module.exports = async (req, res) => {
  const handler = getHandler();

  if (req.method === "GET") {
    const r = handler.agentHealth();
    res.writeHead(r.status, { "content-type": "application/json" });
    res.end(r.body);
    return;
  }

  if (req.method !== "POST") {
    res.writeHead(405, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "method_not_allowed" }));
    return;
  }

  try {
    const rawBody = await readRawBody(req);
    const signature = req.headers[SIGNATURE_HEADER];
    const result = await handler.handlePost(
      rawBody,
      Array.isArray(signature) ? signature[0] : signature,
    );
    const headers = { "content-type": "application/json" };
    if (result.signature) headers[SIGNATURE_HEADER] = result.signature;
    res.writeHead(result.status, headers);
    res.end(result.body);
  } catch (err) {
    const status = err.status || 400;
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: err.status === 413 ? "payload_too_large" : "bad_request" }));
  }
};

module.exports.config = { api: { bodyParser: false } };
