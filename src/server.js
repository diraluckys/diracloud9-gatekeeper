"use strict";
/**
 * Plain Node HTTP server for local runs and non-serverless hosting.
 * Routes:
 *   POST <AGENT_PATH> (default /agent) — the registered agent endpoint (tasks + preflight)
 *   GET  <AGENT_PATH>                  — health check { ok: true, protocolVersion: "v1" }
 *   GET  / and GET /health             — health check { status: "ok" }
 *
 * TLS is terminated by the host (reverse proxy / platform); this server
 * listens on localhost only by default.
 */
const http = require("http");
const { loadConfig } = require("./config");
const { AgentHandler } = require("./handler");
const { SeenStore } = require("./seenStore");

const SIGNATURE_HEADER = "x-agent-games-signature";
const MAX_BODY_BYTES = 1048576;

function createAgentServer(cfg, handler) {
  const config = cfg || loadConfig();
  const agentHandler = handler || new AgentHandler(config, new SeenStore(config.seenStorePath));

  return http.createServer((req, res) => {
    const url = new URL(req.url || "/", "http://localhost");
    const agentPath = config.agentPath;
    const isAgentPath = url.pathname === agentPath;
    const isRootOrHealth = url.pathname === "/" || url.pathname === "/health";

    if (req.method === "GET" && isAgentPath) {
      const r = agentHandler.agentHealth();
      res.writeHead(r.status, { "content-type": "application/json" });
      res.end(r.body);
      return;
    }

    if (req.method === "GET" && isRootOrHealth) {
      const r = agentHandler.health();
      res.writeHead(r.status, { "content-type": "application/json" });
      res.end(r.body);
      return;
    }

    if (req.method === "POST" && isAgentPath) {
      const chunks = [];
      let size = 0;
      let tooLarge = false;
      req.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          tooLarge = true;
          res.writeHead(413, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "payload_too_large" }));
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      req.on("end", async () => {
        if (tooLarge) return;
        const rawBody = Buffer.concat(chunks);
        const signature = req.headers[SIGNATURE_HEADER];
        const result = await agentHandler.handlePost(
          rawBody,
          Array.isArray(signature) ? signature[0] : signature,
        );
        const headers = { "content-type": "application/json" };
        if (result.signature) headers[SIGNATURE_HEADER] = result.signature;
        res.writeHead(result.status, headers);
        res.end(result.body);
      });
      req.on("error", () => {
        if (!res.headersSent) res.writeHead(400);
        res.end();
      });
      return;
    }

    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not_found" }));
  });
}

if (require.main === module) {
  const cfg = loadConfig();
  const server = createAgentServer(cfg);
  server.listen(cfg.port, () => {
    console.log(JSON.stringify({
      level: "info",
      msg: "diracloud9 Proof Gatekeeper listening",
      port: cfg.port,
      agentPath: cfg.agentPath,
      hmacConfigured: Boolean(cfg.hmacSecret),
      kurierConfigured: Boolean(cfg.kurierApiKey),
    }));
    if (!cfg.hmacSecret) {
      console.warn(JSON.stringify({
        level: "warn",
        msg: "AGENT_GAMES_HMAC_SECRET is not set — POSTs will fail with 500 until it is.",
      }));
    }
  });
}

module.exports = { createAgentServer };
