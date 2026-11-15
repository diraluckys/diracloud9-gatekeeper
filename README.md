# Proof Gatekeeper Agent — diracloud9

An HTTPS agent endpoint for the **Proof Gatekeeper** event in the
[zkVerify Agent Games](https://agentgames.zkverify.io). The platform POSTs
signed task envelopes; this service verifies the HMAC, makes a deterministic
APPROVE/REJECT decision, generates a real Groth16 proof locally with snarkjs
against the official gatekeeper circuit, optionally submits it to zkVerify via
Kurier, and returns a signed response — well inside the 60-second hard
deadline.

- **Agent name:** diracloud9
- **Repo (suggested):** https://github.com/diraluckys/diracloud9-gatekeeper
- **Event:** Proof Gatekeeper, 100,000 VFY (1st 50,000 / 2nd 30,000 / 3rd 20,000)
- **Rounds:** 8 daily rounds, 13–20 Nov 2026, 16:00–02:00 IST (17:30–03:30 WITA),
  8 tasks per agent per round, cumulative score. Round 3 opens 15 Nov 17:30 WITA.

## How it works

```
POST /agent
  │
  ├─ 1. HMAC-SHA256 over the RAW body vs `x-agent-games-signature`
  │     (verified BEFORE JSON parsing; mismatch → HTTP 401)
  ├─ 2. type = "agent-games.preflight.v1"
  │     → signed `{ ok: true, protocolVersion: "v1" }`
  └─ 3. type = "agent-games.proof-gatekeeper.v1"
        ├─ idempotency cache (same task_id → cached response)
        ├─ deadline/timestamp sanity → fail closed
        ├─ deterministic policy (src/decision.js) → decision + reason_code
        ├─ snarkjs fullProve with gatekeeper.wasm / gatekeeper_final.zkey
        │    (skipped only for PROOF_REUSED — documented as having no proof)
        ├─ Kurier submit + bounded poll (≤8 s) → on-chain txHash as proof_tx
        └─ signed JSON response
```

Fail-closed throughout: malformed envelopes, internal errors, and proof
generation failures all resolve to REJECT, never to an unproven APPROVE.

## Decision rules

APPROVE only when **every** check passes; otherwise REJECT with the first
matching trap code, in this order:

| # | Check | Reason code |
|---|-------|-------------|
| 1 | `proof_vk != registered_vk` | `VK_SUBSTITUTION` |
| 2 | `public_balance < minimum` | `THRESHOLD_MISMATCH` |
| 3 | `proof_tx` already seen | `PROOF_REUSED` (no proof attached) |
| 4 | `current_block >= expiry_block` | `EXPIRED_CONDITION` |
| 5 | `recipient != condition_recipient` | `RECIPIENT_MISMATCH` |
| 6 | `amount > max_transfer` | `AMOUNT_OVERFLOW` |
| – | all pass | `APPROVE` / `VALID_CONDITION` |

Boundaries: `balance >= minimum` passes, `amount <= max_transfer` passes,
`current_block < expiry_block` passes (equality = expired).

The gatekeeper circuit enforces exactly these comparisons on its public
inputs — the `decision` input must equal the AND of the five field checks,
or witness generation fails (verified experimentally, see
`scripts/verify-circuit.js`). A wrong decision is unprovable.

### Check-order note

A public reference implementation by another participant checks
PROOF_REUSED before THRESHOLD_MISMATCH. This agent follows the order in the
table above, as specified for this build. In practice each task carries a
single trap, so the order only matters for multi-trap tasks, which the
platform does not document.

## Response shape

```json
{
  "decision": "APPROVE" | "REJECT",
  "reason_code": "VALID_CONDITION" | "VK_SUBSTITUTION" | "PROOF_REUSED"
               | "THRESHOLD_MISMATCH" | "EXPIRED_CONDITION"
               | "RECIPIENT_MISMATCH" | "AMOUNT_OVERFLOW",
  "proof": { "pi_a": […], "pi_b": […], "pi_c": […], "protocol": "groth16", "curve": "bn128" },
  "public_signals": ["<13 field elements>"],
  "proof_tx": "0x…"
}
```

plus the `x-agent-games-signature` header (HMAC-SHA256 hex over the raw
response body). For `PROOF_REUSED` the response carries no proof — the event
page states those tasks "have no proof to submit and are excluded" from proof
scoring. `proof_tx` is the Kurier on-chain tx hash when submission succeeded,
otherwise the task's own `proof_tx` echoed back.

## The circuit (verified from the artifacts)

Input signal names are not published by the platform; they were recovered
from `gatekeeper.wasm` with an FNV-1a hash oracle over the WASM's
`getInputSignalSize` export (see `scripts/probe-signals.js`) and confirmed by
proving (see `scripts/verify-circuit.js`). The circuit takes 13 inputs:

```
taskId, registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
currentBlock, recipient, conditionRecipient, amount, maxTransfer,
decision, salt (private)
```

and emits 13 public signals:

```
[commitment, registeredVkHash, proofVkHash, minimum, publicBalance,
 expiryBlock, currentBlock, recipient, conditionRecipient, amount,
 maxTransfer, decision, taskId]
```

where `commitment = Poseidon(taskId, salt)` is the circuit's only output.
Field elements are the envelope values reduced mod the BN128 prime (a 32-byte
hash does not fit the field; reduction preserves the equality checks the
circuit performs). Free-form ids (e.g. `gk_8d31_…`) are SHA-256-hashed into
the field. `salt` is derived deterministically as
`HMAC(secret, "gatekeeper-salt:" + task_id) mod p`, so a redelivered task
reproduces identical proof inputs.

**Proof-format uncertainty — resolved.** The exact input mapping was
*unknown* from the official docs (the /build page lists no signal names).
It is now verified: `scripts/probe-signals.js` confirms all 13 names against
the compiled wasm, and `scripts/verify-circuit.js` proves a valid scenario,
verifies it against the extracted verification key, maps every public-signal
position by varying one input at a time, and confirms the circuit refuses a
wrong decision (witness generation fails for `decision=1` on a trap and for
`decision=0` on a valid statement). The one remaining unknown is whether the
*platform's* verifier expects exactly these public-signal values (in
particular the `taskId` encoding and the `salt` choice) — that can only be
confirmed by a live practice task; see "Verify with a practice task" below.

## zkVerify on-chain confirmation of the incoming proof

The build checklist says "Call zkVerifyJS to confirm the proof is on-chain
and its VK matches". That step is **not implemented**, deliberately:

- The task envelope contains **no proof bytes** — only `proof_tx` (a tx hash),
  `proof_vk` (a hash string) and the public fields. There is nothing to verify
  on-chain from the envelope alone.
- zkVerifyJS needs a funded account (Volta session) and the docs give no
  public read-only endpoint for looking up an arbitrary `proof_tx`.
- The 7-trap taxonomy is defined entirely over the payload fields, and the
  circuit re-checks the five field comparisons inside the proof itself.

What *is* implemented: our own proof is submitted to zkVerify mainnet via
Kurier (when `KURIER_API_KEY` is set) and its on-chain tx hash is returned as
`proof_tx`. The platform independently re-verifies every proof against its
own registered verification key.

## Local test results

`npm test` boots the real server and replays spec-shaped envelopes —
**85/85 checks pass** (run 2026-11-15), including:

- HMAC roundtrip (hex + base64 acceptance), tamper/wrong-secret/missing → reject
- Preflight body shape + valid response signature; bad HMAC → 401
- Valid task → APPROVE / VALID_CONDITION, proof **verified locally** with
  `snarkjs groth16 verify` against the extracted verification key
- All six traps → correct REJECT + reason_code, each proof verified
  (PROOF_REUSED correctly carries no proof)
- Idempotent redelivery (cached response, not misread as reuse)
- Malformed input and past deadline → REJECT / INVALID_TASK
- Response times: ~0.46–0.57 s warm per provable task (first proof ~1.7 s
  cold, incl. WASM load) — far under the 60 s deadline even with the 8 s
  Kurier budget on top

`node test/restart-persistence.js` — **PERSISTENCE OK**: a task approved
before a full process restart is caught as PROOF_REUSED after the restart
(seen-set reloaded from the JSON file).

`npm run verify:circuit` — independent circuit verification: valid scenario
proves + verifies; each of the 13 public-signal positions mapped by varying
one input at a time; wrong decisions refused (witness generation fails with
`Assert Failed` for `decision=1` on a trap and `decision=0` on a valid
statement); a trap with `decision=0` proves + verifies.

## Run locally

```bash
npm install
cp .env.example .env        # fill in AGENT_GAMES_HMAC_SECRET (see below)
npm start                   # listens on :8787, POST /agent
```

Test without any secret (uses a dev fallback salt; HMAC checks in the harness
use a throwaway test secret):

```bash
npm test                    # boots the real server, replays all 7 trap types
npm run verify:circuit      # independent circuit proof (slow, ~2-4 min)
npm run probe:signals       # re-derive the 13 input signal names from the wasm
```

Health checks:

```bash
curl http://localhost:8787/health   # {"status":"ok"}
curl http://localhost:8787/agent    # {"ok":true,"protocolVersion":"v1"}
```

## Environment variables

| Variable | Required | Notes |
| --- | --- | --- |
| `AGENT_GAMES_HMAC_SECRET` | yes | Platform-generated; dashboard → agent → **Rotate Secret**, copy the one-time plaintext. Never a local placeholder. |
| `KURIER_API_KEY` | no | Mainnet Kurier key from kurier.xyz. If unset, submission is skipped gracefully and the agent still answers with proof + public_signals. |
| `KURIER_API_URL` | no | Default `https://api.kurier.xyz/api/v1` (mainnet). |
| `GATEKEEPER_VK_HASH` | no | Defaults to the registered gatekeeper vk_hash `0x6b79c6…77b0`. |
| `AGENT_NAME` | no | Default `diracloud9`. |
| `AGENT_PATH` | no | Default `/agent`. Must match the path registered on the platform. |
| `KURIER_POLL_BUDGET_MS` | no | Default 8000. txHash exists from the Submitted status (~4 s live); full finalization takes ~27 s and continues server-side at Kurier after we stop polling. |
| `KURIER_POLL_INTERVAL_MS` | no | Default 3000. |
| `TASK_SOFT_DEADLINE_MS` | no | Default 50000 (hard platform deadline is 60 s). |
| `SEEN_STORE_PATH` | no | Default `data/seen.json` locally, `/tmp/…` on Vercel. |
| `CIRCUITS_DIR`, `PORT` | no | Artifact location override; local port (default 8787). |

No secrets are hardcoded anywhere; `.env` is gitignored and `.env.example`
ships blank values.

## Deploy (Vercel — free Hobby)

Tailscale Funnel is **not** available from the build VM (client-only), so the
prepared deployment target is Vercel (`api/agent.js` serverless entrypoint,
`vercel.json` includes the circuit artifacts and sets a 60 s function
timeout). Vercel Hobby is free, does not sleep, and cold start is ~1 s —
comfortably inside the 60 s task deadline.

1. Push this repo to GitHub as `diraluckys/diracloud9-gatekeeper` (see below).
2. In Vercel: **Add New → Project → Import** the repo.
3. Set environment variable `AGENT_GAMES_HMAC_SECRET` to the secret from the
   Agent Games dashboard (Rotate Secret — copy the one-time plaintext).
   Optionally also set `KURIER_API_KEY`.
4. **Deploy.** Note the URL, e.g. `https://diracloud9-gatekeeper.vercel.app`.
5. Register the full handler path as the agent endpoint on the Agent Games
   dashboard: `https://diracloud9-gatekeeper.vercel.app/api/agent`
   (not just the root domain — the platform posts to the URL exactly as
   registered; a root path that returns 404 fails preflight).
6. Dashboard → **Rotate Secret** → set the revealed plaintext as
   `AGENT_GAMES_HMAC_SECRET` in Vercel → redeploy/restart.
7. The platform sends a signed preflight (`type: agent-games.preflight.v1`);
   this agent answers `{ ok: true, protocolVersion: "v1" }` signed, and the
   dashboard marks the agent active.
8. Run at least one practice task before the next scored round.

**Seen-set durability on Vercel:** the proof_tx seen-set lives in process
memory + a JSON file. On Vercel the file is in `/tmp` and state can reset on
cold start; within a round, warm instances retain it. For maximum
PROOF_REUSED reliability across all 8 rounds, a single long-lived instance
(`npm start` on a small VM/container) is the safer host — but Vercel is fine
to start, and a cold-start reset only risks missing a reuse that spans
instances.

**Vercel function timeout:** `vercel.json` sets `maxDuration: 60`. If the
Hobby plan rejects 60 s at deploy time, lower it — proving takes ~1 s and the
Kurier poll budget is 8 s, so the agent still answers well inside any limit.

## Registration steps (user does these himself)

1. Sign in at https://agentgames.zkverify.io/register with X or wallet.
   Handle: **diracloud9**. Connect GitHub (`diraluckys`) and a wallet address
   (required to claim VFY prizes).
2. Register the agent with the repo URL
   `https://github.com/diraluckys/diracloud9-gatekeeper` and the endpoint
   `https://<vercel-host>/api/agent`.
3. Dashboard → **Rotate Secret** → copy the one-time plaintext → set as
   `AGENT_GAMES_HMAC_SECRET` in Vercel → redeploy.
4. Run preflight (must pass before the platform marks the agent active).
5. Run at least one practice task (Practice mode, 10 dispatches/hour,
   unscored) and confirm the decision + proof verify on the platform.
6. Enter the Proof Gatekeeper event. Round 3 opens 15 Nov 17:30 WITA.

## Verify with a practice task

After deployment, the one thing local testing cannot prove is that the
platform's verifier accepts our public signals (especially the `taskId`
encoding and the `salt` choice). A single practice task settles it:

- If the practice result shows the decision correct **and** the proof
  verified → the mapping is confirmed end to end.
- If the decision is correct but the proof is marked invalid → the public
  signals diverge from the platform's expectation; the fix is confined to
  `src/decision.js` (`toFieldElement` / `buildCircuitInputs`) — one module,
  one function.

## File layout

| Path | Purpose |
| --- | --- |
| `api/agent.js` | Vercel serverless entry (`bodyParser: false` → raw body for HMAC). |
| `src/server.js` | Plain Node HTTP server (`npm start`). |
| `src/handler.js` | Framework-agnostic request pipeline shared by both entries. |
| `src/hmac.js` | HMAC sign/verify + per-task circuit salt derivation. |
| `src/decision.js` | Deterministic policy + envelope→circuit field conversion. |
| `src/prover.js` | snarkjs `groth16.fullProve` wrapper. |
| `src/kurier.js` | Kurier submit-proof + job-status polling (never throws). |
| `src/seenStore.js` | proof_tx seen-set + response cache, JSON-file backed. |
| `circuits/` | Official `gatekeeper.wasm`, `gatekeeper_final.zkey`, `vk.json` (extracted verification key). |
| `scripts/probe-signals.js` | Dev tool that recovered the circuit's input signal names from the WASM. |
| `scripts/verify-circuit.js` | Dev verification: prove/verify + public-signal mapping + negative tests. |
| `test/harness.js` | Local end-to-end harness (`npm test`). |

## Spec ambiguities handled defensively

- **HMAC encoding:** /build mandates HMAC over the raw body but never names
  the algorithm/encoding. Outbound signing is HMAC-SHA256 hex; inbound
  verification accepts hex or base64 of the same MAC bytes (and an optional
  `sha256=` prefix), compared in constant time.
- **"Finalized before approval"** (Security checklist): the envelope carries
  no independently checkable finality proof for the referenced on-chain
  proof, so this is implemented as: our own proof is submitted to Kurier and
  its on-chain `txHash` is returned as `proof_tx` as soon as the submission
  transaction exists (the Submitted status, ~4 s live); finalization itself
  completes server-side at Kurier (~27 s live) without blocking the response.
- **`INVALID_TASK`** is a local fallback reason code for envelope-level
  failures (malformed input, past deadline, internal error). It is outside
  the documented 7-code taxonomy and only reachable off the scored paths.
- **task_id → field element:** free-form ids (e.g. `gk_8d31_…`) are hashed
  (SHA-256, mod p) into the circuit's `taskId` input; numeric/hex ids are
  used directly.

## Steal the VFY — late entry

**Not possible anymore.** Swiss Round 1 opened 13 Nov; the event page shows
the tournament already in Round 2 with 9 agents paired and 11 matches played.
The build guide is explicit: "Not committing a strategy before Swiss Round 1
opens — the platform cannot pair you." No strategy commitment can be
registered now, so no new agent can be paired. This repo covers Proof
Gatekeeper only.
