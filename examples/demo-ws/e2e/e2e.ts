// E2E: drive the generated TypeScript client over `wss://` against the demo-ws server — SCRAM auth,
// typed `echo`/`add`, a `ticks` subscription, and unsubscribe. Exits non-zero on any failure.
// Usage: `node dist/e2e.js <wss-url>` (with NODE_TLS_REJECT_UNAUTHORIZED=0 for the self-signed cert).
import assert from "node:assert/strict";

import { password } from "truenas-rpc-tsclient";

import { E2eClient } from "./e2e_client";
import type { Tick } from "./e2e_types";

async function main(): Promise<void> {
  // The runtime uses the platform global `WebSocket` (Node >= 22 has it); on older Node, polyfill `ws`.
  if (typeof (globalThis as { WebSocket?: unknown }).WebSocket === "undefined") {
    // @ts-ignore -- `ws` ships no bundled types; we only need its WebSocket as the (browser-compatible) global.
    const ws = await import("ws");
    (globalThis as { WebSocket?: unknown }).WebSocket = ws.WebSocket ?? ws.default;
  }

  const url = process.env.E2E_URL ?? process.argv[2];
  if (url === undefined) {
    console.error("set E2E_URL=wss://host:port (or pass it as argv[2])");
    process.exit(2);
  }

  const client = await E2eClient.connect(url, password("e2e", "e2e-secret"));
  assert.equal(client.negotiated?.protocol, "e2e", "negotiated protocol");

  assert.equal((await client.echo({ msg: "hello" })).msg, "hello", "echo round-trip");
  assert.equal((await client.add({ a: 20, b: 22 })).sum, 42, "add result");

  // Subscribe to ticks; resolve on the first event, then unsubscribe.
  let sub: Awaited<ReturnType<typeof client.subscribe_ticks>> | undefined;
  const tick = await new Promise<Tick>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("no tick within 5s")), 5000);
    client
      .subscribe_ticks({}, (event) => {
        clearTimeout(timer);
        resolve(event);
      })
      .then((s) => {
        sub = s;
      })
      .catch(reject);
  });
  assert.ok(tick.seq >= 1, `tick seq ${tick.seq}`);
  await sub?.unsubscribe();

  console.log(`E2E OK — negotiate + SCRAM auth, echo, add=42, tick seq=${tick.seq}, unsubscribed`);
  process.exit(0);
}

main().catch((err) => {
  console.error("E2E FAILED:", err);
  process.exit(1);
});
