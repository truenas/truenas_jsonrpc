// Verifies the runtime's unbound SCRAM-SHA-512 client (built in WebCrypto) against an INDEPENDENT
// server-side computation (node:crypto) and the TrueNAS PBKDF2 known-answer vector — so a verifier
// minted by the reference server/C library authenticates this client. Run: `npm test` (builds first)
// or `node --test test/` after `tsc`.
import test from "node:test";
import assert from "node:assert/strict";
import nc from "node:crypto";

import { password } from "../dist/index.js";

// --- server side (independent primitives) ----------------------------------------------------
const pbkdf2 = (pw, salt, iters) => nc.pbkdf2Sync(pw, salt, iters, 64, "sha512");
const hmac = (key, data) => nc.createHmac("sha512", key).update(data).digest();
const sha512 = (data) => nc.createHash("sha512").update(data).digest();
const xor = (a, b) => { const o = Buffer.alloc(a.length); for (let i = 0; i < a.length; i++) o[i] = a[i] ^ b[i]; return o; };

test("PBKDF2-HMAC-SHA512 (WebCrypto) matches the TrueNAS known-answer vector", async () => {
  const salt = new TextEncoder().encode("KCwXnX9l35e0ndOu");
  const key = new TextEncoder().encode("DJpfT7q7dHu6RRfeMwP8aJlGeUOmRWbDKnnzxnsc8F1YAsDNbl8aDM4X1cYwPmcC");
  const expected = Buffer.from(
    "sljMczeiN9kEqyOIrjoQ1QiBhnrmL++DtRdeyv+DHmQkkzoypbkzHIVA1iM/NVviC50dVpDKKlD3L2pv9KDdfw==",
    "base64",
  );
  const k = await crypto.subtle.importKey("raw", key, "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-512", salt, iterations: 500_000 }, k, 512);
  assert.deepEqual(Buffer.from(bits), expected, "WebCrypto PBKDF2 must equal the C library's");
});

test("unbound SCRAM round-trips against an independent server (proof + mutual auth)", async () => {
  const secret = "hunter2";
  const cred = password("alice", secret);

  // client-first: "n,,n=alice,r=<cnonce>"
  const first = await cred.first();
  assert.equal(first.mechanism, "SCRAM");
  assert.ok(first.message.startsWith("n,,n=alice,r="), first.message);
  const bare = first.message.slice(3); // "n=alice,r=<cnonce>"
  const cnonce = bare.split(",").find((t) => t.startsWith("r=")).slice(2);

  // server-first (structure of `r=` is opaque to the crypto; mirror the reference unit test).
  const salt = nc.randomBytes(16);
  const iters = 4096;
  const combined = `${cnonce}srv`;
  const serverFirst = `r=${combined},s=${salt.toString("base64")},i=${iters}`;

  // client-final: "c=biws,r=<combined>,p=<proof>"
  const final = await cred.respond({ mechanism: "SCRAM", message: serverFirst });
  const withoutProof = `c=biws,r=${combined}`;
  assert.ok(final.message.startsWith(`${withoutProof},p=`), final.message);
  const proof = Buffer.from(final.message.split(",p=")[1], "base64");

  // server verifies the proof: recover ClientKey and check H(ClientKey) == StoredKey.
  const salted = pbkdf2(Buffer.from(secret), salt, iters);
  const clientKey = hmac(salted, "Client Key");
  const storedKey = sha512(clientKey);
  const serverKey = hmac(salted, "Server Key");
  const authMessage = `${bare},${serverFirst},${withoutProof}`;
  const clientSig = hmac(storedKey, authMessage);
  const recovered = xor(proof, clientSig);
  assert.deepEqual(sha512(recovered), storedKey, "client proof must verify server-side");

  // server-final `v=`: the client must accept the right one and reject a wrong one (mutual auth).
  const serverFinal = `v=${hmac(serverKey, authMessage).toString("base64")}`;
  await assert.doesNotReject(cred.verify({ scram: serverFinal }));
  await assert.rejects(cred.verify({ scram: "v=not-the-right-signature" }));
});

test("username SASL-escaping (= then ,) appears in client-first", async () => {
  const first = await password("a,b=c", "x").first();
  assert.ok(first.message.includes("n=a=2Cb=3Dc"), first.message);
});
