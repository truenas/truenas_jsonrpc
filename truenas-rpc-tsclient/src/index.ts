/**
 * `truenas-rpc-tsclient` — a tiny browser/WebSocket runtime for the generated TrueNAS RPC
 * TypeScript clients (the TS analog of `truenas-rpc-pyclient`). A generated `<Proto>Client`
 * holds an {@link RpcConnection} and calls `.call(method, params)`; this module owns the wire
 * (JSON-RPC 2.0 over a WebSocket, one frame per message — no length prefix), plus
 * **subscriptions** (server->client notifications) and **session authentication**
 * (`$/sessionSetup`: OAuth / bearer tokens, and username/password via unbound SCRAM-SHA-512).
 *
 * Zero dependencies: it uses only the platform `WebSocket`, `JSON`, and `crypto`
 * (`randomUUID` / `getRandomValues` / `subtle`). Auth requires a confidential channel (`wss://`).
 */

/** A byte buffer backed by a plain `ArrayBuffer` (what WebCrypto's `BufferSource` requires). */
type Bytes = Uint8Array<ArrayBuffer>;

/** A server-returned JSON-RPC error, or a local transport failure. */
export class JsonRpcError extends Error {
  readonly code: number;
  readonly data: unknown;

  constructor(code: number, message: string, data?: unknown) {
    super(message);
    this.name = "JsonRpcError";
    this.code = code;
    this.data = data;
  }
}

/** The `$/negotiate` result: the matched protocol, an optional server id, and what the server offers. */
export interface Negotiated {
  protocol: string;
  server: string | null;
  available: string[];
}

/** A live subscription: its server-assigned id, and a way to tear it down. */
export interface Subscription {
  readonly id: string;
  unsubscribe(): Promise<void>;
}

/** The outcome of a `$/sessionSetup` attempt (mirrors the server's `AuthResponse`). */
export type AuthOutcome =
  | { readonly kind: "established"; readonly sessionId: string; readonly userInfo: unknown }
  | { readonly kind: "otpRequired"; readonly username: string }
  | { readonly kind: "denied" }
  | { readonly kind: "authErr" }
  | { readonly kind: "expired" };

/**
 * A client auth mechanism driven over `$/sessionSetup` (+ `$/sessionSetupContinue`): `first` produces
 * the initial mechanism object, `respond` answers each server `CHALLENGE`, and `verify` checks the
 * server's final payload on `SUCCESS` (mutual auth). Build one with {@link oauth} / {@link bearerToken}
 * / {@link password}.
 */
export interface Credential {
  first(): Promise<unknown>;
  respond(challenge: unknown): Promise<unknown>;
  verify(extra: unknown): Promise<void>;
}

interface Pending {
  resolve: (value: unknown) => void;
  reject: (reason: unknown) => void;
}

/**
 * A JSON-RPC 2.0 connection over a WebSocket. The server's `websocket` transport carries one
 * JSON-RPC frame per WebSocket message, so requests/replies are plain `JSON.stringify`/`parse` —
 * replies correlated by a per-call UUID `id`, notifications routed by topic (the `method` field).
 */
export class RpcConnection {
  readonly #ws: WebSocket;
  readonly #pending = new Map<string, Pending>();
  // topic -> (subscription id -> handler); plus the reverse, for unsubscribe teardown.
  readonly #byTopic = new Map<string, Map<string, (params: unknown) => void>>();
  readonly #topicOf = new Map<string, string>();
  #negotiated: Negotiated | null = null;

  private constructor(ws: WebSocket) {
    this.#ws = ws;
    this.#ws.onmessage = (ev: MessageEvent) => this.#onMessage(ev.data);
    this.#ws.onclose = () => this.#failAll(new JsonRpcError(-32000, "connection closed"));
    this.#ws.onerror = () => this.#failAll(new JsonRpcError(-32000, "connection error"));
  }

  /** Open a WebSocket to `url`, `$/negotiate` `protocol`, and return the ready connection. */
  static async connect(url: string, protocol: string): Promise<RpcConnection> {
    const ws = await openSocket(url);
    const conn = new RpcConnection(ws);
    conn.#negotiated = (await conn.call("$/negotiate", { protocol })) as Negotiated;
    return conn;
  }

  /** The `$/negotiate` result, or `null` if this connection was built without negotiating. */
  get negotiated(): Negotiated | null {
    return this.#negotiated;
  }

  /** The protocol names the server offered at `$/negotiate` (discovery), or `null`. */
  get available(): string[] | null {
    return this.#negotiated === null ? null : this.#negotiated.available;
  }

  /** Send a JSON-RPC request and resolve the id-correlated reply (rejects with {@link JsonRpcError}). */
  call(method: string, params: unknown): Promise<unknown> {
    const id = crypto.randomUUID();
    const frame = JSON.stringify({ jsonrpc: "2.0", method, id, params });
    return new Promise<unknown>((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      try {
        this.#ws.send(frame);
      } catch (err) {
        this.#pending.delete(id);
        reject(err);
      }
    });
  }

  /**
   * Drive `credential` to completion over `$/sessionSetup` (+ `$/sessionSetupContinue`): send its
   * first message, answer each `CHALLENGE`, and on `SUCCESS` let it verify the server's final payload
   * (mutual auth). Returns the {@link AuthOutcome}. Auth requires a confidential channel (`wss://`).
   */
  async authenticate(credential: Credential): Promise<AuthOutcome> {
    const first = await credential.first();
    let result = await this.call("$/sessionSetup", { mechanism: first });
    for (;;) {
      const response = asAuthResponse(result);
      switch (response.response_type) {
        case "SUCCESS":
          await credential.verify(response.extra ?? null);
          return {
            kind: "established",
            sessionId: String(response.session_id),
            userInfo: response.user_info ?? null,
          };
        case "CHALLENGE": {
          const next = await credential.respond(response);
          result = await this.call("$/sessionSetupContinue", { mechanism: next });
          break;
        }
        case "OTP_REQUIRED":
          return { kind: "otpRequired", username: String(response.username) };
        case "DENIED":
          return { kind: "denied" };
        case "AUTH_ERR":
          return { kind: "authErr" };
        case "EXPIRED":
          return { kind: "expired" };
        default:
          throw new JsonRpcError(
            -32000,
            `unexpected $/sessionSetup response: ${String(response.response_type)}`,
          );
      }
    }
  }

  /**
   * Subscribe to `topic` (a `server_client` method's wire name) with `params`; `handler` is called
   * with each notification payload. Returns a {@link Subscription} whose `unsubscribe()` cancels it.
   */
  async subscribe(
    topic: string,
    params: unknown,
    handler: (params: unknown) => void,
  ): Promise<Subscription> {
    const id = String(await this.call(topic, params));
    let handlers = this.#byTopic.get(topic);
    if (handlers === undefined) {
      handlers = new Map();
      this.#byTopic.set(topic, handlers);
    }
    handlers.set(id, handler);
    this.#topicOf.set(id, topic);
    return { id, unsubscribe: () => this.#unsubscribe(id) };
  }

  /** Close the underlying socket, failing any in-flight calls and dropping subscriptions. */
  close(): void {
    this.#ws.close();
  }

  async #unsubscribe(id: string): Promise<void> {
    const topic = this.#topicOf.get(id);
    if (topic !== undefined) {
      this.#topicOf.delete(id);
      const handlers = this.#byTopic.get(topic);
      if (handlers !== undefined) {
        handlers.delete(id);
        if (handlers.size === 0) this.#byTopic.delete(topic);
      }
    }
    await this.call("$/cancelRequest", { target_id: id });
  }

  #onMessage(data: unknown): void {
    let msg: {
      id?: unknown;
      method?: unknown;
      params?: unknown;
      result?: unknown;
      error?: { code?: number; message?: string; data?: unknown };
    };
    try {
      msg = JSON.parse(typeof data === "string" ? data : String(data));
    } catch {
      return; // ignore unparseable frames
    }
    const id = msg.id;
    if (typeof id === "string") {
      const pending = this.#pending.get(id);
      if (pending === undefined) return;
      this.#pending.delete(id);
      if (msg.error) {
        pending.reject(new JsonRpcError(msg.error.code ?? -32000, msg.error.message ?? "error", msg.error.data));
      } else {
        pending.resolve(msg.result);
      }
      return;
    }
    // A server->client notification ({method, params}, no id): fan out to the topic's handlers.
    if (typeof msg.method === "string") {
      const handlers = this.#byTopic.get(msg.method);
      if (handlers !== undefined) {
        for (const handler of handlers.values()) {
          try {
            handler(msg.params);
          } catch {
            // a subscriber handler error must not break the read loop
          }
        }
      }
    }
  }

  #failAll(reason: unknown): void {
    for (const pending of this.#pending.values()) pending.reject(reason);
    this.#pending.clear();
    this.#byTopic.clear();
    this.#topicOf.clear();
  }
}

// --- credentials -----------------------------------------------------------------------------

/** OAuth/OIDC: present a validated ID token (a JWT); the server verifies it offline. Single-shot. */
export function oauth(idToken: string): Credential {
  return singleShot({ mechanism: "OAUTH", token: idToken });
}

/** A single-use bearer token minted by an external SPNEGO edge (Kerberos SSO). Single-shot. */
export function bearerToken(token: string): Credential {
  return singleShot({ mechanism: "GSSAPI_BEARER_TOKEN", token });
}

/** Username/password via unbound SCRAM-SHA-512 (computed in WebCrypto). Requires `wss://`. */
export function password(username: string, secret: string): Credential {
  return new ScramCredential(username, secret);
}

/** A single-shot mechanism: send `mechanism` once; a server challenge is a protocol error. */
function singleShot(mechanism: Record<string, unknown>): Credential {
  return {
    first: () => Promise.resolve(mechanism),
    respond: () => Promise.reject(new JsonRpcError(-32000, "this mechanism does not support a challenge")),
    verify: () => Promise.resolve(),
  };
}

/** The GS2 header for UNBOUND SCRAM (`n` = the client declares no channel binding, no authzid). */
const GS2 = "n,,";

/**
 * SCRAM-SHA-512 (unbound) client mechanism. Mirrors the reference `truenas-rpc-client` SCRAM, but
 * declares `n,,` (no channel binding) so it runs from a browser, where the TLS `tls-server-end-point`
 * value is not reachable from JS. Two rounds: client-first -> server-first, client-final -> success.
 */
class ScramCredential implements Credential {
  readonly #username: string;
  readonly #password: Bytes;
  readonly #nonce: string;
  #expectedServerFinal: string | null = null;

  constructor(username: string, secret: string) {
    this.#username = scramEscape(username);
    this.#password = encode(secret);
    const nonce = new Uint8Array(32);
    crypto.getRandomValues(nonce);
    this.#nonce = b64encode(nonce);
  }

  first(): Promise<unknown> {
    // client-first = GS2 header + client-first-bare.
    return Promise.resolve({ mechanism: "SCRAM", message: `${GS2}n=${this.#username},r=${this.#nonce}` });
  }

  async respond(challenge: unknown): Promise<unknown> {
    const serverFirst = (challenge as { message?: unknown }).message;
    if (typeof serverFirst !== "string") {
      throw new JsonRpcError(-32000, "SCRAM challenge missing the server-first message");
    }
    const { combined, saltB64, iterations } = parseServerFirst(serverFirst);
    const salt = b64decode(saltB64);

    // c= is base64(GS2 header); no channel-binding bytes are appended (unbound) -> "biws".
    const cbind = b64encode(encode(GS2));
    const bare = `n=${this.#username},r=${this.#nonce}`;
    const withoutProof = `c=${cbind},r=${combined}`;
    const authMessage = encode(`${bare},${serverFirst},${withoutProof}`);

    const salted = await pbkdf2Sha512(this.#password, salt, iterations);
    const clientKey = await hmacSha512(salted, encode("Client Key"));
    const storedKey = await sha512(clientKey);
    const clientSig = await hmacSha512(storedKey, authMessage);
    const proof = xor(clientKey, clientSig);

    // Precompute the server's expected mutual-auth signature (v=).
    const serverKey = await hmacSha512(salted, encode("Server Key"));
    const serverSig = await hmacSha512(serverKey, authMessage);
    this.#expectedServerFinal = `v=${b64encode(serverSig)}`;

    return { mechanism: "SCRAM", message: `${withoutProof},p=${b64encode(proof)}` };
  }

  verify(extra: unknown): Promise<void> {
    const got = (extra as { scram?: unknown } | null)?.scram;
    const expected = this.#expectedServerFinal;
    if (typeof got !== "string" || expected === null || got !== expected) {
      return Promise.reject(new JsonRpcError(-32000, "SCRAM server signature mismatch (mutual auth failed)"));
    }
    return Promise.resolve();
  }
}

/** Parse a SCRAM server-first message into `{combined-nonce, salt-b64, iterations}`. */
function parseServerFirst(msg: string): { combined: string; saltB64: string; iterations: number } {
  let combined: string | undefined;
  let saltB64: string | undefined;
  let iterations: number | undefined;
  for (const tok of msg.split(",")) {
    if (tok.startsWith("r=")) combined = tok.slice(2);
    else if (tok.startsWith("s=")) saltB64 = tok.slice(2);
    else if (tok.startsWith("i=")) {
      const n = Number.parseInt(tok.slice(2), 10);
      if (Number.isInteger(n)) iterations = n;
    }
  }
  if (combined === undefined || saltB64 === undefined || iterations === undefined || iterations <= 0) {
    throw new JsonRpcError(-32000, `malformed SCRAM server-first: ${msg}`);
  }
  return { combined, saltB64, iterations };
}

/** RFC 5802 SASLprep-lite: escape `=`->`=3D` then `,`->`=2C` (order matters). */
function scramEscape(username: string): string {
  return username.replace(/=/g, "=3D").replace(/,/g, "=2C");
}

// --- WebCrypto primitives (mirror truenas-rpc-auth/scram/crypto.rs) ---------------------------

/** UTF-8 encode to an `ArrayBuffer`-backed byte array (the copy pins the backing store). */
function encode(s: string): Bytes {
  return new Uint8Array(new TextEncoder().encode(s));
}

/** `Hi(key, salt, i)` = PBKDF2-HMAC-SHA512 -> the 64-byte SaltedPassword. */
async function pbkdf2Sha512(pw: Bytes, salt: Bytes, iterations: number): Promise<Bytes> {
  const key = await crypto.subtle.importKey("raw", pw, "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-512", salt, iterations }, key, 512);
  return new Uint8Array(bits);
}

/** `HMAC-SHA512(key, data)` -> 64 bytes. */
async function hmacSha512(key: Bytes, data: Bytes): Promise<Bytes> {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-512" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}

/** `H(data)` = SHA-512 -> 64 bytes. */
async function sha512(data: Bytes): Promise<Bytes> {
  return new Uint8Array(await crypto.subtle.digest("SHA-512", data));
}

/** `a XOR b` (equal-length byte arrays). */
function xor(a: Bytes, b: Bytes): Bytes {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

// Binary-safe base64 (browser `btoa`/`atob`, also global in Node >= 16); inputs here are <= 96 bytes.
function b64encode(bytes: Bytes): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function b64decode(s: string): Bytes {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Interpret a `$/sessionSetup` result's `{ response: ... }` envelope. */
function asAuthResponse(result: unknown): { response_type: string; [key: string]: unknown } {
  const response = (result as { response?: unknown } | null)?.response;
  if (response === null || typeof response !== "object") {
    throw new JsonRpcError(-32000, "$/sessionSetup: malformed result");
  }
  return response as { response_type: string; [key: string]: unknown };
}

/** Resolve once the socket is open (rejecting on an early connection failure). */
function openSocket(url: string): Promise<WebSocket> {
  return new Promise<WebSocket>((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.onopen = () => resolve(ws);
    ws.onerror = () => reject(new JsonRpcError(-32000, `failed to connect to ${url}`));
  });
}
