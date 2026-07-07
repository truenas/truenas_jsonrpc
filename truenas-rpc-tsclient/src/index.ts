/**
 * `truenas-rpc-tsclient` — a tiny browser/WebSocket runtime for the generated TrueNAS RPC
 * TypeScript clients (the TS analog of `truenas-rpc-pyclient`). A generated `<Proto>Client`
 * holds an {@link RpcConnection} and calls `.call(method, params)`; this module owns the wire
 * (JSON-RPC 2.0 over a WebSocket, one frame per message — no length prefix).
 *
 * Zero dependencies: it uses only the platform `WebSocket`, `JSON`, and `crypto.randomUUID`.
 * Subscriptions (server->client notifications) are out of scope in this basic runtime.
 */

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

interface Pending {
  resolve: (value: unknown) => void;
  reject: (reason: unknown) => void;
}

/**
 * A JSON-RPC 2.0 connection over a WebSocket. The server's `websocket` transport carries one
 * JSON-RPC frame per WebSocket message, so requests/replies are plain `JSON.stringify`/`parse` —
 * correlated by a per-call UUID `id`.
 */
export class RpcConnection {
  readonly #ws: WebSocket;
  readonly #pending = new Map<string, Pending>();
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

  /** Close the underlying socket, failing any in-flight calls. */
  close(): void {
    this.#ws.close();
  }

  #onMessage(data: unknown): void {
    let msg: {
      id?: unknown;
      result?: unknown;
      error?: { code?: number; message?: string; data?: unknown };
    };
    try {
      msg = JSON.parse(typeof data === "string" ? data : String(data));
    } catch {
      return; // ignore unparseable frames
    }
    const id = msg.id;
    // A reply carries a string `id`; a server->client notification does not (ignored in v1).
    if (typeof id !== "string") return;
    const pending = this.#pending.get(id);
    if (pending === undefined) return;
    this.#pending.delete(id);
    if (msg.error) {
      pending.reject(new JsonRpcError(msg.error.code ?? -32000, msg.error.message ?? "error", msg.error.data));
    } else {
      pending.resolve(msg.result);
    }
  }

  #failAll(reason: unknown): void {
    for (const pending of this.#pending.values()) pending.reject(reason);
    this.#pending.clear();
  }
}

/** Resolve once the socket is open (rejecting on an early connection failure). */
function openSocket(url: string): Promise<WebSocket> {
  return new Promise<WebSocket>((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.onopen = () => resolve(ws);
    ws.onerror = () => reject(new JsonRpcError(-32000, `failed to connect to ${url}`));
  });
}
