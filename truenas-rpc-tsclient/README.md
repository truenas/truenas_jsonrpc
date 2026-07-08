# truenas-rpc-tsclient

The browser/WebSocket runtime for the generated TrueNAS RPC **TypeScript** clients (the TS analog of
`truenas-rpc-pyclient`). Zero dependencies — it uses only the platform `WebSocket`, `JSON`, and
`crypto`. It owns the wire (JSON-RPC 2.0, one frame per WebSocket message), subscriptions, and
session authentication (`$/sessionSetup`).

A generated `<Proto>Client` holds an `RpcConnection` and exposes one method per RPC; you touch this
package directly mainly to build a credential.

## Usage

```ts
import { CatalogV1Client } from "./catalog_v1_client"; // generated
import { password, oauth, bearerToken } from "truenas-rpc-tsclient";

// Connect + authenticate (auth requires wss://); pick one credential:
const client = await CatalogV1Client.connect("wss://host/rpc", password("alice", "s3cret"));
//   ...or oauth(idToken), or bearerToken(token).

// Typed request/response:
const result = await client.get_item({ id: 42 });

// Subscriptions (callback style):
const sub = await client.subscribe_events({ topic: "pool" }, (e) => console.log(e.status));
await sub.unsubscribe();
```

## Auth mechanisms

| Credential | Mechanism | Notes |
|---|---|---|
| `password(user, pass)` | unbound SCRAM-SHA-512 | Username/password, computed in WebCrypto. Needs the server's opt-in `scram_unbound`. |
| `oauth(idToken)` | OAuth/OIDC | A JWT id-token from your IdP (auth-code + PKCE, out of band). |
| `bearerToken(token)` | GSSAPI_BEARER_TOKEN | A single-use token minted by an HTTP SPNEGO edge (Kerberos SSO) — browsers can't do GSSAPI directly. |

All require `wss://` (a confidential channel). Not covered: mTLS (browser-managed at the TLS layer),
filterable queries, and raw-fd transfers.

## Build / test

```
npm install
npm run build      # emit dist/
npm test           # tsc + node --test (SCRAM known-answer vector + a round-trip)
```
