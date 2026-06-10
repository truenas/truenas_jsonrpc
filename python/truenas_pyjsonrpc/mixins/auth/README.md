# truenas_pyjsonrpc.mixins.auth

A reusable, **channel-aware** authentication layer for
[`truenas_pyjsonrpc`](../..) — the middlewared-style `auth.login_ex` flow,
ready to plug into a protocol's session setup. Subclass `AuthStack`, implement the
credential checks you support, and `install()` it. Depends only on `truenas_pyjsonrpc`;
SCRAM additionally needs the `truenas_pyscram` C extension (Debian
`python3-truenas-scram`), an optional dependency loaded lazily.

The mechanisms are deliberately **non-plaintext** — no password or bearer token crosses the
wire.

## What it does

- **AF_UNIX → peer credentials** (`SO_PEERCRED`): trust a local connection by its uid
  (e.g. root), with **fallthrough to login** if your policy declines.
- **TCP / WebSocket → login mechanisms**: `SCRAM` (RFC 5802), `GSSAPI` (Kerberos), and
  **mTLS** (`CLIENT_CERTIFICATE`), with an optional **OTP** second factor after SCRAM.
- **SCRAM (RFC 5802), via `truenas_pyscram`**: the C extension does the SCRAM-SHA-512
  crypto; this layer just marshals the two-round-trip exchange. You store only a per-user
  **verifier** (salt + iterations + `StoredKey`/`ServerKey`), never the secret. No secret
  crosses the wire and a captured exchange can't be replayed, so SCRAM needs no secure
  channel and gives the client mutual authentication of the server.
- **GSSAPI (Kerberos, RFC 4752)**: a **variable-round** token exchange, exposed as a single
  overridable `gssapi_step` hook. The base class ships a **stub** (it rejects); a real impl
  wraps `gssapi.SecurityContext` — see [GSSAPI design](#gssapi-design).
- **Channel binding**: each mechanism is refused unless the connection provides the
  capability it needs (a client cert for mTLS). SCRAM and GSSAPI are replay-resistant and
  carry no channel requirement.
- **Audit-safe**: secret fields are `SECRET`-marked, so the protocol redacts them in audit.
- **TrueNAS hosts**: a ready-made [`TrueNASAuth`](#truenas--pam-integration-truenasauth)
  delegates SCRAM to **PAM** (`pam_truenas`) so a local service authenticates exactly like
  middleware — no in-process credential store.

It mirrors middleware's `auth.login_ex` / `auth.login_ex_continue` (tagged-union
`mechanism` in, tagged-union `response_type` out, with a two-step OTP).

## Plug it in

```python
from truenas_pyjsonrpc import JSONRPCProtocol
from truenas_pyjsonrpc.mixins.auth import AuthStack, Authenticated, NeedsOtp, Reject

class MyAuth(AuthStack):
    # AF_UNIX: trust local root; everyone else falls through to login
    def peercred(self, peer):
        if peer.uid == 0:
            return Authenticated({"user": "root"})
        return None

    # SCRAM: return the stored verifier; the framework runs the RFC 5802 exchange
    def scram_credentials(self, username):
        return load_scram_verifier(username)      # a ScramCredentials, or None if unknown

    def client_certificate(self, peercert, *, peer):
        return Authenticated(map_cert_to_user(peercert))

protocol = JSONRPCProtocol(methods, name="truenas.api.v1", audit_handler=audit)
MyAuth().install(protocol)        # registers $/sessionSetup + $/sessionSetupContinue
```

`install()` wires the two control methods with the protocol's `(SessionLifecycle, result)`
contract; downstream methods are gated until the session is `ESTABLISHED`. Override only
the verifiers you support — the rest reject by default.

## Outcomes (what a verifier returns)

| return | meaning |
|--------|---------|
| `Authenticated(identity, user_info=None)` | success → `SUCCESS`; session `ESTABLISHED`; `identity` is stored on `session_state.server_state_internal` (what method/authorization handlers read) |
| `NeedsOtp(pending, username)` | first factor ok → a second factor is required; session `INIT`; `pending` is handed back to `otp()` on `$/sessionSetupContinue` |
| `Reject(response="AUTH_ERR")` | failure → `AUTH_ERR` (default) / `EXPIRED` / `DENIED` (lifecycle unchanged) |

A bad credential returns a *response* — it never raises. (Reserve `raise JsonRpcError(...)`
for hard errors you want surfaced as a JSON-RPC error rather than an auth response.)

## SCRAM + OTP (a second factor)

To require a one-time password **after** a SCRAM login, override `scram_finish` to return
`(server_final, NeedsOtp(...))` instead of `(server_final, Authenticated(...))`, and
implement `otp()`. The SCRAM proof is verified first (mutual auth still holds); the final
SCRAM reply carries `otp_required=True` and the session stays `INIT`, so the client verifies
the server signature and then continues with an `OTP_TOKEN`:

```python
class ScramThenOtp(AuthStack):
    def scram_credentials(self, username):
        return load_scram_verifier(username)

    def scram_finish(self, pending, client_final_rfc, *, peer):
        out = super().scram_finish(pending, client_final_rfc, peer=peer)   # verify the proof
        if isinstance(out, Reject):
            return out
        server_final, authd = out
        return server_final, NeedsOtp(pending=authd.identity, username=...)

    def otp(self, pending, otp_token, *, peer):
        return Authenticated(pending) if check_otp(pending, otp_token) else Reject()
```

## Channel binding

The connection's channel provides `Capability` values (derived from the server-seeded
`Peer`); each mechanism declares the capabilities it requires. A mechanism offered on a
channel that lacks its requirement is refused with `DENIED` before the verifier runs.

| capability | present when |
|------------|--------------|
| `LOCAL` | AF_UNIX |
| `PEERCRED` | AF_UNIX with `SO_PEERCRED` uid |
| `ENCRYPTED` | TLS / kTLS, AF_UNIX, or a loopback TCP peer |
| `CLIENT_CERT` | the peer presented a TLS client certificate |

| mechanism | requires (default) |
|-----------|---------------------|
| `CLIENT_CERTIFICATE` | `CLIENT_CERT` |
| `SCRAM`, `GSSAPI` | *(none — replay-resistant, safe on any channel)* |

Override `channel_capabilities(peer)` or the class-level `requirements` map to customize.

## SCRAM verifiers

For SCRAM you store a **verifier**, not the secret. `generate_scram_credentials()` mints a
fresh random credential — the modern replacement for a plaintext API key — using
`truenas_pyscram`:

```python
from truenas_pyjsonrpc.mixins.auth import generate_scram_credentials

creds, secret = generate_scram_credentials(identity=user_id, user_info={...})
# persist creds.salt, creds.iterations, creds.stored_key, creds.server_key (+ identity);
# hand `secret` (the base64 SaltedPassword) to the client ONCE — the server never needs it
```

Then `scram_credentials(username)` returns a `ScramCredentials` rebuilt from those stored
fields, or `None` for an unknown user (→ `AUTH_ERR` at the first message). On success the
session's identity is `creds.identity` (falling back to the username).

This layer does **not** fabricate challenges to mask whether an account exists — that
trades correctness for a partial defense. If you want to hide account existence, have
`scram_credentials()` return a *stable decoy* verifier instead of `None`; that is an
explicit application policy.

## GSSAPI design

GSSAPI (Kerberos, RFC 4752) is a **variable-round** mechanism: the acceptor may need several
client↔server token exchanges before the context completes. So instead of SCRAM's fixed
begin/finish, it is one hook, `gssapi_step(pending, token, *, peer)`, called once per round:

- `pending` is `None` on the **first** token (from `$/sessionSetup`), and otherwise the
  opaque state you returned from the previous round (carry your live server-side GSS context
  there).
- Return `GssapiChallenge(server_token, pending)` to send another challenge (session stays
  `INIT`, the client replies with the next `GSSAPI` token), `(final_token, Authenticated(...))`
  when the context completes (session `ESTABLISHED`), or `Reject()`.

Unlike SCRAM, GSSAPI has **no OTP second factor** — it completes straight to `Authenticated`.
Kerberos multi-factor is enforced at the KDC (OTP preauth, PKINIT, FAST), so a completed
context already represents the assured identity; there is no `gssapi_step` → `NeedsOtp` path.

The base class ships a **stub** that rejects. A real implementation uses
[`python-gssapi`](https://github.com/pythongssapi/python-gssapi) (see its
[acceptor tutorial](https://pythongssapi.github.io/python-gssapi/basic-tutorial.html)):

```python
import gssapi
from truenas_pyjsonrpc.mixins.auth import AuthStack, Authenticated, GssapiChallenge, Reject

class KerberosAuth(AuthStack):
    def gssapi_step(self, pending, token, *, peer):
        # first round: a fresh acceptor context (default host-keytab creds, usage="accept");
        # later rounds: reuse the in-progress context carried in `pending`.
        ctx = pending or gssapi.SecurityContext(usage="accept")
        try:
            out = ctx.step(token)                 # -> bytes (server token) or None
        except gssapi.exceptions.GSSError:        # malformed/invalid client token, etc.
            return Reject()
        if ctx.complete:
            return (out or b""), Authenticated({"username": str(ctx.initiator_name)})
        return GssapiChallenge(server_token=out or b"", pending=ctx)
```

For a production impl (left to the application):

- **Credentials**: `SecurityContext(usage="accept")` uses the default acceptor credentials —
  the host service keytab, selected by `KRB5_KTNAME` / `krb5.conf`. Pass
  `creds=gssapi.Credentials(usage="accept", name=<service principal>)` to pin a specific
  service principal.
- **Channel binding**: bind the GSS context to the TLS channel (from `peer`) to defend against
  credential forwarding — pass `channel_bindings=gssapi.raw.ChannelBindings(application_data=…)`
  to `SecurityContext` at construction (the first round).
- **Deferred errors**: `python-gssapi` defers some `.step()` failures (it may hand back a token
  now and raise on the next call), so treat any raised `GSSError` as a reject rather than
  assuming it fires on the exact offending round.
- **PAM alternative**: on a host configured for it, `pam_krb5` can validate a Kerberos
  credential through PAM instead, mirroring how `TrueNASAuth` relays SCRAM through `pam_truenas`.

GSSAPI carries no `requirements` entry by default (it is replay-resistant; channel binding is
recommended rather than enforced).

## TrueNAS / PAM integration (`TrueNASAuth`)

The verifier model above is for a standalone service with its own credential store. On a
**TrueNAS host**, authenticate the way middleware does instead — delegate to **PAM**, so a
local service consumes the host's `pam_truenas` PAM files and holds no credentials at all:

```python
from truenas_pyjsonrpc.mixins.auth import TrueNASAuth

TrueNASAuth().install(protocol)            # SCRAM relayed through pam_truenas
```

**SCRAM** is **relayed** to the `pam_truenas` module on `scram_service` (default
`"truenas-api-key"`): the client's `client-first`/`client-final` RFC strings are passed into
the PAM conversation and the module returns `server-first`/`server-final`. The verifier lives
in the **system keyring**; this layer (and your service) never see it. This is the alternative
to the in-process verifier model — it overrides `scram_begin`/`scram_finish`.

PAM **service names are deployment-specific** — production TrueNAS installs `truenas-api-key`;
the `pam_truenas` test host uses `middleware-scram`. Pass `scram_service` to match. Restrict the
offered mechanisms with `mechanisms` (default `{"SCRAM"}`), and pass `authenticator_factory` to
inject the PAM connection origin / env.

`truenas_pypam` + `truenas_authenticator` (Debian `python3-truenas-pypam`) are an **optional**
dependency loaded lazily — `truenas_pyjsonrpc.mixins.auth` imports without them and the PAM paths
reject cleanly (check `PAM_AVAILABLE`). See `examples/serve_truenas_scram.py` +
`examples/client_truenas_scram.py` for a runnable SCRAM-only TCP+TLS server and an API-key
client.

## Wire messages

A request carries a tagged-union `mechanism`; a reply carries a tagged-union `response`
(wrapped in `AuthResult`). Mechanisms: `SCRAM {scram_type, rfc_str}`, `GSSAPI {token}`,
`CLIENT_CERTIFICATE {}`, `OTP_TOKEN {otp_token}` (the OTP secret is redacted in audit).
Responses: `SUCCESS {user_info?}`, `OTP_REQUIRED {username}`, `SCRAM_RESPONSE {scram_type,
rfc_str, user_info?, otp_required}`, `GSSAPI_RESPONSE {token, complete, user_info?}`,
`AUTH_ERR`, `EXPIRED`, `DENIED`. (`token` fields are `bytes`, base64-encoded on the JSON wire.)

## Client side

A client drives it with `BaseClient.setup(...)` / `setup_continue(...)`:

```python
c.setup({})                                                # AF_UNIX peercred

# SCRAM is two steps: send client-first, then client-final using the server's challenge.
r = c.setup({"mechanism": {"mechanism": "SCRAM",
                           "scram_type": "CLIENT_FIRST_MESSAGE", "rfc_str": client_first}})
c.setup_continue({"mechanism": {"mechanism": "SCRAM",
                                "scram_type": "CLIENT_FINAL_MESSAGE", "rfc_str": client_final}})
# if the SCRAM reply set otp_required (or for any OTP_REQUIRED), send the second factor:
c.setup_continue({"mechanism": {"mechanism": "OTP_TOKEN", "otp_token": "123456"}})

# GSSAPI is variable-round: send a token, then reply to each GSSAPI_RESPONSE until complete.
r = c.setup({"mechanism": {"mechanism": "GSSAPI", "token": client_token}})   # bytes -> base64
while not r["response"]["complete"]:
    r = c.setup_continue({"mechanism": {"mechanism": "GSSAPI", "token": next_client_token}})
```
