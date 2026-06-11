# truenas_pyjsonrpc.mixins.audit

Structured, **middleware-shaped** syslog auditing for
[`truenas_pyjsonrpc`](../..). Pass one handler and every audited call is
emitted to syslog as a `@cee:`-prefixed JSON record with the same `TNAUDIT` envelope TrueNAS
middleware logs. Depends only on the standard library + `truenas_pyjsonrpc`.

```python
from truenas_pyjsonrpc import JSONRPCProtocol
from truenas_pyjsonrpc.mixins.audit import SyslogAuditHandler

audit = SyslogAuditHandler(service="vm.api")           # -> /var/run/syslog-ng/vm.api.sock (STREAM)
protocol = JSONRPCProtocol(methods, name="vm.api.v1", version="1.0.0",
                           audit_handler=audit, use_audit_queue=True)
```

`SyslogAuditHandler` **is** the protocol's `audit_handler` callable. The dispatch core already
decides *what* to audit (methods declared `JSONRPCMethod(..., audit=True, audit_message=...)`,
plus the always-audited control ops `$/sessionSetup`/`Continue`/`Close` and `$/cancelRequest`)
and **redacts secrets** (`Annotated[str, SECRET]` → `********`) before the handler runs — this
package only formats and emits.

## The record

Each call is one syslog line: `@cee:` followed by JSON. `svc_data` and `event_data` are nested
JSON **strings** (exactly as middleware nests them).

```
@cee:{"TNAUDIT": {
  "aid": "<uuid4>",                       // unique audit id
  "vers": {"major": 0, "minor": 1},
  "addr": "10.0.0.5:52344",               // client origin
  "user": "admin",                        // authenticated user
  "sess": "<session uuid>",
  "time": "2026-06-09 18:42:11.502134",   // UTC
  "svc": "vm.api",                        // your service name
  "svc_data": "{\"vers\":..., \"origin\":\"10.0.0.5:52344\", \"protocol\":\"JSONRPC\", \"credentials\": {\"credentials\":\"USER_SESSION\", \"credentials_data\": {\"username\":\"admin\", ...}}}",
  "event": "METHOD_CALL",
  "event_data": "{\"method\":\"pool.create\", \"params\":[{\"name\":\"tank\"}], \"description\":\"Create pool tank\", \"success\":true, \"error\":null, \"vers\":...}",
  "success": true
}}
```

### `event` classification

| `request.method` | default `event` |
|------------------|-----------------|
| `pool.create`, any normal method | `METHOD_CALL` |
| `$/sessionSetup`, `$/sessionSetupContinue`, `$/sessionClose`, `$/cancelRequest` | `CONTROL_MESSAGE` |

Override by passing a custom `event_classifier` to an `AuditFormatter` (e.g. map
`$/sessionSetup` → `"AUTHENTICATION"`). `event_data` for a `METHOD_CALL` carries
`{method, params, description, success, error}`; `CONTROL_MESSAGE` additionally includes the
`result`.

## Identity & origin

`user`, `addr`, and the `credentials` block are pulled from `session_state.server_state_internal`
by small overridable callables (`default_username` / `default_origin` / `default_credentials`),
which handle a **dict identity** (e.g. `truenas_pyjsonrpc.mixins.auth`'s
`{"username", "account_attributes", "origin", "api_key_id"?}`) and the server-seeded **`Peer`**.

For `addr` to be present on method-call audits, the authenticated identity must carry an
`origin` — `truenas_pyjsonrpc.mixins.auth` captures the connection origin into the identity at auth
time, so `TrueNASAuth` / the verifier model populate it automatically. Supply your own
extractors for a different identity shape:

```python
from truenas_pyjsonrpc.mixins.audit import AuditFormatter, SyslogAuditHandler

fmt = AuditFormatter("vm.api", username=lambda ss: ss.server_state_internal["who"])
audit = SyslogAuditHandler("vm.api", formatter=fmt)
```

## Destination

The default is a syslog-ng **STREAM** unix socket at `/var/run/syslog-ng/<service>.sock` (the
socket must exist when the handler is constructed). Point it elsewhere:

```python
import socket
SyslogAuditHandler(service="vm.api", address="/dev/log", socktype=socket.SOCK_DGRAM)
SyslogAuditHandler(service="vm.api", address=("loghost", 514), socktype=socket.SOCK_DGRAM)
```

`ident` (syslog tag, default `TNAUDIT_<SERVICE>: `) and `facility` are configurable.

## Threading

Recommend `use_audit_queue=True`: the protocol enqueues audit work and the server drains it on
a dedicated thread, where the (possibly blocking) syslog write belongs — off the dispatch path.
The handler does no internal queueing of its own. Without the queue it emits inline on the
dispatch thread. Either way `__call__` never raises (auditing can't break dispatch).
