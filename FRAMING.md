# Framing seam — future work

Design notes for a pluggable **framing** layer — **layer 2** of the stack in
[ARCHITECTURE.md](ARCHITECTURE.md#layers) — so header-carrying binary protocols (SMB DSI,
NFS/ONC-RPC record marking) could replace the hardcoded 4-byte length prefix. This is the Tier-3
"Gap 2" of [PROTOCOL_SPINE_ASSESSMENT.md](PROTOCOL_SPINE_ASSESSMENT.md) — captured here, **not built**.
It is design-only; no code is committed for it.

## Where the layers sit today

(The full stack is [ARCHITECTURE.md → Layers](ARCHITECTURE.md#layers); this is the framing-layer view.)

```
socket bytes ──[framing]──> opaque body ──[codec sniff]──> typed params ──[dispatch]──> handler
              4-byte len                 in-body magic                    op-table
```

- **Framing is one hardcoded shape:** a 4-byte big-endian length prefix, then exactly that many body
  bytes. Inbound: `connection.rs::take_frame` (`HEADER = 4`, `connection.rs:47`; the split at `:71-84`);
  outbound: `framing.rs::frame_into` (`:55-58`, the single framing source), `HEADER_SIZE = 4`
  (`framing.rs:16`). The constant is duplicated in both files.
- **The body is opaque to framing.** Inbound it's handed up zero-copy as `bytes::Bytes`
  (`connection.rs:83,177`); the wire is then chosen by an *in-body* magic sniff inside `dispatch`
  (`truenas-rpc/src/protocol.rs:790-795`: `if is_xdr(wire) …`), where `is_xdr` compares the body's
  first 4 bytes to `"TXDR"` (`truenas-xdr/src/frame.rs`).
- **The existing binary (XDR) wire is _not_ a second framing.** It rides the *same* length prefix; its
  magic + version + `proc_id` + 16-byte request id live **inside** the opaque body as an XDR envelope
  (`truenas-xdr/src/frame.rs`), recovered by the codec from the body. So today there is exactly one
  framing and the "binary wire" is purely a codec choice. The [`Codec` seam](PROTOCOL_SPINE_ASSESSMENT.md)
  (landed) sits at the codec arrow; the dispatch op-table is `HashMap<u32>` (XDR proc-id) /
  `HashMap<Arc<str>>` (JSON name) sharing one `Arc<Method>` (`protocol.rs:650-651`).

## Why header-carrying protocols don't fit the current seam

SMB DSI and ONC-RPC put the request's **opcode and id in the framing header**, not the body, and
ONC-RPC fragments a message across multiple records — both break assumptions baked into `take_frame`
and `dispatch`:

| | JSON / TXDR (today) | SMB DSI | NFS / ONC-RPC |
|---|---|---|---|
| Frame delimiter | 4-byte length prefix | 16-byte header (flags, **command**, **requestID**, dataOffset, totalDataLength) | 4-byte record marker: **last-fragment bit** + 31-bit length |
| One frame = one message | ✓ | ✓ | ✗ — a message spans fragments (reassembly required) |
| Opcode / id location | *in body* | **in header** (command + requestID) | in body (RPC call), but framing must reassemble first |
| Reply framing | length derivable from `payload.len()` | header must **echo command + requestID** | set last-frag bit + length |

Concretely, the seam would need:

1. **Inbound: yield `{ header-metadata, body }`, not a bare `Bytes`.** `dispatch(wire: &[u8])`
   (`protocol.rs:790`) receives only the opaque body — there is no channel for header-carried fields.
   A `Framing` trait's read side must surface `{ opcode/command, request_id, body }` out-of-band so
   dispatch can route on the opcode and audit/echo the id without the codec re-parsing them out of the
   body (the way XDR does today, `truenas-xdr/src/frame.rs`).
2. **Inbound: own fragment reassembly.** `take_frame` assumes "a u32 length, then exactly that many
   bytes is one whole message" (`connection.rs:79-83`), and treats the prefix as a plain magnitude
   checked against `limit` (`:76`). ONC-RPC's record marking puts a *last-fragment flag* in the high
   bit and allows multi-record messages — so the trait must buffer fragments and clear the flag bit
   before the length check.
3. **Outbound: widen the write path.** The writer channel is `UnboundedSender<Vec<u8>>` carrying only
   opaque body bytes (`connection.rs:54,154`), and `write_loop` synthesizes a **fixed** 4-byte length
   from `payload.len()` alone, concatenating queued replies for one write (`:128-138`; and the new
   **vectored** fast path `write_all_vectored` builds `[len4][body]` IoSlices the same way). A
   header-carrying reply framing (DSI must echo command+requestID; ONC-RPC sets last-frag+length) would
   force the channel item to widen beyond `Vec<u8>` (carry per-reply `rid`/`command`), build a per-reply
   header, and possibly emit multiple record fragments — which **defeats both the single-`extend`
   coalescing and the writev path**. `Dispatched::Reply(Vec<u8>)` (`protocol.rs`) and the transfer
   control writes (`write_framed`) share the same "framing applied uniformly at write time as a length
   prefix" assumption.

## Shape of the work

- A `Framing` trait (read: `&mut buffer -> Option<{opcode, request_id, body}>` with owned reassembly;
  write: `(rid, command, body) -> bytes`/fragments), selected per listener, replacing the hardcoded
  `take_frame`/`frame_into` calls. The 4-byte-prefix framing becomes its default impl.
- Pairs with the `dyn ProtocolEngine` seam (assessment "Gap 3"): framing yields the opcode, the engine
  owns the op-table + control verbs (DSI Tickle/Attention; ONC-RPC NULLPROC; SMB SESSION_SETUP). Server
  → client push already exists (`Outbound`).
- **Security:** each engine ships its own framing/reassembly parser that runs **before authentication**
  — new, unaudited pre-auth attack surface (the most sensitive code in the stack). Each needs its own
  review and fuzzing.
- Scope: multi-week, and only worth greenlighting against a serde-shaped target (NFSv3/ONC-RPC is the
  genuine fit; SMB/AFP exercise only the transport/authz half — see the assessment).

## Adjacent micro-opt (noted, not blocking)

The XDR op-table is a `HashMap<u32, Arc<Method>>` keyed by proc-id (`protocol.rs:651`). A dense `Vec`
indexed by proc-id would be a true O(1) array "optable", but proc-ids are sparse (constrained `> 1000`,
`truenas-xdr/src/frame.rs`), so a dense table needs offset-indexing or wastes memory — not a clean win;
revisit only if a profile shows the hashmap lookup mattering against serde/handler cost.
