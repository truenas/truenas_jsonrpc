# Assessment: a generic service spine with interchangeable protocols

## Context

The question: turn the current stack into a **generic service spine** where the server owns an
internal op-dispatch table, and `jsonrpc + xdr + auth/authz` is just the *default* op-table —
replaceable by a third party who wants to build, say, a legacy AFP server
(`/CODE/claudedir/netatalk`). Their workflow, as imagined: drop in a crate with "a serde layer for
the wire protocol," add the normal json-idl files, run codegen, done.

This is an assessment of **feasibility, maintenance cost, and performance cost** — not an
implementation request. The honest finding up front: **the spine is real and already half-built (TXDR
proves it), the worthwhile refactor is bounded and pays for itself, but the full "any protocol" vision
is a genuine architectural project — and AFP specifically is the wrong flagship for it**, because AFP
bypasses the serde + json-idl machinery that is the pitch's headline feature.

## What already exists — the spine is real

Grounded in the code, three layers are **already protocol-neutral** and reused verbatim by the TXDR
binary wire (zero XDR references leak into the server crate) — in the
[layer-stack](ARCHITECTURE.md#layers) vocabulary, the **Transport**+**Framing** layers, the
**Authorization** gate, and the **Dispatch** op-table:

- **Transport half.** Accept loops, TLS/kTLS, peer-cred (`SO_PEERCRED`), `SCM_RIGHTS`,
  `Peer`/`Channel`/`Capability`/`TransportPosture`, `Outbound`, the session registry — all JSON-free.
- **Authz/authn core.** `authorize`/`commit`/`AuthSessionState`, the native role-mask subset gate, the
  audit seam. Authorization is a mask test; audit consumes a `serde_json::Value`.
- **The op-table itself is now a standalone, wire-neutral type — `Service<S>`.** The Stage 1 extraction
  lifted it off `JsonRpcProtocol`: `Service` owns the registry, the `decode → authorize → run → audit`
  run core, and the session registry, and each wire is a *view* over one `Service` (`JsonRpcProtocol`,
  `OncRpcProtocol`). It is key-type-agnostic — one `Arc<Method>` lives in **two** registries
  simultaneously (`Registry`: `methods: HashMap<Arc<str>, …>` by name and `xdr_methods:
  HashMap<u32, …>` by proc-id, sharing the same `Arc`). This is the existence proof that the registry
  key is swappable — an AFP opcode table (`HashMap<u16, Arc<Method>>`) is the same shape.
- **Dispatch pipeline.** `decode → authorize → run → audit` is the shared run core *inside* `Service`,
  reached from the JSON path (`dispatch_parsed`), the XDR path (`dispatch_xdr`), and the engine-facing
  `Service::run_proc`.
- **The transport↔protocol seam is mostly neutral.** `Dispatched` hands the server opaque bytes
  (`Reply(Vec<u8>)`) or `Nothing` — both protocol-agnostic.

**Conclusion: "transport + authz + op-table" is not a thing to build — it exists, and as of Stage 1 it
is *factored*: the op-table is the standalone `Service<S>`, with `JsonRpcProtocol` and `OncRpcProtocol`
as wire-views over it.** TXDR and ONC RPC are the living proof a second (and third) wire reuses ~all of it.

## What is JSON/serde-bound — the gaps

Four seams stand between "two hardcoded wires" and "interchangeable protocols". Each is grounded:

**Gap 1 — Serde is the data-model floor; there is no `Codec` abstraction.** Every erased method trait
bakes serde in *and* open-codes JSON + XDR as a **pair of methods**: `decode`/`run` (serde_json) plus
`xdr_decode`/`xdr_run` (`truenas_xdr`), on each of `ErasedSync`, `ErasedAsync`, the `Filterable`
erasure, and `ErasedTransfer` (`method.rs:56-101`, `method.rs:262-335`). The handler bound is hard:
`A: DeserializeOwned + Serialize, R: Serialize` (`method.rs:108-113`). Two consequences:
  - A third *serde-shaped* wire means adding a third method-pair (`afp_decode`/`afp_run`) to **every**
    erased trait — the N×M open-coding explosion — unless this is refactored into one `Codec` seam.
  - A *non-serde* protocol can't satisfy the bound cleanly, and the authz/audit seam still wants a
    `serde_json::Value` (the XDR path *reflects* its decoded params into one precisely so authz/audit
    keep working — `method.rs:133-136`). A protocol whose messages aren't serde-shaped can't produce
    that Value for free.

**Gap 2 — Framing is a hardcoded `u32·blob`, no trait.** `take_frame` (`connection.rs:71-84`)
hardcodes a 4-byte big-endian length prefix and yields an opaque body. DSI (AFP's transport) needs a
**16-byte header carrying command + requestID + dataOffset + totalDataLength *before* the payload** —
the framing layer must surface the opcode, not just "a blob." A `Framing` trait yielding
`(header-metadata, body)` is required, and it must coexist with the write-coalescing fast path
(`connection.rs:112+`) that today assumes opaque pre-framed bytes. **Grounded design notes for this
seam — what it must surface, fragment reassembly, and the write-path impact — live in
[`FRAMING.md`](FRAMING.md).**

**Gap 3 — No `dyn ProtocolEngine` dispatch seam.** The wire is chosen by a single magic-byte `if` at
`dispatch()` (`protocol.rs:790-801`: `if is_xdr(wire) …`). Making the protocol *replaceable* (not just
JSON-or-XDR) means hoisting that into a `dyn ProtocolEngine` the server holds, with JSON-RPC as the
default impl — and neutralizing the JSON-RPC-specific `Dispatched` variants (`Transfer`,
`Passthrough`, `Sessions`) that currently leak through the seam.

**Gap 4 — The control plane is JSON-RPC-specific.** `$/negotiate`, `$/sessionSetup`, `$/describe`,
`$/sessions`, `$/cancelRequest`, UUID id semantics, and the error-code taxonomy are all envelope
concepts. A different protocol has its own control verbs (DSI Tickle/Attention/CloseSession; AFP
Login/Logout) — these are **not reusable**; each engine reimplements them. (Server→client push *is*
reusable: the `Outbound`/subscription machinery already does server-initiated messages, which is what
DSIAttention/DSITickle need.)

**Codegen has no backend abstraction.** The three emitters (`emit_server`/`emit_client`/
`emit_openrpc`, `lib.rs:145-155`) all emit JSON-shaped serde structs from a JSON-Schema-subset IDL
(`model.rs`). XDR is **not** a fourth backend — it's a per-struct `xdr: bool` flag that toggles one
extra *derive* on the same serde struct (`emit_server.rs:96,124`). That trick works *only because XDR
is itself a serde-model codec*. It does not generalize to a wire that isn't serde-shaped.

## Feasibility — three tiers of increasing cost

**Tier 1 — reuse the spine as a library (already possible, ~free).** Build a server on the existing
transport + TLS + peer-cred + session registry + authorize/commit core, with your own dispatch on
top. Real and shippable now; TXDR demonstrates it.

**Tier 2 — a `Codec` trait collapsing JSON/XDR and admitting a third *serde-shaped* wire
(bounded, ~weeks).** Refactor the four erased traits' method-pairs into one codec-parameterized path.
This is a clean, self-justifying refactor: it deletes the JSON/XDR open-coding (Gap 1) and makes any
serde-shaped binary wire cheap to add. **Worth doing on its own merits, independent of the AFP
question.**

**Tier 3 — the full "interchangeable protocols" vision (large, a real architectural project).** Add
the `Framing` trait (Gap 2), the `dyn ProtocolEngine` seam (Gap 3), per-engine control planes
(Gap 4), and a codegen backend abstraction. Feasible — none of it is blocked — but it is a
multi-month effort, and its payoff is **gated on the target protocol being serde-shaped.**

## Maintenance costs

- **N×M codepath burden (the dominant cost).** Today: 2 wires × 4 erasure kinds = 8 hand-kept
  decode/run methods. Every new `MethodImpl` variant must implement both wires; every new wire
  multiplies. A third protocol → 12, a fourth → 16. The Tier-2 `Codec` trait converts this
  multiplication into addition (N codecs + M kinds, each isolated) — which is exactly why Tier 2 is
  worth doing before anything else.
- **An interface contract that is currently implicit.** A `dyn ProtocolEngine` forces every protocol
  author to uphold the subtle, currently-one-implementation contract: `Dispatched` semantics, session
  lifecycle, and ordering invariants like *INVALID_PARAMS precedes NOT_AUTHORIZED* (`method.rs`
  comments; enforced in dispatch). Generalizing means **documenting and testing that as a public
  interface** — a permanent ongoing cost.
- **Pre-auth security surface multiplies.** The auth/authz core is reusable, but each engine ships its
  **own framing parser that runs before authentication**. Every new engine is new, unaudited pre-auth
  attack surface — the most security-sensitive code in the stack.
- **A second codegen backend + a richer IDL.** json-idl is a JSON-Schema subset; it cannot express
  AFP's bitmaps, offset back-patching, or fixed-record layouts. Supporting a non-serde wire means
  either a new IDL dialect + emitter to maintain, or the author hand-writes the body codec (which, for
  AFP, they will — see below).

## Performance costs

- **Dispatch/codec genericity is essentially free.** There is *already* one vtable hop per call (the
  `Box<dyn ErasedSync>` erasure). A `dyn ProtocolEngine` adds **one** more indirection at the top of
  dispatch — negligible against serde decode + handler cost. A `Codec` as a generic parameter
  monomorphizes to **zero** runtime cost (measured: ±2% vs today — see "Tier 2 A/B performance
  comparison" below). A **payload-generic `dyn Codec`** is the exception: it is *not* one vtable call
  but a full `erased-serde` protocol erasure, measured at **+74% to +397%** per dispatch — so keep
  dynamic codecs off the hot path (enum-dispatch a closed wire set instead, also measured free).
- **The real perf risk is in framing/transfer, not dispatch.** The current wins — write coalescing
  (`connection.rs:112+`), kTLS raw-fd bulk transfer, sendfile, no per-request task spawn, opaque
  `Reply(Vec<u8>)` with no re-encode — must survive genericization. A `Framing` trait that forces an
  extra copy per message, or that must *interleave* header fields into the body (DSI), can defeat the
  single-`write_all` coalescing. **Verdict: low cost for dispatch/codec; moderate and
  protocol-specific for framing/transfer when the new protocol needs out-of-band streaming — which AFP
  does (DSIWrite offset streaming, sendfile reads with DSI_NOREPLY).**

## The AFP reality check — the honest verdict

**AFP is a poor showcase for this architecture.** The cheap 20% lines up; the expensive 80% bypasses
exactly the machinery the pitch is selling:

- **What fits (the cheap 20%):** an opcode→handler table (the op-table is already key-agnostic),
  pre-auth gating, multi-round auth control flow (AFP's `AFPERR_AUTHCONT` UAM loop maps onto the
  existing `$/sessionSetup` multi-round seam), and server→client push (DSIAttention/DSITickle ride the
  existing `Outbound`).
- **What does *not* fit (the expensive 80%, and it is the headline feature):**
  - AFP handlers take raw `char *ibuf / char *rbuf` buffers, not typed structs.
  - **Bitmap-driven, runtime-variable field selection with back-patched offset pointers** (`file.c`
    `getmetadata`) — this is precisely the `deserialize_any` shape `truenas-xdr` documents as
    unsupported. serde's statically-known-shape model does not express it.
  - Out-of-band `DSIWrite` offset streaming and sendfile/`DSI_NOREPLY` reads.
  - Massive per-session handle state (forks/volumes/dircache/CNID) — *this part* fits, since the
    spine's per-session state is already `S`-generic.

So the "serde layer for the wire protocol" the vision imagines is **the exact part that does not exist
for AFP**, because AFP's wire is not serde-shaped. An AFP author would hand-write the bitmap/offset
munging anyway and the json-idl + codegen + serde path — the headline — would sit unused. The serde +
codegen machinery would carry none of AFP's real weight.

**The protocol that *would* showcase this well is a fixed-record RPC-style one — ONC RPC / NFS-shaped.
That is literally what TXDR already is.** The sweet spot is statically-shaped request/reply protocols;
the poor fit is legacy binary protocols with bitmap/offset wire formats and out-of-band streaming.

## NFS & SMB on the spine — verified against the specs

Tested the "serde-shaped fixed-record" boundary against the real specs (NFSv4.1 `rfc8881`, NFSv4.2
`rfc7862`; ONC-RPC/XDR/NFSv3 from the heimdal + pynfs `.x` trees; SMB from `[MS-SMB2].pdf`). The
boundary is exactly what `truenas-xdr` documents it cannot cross (`de.rs:97` — `deserialize_any`
unsupported; no bitmaps, offset-chasing, or dynamic-key maps).

**The reusable spine fits all four protocols.** Framing (one `Framing` impl per wire), the keyed
op-table, the multi-round auth seam, and server→client push are universal:
- Multi-round auth → `$/sessionSetup`: RPCSEC_GSS loops via NULLPROC control calls (RFC 2203 §5); SMB
  SESSION_SETUP loops on `STATUS_MORE_PROCESSING_REQUIRED` carrying a SPNEGO/GSS blob (MS-SMB2
  §3.3.5.5.3); AFP's UAM `AFPERR_AUTHCONT` loop.
- Server→client push → `Outbound`: NFSv4 backchannel `CB_COMPOUND` (RFC 8881 §2.10.3.1); SMB
  oplock/lease breaks + async interim; DSIAttention/Tickle.

**The serde + json-idl + codegen headline carries the wire only for serde-shaped protocols:**

| Seam | NFSv3 | NFSv4 | SMB2/3 | AFP |
|---|---|---|---|---|
| Framing | RPC record-marking (4B, top-bit=last-frag, multi-fragment) | same | 4B len + fixed 64B header (`Command` @ fixed offset) | 16B DSI header |
| Op-table key | `(prog,vers,proc)` u32 | proc=COMPOUND → `nfs_opnum4` per array elem | u16 `Command` | u8 command |
| One op / message | ✓ | ✗ **COMPOUND = array of ops** | ✗ **NextCommand chain + cross-op state** | ✓ |
| **Body is serde-shaped** | ✓ flat fixed-record | ◑ except **`fattr4`** (bitmap4+opaque blob, positional) | ✗ **Offset/Length self-addressing, back-patched; StructureSize≠size** | ✗ bitmap + back-patched offsets |
| Nested runtime-tagged blobs | — | fattr4 attrs (number-tagged) | create-contexts (Next-chained, string-tag) | — |
| Control plane | minimal | sessions/delegations | **credits + async + signing + SMB3 encryption** | tickle/attention + out-of-band DSIWrite |

Citations: NFSv4 `COMPOUND4args{ nfs_argop4 argarray<> }` (RFC 8881 §18.16.3; `nfs4.x`); `fattr4 =
{bitmap4 attrmask; opaque attrlist4 attr_vals}` parsed lowest-attribute-number-first (RFC 8881 §3.3.7,
§18.7.3); NFSv3 `fattr3` flat fixed struct (`nfs3.x`, RFC 1813 §2.5). SMB2
`NameOffset`/`CreateContextsOffset` with constant `StructureSize=57` "regardless of how long Buffer[]
actually is" (MS-SMB2 §2.2.13); `SecurityBufferOffset` (§2.2.5); `NextCommand` compound chain
(§2.2.1.2, §3.3.5.2.7.1); `SMB2_CREATE_CONTEXT` Next-chained string-tagged blobs (§2.2.13.2);
credits / async / signing / transform-header encryption (§3.2.4.1.2, §3.3.4.2, §3.1.4.1, §2.2.41).

**Verdict — the discriminator is the (`one op / message` × `body is serde-shaped`) pair:**
- **NFSv3 / ONC-RPC is the genuine showcase.** It *is* XDR (the codec already exists), flat
  fixed-records, one proc per message. The headline machinery carries the whole wire.
- **NFSv4 fits with two localized carve-outs:** a COMPOUND/CB_COMPOUND sub-loop over an
  opcode-tagged-union array (with cross-op current-filehandle state), and a hand-written `fattr4`
  bitmap codec. Everything else is serde-shaped.
- **SMB2/3 and AFP fail the body row.** Their wires are offset/bitmap self-addressing — hand-coded
  regardless of any `Codec` trait — and SMB adds compounding + a heavy credit/async/signing/encryption
  control plane. For these the spine is a useful **transport + authz + op-dispatch + multi-round-auth
  substrate (the half TXDR already proved)**, but json-idl/codegen carries little of the wire: you
  hand-write the body codec and the control-plane state machines.

So "NFS or SMB on the spine" splits cleanly: **NFS (especially v3) is a real fit for the full stack;
SMB exercises only the transport/authz half** — the same half AFP would, with a heavier control plane.

## Recommendation

1. **Do Tier 2 (the `Codec` trait) regardless** — it pays for itself by deleting the JSON/XDR
   open-coding (`method.rs`), shrinks the N×M maintenance surface, and is the prerequisite that makes
   any future serde-shaped wire cheap. This is the high-confidence, bounded win.
2. **Treat Tier 3 (full interchangeable protocols) as a deliberate, separately-scoped project** —
   `Framing` trait + `dyn ProtocolEngine` + per-engine control plane + codegen backend + a per-engine
   pre-auth security review — and **only greenlight it against a serde-shaped target** (an
   RPC/NFS-style protocol), where the headline machinery actually carries the load.
3. **Do not use AFP as the proof-of-concept.** It exercises only the cheap 20% and would leave the
   expensive, security-sensitive 80% (binary framing, bitmap/offset codec, out-of-band streaming)
   hand-written and outside the spine — making the architecture look validated when its core claim
   (serde + json-idl + codegen carries new protocols) was never tested.

## Critical files (evidence + where the work would land)

- `truenas-rpc/src/method.rs` — the four erased traits with open-coded JSON+XDR method pairs and
  the `DeserializeOwned + Serialize` bound (`:56-101`, `:108-113`, `:262-335`); the `MethodImpl`
  variants (`:595-617`). **The Tier-2 `Codec` refactor lands here.**
- `truenas-rpc/src/protocol.rs` — the two registries + shared `Arc` (`:312-314`, `:387-390`); the
  magic-byte wire fork in `dispatch()` (`:790-801`); `dispatch_xdr`/`dispatch_parsed`; the
  `Dispatched` seam (`:46`). **The Tier-3 `ProtocolEngine` seam lands here.**
- `truenas-rpc-server/src/connection.rs` — `take_frame` hardcoded `u32·blob` (`:71-84`) and the
  write-coalescing fast path (`:112+`). **The Tier-3 `Framing` trait + perf-sensitive path.**
- `truenas-rpc-codegen/src/{lib.rs,model.rs,emit_server.rs}` — three serde-struct emitters, no
  backend trait; XDR as a per-struct derive toggle (`emit_server.rs:96,124`). **A non-serde wire needs
  a new backend + IDL here.**
- `truenas-xdr/src/frame.rs` — the magic-prefixed in-body TXDR frame/envelope (codec/envelope-side
  addressing, not the Framing layer — see FRAMING.md); the existence proof for Tier 1, and the
  natural template for a fixed-record showcase protocol.

## Tier 2 A/B performance comparison (measured)

**Goal.** *Measure*, not assert, the per-dispatch cost of the Tier-2 `Codec` refactor vs today's
open-coded design — so the "generic = free / `dyn` = one negligible hop" claim is backed by numbers.
Built and run 2026-06-27; results below. Harness: `bench/codec_ab/` (untracked, per `rust/.gitignore`'s
`/bench/` rule — same convention as `bench/unix_ab`).

**What Tier 2 changes (the only thing measured).** Today each erased method open-codes the wire:
`ErasedSync::{decode,run}` call `serde_json` directly and `{xdr_decode,xdr_run}` call `truenas_xdr`
directly (`method.rs:115-148`). Tier 2 hoists those into one `Codec` seam. The microbench reuses the
**real** codecs (serde_json + truenas-xdr) and holds everything else constant — same payloads, same
handler, same `decode → Box<dyn Any> → run` split, same single erased-method vtable hop — so the only
variable is how the codec is reached. Four shapes, each erasing the same `Method<A,R,F>`:
- **A** — today: open-coded per-wire methods (`json_*`/`xdr_*`), concrete codec inlined (faithful to
  `ClosureSync`, `method.rs:108-148`).
- **B1** — `Codec` as a generic type param (`impl<C: Codec>`): monomorphizes per (method × codec), like
  today's `A`/`R` generics → expected codegen-identical to A.
- **B2-enum** — one method pair, single registry, `match Wire { Json | Xdr }` inside (a branch).
- **B2-dyn** — one method pair, single registry, payload-generic `&dyn Codec`. A `dyn Codec` cannot
  carry a generic `decode<T>` (object safety), so the realistic design erases the (de)serializer via
  `erased-serde`. *This is the shape the plan called "`&dyn Codec`, one negligible vtable hop."*

**Why a microbenchmark is decisive.** The seam difference is call-shape only, wrapping *identical* serde
work. An end-to-end AF_UNIX run (`bench/unix_ab`) would bury a ~1 ns delta under syscall/framing/authz
cost — so the micro isolates the seam; the e2e is only a systemic-regression backstop.

**Results** — min ns/op, 600k iters × 5 runs, `--release` (`opt-level=3`, `lto`, `codegen-units=1`),
pinned to one core; `std::hint::black_box` on inputs, outputs, and the erased trait objects. Δ vs A:

| payload | wire | op     |  A (ns) |  B1 Δ | B2-enum Δ |  B2-dyn Δ |
|---------|------|--------|--------:|------:|----------:|----------:|
| scalar  | json | decode |     765 | −0.3% |     −0.1% |  **+81%** |
| scalar  | json | rtrip  |     978 | +0.2% |     +0.5% |  **+74%** |
| scalar  | xdr  | decode |     103 | +0.3% |     +2.4% | **+397%** |
| scalar  | xdr  | rtrip  |     299 | +0.4% |     +1.4% | **+210%** |
| bulk    | json | decode |    2560 | +0.5% |     −0.2% | **+103%** |
| bulk    | json | rtrip  |    3312 | +1.8% |     −0.4% | **+110%** |
| bulk    | xdr  | decode |    1034 | −0.2% |     −0.1% | **+232%** |
| bulk    | xdr  | rtrip  |    1765 | −0.1% |     −0.1% | **+190%** |

(scalar = 6 flat fields, 76 B JSON / 36 B XDR; bulk = strings + two vecs, 172 B / 304 B. `decode` =
typed-decode only; `rtrip` = decode → handler → encode.)

**Findings.**
1. **B1 (generic `Codec`) is free.** Within ±2% of today across every cell — monomorphized, so
   codegen-identical to the open-coded path. The plan's "generic = free" holds.
2. **B2-enum (single-registry enum-dispatch) is also free.** Within ±2.5% (the +2.4% is scalar-XDR
   decode, where the ~100 ns baseline makes a ~2 ns branch look large in %). A *single* registry that
   `match`es the wire costs nothing meaningful — you do **not** need per-codec monomorphization to
   collapse the two registries into one.
3. **B2-dyn (payload-generic `&dyn Codec`) is expensive — the plan was wrong on this point.** +74% to
   +397%, not "one negligible hop." A payload-generic `dyn Codec` is not a single vtable call; via
   `erased-serde` it erases the *entire* serde Serializer/Deserializer protocol — many virtual calls per
   field. The hit is worst on XDR (+200…+400%) precisely because XDR's own decode is so cheap (~100 ns)
   that the erasure overhead dominates; on the costlier JSON path it is "only" ~2×.

**Decision rule / recommendation (revised by the data).**
- **Take Tier 2 as B2-enum (preferred) or B1 — both are free.** Either collapses today's hand-kept
  JSON/XDR method-pairs into one seam. B2-enum keeps a *single* registry (no per-codec monomorphization
  bloat) at no measurable cost, so it is the better default; B1 is equivalent where monomorphization is
  wanted for other reasons. This is the high-confidence, bounded win the assessment recommends.
- **Do not put a payload-generic `&dyn Codec` (erased-serde) on the hot path.** If some future need
  wants truly open-ended, runtime-pluggable codecs behind one object, budget a ~2–4× per-dispatch cost —
  or (better) keep the wire set closed and enum-dispatched.
- Behavior parity is guaranteed separately by `cargo test --workspace --all-features` + `./coverage.sh`
  (the JSON/XDR suites are the acceptance spec); the codec seam is behavior-preserving.

**Implemented (2026-06-27) — B2-enum landed in the core.** The open-coded JSON/XDR method-pairs are
collapsed: `ErasedSync`/`ErasedAsync` go from four wire-methods (`decode`/`run` + `xdr_decode`/`xdr_run`)
to one `decode`/`run` pair delegating to a `Codec` (`Json | Xdr`) seam — a `WireParams` in, a `WireReply`
out, with the per-wire serde behind `decode_plain` + `Codec::encode_result`
(`truenas-rpc/src/method.rs`). The four `protocol.rs` dispatch sites pass `WireParams::{Json,Xdr}` /
`Codec::{Json,Xdr}` and unwrap the reply. Adding a third serde-shaped wire is now a new `Codec` arm + a
dispatch entry, not a method-pair on every erasure. Behavior-preserving: `cargo test --workspace
--all-features` green, `./coverage.sh` 100%, `cargo clippy --workspace --all-features --all-targets` clean.

**End-to-end backstop (run 2026-06-27).** Rust `bench/unix_ab` `bench_server` (serves `bench.add` over
both wires), current dispatch vs the Tier-2 dispatch, conns=8 × 30k iters/conn. req/s, before → after:

| mode  | depth | wire | before  | after   |   Δ   |
|-------|-------|------|--------:|--------:|------:|
| async | 16    | xdr  | 350,883 | 346,160 | −1.3% |
| async | 16    | json | 242,493 | 239,402 | −1.3% |
| sync  | 16    | xdr  | 105,437 | 110,496 | +4.8% |
| sync  | 16    | json |  92,925 |  93,538 | +0.7% |
| async |  1    | xdr  |  63,231 |  63,162 | −0.1% |
| async |  1    | json |  56,645 |  54,885 | −3.1% |
| sync  |  1    | xdr  |  46,391 |  44,313 | −4.5% |
| sync  |  1    | json |  39,166 |  38,937 | −0.6% |

All within ±5% with no systematic direction (the sync-XDR rows move opposite ways) — single-run socket
noise, not signal. The seam choice vanishes into systemic wire cost, as the microbench predicted.

**Reproduce.** Microbench: `cd rust/bench/codec_ab && ./run.sh [iters] [runs] [cpu]` (defaults `600000 5`;
its own workspace; deps = `truenas-xdr` + `serde` + `serde_json`, plus `erased-serde` for the B2-dyn arm).
E2e: the Rust rows of `rust/bench/unix_ab/run_xdr_vs_json.sh` (`bench_server` over both wires).
