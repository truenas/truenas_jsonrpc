//! Rule-of-two: a **second, non-JSON-RPC** [`ProtocolRuntime`] driven by the *same* generic
//! [`Client`] engine — proving the engine holds no JSON-RPC assumptions. This mock addresses methods
//! by a `u32` op-code, correlates replies by a `u64`, frames with a **little-endian** length prefix
//! (JSON-RPC's is big-endian), speaks a trivial binary wire, and implements **no** optional
//! capabilities (no negotiate/auth/subscribe/close). If the engine round-trips a call over it, the
//! neutral core is honest.

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use truenas_rpc_client::{
    Client, ClientConfig, ClientError, Endpoint, Framing, Inbound, ProtocolRuntime,
};

/// A 4-byte **little-endian** length prefix (deliberately unlike JSON-RPC's big-endian one).
struct MockFraming;
impl Framing for MockFraming {
    fn take_frame(&self, acc: &mut BytesMut, limit: usize) -> Result<Option<Vec<u8>>, ClientError> {
        if acc.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_le_bytes([acc[0], acc[1], acc[2], acc[3]]) as usize;
        if len > limit {
            return Err(ClientError::Decode(format!(
                "mock frame {len} > limit {limit}"
            )));
        }
        if acc.len() < 4 + len {
            return Ok(None);
        }
        let _ = acc.split_to(4);
        Ok(Some(acc.split_to(len).to_vec()))
    }
    fn frame_into(&self, out: &mut Vec<u8>, payload: &[u8]) {
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
    }
}

/// The mock runtime. Request wire: `[key: u64 LE][op: u32 LE][params]`. Reply wire: `[key: u64 LE]
/// [result]`. No prefix trickery — one connection, so the raw sequence number is a fine key.
#[derive(Default)]
struct MockRuntime {
    framing: MockFraming,
}
impl Default for MockFraming {
    fn default() -> Self {
        MockFraming
    }
}

impl ProtocolRuntime for MockRuntime {
    type MethodKey = u32;
    type CorrelationKey = u64;
    type Topic = ();
    type Framing = MockFraming;

    fn framing(&self) -> &MockFraming {
        &self.framing
    }
    fn key_for_seq(&self, seq: u64) -> u64 {
        seq
    }
    fn encode_call(&self, method: &u32, params: &[u8], key: &u64) -> Vec<u8> {
        let mut w = Vec::with_capacity(12 + params.len());
        w.extend_from_slice(&key.to_le_bytes());
        w.extend_from_slice(&method.to_le_bytes());
        w.extend_from_slice(params);
        w
    }
    fn parse_inbound(&self, frame: &[u8]) -> Result<Inbound<Self>, ClientError> {
        if frame.len() < 8 {
            return Err(ClientError::Decode("mock reply too short".into()));
        }
        let key = u64::from_le_bytes(frame[..8].try_into().unwrap());
        Ok(Inbound::Reply {
            key,
            result: Ok(frame[8..].to_vec()),
        })
    }
}

/// A raw-tokio "server" for the mock wire: read a `[len LE][key op params]` frame, reply with
/// `[len LE][key params]` — echoing the key (so the engine correlates) and the params (so the test
/// can assert the round-trip). No framework anywhere.
async fn mock_serve(listener: UnixListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let mut acc: Vec<u8> = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                while acc.len() >= 4 {
                    let len = u32::from_le_bytes([acc[0], acc[1], acc[2], acc[3]]) as usize;
                    if acc.len() < 4 + len {
                        break;
                    }
                    let body = &acc[4..4 + len];
                    let (key, params) = (&body[0..8], &body[12..]); // skip key(8)+op(4)
                    let mut reply = Vec::with_capacity(8 + params.len());
                    reply.extend_from_slice(key);
                    reply.extend_from_slice(params);
                    let mut framed = (reply.len() as u32).to_le_bytes().to_vec();
                    framed.extend_from_slice(&reply);
                    if stream.write_all(&framed).await.is_err() {
                        return;
                    }
                    acc.drain(..4 + len);
                }
                match stream.read(&mut tmp).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => acc.extend_from_slice(&tmp[..n]),
                }
            }
        });
    }
}

#[tokio::test]
async fn mock_runtime_round_trips_through_the_neutral_engine() {
    let path = std::env::temp_dir().join(format!("tnrpc-mock-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap(); // bound before we connect
    tokio::spawn(mock_serve(listener));

    let (client, _notifs) = Client::connect(
        MockRuntime::default(),
        &Endpoint::unix(&path),
        ClientConfig::default(),
    )
    .await
    .unwrap();

    // Two calls: each draws its own sequence key, so correct correlation is what returns the right
    // echo. Method key is a bare `u32` op-code — no method *name* anywhere.
    assert_eq!(client.call(&7u32, b"hello").await.unwrap(), b"hello");
    assert_eq!(client.call(&42u32, b"world").await.unwrap(), b"world");

    let _ = std::fs::remove_file(&path);
}
