//! SCRAM-SHA-512-**PLUS** client mechanism (the `scram` feature). Two rounds over `$/sessionSetup` /
//! `$/sessionSetupContinue`: client-first → server-first (challenge), client-final → server-final
//! (success). Channel binding is **mandatory** (`p=tls-server-end-point`), so it only runs over a TLS
//! transport whose [`Client::channel_binding`] is present; the client's `c=` echoes that binding, and
//! the server's mutual-auth `v=` is verified on success.
//!
//! The crypto primitives are duplicated from `truenas-rpc-auth`'s server-side SCRAM (that crate pulls
//! `truenas-rpc-server`, so the client can't depend on it) — RFC-fixed and guarded by the same
//! known-answer vector as the C `truenas_scram`, so the derived keys stay byte-identical.

use openssl::base64::{decode_block, encode_block};
use openssl::hash::{Hasher, MessageDigest};
use openssl::pkcs5::pbkdf2_hmac;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use serde_json::{json, Value};

use crate::auth::{AuthOutcome, Mechanism};
use crate::engine::{Authenticates, Client};
use crate::error::ClientError;

/// The GS2 header for SCRAM-PLUS (`tls-server-end-point` binding, no authzid).
const GS2: &str = "p=tls-server-end-point,,";

impl<P: Authenticates> Client<P> {
    /// SCRAM-SHA-512-PLUS login as `username` with `password` (the raw secret bytes). Requires a TLS
    /// transport (the exchange binds to `tls-server-end-point`), so it errors with
    /// [`ClientError::Auth`] on a plaintext connection; on success the server's mutual-auth signature
    /// is verified. Returns the [`AuthOutcome`] (a wrong password is a server refusal → `AuthErr`).
    pub async fn authenticate_scram(
        &self,
        username: &str,
        password: &[u8],
    ) -> Result<AuthOutcome, ClientError> {
        let binding = self.channel_binding().ok_or_else(|| {
            ClientError::Auth(
                "SCRAM-PLUS requires a TLS transport with a channel binding (use tls:// or wss://)"
                    .to_string(),
            )
        })?;
        let scram = ScramClient::new(username, password, binding);
        self.authenticate_with(scram).await
    }
}

/// A SCRAM-SHA-512-PLUS client mechanism, bound to the connection's `tls-server-end-point`.
struct ScramClient {
    username: String,
    password: Vec<u8>,
    channel_binding: Vec<u8>,
    nonce_b64: String,
    // The `v=…` we expect the server to return, computed at client-final (for mutual auth).
    expected_server_final: Option<String>,
}

impl ScramClient {
    fn new(username: &str, password: &[u8], channel_binding: &[u8]) -> Self {
        let mut nonce = [0u8; 32];
        openssl::rand::rand_bytes(&mut nonce).expect("RAND_bytes");
        ScramClient {
            username: escape(username),
            password: password.to_vec(),
            channel_binding: channel_binding.to_vec(),
            nonce_b64: encode_block(&nonce),
            expected_server_final: None,
        }
    }
}

impl Mechanism for ScramClient {
    fn first(&mut self) -> Result<Value, ClientError> {
        // client-first = GS2 header + client-first-bare.
        let msg = format!("{GS2}n={},r={}", self.username, self.nonce_b64);
        Ok(json!({ "mechanism": "SCRAM", "message": msg }))
    }

    fn respond(&mut self, data: &Value) -> Result<Value, ClientError> {
        let server_first = data
            .get("message")
            .and_then(Value::as_str)
            .ok_or_else(|| ClientError::Auth("challenge missing the SCRAM server-first".into()))?;

        // The server returns `r=` as base64(raw-client-nonce ++ raw-server-nonce), so it echoes our
        // nonce in the first 32 raw bytes; use its combined value verbatim in the AuthMessage.
        let (combined, salt_b64, iters) = parse_server_first(server_first)?;
        let salt =
            decode_block(&salt_b64).map_err(|e| ClientError::Auth(format!("bad SCRAM salt: {e}")))?;

        // c= is base64(GS2-header + channel-binding); this is what binds the exchange to the channel.
        let mut cbind = GS2.as_bytes().to_vec();
        cbind.extend_from_slice(&self.channel_binding);
        let c = encode_block(&cbind);
        let bare = format!("n={},r={}", self.username, self.nonce_b64);
        let without_proof = format!("c={c},r={combined}");
        let auth_message = format!("{bare},{server_first},{without_proof}");

        let salted = salted_password(&self.password, &salt, iters);
        let client_key = hmac_sha512(&salted, b"Client Key");
        let stored_key = sha512(&client_key);
        let client_sig = hmac_sha512(&stored_key, auth_message.as_bytes());
        let proof = xor64(&client_key, &client_sig);

        // The server proves knowledge of ServerKey with `v=`; precompute what we expect.
        let server_key = hmac_sha512(&salted, b"Server Key");
        let server_sig = hmac_sha512(&server_key, auth_message.as_bytes());
        self.expected_server_final = Some(format!("v={}", encode_block(&server_sig)));

        let client_final = format!("{without_proof},p={}", encode_block(&proof));
        Ok(json!({ "mechanism": "SCRAM", "message": client_final }))
    }

    fn verify(&mut self, extra: Option<&Value>) -> Result<(), ClientError> {
        let got = extra
            .and_then(|e| e.get("scram"))
            .and_then(Value::as_str)
            .ok_or_else(|| ClientError::Auth("success missing the SCRAM server-final".into()))?;
        let expected = self
            .expected_server_final
            .as_deref()
            .ok_or_else(|| ClientError::Auth("no server signature was expected".into()))?;
        // Constant-time compare the `v=…` strings (mutual auth: the server knows the credential).
        // Guard the length first — `openssl::memcmp::eq` panics on a length mismatch, so a server
        // returning a wrong-length `v=` must be rejected here, not allowed to abort the process.
        if got.len() == expected.len() && openssl::memcmp::eq(got.as_bytes(), expected.as_bytes()) {
            Ok(())
        } else {
            Err(ClientError::Auth("server signature mismatch (mutual auth failed)".into()))
        }
    }
}

/// Parse a SCRAM server-first message into `(combined-nonce, salt-b64, iterations)`.
fn parse_server_first(msg: &str) -> Result<(String, String, u32), ClientError> {
    let (mut r, mut s, mut i) = (None, None, None);
    for tok in msg.split(',') {
        if let Some(v) = tok.strip_prefix("r=") {
            r = Some(v.to_string());
        } else if let Some(v) = tok.strip_prefix("s=") {
            s = Some(v.to_string());
        } else if let Some(v) = tok.strip_prefix("i=") {
            i = v.parse().ok();
        }
    }
    match (r, s, i) {
        (Some(r), Some(s), Some(i)) if i > 0 => Ok((r, s, i)),
        _ => Err(ClientError::Auth(format!("malformed SCRAM server-first: {msg:?}"))),
    }
}

/// RFC 5802 SASLprep-lite: escape `=`→`=3D` then `,`→`=2C` in a username (order matters).
fn escape(username: &str) -> String {
    username.replace('=', "=3D").replace(',', "=2C")
}

// --- crypto primitives (duplicated from truenas-rpc-auth/scram/crypto.rs; KAT-guarded below) ------

/// `Hi(key, salt, i)` = PBKDF2-HMAC-SHA512 → the 64-byte SaltedPassword.
fn salted_password(key: &[u8], salt: &[u8], iterations: u32) -> [u8; 64] {
    let mut out = [0u8; 64];
    pbkdf2_hmac(key, salt, iterations as usize, MessageDigest::sha512(), &mut out)
        .expect("PBKDF2-HMAC-SHA512");
    out
}

/// `HMAC-SHA512(key, data)` → 64 bytes.
fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let pkey = PKey::hmac(key).expect("HMAC key");
    let mut signer = Signer::new(MessageDigest::sha512(), &pkey).expect("HMAC signer");
    signer.update(data).expect("HMAC update");
    signer.sign_to_vec().expect("HMAC sign").try_into().expect("64-byte HMAC")
}

/// `H(data)` = SHA-512 → 64 bytes.
fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h = Hasher::new(MessageDigest::sha512()).expect("SHA-512 hasher");
    h.update(data).expect("SHA-512 update");
    h.finish().expect("SHA-512 finish").as_ref().try_into().expect("64-byte digest")
}

/// `a XOR b`, 64 bytes.
fn xor64(a: &[u8; 64], b: &[u8; 64]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for ((o, x), y) in out.iter_mut().zip(a).zip(b) {
        *o = x ^ y;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-exact against the TrueNAS C library's known-answer vector (the same guard the server-side
    /// crypto uses), so a verifier minted by the C library authenticates this client.
    #[test]
    fn pbkdf2_sha512_known_answer() {
        let salt = b"KCwXnX9l35e0ndOu";
        let key = b"DJpfT7q7dHu6RRfeMwP8aJlGeUOmRWbDKnnzxnsc8F1YAsDNbl8aDM4X1cYwPmcC";
        let expected = decode_block(
            "sljMczeiN9kEqyOIrjoQ1QiBhnrmL++DtRdeyv+DHmQkkzoypbkzHIVA1iM/NVviC50dVpDKKlD3L2pv9KDdfw==",
        )
        .unwrap();
        assert_eq!(salted_password(key, salt, 500_000).as_slice(), expected.as_slice());
    }

    #[test]
    fn username_escaping() {
        assert_eq!(escape("a,b=c"), "a=2Cb=3Dc");
    }

    /// A well-formed server-first for a fresh `ScramClient` (echoes its nonce, a valid salt + iters).
    fn drive(client: &mut ScramClient) {
        let _first = client.first().unwrap();
        let server_first =
            format!("r={}srv,s={},i=4096", client.nonce_b64, encode_block(b"some-salt-bytes"));
        client.respond(&json!({ "message": server_first })).unwrap();
    }

    #[test]
    fn verify_rejects_a_wrong_or_missing_server_final() {
        let mut c = ScramClient::new("alice", b"key", b"binding");
        drive(&mut c);
        // A wrong server signature is a mutual-auth failure (the client refuses).
        assert!(c.verify(Some(&json!({ "scram": "v=not-the-right-signature" }))).is_err());
        // A success with no server-final at all is also refused.
        assert!(c.verify(None).is_err());
    }

    #[test]
    fn respond_rejects_a_malformed_server_first() {
        let mut c = ScramClient::new("alice", b"key", b"binding");
        let _ = c.first().unwrap();
        // Missing the iteration count → not a usable server-first.
        assert!(c.respond(&json!({ "message": "r=abc,s=c2FsdA==" })).is_err());
        // Missing the `message` field entirely.
        assert!(c.respond(&json!({})).is_err());
    }
}
