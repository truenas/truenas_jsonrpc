//! Parsing / building the RFC-5802 SCRAM message strings (the server side), and the `AuthMessage`.
//! base64 is OpenSSL's (`encode_block`/`decode_block`) — the same the C `truenas_scram` uses.

use openssl::base64::{decode_block, encode_block};

/// The GS2 channel-binding flag from a `client-first-message`.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Cbind {
    /// `p=tls-server-end-point` — the only flag SCRAM-PLUS accepts.
    TlsServerEndPoint,
    /// `n` — the client doesn't use channel binding.
    NotUsed,
    /// `y` — the client would, but believed the server wouldn't (a downgrade signal).
    Downgrade,
}

/// A parsed `client-first-message`.
pub(super) struct ClientFirst {
    /// The verbatim GS2 header prefix (`"<flag>,<authzid>,"`) — the cbind-input the client-final's
    /// `c=` must echo (plus the channel-binding data).
    pub gs2_header: String,
    /// The channel-binding flag.
    pub cbind: Cbind,
    /// The `n=` username (still escaped, possibly carrying `:api_key_id`).
    pub username_raw: String,
    /// The `r=` client nonce (base64).
    pub client_nonce_b64: String,
    /// The `client-first-message-bare` (`n=…,r=…`) — used verbatim in the `AuthMessage`.
    pub bare: String,
}

/// SASL-unescape a `saslname` (`=2C` → `,`, `=3D` → `=`) for credential lookup. (The wire/AuthMessage
/// form stays escaped.)
pub(super) fn unescape_username(s: &str) -> String {
    s.replace("=2C", ",").replace("=3D", "=")
}

pub(super) fn parse_client_first(s: &str) -> Option<ClientFirst> {
    // <gs2-cbind-flag>,<authzid?>,<client-first-message-bare>
    let mut it = s.splitn(3, ',');
    let flag = it.next()?;
    let _authzid = it.next()?;
    let bare = it.next()?;
    let gs2_header = s.get(..s.len() - bare.len())?.to_string();

    let cbind = match flag {
        "n" => Cbind::NotUsed,
        "y" => Cbind::Downgrade,
        "p=tls-server-end-point" => Cbind::TlsServerEndPoint,
        _ => return None, // unknown flag / a different p=binding
    };

    let mut username = None;
    let mut nonce = None;
    for tok in bare.split(',') {
        if let Some(v) = tok.strip_prefix("n=") {
            username = Some(v.to_string());
        } else if let Some(v) = tok.strip_prefix("r=") {
            nonce = Some(v.to_string());
        }
    }
    Some(ClientFirst {
        gs2_header,
        cbind,
        username_raw: username?,
        client_nonce_b64: nonce?,
        bare: bare.to_string(),
    })
}

/// Build the `server-first-message` `r=…,s=…,i=…`, returning it plus the combined-nonce base64 (the
/// `r=` value the client-final must echo). The combined nonce is `raw(client) ++ raw(server)`.
pub(super) fn server_first(
    client_nonce_b64: &str,
    server_nonce: &[u8; 32],
    salt: &[u8],
    iterations: u32,
) -> Option<(String, String)> {
    let mut combined = decode_block(client_nonce_b64).ok()?;
    combined.extend_from_slice(server_nonce);
    let combined_b64 = encode_block(&combined);
    let msg = format!("r={combined_b64},s={},i={iterations}", encode_block(salt));
    Some((msg, combined_b64))
}

/// A parsed `client-final-message`.
pub(super) struct ClientFinal {
    /// `c=` — base64 of the cbind-input (gs2-header ++ channel-binding data).
    pub cbind_b64: String,
    /// `r=` — the combined nonce (must equal the server-first's).
    pub nonce_b64: String,
    /// `p=` — the base64 ClientProof.
    pub proof_b64: String,
    /// `client-final-message-without-proof` (`c=…,r=…`) — used in the `AuthMessage`.
    pub without_proof: String,
}

pub(super) fn parse_client_final(s: &str) -> Option<ClientFinal> {
    let mut c = None;
    let mut r = None;
    let mut p = None;
    for tok in s.split(',') {
        if let Some(v) = tok.strip_prefix("c=") {
            c = Some(v.to_string());
        } else if let Some(v) = tok.strip_prefix("r=") {
            r = Some(v.to_string());
        } else if let Some(v) = tok.strip_prefix("p=") {
            p = Some(v.to_string());
        }
    }
    let without_proof = s.get(..s.rfind(",p=")?)?.to_string();
    Some(ClientFinal {
        cbind_b64: c?,
        nonce_b64: r?,
        proof_b64: p?,
        without_proof,
    })
}

/// `AuthMessage = client-first-bare "," server-first "," client-final-without-proof`.
pub(super) fn auth_message(
    client_first_bare: &str,
    server_first: &str,
    client_final_without_proof: &str,
) -> String {
    format!("{client_first_bare},{server_first},{client_final_without_proof}")
}
