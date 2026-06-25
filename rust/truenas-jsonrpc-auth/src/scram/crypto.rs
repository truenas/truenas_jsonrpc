//! SCRAM-SHA-512 primitives over the system OpenSSL — the same `libcrypto` the C `truenas_scram`
//! uses, so the derived keys are byte-identical (proven by the known-answer test below).

use openssl::hash::{Hasher, MessageDigest};
use openssl::pkcs5::pbkdf2_hmac;
use openssl::pkey::PKey;
use openssl::sign::Signer;

/// SHA-512 output length (salted-password / keys / signatures are all 64 bytes).
pub const KEY_LEN: usize = 64;

/// `Hi(key, salt, i)` = PBKDF2-HMAC-SHA512 → the 64-byte SaltedPassword.
pub fn salted_password(key: &[u8], salt: &[u8], iterations: u32) -> [u8; KEY_LEN] {
    let mut out = [0u8; KEY_LEN];
    pbkdf2_hmac(key, salt, iterations as usize, MessageDigest::sha512(), &mut out)
        .expect("PBKDF2-HMAC-SHA512");
    out
}

/// `HMAC-SHA512(key, data)` → 64 bytes.
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; KEY_LEN] {
    let pkey = PKey::hmac(key).expect("HMAC key");
    let mut signer = Signer::new(MessageDigest::sha512(), &pkey).expect("HMAC signer");
    signer.update(data).expect("HMAC update");
    signer.sign_to_vec().expect("HMAC sign").try_into().expect("64-byte HMAC")
}

/// `H(data)` = SHA-512 → 64 bytes.
pub fn sha512(data: &[u8]) -> [u8; KEY_LEN] {
    let mut h = Hasher::new(MessageDigest::sha512()).expect("SHA-512 hasher");
    h.update(data).expect("SHA-512 update");
    let d = h.finish().expect("SHA-512 finish");
    d.as_ref().try_into().expect("64-byte digest")
}

/// `a XOR b`, 64 bytes.
pub fn xor(a: &[u8; KEY_LEN], b: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let mut out = [0u8; KEY_LEN];
    for ((o, x), y) in out.iter_mut().zip(a).zip(b) {
        *o = x ^ y;
    }
    out
}

/// Constant-time equality (OpenSSL `CRYPTO_memcmp`). Returns `false` on a length mismatch.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && openssl::memcmp::eq(a, b)
}

/// 32 cryptographically-random bytes (a SCRAM client/server nonce).
pub fn random_nonce() -> [u8; 32] {
    let mut buf = [0u8; 32];
    openssl::rand::rand_bytes(&mut buf).expect("RAND_bytes");
    buf
}

/// Derive the RFC-5802 server-side verifier `(StoredKey, ServerKey)` from raw key material — used
/// to *mint* a credential (and to validate against the known-answer vector). The server stores
/// only these two keys + the salt + iteration count, never the key itself.
pub fn derive_verifier(key: &[u8], salt: &[u8], iterations: u32) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let salted = salted_password(key, salt, iterations);
    let client_key = hmac_sha512(&salted, b"Client Key");
    let stored_key = sha512(&client_key);
    let server_key = hmac_sha512(&salted, b"Server Key");
    (stored_key, server_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::base64::decode_block;

    /// Byte-exact against the TrueNAS C library's known-answer vector
    /// (`pam_truenas/tests/conftest.py`): if PBKDF2-HMAC-SHA512 matches, the whole verifier chain
    /// interoperates with credentials minted by the C library.
    #[test]
    fn pbkdf2_sha512_known_answer() {
        let salt = b"KCwXnX9l35e0ndOu"; // 16 raw bytes
        let key = b"DJpfT7q7dHu6RRfeMwP8aJlGeUOmRWbDKnnzxnsc8F1YAsDNbl8aDM4X1cYwPmcC";
        let expected =
            decode_block("sljMczeiN9kEqyOIrjoQ1QiBhnrmL++DtRdeyv+DHmQkkzoypbkzHIVA1iM/NVviC50dVpDKKlD3L2pv9KDdfw==")
                .unwrap();
        assert_eq!(salted_password(key, salt, 500_000).as_slice(), expected.as_slice());
    }

    #[test]
    fn verify_round_trips_a_self_minted_proof() {
        // Mint a verifier, then run the client side and confirm the server check accepts it.
        let key = b"super-secret-api-key-material";
        let salt = b"0123456789abcdef";
        let (stored_key, server_key) = derive_verifier(key, salt, 4096);

        // Client recomputes ClientKey/StoredKey from the key, signs a fixed AuthMessage.
        let salted = salted_password(key, salt, 4096);
        let client_key = hmac_sha512(&salted, b"Client Key");
        let auth_message = b"n=u,r=abc,r=abcdef,s=...,i=4096,c=biws,r=abcdef";
        let client_sig = hmac_sha512(&sha512(&client_key), auth_message);
        let client_proof = xor(&client_key, &client_sig);

        // Server recovers ClientKey = proof XOR sig and checks H(ClientKey) == StoredKey.
        let server_sig = hmac_sha512(&stored_key, auth_message);
        let recovered = xor(&client_proof, &server_sig);
        assert!(ct_eq(&sha512(&recovered), &stored_key));

        // ServerSignature for the client's mutual-auth check.
        let _v = hmac_sha512(&server_key, auth_message);
    }
}
