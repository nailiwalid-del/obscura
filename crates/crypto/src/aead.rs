//! Chiffrement authentifié en cascade : XChaCha20-Poly1305( AES-256-GCM(m) ).
//! Deux familles de chiffrement indépendantes (ARX vs réseau de substitution-permutation),
//! clés indépendantes dérivées par KDF : la confidentialité tient si L'UN des deux tient.

use crate::CryptoError;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};

const AES_NONCE_LEN: usize = 12;
const XCHACHA_NONCE_LEN: usize = 24;

fn keys(master: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    (
        crate::hash::derive_key("obscura/aead/aes256gcm/v1", master),
        crate::hash::derive_key("obscura/aead/xchacha20/v1", master),
    )
}

/// Chiffre `plaintext` (avec données associées `aad`) sous la clé maître.
pub fn encrypt(master: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let (k_aes, k_xc) = keys(master);

    // Couche interne : AES-256-GCM
    let aes = Aes256Gcm::new_from_slice(&k_aes).expect("taille de clé");
    let mut n1 = [0u8; AES_NONCE_LEN];
    OsRng.fill_bytes(&mut n1);
    let inner = aes
        .encrypt(
            Nonce::from_slice(&n1),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("chiffrement AES");

    // Couche externe : XChaCha20-Poly1305 sur (nonce1 ‖ inner)
    let mut wrapped = n1.to_vec();
    wrapped.extend_from_slice(&inner);
    let xc = XChaCha20Poly1305::new_from_slice(&k_xc).expect("taille de clé");
    let mut n2 = [0u8; XCHACHA_NONCE_LEN];
    OsRng.fill_bytes(&mut n2);
    let outer = xc
        .encrypt(XNonce::from_slice(&n2), Payload { msg: &wrapped, aad })
        .expect("chiffrement XChaCha");

    let mut out = n2.to_vec();
    out.extend_from_slice(&outer);
    out
}

/// Déchiffre. Échoue si l'une OU l'autre des couches détecte une altération.
pub fn decrypt(master: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < XCHACHA_NONCE_LEN + 16 {
        return Err(CryptoError::DecryptionFailed);
    }
    let (k_aes, k_xc) = keys(master);

    let (n2, outer) = ciphertext.split_at(XCHACHA_NONCE_LEN);
    let xc = XChaCha20Poly1305::new_from_slice(&k_xc).expect("taille de clé");
    let wrapped = xc
        .decrypt(XNonce::from_slice(n2), Payload { msg: outer, aad })
        .map_err(|_| CryptoError::DecryptionFailed)?;

    if wrapped.len() < AES_NONCE_LEN + 16 {
        return Err(CryptoError::DecryptionFailed);
    }
    let (n1, inner) = wrapped.split_at(AES_NONCE_LEN);
    let aes = Aes256Gcm::new_from_slice(&k_aes).expect("taille de clé");
    aes.decrypt(Nonce::from_slice(n1), Payload { msg: inner, aad })
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let k = [7u8; 32];
        let ct = encrypt(&k, b"aad", b"secret");
        assert_eq!(decrypt(&k, b"aad", &ct).unwrap(), b"secret");
    }

    #[test]
    fn alteration_detectee() {
        let k = [7u8; 32];
        let mut ct = encrypt(&k, b"aad", b"secret");
        let dernier = ct.len() - 1;
        ct[dernier] ^= 1;
        assert!(decrypt(&k, b"aad", &ct).is_err());
    }

    #[test]
    fn mauvaise_cle_ou_aad_rejetee() {
        let k = [7u8; 32];
        let ct = encrypt(&k, b"aad", b"secret");
        assert!(decrypt(&[8u8; 32], b"aad", &ct).is_err());
        assert!(decrypt(&k, b"autre", &ct).is_err());
    }

    #[test]
    fn non_deterministe() {
        let k = [7u8; 32];
        assert_ne!(encrypt(&k, b"", b"m"), encrypt(&k, b"", b"m"));
    }
}
