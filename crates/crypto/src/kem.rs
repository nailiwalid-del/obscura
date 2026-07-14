//! KEM hybride : X25519 (courbes elliptiques) + ML-KEM-768 (réseaux euclidiens, FIPS 203).
//! Le secret partagé combine les deux via KDF sur le transcript complet :
//! il reste sûr tant que L'UN des deux problèmes sous-jacents tient.

use crate::CryptoError;
use pqcrypto_kyber::kyber768 as mlkem768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

pub const X25519_PK_LEN: usize = 32;

/// Identifiant d'algorithme (versioning explicite : la migration round-3 → FIPS 203
/// n'est pas transparente ; deux versions peuvent cohabiter sur la chaîne).
pub const KEM_ALGO_ID: &str = "x25519+kyber768-round3";
pub const KEM_ALGO_VERSION: u8 = 0x01;

#[derive(Clone)]
pub struct KemPublicKey {
    pub x25519: [u8; 32],
    pub mlkem: mlkem768::PublicKey,
}

pub struct KemSecretKey {
    x25519: StaticSecret,
    mlkem: mlkem768::SecretKey,
}

pub struct KemKeypair {
    pub public: KemPublicKey,
    pub secret: KemSecretKey,
}

#[derive(Clone)]
pub struct KemCiphertext {
    pub x25519_eph: [u8; 32],
    pub mlkem_ct: mlkem768::Ciphertext,
}

impl KemKeypair {
    pub fn generate() -> Self {
        let mut xb = [0u8; 32];
        OsRng.fill_bytes(&mut xb);
        let xsk = StaticSecret::from(xb);
        let xpk = XPublicKey::from(&xsk);
        let (mpk, msk) = mlkem768::keypair();
        KemKeypair {
            public: KemPublicKey {
                x25519: *xpk.as_bytes(),
                mlkem: mpk,
            },
            secret: KemSecretKey {
                x25519: xsk,
                mlkem: msk,
            },
        }
    }
}

/// Combine les deux secrets en liant tout le transcript (clés publiques + ciphertexts) :
/// empêche les attaques par mélange de sessions.
fn combine(ss1: &[u8], ss2: &[u8], eph_pk: &[u8], mlkem_ct: &[u8], pk: &KemPublicKey) -> [u8; 32] {
    let mut t =
        Vec::with_capacity(ss1.len() + ss2.len() + eph_pk.len() + mlkem_ct.len() + 32 + 1184);
    t.extend_from_slice(ss1);
    t.extend_from_slice(ss2);
    t.extend_from_slice(eph_pk);
    t.extend_from_slice(mlkem_ct);
    t.extend_from_slice(&pk.x25519);
    t.extend_from_slice(pk.mlkem.as_bytes());
    t.push(KEM_ALGO_VERSION);
    crate::hash::derive_key("obscura/kem/x25519+kyber768-round3/combine/v2", &t)
}

/// Encapsule vers `pk` : retourne (ciphertext, secret partagé 32 o).
pub fn encapsulate(pk: &KemPublicKey) -> (KemCiphertext, [u8; 32]) {
    let mut eb = [0u8; 32];
    OsRng.fill_bytes(&mut eb);
    let esk = StaticSecret::from(eb);
    let epk = XPublicKey::from(&esk);
    let ss1 = esk.diffie_hellman(&XPublicKey::from(pk.x25519));
    let (ss2, ct2) = mlkem768::encapsulate(&pk.mlkem);
    let ss = combine(
        ss1.as_bytes(),
        ss2.as_bytes(),
        epk.as_bytes(),
        ct2.as_bytes(),
        pk,
    );
    (
        KemCiphertext {
            x25519_eph: *epk.as_bytes(),
            mlkem_ct: ct2,
        },
        ss,
    )
}

/// Décapsule avec la paire de clés du destinataire.
pub fn decapsulate(kp: &KemKeypair, ct: &KemCiphertext) -> [u8; 32] {
    let ss1 = kp
        .secret
        .x25519
        .diffie_hellman(&XPublicKey::from(ct.x25519_eph));
    let ss2 = mlkem768::decapsulate(&ct.mlkem_ct, &kp.secret.mlkem);
    combine(
        ss1.as_bytes(),
        ss2.as_bytes(),
        &ct.x25519_eph,
        ct.mlkem_ct.as_bytes(),
        &kp.public,
    )
}

impl KemPublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = vec![KEM_ALGO_VERSION];
        v.extend_from_slice(&self.x25519);
        v.extend_from_slice(self.mlkem.as_bytes());
        v
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        if b.len() != 1 + 32 + mlkem768::public_key_bytes() || b[0] != KEM_ALGO_VERSION {
            return Err(CryptoError::InvalidEncoding("KemPublicKey"));
        }
        let mut x = [0u8; 32];
        x.copy_from_slice(&b[1..33]);
        let m = mlkem768::PublicKey::from_bytes(&b[33..])
            .map_err(|_| CryptoError::InvalidEncoding("mlkem pk"))?;
        Ok(KemPublicKey {
            x25519: x,
            mlkem: m,
        })
    }
}

impl KemCiphertext {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = vec![KEM_ALGO_VERSION];
        v.extend_from_slice(&self.x25519_eph);
        v.extend_from_slice(self.mlkem_ct.as_bytes());
        v
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        if b.len() != 1 + 32 + mlkem768::ciphertext_bytes() || b[0] != KEM_ALGO_VERSION {
            return Err(CryptoError::InvalidEncoding("KemCiphertext"));
        }
        let mut x = [0u8; 32];
        x.copy_from_slice(&b[1..33]);
        let m = mlkem768::Ciphertext::from_bytes(&b[33..])
            .map_err(|_| CryptoError::InvalidEncoding("mlkem ct"))?;
        Ok(KemCiphertext {
            x25519_eph: x,
            mlkem_ct: m,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let kp = KemKeypair::generate();
        let (ct, ss_a) = encapsulate(&kp.public);
        let ss_b = decapsulate(&kp, &ct);
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn mauvaise_cle_donne_secret_different() {
        let kp1 = KemKeypair::generate();
        let kp2 = KemKeypair::generate();
        let (ct, ss_a) = encapsulate(&kp1.public);
        let ss_mauvais = decapsulate(
            &kp2,
            &KemCiphertext {
                x25519_eph: ct.x25519_eph,
                mlkem_ct: ct.mlkem_ct.clone(),
            },
        );
        assert_ne!(ss_a, ss_mauvais);
    }

    #[test]
    fn serialisation() {
        let kp = KemKeypair::generate();
        let (ct, _) = encapsulate(&kp.public);
        let pk2 = KemPublicKey::from_bytes(&kp.public.to_bytes()).unwrap();
        let ct2 = KemCiphertext::from_bytes(&ct.to_bytes()).unwrap();
        assert_eq!(pk2.x25519, kp.public.x25519);
        assert_eq!(ct2.to_bytes(), ct.to_bytes());
    }
}
