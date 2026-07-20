//! Signature hybride : Ed25519 + Dilithium3 (round-3, byte 0x01).
//! La vérification exige que LES DEUX signatures soient valides :
//! forger exige de casser les courbes elliptiques ET les réseaux euclidiens.

use crate::CryptoError;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use rand_core::{OsRng, RngCore};

pub const ED25519_SIG_LEN: usize = 64;

/// Identifiant d'algorithme (versioning explicite, cf. kem.rs).
pub const SIG_ALGO_ID: &str = "ed25519+dilithium3-round3";
pub const SIG_ALGO_VERSION: u8 = 0x01;

#[derive(Clone)]
pub struct SigPublicKey {
    pub ed25519: VerifyingKey,
    pub dilithium: dilithium3::PublicKey,
}

pub struct SigKeypair {
    pub public: SigPublicKey,
    ed25519: SigningKey,
    dilithium: dilithium3::SecretKey,
}

#[derive(Clone)]
pub struct HybridSignature {
    pub ed25519: Signature,
    pub dilithium: dilithium3::DetachedSignature,
}

impl SigKeypair {
    pub fn generate() -> Self {
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        let esk = SigningKey::from_bytes(&b);
        let epk = esk.verifying_key();
        let (mpk, msk) = dilithium3::keypair();
        SigKeypair {
            public: SigPublicKey {
                ed25519: epk,
                dilithium: mpk,
            },
            ed25519: esk,
            dilithium: msk,
        }
    }

    /// Signe avec les deux algorithmes (message préfixé par domaine).
    pub fn sign(&self, domain: &str, msg: &[u8]) -> HybridSignature {
        let m = frame(domain, msg);
        HybridSignature {
            ed25519: self.ed25519.sign(&m),
            dilithium: dilithium3::detached_sign(&m, &self.dilithium),
        }
    }
}

fn frame(domain: &str, msg: &[u8]) -> Vec<u8> {
    let mut m = (domain.len() as u64).to_le_bytes().to_vec();
    m.extend_from_slice(domain.as_bytes());
    m.extend_from_slice(&(SIG_ALGO_ID.len() as u64).to_le_bytes());
    m.extend_from_slice(SIG_ALGO_ID.as_bytes());
    m.extend_from_slice(msg);
    m
}

/// Valide si et seulement si LES DEUX signatures sont valides.
pub fn verify(pk: &SigPublicKey, domain: &str, msg: &[u8], sig: &HybridSignature) -> bool {
    let m = frame(domain, msg);
    // `verify_strict` : rejette les S non canoniques et les clés d'ordre faible,
    // fermant la malléabilité de signature d'Ed25519 (RFC 8032 §5.4.5 / §8).
    let ed_ok = pk.ed25519.verify_strict(&m, &sig.ed25519).is_ok();
    let pq_ok = dilithium3::verify_detached_signature(&sig.dilithium, &m, &pk.dilithium).is_ok();
    ed_ok && pq_ok
}

impl SigPublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = vec![SIG_ALGO_VERSION];
        v.extend_from_slice(&self.ed25519.to_bytes());
        v.extend_from_slice(self.dilithium.as_bytes());
        v
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        if b.len() != 1 + 32 + dilithium3::public_key_bytes() || b[0] != SIG_ALGO_VERSION {
            return Err(CryptoError::InvalidEncoding("SigPublicKey"));
        }
        let mut e = [0u8; 32];
        e.copy_from_slice(&b[1..33]);
        let ed =
            VerifyingKey::from_bytes(&e).map_err(|_| CryptoError::InvalidEncoding("ed25519 pk"))?;
        let ml = dilithium3::PublicKey::from_bytes(&b[33..])
            .map_err(|_| CryptoError::InvalidEncoding("dilithium pk"))?;
        Ok(SigPublicKey {
            ed25519: ed,
            dilithium: ml,
        })
    }
}

impl HybridSignature {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = vec![SIG_ALGO_VERSION];
        v.extend_from_slice(&self.ed25519.to_bytes());
        v.extend_from_slice(self.dilithium.as_bytes());
        v
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        if b.len() != 1 + ED25519_SIG_LEN + dilithium3::signature_bytes() || b[0] != SIG_ALGO_VERSION {
            return Err(CryptoError::InvalidEncoding("HybridSignature"));
        }
        let mut e = [0u8; 64];
        e.copy_from_slice(&b[1..65]);
        let ml = dilithium3::DetachedSignature::from_bytes(&b[65..])
            .map_err(|_| CryptoError::InvalidEncoding("dilithium sig"))?;
        Ok(HybridSignature {
            ed25519: Signature::from_bytes(&e),
            dilithium: ml,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let kp = SigKeypair::generate();
        let sig = kp.sign("test/v1", b"message");
        assert!(verify(&kp.public, "test/v1", b"message", &sig));
        assert!(!verify(&kp.public, "test/v1", b"messagf", &sig));
        assert!(!verify(&kp.public, "autre/v1", b"message", &sig));
    }

    #[test]
    fn mauvaise_cle_rejette() {
        let kp1 = SigKeypair::generate();
        let kp2 = SigKeypair::generate();
        let sig = kp1.sign("test/v1", b"message");
        assert!(!verify(&kp2.public, "test/v1", b"message", &sig));
    }

    #[test]
    fn signature_partielle_rejetee() {
        // Une signature dont SEULE la partie Ed25519 est valide doit être rejetée.
        let kp = SigKeypair::generate();
        let sig_a = kp.sign("test/v1", b"message");
        let sig_b = kp.sign("test/v1", b"autre message");
        let hybride_invalide = HybridSignature {
            ed25519: sig_a.ed25519,
            dilithium: sig_b.dilithium,
        };
        assert!(!verify(
            &kp.public,
            "test/v1",
            b"message",
            &hybride_invalide
        ));
    }

    #[test]
    fn serialisation() {
        let kp = SigKeypair::generate();
        let sig = kp.sign("test/v1", b"m");
        let pk2 = SigPublicKey::from_bytes(&kp.public.to_bytes()).unwrap();
        let sig2 = HybridSignature::from_bytes(&sig.to_bytes()).unwrap();
        assert!(verify(&pk2, "test/v1", b"m", &sig2));
    }
}
