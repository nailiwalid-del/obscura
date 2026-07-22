//! Signature hybride : Ed25519 + ML-DSA-65 (FIPS 204, byte 0x02).
//! La vérification exige que LES DEUX signatures soient valides :
//! forger exige de casser les courbes elliptiques ET les réseaux euclidiens.
//!
//! Migration T1 (plan Testnet 0) : la version round-3 (Dilithium3, 0x01) est
//! REFUSÉE PAR SON NOM (`CryptoError::AlgoPerime`), jamais réinterprétée. La
//! signature grossit de 16 o (3309 vs 3293) — sous tous les majorants du dépôt.
//!
//! Zeroize : la moitié Ed25519 (`SigningKey` dalek) s'efface au drop ; la moitié
//! ML-DSA est stockée en `Zeroizing<Vec<u8>>` et le type pqcrypto RECONSTRUIT à
//! chaque signature (repli T1.5 — pqcrypto-mldsa n'expose pas de zeroize).

use crate::CryptoError;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

pub const ED25519_SIG_LEN: usize = 64;

/// Identifiant d'algorithme (versioning explicite, cf. kem.rs). `0x01` = round-3,
/// PÉRIMÉ et refusé par son nom ; `0x02` = FIPS 204 (courant).
pub const SIG_ALGO_ID: &str = "ed25519+mldsa65-fips204";
pub const SIG_ALGO_VERSION: u8 = 0x02;
const SIG_ALGO_VERSION_PERIMEE: u8 = 0x01;

/// Contrôle de version (cf. `kem::verifier_version` — même règle).
fn verifier_version(b: &[u8], quoi: &'static str) -> Result<(), CryptoError> {
    match b.first() {
        Some(&SIG_ALGO_VERSION) => Ok(()),
        Some(&SIG_ALGO_VERSION_PERIMEE) => Err(CryptoError::AlgoPerime {
            quoi,
            version: SIG_ALGO_VERSION_PERIMEE,
        }),
        _ => Err(CryptoError::InvalidEncoding(quoi)),
    }
}

#[derive(Clone)]
pub struct SigPublicKey {
    pub ed25519: VerifyingKey,
    pub mldsa: mldsa65::PublicKey,
}

pub struct SigKeypair {
    pub public: SigPublicKey,
    ed25519: SigningKey,
    /// Octets du secret ML-DSA, effacés au drop ; le type pqcrypto est reconstruit
    /// à chaque signature (cf. tête de module).
    mldsa: Zeroizing<Vec<u8>>,
}

#[derive(Clone)]
pub struct HybridSignature {
    pub ed25519: Signature,
    pub mldsa: mldsa65::DetachedSignature,
}

impl SigKeypair {
    pub fn generate() -> Self {
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        let esk = SigningKey::from_bytes(&b);
        let epk = esk.verifying_key();
        let (mpk, msk) = mldsa65::keypair();
        SigKeypair {
            public: SigPublicKey {
                ed25519: epk,
                mldsa: mpk,
            },
            ed25519: esk,
            mldsa: Zeroizing::new(msk.as_bytes().to_vec()),
        }
    }

    /// Signe avec les deux algorithmes (message préfixé par domaine).
    pub fn sign(&self, domain: &str, msg: &[u8]) -> HybridSignature {
        let m = frame(domain, msg);
        // Reconstruction depuis les octets zeroizés — validés à la construction.
        let msk = mldsa65::SecretKey::from_bytes(&self.mldsa)
            .expect("secret ML-DSA validé à la construction");
        HybridSignature {
            ed25519: self.ed25519.sign(&m),
            mldsa: mldsa65::detached_sign(&m, &msk),
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
    let pq_ok = mldsa65::verify_detached_signature(&sig.mldsa, &m, &pk.mldsa).is_ok();
    ed_ok && pq_ok
}

impl SigKeypair {
    /// Sérialise la paire COMPLÈTE, **clés secrètes comprises**.
    ///
    /// ⚠️ DANGER : le résultat est du MATÉRIEL DE CLÉ EN CLAIR. Quiconque l'obtient
    /// peut signer à la place de ce nœud. À n'écrire que dans un fichier aux
    /// permissions restreintes, jamais en journal, jamais sur le réseau.
    ///
    /// Existe pour qu'un nœud conserve son IDENTITÉ entre deux redémarrages : sans
    /// cela ses pairs ne le reconnaissent pas, et toute réputation accumulée est
    /// perdue à chaque lancement.
    ///
    /// Format : `version ‖ ed25519_sk (32 o) ‖ mldsa_pk ‖ mldsa_sk`.
    /// La publique Ed25519 est DÉRIVÉE de la secrète ; celle de ML-DSA ne l'est
    /// pas avec cette crate, elle doit donc être stockée — asymétrie du format qui
    /// tient à la bibliothèque, pas au protocole.
    pub fn to_bytes_secret(&self) -> Vec<u8> {
        let mut v = vec![SIG_ALGO_VERSION];
        v.extend_from_slice(&self.ed25519.to_bytes());
        v.extend_from_slice(self.public.mldsa.as_bytes());
        v.extend_from_slice(&self.mldsa);
        v
    }

    /// Restaure une paire depuis `to_bytes_secret`. Un fichier round-3 (0x01) est
    /// refusé PAR SON NOM — le nœud dit quoi regénérer au lieu d'un « illisible ».
    pub fn from_bytes_secret(b: &[u8]) -> Result<Self, CryptoError> {
        verifier_version(b, "SigKeypair")?;
        let n_pk = mldsa65::public_key_bytes();
        let n_sk = mldsa65::secret_key_bytes();
        if b.len() != 1 + 32 + n_pk + n_sk {
            return Err(CryptoError::InvalidEncoding("SigKeypair"));
        }
        let mut e = [0u8; 32];
        e.copy_from_slice(&b[1..33]);
        let esk = SigningKey::from_bytes(&e);
        let epk = esk.verifying_key();
        let mpk = mldsa65::PublicKey::from_bytes(&b[33..33 + n_pk])
            .map_err(|_| CryptoError::InvalidEncoding("mldsa pk"))?;
        // Validé une fois pour toutes ; la reconstruction à l'usage n'échoue plus.
        mldsa65::SecretKey::from_bytes(&b[33 + n_pk..])
            .map_err(|_| CryptoError::InvalidEncoding("mldsa sk"))?;
        Ok(SigKeypair {
            public: SigPublicKey {
                ed25519: epk,
                mldsa: mpk,
            },
            ed25519: esk,
            mldsa: Zeroizing::new(b[33 + n_pk..].to_vec()),
        })
    }
}

impl SigPublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = vec![SIG_ALGO_VERSION];
        v.extend_from_slice(&self.ed25519.to_bytes());
        v.extend_from_slice(self.mldsa.as_bytes());
        v
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        verifier_version(b, "SigPublicKey")?;
        if b.len() != 1 + 32 + mldsa65::public_key_bytes() {
            return Err(CryptoError::InvalidEncoding("SigPublicKey"));
        }
        let mut e = [0u8; 32];
        e.copy_from_slice(&b[1..33]);
        let ed =
            VerifyingKey::from_bytes(&e).map_err(|_| CryptoError::InvalidEncoding("ed25519 pk"))?;
        let ml = mldsa65::PublicKey::from_bytes(&b[33..])
            .map_err(|_| CryptoError::InvalidEncoding("mldsa pk"))?;
        Ok(SigPublicKey {
            ed25519: ed,
            mldsa: ml,
        })
    }
}

impl HybridSignature {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = vec![SIG_ALGO_VERSION];
        v.extend_from_slice(&self.ed25519.to_bytes());
        v.extend_from_slice(self.mldsa.as_bytes());
        v
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        verifier_version(b, "HybridSignature")?;
        if b.len() != 1 + ED25519_SIG_LEN + mldsa65::signature_bytes() {
            return Err(CryptoError::InvalidEncoding("HybridSignature"));
        }
        let mut e = [0u8; 64];
        e.copy_from_slice(&b[1..65]);
        let ml = mldsa65::DetachedSignature::from_bytes(&b[65..])
            .map_err(|_| CryptoError::InvalidEncoding("mldsa sig"))?;
        Ok(HybridSignature {
            ed25519: Signature::from_bytes(&e),
            mldsa: ml,
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
            mldsa: sig_b.mldsa,
        };
        assert!(!verify(
            &kp.public,
            "test/v1",
            b"message",
            &hybride_invalide
        ));
    }

    /// Roundtrip de la paire COMPLÈTE : une identité restaurée doit produire des
    /// signatures que l'ancienne clé publique vérifie — c'est ce qui permet à un
    /// nœud de rester LE MÊME pair après redémarrage.
    #[test]
    fn roundtrip_paire_secrete() {
        let kp = SigKeypair::generate();
        let restauree = SigKeypair::from_bytes_secret(&kp.to_bytes_secret()).unwrap();
        assert_eq!(
            restauree.public.to_bytes(),
            kp.public.to_bytes(),
            "identité publique préservée"
        );
        // Une signature de la paire restaurée vérifie sous la clé publique d'origine.
        let sig = restauree.sign("test/v1", b"apres redemarrage");
        assert!(verify(&kp.public, "test/v1", b"apres redemarrage", &sig));
    }

    /// Des octets tronqués ou d'une autre version sont rejetés sans panique.
    #[test]
    fn paire_secrete_malformee_rejetee() {
        let kp = SigKeypair::generate();
        let b = kp.to_bytes_secret();
        assert!(SigKeypair::from_bytes_secret(&b[..b.len() - 1]).is_err());
        assert!(SigKeypair::from_bytes_secret(&[]).is_err());
        let mut mauvaise_version = b.clone();
        mauvaise_version[0] = 0x03; // version FUTURE inconnue
        assert!(SigKeypair::from_bytes_secret(&mauvaise_version).is_err());

        // Un objet ROUND-3 (0x01) est refusé PAR SON NOM (T1.1).
        let mut round3 = b.clone();
        round3[0] = 0x01;
        assert!(matches!(
            SigKeypair::from_bytes_secret(&round3),
            Err(crate::CryptoError::AlgoPerime { version: 0x01, .. })
        ));
        let kp2 = SigKeypair::generate();
        let mut sig_round3 = kp2.sign("test/v1", b"m").to_bytes();
        sig_round3[0] = 0x01;
        assert!(matches!(
            HybridSignature::from_bytes(&sig_round3),
            Err(crate::CryptoError::AlgoPerime { version: 0x01, .. })
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
