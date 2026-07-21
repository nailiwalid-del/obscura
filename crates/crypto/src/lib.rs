//! Primitives cryptographiques hybrides d'Obscura.
//!
//! Défense en profondeur : chaque fonction combine deux primitives de familles
//! mathématiques indépendantes — la sécurité tient si AU MOINS UNE tient.

pub mod aead;
pub mod hash;
pub mod kem;
pub mod sig;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("échec de déchiffrement (clé invalide ou données corrompues)")]
    DecryptionFailed,
    #[error("encodage invalide : {0}")]
    InvalidEncoding(&'static str),
    #[error("signature invalide")]
    InvalidSignature,
    /// Le Diffie-Hellman X25519 a produit un secret NUL : le pair a présenté un point
    /// d'ordre faible. Accepter ce cas ferait tomber SILENCIEUSEMENT la moitié
    /// courbes-elliptiques du KEM hybride — la sécurité reposerait alors sur Kyber
    /// seul, sans que personne ne le sache. C'est exactement ce que la défense en
    /// profondeur promet d'empêcher, d'où un rejet explicite (RFC 7748 §6.1).
    #[error("secret X25519 non contributif (point d'ordre faible)")]
    NonContributif,
}
