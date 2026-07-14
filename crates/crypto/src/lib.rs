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
}
