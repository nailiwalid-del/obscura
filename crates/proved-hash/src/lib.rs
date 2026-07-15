//! Représentations canoniques du domaine « hash prouvé » d'Obscura (validity-only).
//!
//! 3a0 : types + encodage + domaines, SANS Rescue ni prouveur. Voir
//! docs/superpowers/specs/2026-07-15-phase3-decision-et-3a0-design.md.

pub mod amount;
pub mod digest;
pub mod domain;
pub mod felt;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EncodingError {
    #[error("Felt non canonique (>= p) : {0}")]
    NonCanonicalFelt(u64),
    #[error("longueur invalide : attendu {expected}, reçu {got}")]
    InvalidLength { expected: usize, got: usize },
    #[error("limb hors range (>= 2^16) : {0}")]
    LimbOutOfRange(u64),
}
