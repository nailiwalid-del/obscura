//! Ledger privé d'Obscura : notes engagées, nullifiers, arbre de Merkle, validation.

pub mod keys;
pub mod merkle;
pub mod note;
pub mod proved_state;
pub mod proved_wallet;
pub mod state;
pub mod tx;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Commitment de note (64 octets : BLAKE3 ‖ SHA3-256, jamais tronqué).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct Commitment(pub [u8; 32], pub [u8; 32]);

impl Commitment {
    pub fn from_bytes64(b: &[u8; 64]) -> Self {
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&b[..32]);
        y.copy_from_slice(&b[32..]);
        Commitment(x, y)
    }
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.0);
        out[32..].copy_from_slice(&self.1);
        out
    }
}

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("racine de Merkle inconnue")]
    UnknownRoot,
    #[error("chemin de Merkle invalide")]
    InvalidPath,
    #[error("double dépense détectée (nullifier déjà vu)")]
    DoubleSpend,
    #[error("signature de dépense invalide")]
    InvalidSignature,
    #[error("transaction déséquilibrée")]
    Unbalanced,
    #[error("encodage invalide")]
    Encoding,
    #[error("index de note introuvable")]
    UnknownIndex,
    #[error("preuve de transaction invalide")]
    InvalidProof,
}
