//! Circuits de validité d'Obscura (AIR winterfell).
//!
//! ⚠️ **validity-only** : ces preuves établissent l'INTÉGRITÉ, PAS la
//! confidentialité. Winterfell n'est pas zero-knowledge : la preuve ne masque pas
//! le témoin. Ne jamais présenter une preuve d'ici comme `zk`/`private`/`shielded`.
//! Le witness-hiding est un jalon séparé et gaté (« Phase 3z »).

pub mod balance;
pub mod membership;
pub mod merkle_level;
pub mod merkle_path;
pub mod owner_hash;
pub mod range_check;
pub mod rescue_perm;
pub mod rescue_round;
pub mod sponge;

pub use balance::{prove_balance, verify_balance};
pub use membership::{prove_membership, verify_membership, MembershipProof};
pub use range_check::{prove_range, verify_range, RANGE_BITS};
pub use merkle_level::{prove_merkle_level, verify_merkle_level};
pub use merkle_path::{prove_merkle_path, verify_merkle_path};
pub use owner_hash::{prove_owner, verify_owner};
pub use rescue_perm::{prove_permutation, verify_permutation};
pub use sponge::{prove_nk, prove_nullifier, prove_sponge, verify_sponge};

use winterfell::{Proof, ProofOptions};

/// Preuve de VALIDITÉ (intégrité). **Pas** witness-hiding — voir l'avertissement du crate.
pub struct ValidityProof(pub Proof);

/// Paramètres de preuve partagés (prototype), visant >= 95 bits conjecturés.
///
/// IMPORTANT : Goldilocks est un corps de 64 bits — SANS extension, la sécurité
/// plafonne à ~63 bits et winterfell REFUSE la preuve. L'extension quadratique
/// (~128 bits) est donc obligatoire ici, pas une optimisation.
pub(crate) fn proof_options() -> ProofOptions {
    ProofOptions::new(
        32,
        8,
        0,
        winterfell::FieldExtension::Quadratic,
        8,
        127,
        winterfell::BatchingMethod::Linear,
        winterfell::BatchingMethod::Linear,
    )
}
