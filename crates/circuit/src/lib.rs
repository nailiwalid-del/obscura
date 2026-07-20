//! Circuits de validité d'Obscura (AIR winterfell).
//!
//! **Statut de confidentialité (3z-b1)** : la preuve MONOLITHIQUE — le chemin de
//! consensus `tx::prove_tx`/`tx::verify_tx` (module `monolith`) — est
//! **witness-hiding (HVZK dans le modèle de l'oracle aléatoire)** via des lignes
//! de blinding (cf. docs/STARK_STATEMENT.md, « Witness-hiding du monolithe —
//! argument HVZK »). Caveat obligatoire : honnête-vérifieur (Fiat-Shamir),
//! prototype non audité, argument non formalisé au niveau publication — ne pas
//! présenter comme « zero-knowledge » sans ces qualificatifs.
//!
//! ⚠️ Les gadgets AUTONOMES de ce crate (`owner_hash`, `sponge`, `merkle_*`,
//! `membership`, `range_check`, `balance`, `key`, `spend`, `output`,
//! `rescue_perm`, …) restent **validity-only** : ils établissent l'INTÉGRITÉ,
//! pas la confidentialité — ne jamais les présenter comme
//! `zk`/`private`/`shielded`.

pub mod balance;
pub mod key;
pub mod membership;
pub mod merkle_level;
pub mod merkle_path;
pub mod monolith;
pub mod output;
pub mod owner_hash;
pub mod range_check;
pub mod rescue_perm;
pub mod rescue_round;
pub mod spend;
pub mod sponge;
pub mod tx;

pub use balance::{prove_balance, verify_balance};
pub use key::{prove_key, verify_key};
pub use membership::{prove_membership, verify_membership, MembershipProof};
pub use range_check::{prove_range, verify_range, RANGE_BITS};
pub use merkle_level::{prove_merkle_level, verify_merkle_level};
pub use merkle_path::{prove_merkle_path, verify_merkle_path};
pub use output::{prove_output, verify_output, OutputProof};
pub use owner_hash::{prove_owner, verify_owner};
pub use rescue_perm::{prove_permutation, verify_permutation};
pub use spend::{prove_spend, verify_spend, SpendNote, SpendProof};
pub use tx::{
    prove_tx, verify_proved_tx_full, verify_tx, EncNote, ProvedInput, ProvedTx, INTENT_DOMAIN,
};
pub use sponge::{
    prove_nk, prove_note_commitment, prove_nullifier, prove_sponge, verify_note_commitment,
    verify_sponge,
};

use winterfell::{Proof, ProofOptions};

/// Preuve de VALIDITÉ (intégrité). Witness-hiding (HVZK en ROM) UNIQUEMENT
/// lorsqu'elle est produite par le monolithe (`tx::prove_tx`, lignes de blinding
/// 3z-b1) ; produite par un gadget autonome, elle ne masque PAS son témoin —
/// voir l'avertissement du crate.
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

/// Paramètres à blowup 16 pour les AIR dont les contraintes gatées montent en degré
/// (chemin de Merkle, monolithe). Partagé pour éviter la divergence de facteurs.
pub(crate) fn proof_options_hi() -> ProofOptions {
    ProofOptions::new(
        32,
        16,
        0,
        winterfell::FieldExtension::Quadratic,
        8,
        127,
        winterfell::BatchingMethod::Linear,
        winterfell::BatchingMethod::Linear,
    )
}
