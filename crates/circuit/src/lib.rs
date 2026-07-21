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

// Modules CONSENSUS (toujours compilés) : le monolithe réutilise les helpers
// `pub(crate)` de `sponge`/`merkle_path`/`rescue_round`, plus `SpendNote`
// (spend) et `RANGE_BITS` (range_check).
pub mod merkle_path;
pub mod monolith;
pub mod range_check;
pub mod rescue_round;
pub mod spend;
pub mod sponge;
pub mod tx;

// Modules ENTIÈREMENT autonomes (aucun helper réutilisé par le consensus) :
// gatés en bloc derrière `dev-circuits`.
#[cfg(feature = "dev-circuits")]
pub mod balance;
#[cfg(feature = "dev-circuits")]
pub mod key;
#[cfg(feature = "dev-circuits")]
pub mod membership;
#[cfg(feature = "dev-circuits")]
pub mod merkle_level;
#[cfg(feature = "dev-circuits")]
pub mod output;
#[cfg(feature = "dev-circuits")]
pub mod owner_hash;
#[cfg(feature = "dev-circuits")]
pub mod rescue_perm;

// --- Surface CONSENSUS (build nu) ---
pub use range_check::RANGE_BITS;
pub use spend::SpendNote;
pub use tx::{
    prove_tx, verify_proved_tx_full, verify_tx, EncNote, ProvedInput, ProvedTx, TxDecodeError,
    INTENT_DOMAIN, MAX_IN, MAX_OUT,
};

// --- Surface DEV (`--features dev-circuits`) : sous-circuits standalone ---
#[cfg(feature = "dev-circuits")]
pub use balance::{prove_balance, verify_balance};
#[cfg(feature = "dev-circuits")]
pub use key::{prove_key, verify_key};
#[cfg(feature = "dev-circuits")]
pub use membership::{prove_membership, verify_membership, MembershipProof};
#[cfg(feature = "dev-circuits")]
pub use range_check::{prove_range, verify_range};
#[cfg(feature = "dev-circuits")]
pub use merkle_level::{prove_merkle_level, verify_merkle_level};
#[cfg(feature = "dev-circuits")]
pub use merkle_path::{prove_merkle_path, verify_merkle_path};
#[cfg(feature = "dev-circuits")]
pub use output::{prove_output, verify_output, OutputProof};
#[cfg(feature = "dev-circuits")]
pub use owner_hash::{prove_owner, verify_owner};
#[cfg(feature = "dev-circuits")]
pub use rescue_perm::{prove_permutation, verify_permutation};
#[cfg(feature = "dev-circuits")]
pub use spend::{prove_spend, verify_spend, SpendProof};
#[cfg(feature = "dev-circuits")]
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
// N'est appelée que par les sous-circuits standalone (le monolithe utilise
// `proof_options_hi`) — reste compilée en build nu (spec §2), d'où l'allow.
#[cfg_attr(not(feature = "dev-circuits"), allow(dead_code))]
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
