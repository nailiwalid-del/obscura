//! Circuits de validité d'Obscura (AIR winterfell).
//!
//! ⚠️ **validity-only** : ces preuves établissent l'INTÉGRITÉ, PAS la
//! confidentialité. Winterfell n'est pas zero-knowledge : la preuve ne masque pas
//! le témoin. Ne jamais présenter une preuve d'ici comme `zk`/`private`/`shielded`.
//! Le witness-hiding est un jalon séparé et gaté (« Phase 3z »).

pub mod rescue_perm;

pub use rescue_perm::{prove_permutation, verify_permutation, ValidityProof};
