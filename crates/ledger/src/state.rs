//! État du ledger : arbre des commitments + nullifiers dépensés.
//!
//! AVERTISSEMENT (v0.2) : `apply_transparent` est un MODE DE DÉVELOPPEMENT.
//! Il ne vérifie NI la liaison nullifier↔note, NI l'autorité de dépense réelle,
//! NI l'équilibre des montants, et il révèle des données qui cassent l'anonymat.
//! La règle de consensus réelle est la preuve STARK (docs/STARK_STATEMENT.md).

use crate::merkle::{verify_path, MerkleTree};
use crate::tx::{Transaction, SIG_DOMAIN};
use crate::{Commitment, LedgerError};
use crypto::sig;
use std::collections::HashSet;

pub struct LedgerState {
    pub tree: MerkleTree,
    nullifiers: HashSet<[u8; 32]>,
    recent_roots: HashSet<[u8; 32]>,
}

impl Default for LedgerState {
    fn default() -> Self {
        Self::new()
    }
}

impl LedgerState {
    /// État aux paramètres consensus (profondeur 32).
    pub fn new() -> Self {
        Self::with_tree(MerkleTree::consensus())
    }

    /// État en profondeur réduite — tests/dev uniquement.
    pub fn new_dev() -> Self {
        Self::with_tree(MerkleTree::new(crate::merkle::DEV_DEPTH))
    }

    fn with_tree(tree: MerkleTree) -> Self {
        let mut roots = HashSet::new();
        roots.insert(tree.root());
        LedgerState { tree, nullifiers: HashSet::new(), recent_roots: roots }
    }

    /// Émission (coinbase/faucet du prototype) : insère un commitment directement.
    pub fn mint(&mut self, c: &Commitment) -> u64 {
        let idx = self.tree.append(c);
        self.recent_roots.insert(self.tree.root());
        idx
    }

    pub fn is_spent(&self, nullifier: &[u8; 32]) -> bool {
        self.nullifiers.contains(nullifier)
    }

    /// Valide et applique une transaction en MODE TRANSPARENT (dev uniquement).
    ///
    /// Voir l'avertissement en tête de module : ce chemin n'implémente PAS la
    /// règle de consensus cible (statement STARK P1–P7) et n'est pas privé.
    pub fn apply_transparent(&mut self, tx: &Transaction) -> Result<Vec<u64>, LedgerError> {
        let digest = tx.digest();

        // 1-4 : validation de chaque entrée
        let mut seen = HashSet::new();
        for i in &tx.inputs {
            if !self.recent_roots.contains(&i.root) {
                return Err(LedgerError::UnknownRoot);
            }
            if !verify_path(&i.root, &i.commitment, &i.path, self.tree.depth()) {
                return Err(LedgerError::InvalidPath);
            }
            if self.nullifiers.contains(&i.nullifier) || !seen.insert(i.nullifier) {
                return Err(LedgerError::DoubleSpend);
            }
            let pk = sig::SigPublicKey::from_bytes(&i.spend_pk)
                .map_err(|_| LedgerError::Encoding)?;
            let s = sig::HybridSignature::from_bytes(&i.sig)
                .map_err(|_| LedgerError::Encoding)?;
            if !sig::verify(&pk, SIG_DOMAIN, &digest, &s) {
                return Err(LedgerError::InvalidSignature);
            }
        }

        // Application atomique
        for i in &tx.inputs {
            self.nullifiers.insert(i.nullifier);
        }
        let mut indices = Vec::with_capacity(tx.outputs.len());
        for o in &tx.outputs {
            indices.push(self.tree.append(&o.commitment));
        }
        self.recent_roots.insert(self.tree.root());
        Ok(indices)
    }
}
