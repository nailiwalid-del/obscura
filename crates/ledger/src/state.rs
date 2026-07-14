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
use std::collections::{HashSet, VecDeque};

/// Nombre de racines récentes acceptées (fenêtre glissante). Une transaction
/// bâtie sur un état plus ancien que cette fenêtre est rejetée (UnknownRoot).
/// Borne la mémoire ET donne un vrai sens à « récente » : sans borne, une racine
/// arbitrairement ancienne resterait valide pour toujours et l'ensemble croîtrait
/// sans fin.
pub const RECENT_ROOTS_WINDOW: usize = 100;

pub struct LedgerState {
    pub tree: MerkleTree,
    nullifiers: HashSet<[u8; 32]>,
    recent_roots: HashSet<[u8; 32]>,
    /// Ordre d'insertion des racines, pour purger la plus ancienne (FIFO).
    roots_order: VecDeque<[u8; 32]>,
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
        let mut s = LedgerState {
            tree,
            nullifiers: HashSet::new(),
            recent_roots: HashSet::new(),
            roots_order: VecDeque::new(),
        };
        let root = s.tree.root();
        s.remember_root(root);
        s
    }

    /// Mémorise une racine dans la fenêtre glissante, en purgeant la plus
    /// ancienne si la capacité est dépassée.
    fn remember_root(&mut self, root: [u8; 32]) {
        if self.recent_roots.insert(root) {
            self.roots_order.push_back(root);
            if self.roots_order.len() > RECENT_ROOTS_WINDOW {
                if let Some(old) = self.roots_order.pop_front() {
                    self.recent_roots.remove(&old);
                }
            }
        }
    }

    /// Émission (coinbase/faucet du prototype) : insère un commitment directement.
    pub fn mint(&mut self, c: &Commitment) -> u64 {
        let idx = self.tree.append(c);
        let root = self.tree.root();
        self.remember_root(root);
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
        let root = self.tree.root();
        self.remember_root(root);
        Ok(indices)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fenetre_de_racines_bornee_et_purge_les_anciennes() {
        let mut state = LedgerState::new_dev();
        let racine_genese = state.tree.root();
        assert!(state.recent_roots.contains(&racine_genese));

        // Assez d'émissions pour évincer la racine de genèse de la fenêtre.
        for i in 0..(RECENT_ROOTS_WINDOW as u64 + 5) {
            let c = Commitment([i as u8; 32], [(i as u8).wrapping_add(1); 32]);
            state.mint(&c);
        }

        // Mémoire bornée : jamais plus que la fenêtre.
        assert!(state.recent_roots.len() <= RECENT_ROOTS_WINDOW);
        assert_eq!(state.recent_roots.len(), state.roots_order.len());
        // La racine de genèse, trop ancienne, n'est plus acceptée.
        assert!(!state.recent_roots.contains(&racine_genese));
        // La racine courante l'est.
        assert!(state.recent_roots.contains(&state.tree.root()));
    }
}
