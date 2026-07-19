//! État du ledger PROUVÉ (3c) : arbre Rescue + nullifiers, piloté par la preuve STARK.
//!
//! Contrairement à `state::apply_transparent` (mode de dev non-sound), `apply_proved_tx`
//! applique la RÈGLE DE CONSENSUS CIBLE : il vérifie la preuve `ProvedTx`
//! (`circuit::verify_tx`, qui établit P1–P7 + non-rejeu) contre une racine récente,
//! puis dépense les nullifiers et insère les commitments de sortie dans l'arbre Rescue.
//! L'arbre est le MÊME que celui contre lequel le circuit prouve l'appartenance
//! (`proved_hash::merkle::ProvedMerkleTree`).
//!
//! Hors périmètre (→ ledger/Phase 3z) : signature hybride d'intention sur `tx_digest`,
//! généralisation M-in/N-out, witness-hiding.

use crate::LedgerError;
use circuit::{verify_tx, ProvedTx};
use proved_hash::digest::Digest;
use proved_hash::merkle::ProvedMerkleTree;
use std::collections::{HashSet, VecDeque};

/// Fenêtre glissante de racines récentes acceptées (cf. `state::RECENT_ROOTS_WINDOW`).
pub const RECENT_ROOTS_WINDOW: usize = 100;

pub struct ProvedLedgerState {
    pub tree: ProvedMerkleTree,
    nullifiers: HashSet<[u8; 32]>,
    recent_roots: HashSet<[u8; 32]>,
    roots_order: VecDeque<[u8; 32]>,
}

impl ProvedLedgerState {
    /// État aux paramètres consensus (profondeur 32).
    pub fn new() -> Self {
        Self::with_tree(ProvedMerkleTree::consensus())
    }

    /// État en profondeur `depth` — tests/dev uniquement.
    pub fn with_depth(depth: usize) -> Self {
        Self::with_tree(ProvedMerkleTree::new(depth))
    }

    fn with_tree(tree: ProvedMerkleTree) -> Self {
        let mut s = ProvedLedgerState {
            tree,
            nullifiers: HashSet::new(),
            recent_roots: HashSet::new(),
            roots_order: VecDeque::new(),
        };
        let root = s.tree.root();
        s.remember_root(root);
        s
    }

    fn remember_root(&mut self, root: Digest) {
        let key = root.to_bytes();
        if self.recent_roots.insert(key) {
            self.roots_order.push_back(key);
            if self.roots_order.len() > RECENT_ROOTS_WINDOW {
                if let Some(old) = self.roots_order.pop_front() {
                    self.recent_roots.remove(&old);
                }
            }
        }
    }

    /// Émission (faucet du prototype) : insère un commitment prouvé, retourne son index.
    pub fn mint(&mut self, cm: &Digest) -> u64 {
        let idx = self.tree.append(cm);
        let root = self.tree.root();
        self.remember_root(root);
        idx
    }

    pub fn is_spent(&self, nullifier: &Digest) -> bool {
        self.nullifiers.contains(&nullifier.to_bytes())
    }

    /// Valide et applique une transaction PROUVÉE (règle de consensus cible).
    ///
    /// Étapes : (1) l'anchor est une racine récente ; (2) la preuve établit P1–P7 +
    /// non-rejeu (`verify_tx`) ; (3) aucun nullifier déjà dépensé, ni doublon interne ;
    /// puis application atomique (dépense des nullifiers, insertion des sorties).
    /// Retourne les index d'insertion des commitments de sortie.
    pub fn apply_proved_tx(&mut self, tx: &ProvedTx) -> Result<Vec<u64>, LedgerError> {
        // 1. Anchor connu et récent.
        if !self.recent_roots.contains(&tx.anchor.to_bytes()) {
            return Err(LedgerError::UnknownRoot);
        }
        // 2. La preuve établit P1–P7 + liaison tx_digest contre CET anchor.
        if !verify_tx(&tx.anchor, self.tree.depth(), tx) {
            return Err(LedgerError::InvalidProof);
        }
        // 3. Nullifiers non dépensés + pas de doublon dans la tx.
        let mut seen = HashSet::new();
        for sp in &tx.spends {
            let nf = sp.nullifier.to_bytes();
            if self.nullifiers.contains(&nf) || !seen.insert(nf) {
                return Err(LedgerError::DoubleSpend);
            }
        }
        // Application atomique.
        for sp in &tx.spends {
            self.nullifiers.insert(sp.nullifier.to_bytes());
        }
        let mut indices = Vec::with_capacity(tx.output_commitments.len());
        for oc in &tx.output_commitments {
            indices.push(self.tree.append(oc));
        }
        let root = self.tree.root();
        self.remember_root(root);
        Ok(indices)
    }
}

impl Default for ProvedLedgerState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit::{prove_tx, ProvedInput, SpendNote};
    use proved_hash::domain::Domain;
    use proved_hash::felt::Felt;
    use proved_hash::rescue;

    fn digest(seed: u64) -> Digest {
        Digest(core::array::from_fn(|i| {
            Felt::from_canonical_u64(seed + i as u64).unwrap()
        }))
    }

    const DEPTH: usize = 4; // petit pour la vitesse (membership@32 validé ailleurs)

    /// Prépare un état avec 2 notes d'entrée émises et construit une tx équilibrée.
    /// Retourne (état, tx, indices d'entrée).
    fn setup() -> (ProvedLedgerState, circuit::ProvedTx) {
        let secret = proved_hash::digest::ShieldedSecret::from_felts(core::array::from_fn(|i| {
            Felt::from_canonical_u64(700 + i as u64).unwrap()
        }));
        let owner = rescue::hash(Domain::Owner, secret.as_felts());

        let n0 = SpendNote { value: 1_000, owner, rho: digest(20), r: digest(30) };
        let n1 = SpendNote { value: 500, owner, rho: digest(40), r: digest(50) };
        let cm0 = rescue::note_commitment(n0.value, &n0.owner, &n0.rho, &n0.r);
        let cm1 = rescue::note_commitment(n1.value, &n1.owner, &n1.rho, &n1.r);

        let mut state = ProvedLedgerState::with_depth(DEPTH);
        let i0 = state.mint(&cm0);
        let i1 = state.mint(&cm1);
        let path0 = state.tree.path(i0).unwrap();
        let path1 = state.tree.path(i1).unwrap();

        let o0 = SpendNote { value: 900, owner: digest(60), rho: digest(61), r: digest(62) };
        let o1 = SpendNote { value: 580, owner: digest(70), rho: digest(71), r: digest(72) };

        let inputs = [
            ProvedInput { note: n0, path: path0, index: i0 },
            ProvedInput { note: n1, path: path1, index: i1 },
        ];
        let (_root, tx) = prove_tx(&secret, inputs, [o0, o1], 20);
        (state, tx)
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn applique_une_tx_prouvee() {
        let (mut state, tx) = setup();
        // Les nullifiers ne sont pas encore dépensés.
        assert!(!state.is_spent(&tx.spends[0].nullifier));
        let indices = state.apply_proved_tx(&tx).expect("tx valide");
        assert_eq!(indices.len(), 2); // 2 sorties insérées
        // Nullifiers désormais dépensés.
        assert!(state.is_spent(&tx.spends[0].nullifier));
        assert!(state.is_spent(&tx.spends[1].nullifier));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn double_depense_rejetee() {
        let (mut state, tx) = setup();
        assert!(state.apply_proved_tx(&tx).is_ok());
        // Rejouer la même tx : nullifiers déjà dépensés.
        assert!(matches!(
            state.apply_proved_tx(&tx),
            Err(LedgerError::DoubleSpend)
        ));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn anchor_inconnu_rejete() {
        let (mut state, mut tx) = setup();
        tx.anchor = digest(123456); // racine jamais vue
        assert!(matches!(
            state.apply_proved_tx(&tx),
            Err(LedgerError::UnknownRoot)
        ));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn preuve_falsifiee_rejetee() {
        let (mut state, mut tx) = setup();
        // Sabotage de l'équilibre : anchor reste récent mais verify_tx échoue.
        tx.outputs[0].value += 1;
        assert!(matches!(
            state.apply_proved_tx(&tx),
            Err(LedgerError::InvalidProof)
        ));
    }
}
