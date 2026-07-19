//! Arbre de Merkle « hash prouvé » (Rescue-Prime) — référence HORS-CIRCUIT.
//!
//! C'est le pendant Rescue du `ledger::merkle` (BLAKE3) : il définit la feuille, le
//! nœud et la racine tels que le CIRCUIT (3b2b) devra les reproduire. Le différentiel
//! natif ⟷ circuit se fera contre `root` ci-dessous.
//!
//! Convention de bit alignée sur `ledger::merkle::verify_path` :
//! `bit 0 → (courant, frère)`, `bit 1 → (frère, courant)`, du bas vers le haut.

use crate::digest::Digest;
use crate::domain::Domain;
use crate::rescue;

/// Profondeur consensus (2^32 feuilles), cf. `ledger::merkle::CONSENSUS_DEPTH`.
pub const CONSENSUS_DEPTH: usize = 32;

/// Feuille : hash prouvé du commitment.
pub fn leaf(cm: &Digest) -> Digest {
    rescue::hash(Domain::MerkleLeaf, &cm.0)
}

/// Nœud interne : compression 2→1 domaine-séparée de (gauche, droite).
pub fn node(left: &Digest, right: &Digest) -> Digest {
    rescue::merge(Domain::MerkleNode, left, right)
}

/// Repli d'un chemin depuis une feuille DÉJÀ hachée `leaf`, en remontant `path`
/// selon les bits de `index`. C'est le cœur du calcul de racine (sans le hash de
/// feuille) — la référence du différentiel du chaînage en circuit (3b2b).
pub fn fold(leaf: &Digest, path: &[Digest], index: u64) -> Digest {
    let mut cur = *leaf;
    for (level, sib) in path.iter().enumerate() {
        let bit = (index >> level) & 1;
        cur = if bit == 0 {
            node(&cur, sib)
        } else {
            node(sib, &cur)
        };
    }
    cur
}

/// Racine obtenue en remontant `path` (frères, du bas vers le haut) depuis la
/// feuille `cm`, l'ordre à chaque niveau étant dicté par le bit de `index`.
pub fn root(cm: &Digest, path: &[Digest], index: u64) -> Digest {
    fold(&leaf(cm), path, index)
}

/// Profondeur réduite pour tests/dev, cf. `ledger::merkle::DEV_DEPTH`.
pub const DEV_DEPTH: usize = 16;

/// Feuille des sous-arbres vides (payload de longueur 0 → distinct de tout `leaf(cm)`
/// dont le payload fait 4 Felts : les `LEN` du préambule diffèrent).
fn empty_leaf() -> Digest {
    rescue::hash(Domain::MerkleLeaf, &[])
}

/// Hashs des sous-arbres vides pour chaque profondeur `0..=depth`.
fn empties(depth: usize) -> Vec<Digest> {
    let mut e = Vec::with_capacity(depth + 1);
    e.push(empty_leaf());
    for d in 0..depth {
        e.push(node(&e[d], &e[d]));
    }
    e
}

/// Arbre de Merkle « hash prouvé » incrémental — le pendant Rescue de
/// `ledger::merkle::MerkleTree`. Les chemins qu'il produit sont **compatibles
/// circuit** : `root(cm, tree.path(i), i) == tree.root()` (relation prouvée par
/// `circuit::membership`). Convention de bit identique (`bit 0 → (courant, frère)`).
pub struct ProvedMerkleTree {
    leaves: Vec<Digest>,
    depth: usize,
}

impl ProvedMerkleTree {
    pub fn new(depth: usize) -> Self {
        assert!(depth > 0 && depth <= 48, "profondeur invalide");
        ProvedMerkleTree {
            leaves: Vec::new(),
            depth,
        }
    }

    /// Arbre aux paramètres consensus (profondeur 32).
    pub fn consensus() -> Self {
        Self::new(CONSENSUS_DEPTH)
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Ajoute un commitment, retourne son index.
    pub fn append(&mut self, cm: &Digest) -> u64 {
        assert!(
            (self.leaves.len() as u128) < (1u128 << self.depth),
            "arbre plein"
        );
        self.leaves.push(leaf(cm));
        (self.leaves.len() - 1) as u64
    }

    /// Racine courante (feuilles réelles + sous-arbres vides).
    pub fn root(&self) -> Digest {
        let e = empties(self.depth);
        let mut level = self.leaves.clone();
        for ed in e.iter().take(self.depth) {
            if level.is_empty() {
                return e[self.depth];
            }
            if level.len() % 2 == 1 {
                level.push(*ed);
            }
            level = level.chunks(2).map(|p| node(&p[0], &p[1])).collect();
        }
        level[0]
    }

    /// Chemin d'appartenance (frères, du bas vers le haut) pour la feuille `index`.
    /// `None` si l'index dépasse le nombre de feuilles.
    pub fn path(&self, index: u64) -> Option<Vec<Digest>> {
        if index as usize >= self.leaves.len() {
            return None;
        }
        let e = empties(self.depth);
        let mut level = self.leaves.clone();
        let mut idx = index as usize;
        let mut siblings = Vec::with_capacity(self.depth);
        for ed in e.iter().take(self.depth) {
            if level.len() % 2 == 1 {
                level.push(*ed);
            }
            let sib = idx ^ 1;
            siblings.push(if sib < level.len() { level[sib] } else { *ed });
            level = level.chunks(2).map(|p| node(&p[0], &p[1])).collect();
            idx >>= 1;
        }
        Some(siblings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::felt::Felt;

    fn digest(seed: u64) -> Digest {
        Digest(core::array::from_fn(|i| {
            Felt::from_canonical_u64(seed + i as u64).unwrap()
        }))
    }

    #[test]
    fn racine_deterministe() {
        let cm = digest(1);
        let path = [digest(10), digest(20), digest(30)];
        assert_eq!(root(&cm, &path, 0b101), root(&cm, &path, 0b101));
    }

    #[test]
    fn le_bit_change_l_ordre() {
        // Un seul niveau : bit 0 = node(feuille, frère), bit 1 = node(frère, feuille).
        let cm = digest(1);
        let sib = digest(10);
        let leaf = leaf(&cm);
        assert_eq!(root(&cm, &[sib], 0), node(&leaf, &sib));
        assert_eq!(root(&cm, &[sib], 1), node(&sib, &leaf));
        assert_ne!(root(&cm, &[sib], 0), root(&cm, &[sib], 1));
    }

    #[test]
    fn un_frere_different_change_la_racine() {
        let cm = digest(1);
        let path_a = [digest(10), digest(20)];
        let path_b = [digest(10), digest(21)];
        assert_ne!(root(&cm, &path_a, 0), root(&cm, &path_b, 0));
    }

    #[test]
    fn profondeur_consensus() {
        // Une racine de profondeur 32 se calcule sans panique et est déterministe.
        let cm = digest(7);
        let path: Vec<Digest> = (0..CONSENSUS_DEPTH as u64).map(|i| digest(100 + i)).collect();
        let r = root(&cm, &path, 0xDEAD_BEEF);
        assert_eq!(r, root(&cm, &path, 0xDEAD_BEEF));
    }

    /// L'arbre incrémental produit des chemins COMPATIBLES CIRCUIT : pour chaque
    /// feuille, `root(cm, tree.path(i), i) == tree.root()` — exactement la relation
    /// que `circuit::membership` prouve.
    #[test]
    fn arbre_incremental_chemins_compatibles_circuit() {
        for depth in [DEV_DEPTH, CONSENSUS_DEPTH] {
            let mut tree = ProvedMerkleTree::new(depth);
            let cms: Vec<Digest> = (0..5u64).map(|i| digest(1 + i * 10)).collect();
            for cm in &cms {
                tree.append(cm);
            }
            let r = tree.root();
            for (i, cm) in cms.iter().enumerate() {
                let path = tree.path(i as u64).unwrap();
                assert_eq!(path.len(), depth);
                assert_eq!(root(cm, &path, i as u64), r, "feuille {i} @ depth {depth}");
            }
        }
    }

    #[test]
    fn arbre_racine_change_avec_les_ajouts_et_index_hors_borne() {
        let mut tree = ProvedMerkleTree::consensus();
        let r0 = tree.root();
        tree.append(&digest(42));
        assert_ne!(r0, tree.root());
        assert!(tree.path(0).is_some());
        assert!(tree.path(1).is_none()); // une seule feuille
    }
}
