//! Arbre de Merkle des commitments (BLAKE3 domain-séparé).
//!
//! Profondeur 32 en consensus (2^32 notes), 16 en mode dev.
//! NOTE (v0.2) : le hash de nœud migrera vers Rescue-Prime EN MÊME TEMPS que le
//! circuit STARK — jamais avant (l'arbre consensus et l'arbre prouvé doivent être
//! identiques). Voir docs/STARK_STATEMENT.md.

use crate::Commitment;
use crypto::hash;
use serde::{Deserialize, Serialize};

/// Profondeur consensus : 2^32 notes.
pub const CONSENSUS_DEPTH: usize = 32;
/// Profondeur réduite pour tests/dev uniquement.
pub const DEV_DEPTH: usize = 16;

fn leaf_hash(c: &Commitment) -> [u8; 32] {
    hash::blake3_domain("obscura/merkle/leaf/v1", &c.to_bytes())
}

fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(l);
    b[32..].copy_from_slice(r);
    hash::blake3_domain("obscura/merkle/node/v1", &b)
}

/// Hashs des sous-arbres vides pour chaque profondeur 0..=depth.
fn empties(depth: usize) -> Vec<[u8; 32]> {
    let mut e = Vec::with_capacity(depth + 1);
    e.push(hash::blake3_domain("obscura/merkle/empty/v1", &[]));
    for d in 0..depth {
        e.push(node_hash(&e[d].clone(), &e[d].clone()));
    }
    e
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MerklePath {
    pub index: u64,
    pub siblings: Vec<[u8; 32]>, // `depth` éléments, du bas vers le haut
}

pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
    depth: usize,
}

impl MerkleTree {
    pub fn new(depth: usize) -> Self {
        assert!(depth > 0 && depth <= 48, "profondeur invalide");
        MerkleTree {
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
    pub fn append(&mut self, c: &Commitment) -> u64 {
        assert!(
            (self.leaves.len() as u128) < (1u128 << self.depth),
            "arbre plein"
        );
        self.leaves.push(leaf_hash(c));
        (self.leaves.len() - 1) as u64
    }

    pub fn root(&self) -> [u8; 32] {
        let e = empties(self.depth);
        let mut level = self.leaves.clone();
        for d in 0..self.depth {
            if level.is_empty() {
                return e[self.depth];
            }
            if level.len() % 2 == 1 {
                level.push(e[d]);
            }
            level = level.chunks(2).map(|p| node_hash(&p[0], &p[1])).collect();
        }
        level[0]
    }

    /// Chemin d'appartenance pour la feuille `index`.
    pub fn path(&self, index: u64) -> Option<MerklePath> {
        if index as usize >= self.leaves.len() {
            return None;
        }
        let e = empties(self.depth);
        let mut level = self.leaves.clone();
        let mut idx = index as usize;
        let mut siblings = Vec::with_capacity(self.depth);
        for &e_d in e.iter().take(self.depth) {
            if level.len() % 2 == 1 {
                level.push(e_d);
            }
            let sib = idx ^ 1;
            siblings.push(if sib < level.len() { level[sib] } else { e_d });
            level = level.chunks(2).map(|p| node_hash(&p[0], &p[1])).collect();
            idx >>= 1;
        }
        Some(MerklePath { index, siblings })
    }
}

/// Vérifie l'appartenance d'un commitment à l'arbre de racine `root`.
/// `depth` est la profondeur consensus attendue : un chemin d'une autre
/// profondeur est rejeté.
pub fn verify_path(root: &[u8; 32], c: &Commitment, path: &MerklePath, depth: usize) -> bool {
    if path.siblings.len() != depth {
        return false;
    }
    let mut cur = leaf_hash(c);
    let mut idx = path.index;
    for sib in &path.siblings {
        cur = if idx & 1 == 0 {
            node_hash(&cur, sib)
        } else {
            node_hash(sib, &cur)
        };
        idx >>= 1;
    }
    cur == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(i: u8) -> Commitment {
        Commitment([i; 32], [i.wrapping_add(1); 32])
    }

    #[test]
    fn appartenance_valide_dev_et_consensus() {
        for depth in [DEV_DEPTH, CONSENSUS_DEPTH] {
            let mut t = MerkleTree::new(depth);
            for i in 0..5 {
                t.append(&c(i));
            }
            let root = t.root();
            for i in 0..5u64 {
                let p = t.path(i).unwrap();
                assert!(verify_path(&root, &c(i as u8), &p, depth));
            }
        }
    }

    #[test]
    fn mauvais_commitment_ou_profondeur_rejete() {
        let mut t = MerkleTree::new(DEV_DEPTH);
        t.append(&c(1));
        t.append(&c(2));
        let root = t.root();
        let p = t.path(0).unwrap();
        assert!(!verify_path(&root, &c(9), &p, DEV_DEPTH));
        // un chemin de profondeur dev ne passe pas en consensus
        assert!(!verify_path(&root, &c(1), &p, CONSENSUS_DEPTH));
    }

    #[test]
    fn la_racine_change_avec_les_ajouts() {
        let mut t = MerkleTree::consensus();
        let r0 = t.root();
        t.append(&c(1));
        assert_ne!(r0, t.root());
    }
}
