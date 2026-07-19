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

/// Racine obtenue en remontant `path` (frères, du bas vers le haut) depuis la
/// feuille `cm`, l'ordre à chaque niveau étant dicté par le bit de `index`.
pub fn root(cm: &Digest, path: &[Digest], index: u64) -> Digest {
    let mut cur = leaf(cm);
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
}
