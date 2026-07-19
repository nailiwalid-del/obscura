//! P1 (validité, PAR COMPOSITION) : appartenance de `cm` à l'arbre de racine `root`.
//!
//! Compose deux preuves liées par un `leaf_digest` PUBLIC partagé :
//! 1. hash de feuille : `leaf_digest = H_MerkleLeaf(cm)` (sponge B=1) ;
//! 2. chaînage : `root = fold(leaf_digest, path, index)` (`merkle_path`).
//!
//! Le vérifieur fournit le MÊME `leaf_digest` aux deux → prouve « ∃ cm, path, index :
//! H_MerkleLeaf(cm) = leaf_digest ∧ fold(leaf_digest, path, index) = root », i.e.
//! l'appartenance d'un `cm` témoin à l'arbre.
//!
//! ⚠️ **validity-only + non privé** : `leaf_digest` est révélé (il ne l'est pas dans
//! la version monolithique privée, où il reste témoin interne — c'est le circuit
//! complet P1–P7 de 3b5). Preuves à générer en `--release` (cf. `merkle_path`).

use crate::merkle_path::{prove_merkle_path, verify_merkle_path};
use crate::sponge::{prove_sponge, verify_sponge};
use crate::ValidityProof;
use proved_hash::digest::{Digest, DIGEST_FELTS};
use proved_hash::domain::Domain;

/// Preuve d'appartenance composée. `leaf_digest` est l'entrée publique partagée.
pub struct MembershipProof {
    pub leaf_digest: Digest,
    pub leaf_proof: ValidityProof,
    pub path_proof: ValidityProof,
}

/// Prouve que `cm` appartient à l'arbre dont la racine est retournée, via `path`
/// (frères) et `index` (bits de position). À générer en `--release`.
pub fn prove_membership(cm: &Digest, path: &[Digest], index: u64) -> (Digest, MembershipProof) {
    let (leaf_digest, leaf_proof) = prove_sponge(Domain::MerkleLeaf, &cm.0, &[]);
    let (root, path_proof) = prove_merkle_path(&leaf_digest, path, index);
    (
        root,
        MembershipProof {
            leaf_digest,
            leaf_proof,
            path_proof,
        },
    )
}

/// Vérifie une preuve d'appartenance contre la racine publique `root`.
pub fn verify_membership(root: &Digest, depth: usize, proof: &MembershipProof) -> bool {
    // Le hash de feuille produit bien `leaf_digest`...
    verify_sponge(
        Domain::MerkleLeaf,
        DIGEST_FELTS,
        &proof.leaf_digest,
        &[],
        &proof.leaf_proof,
    )
    // ...et le chaînage mène de CE `leaf_digest` à `root`.
    && verify_merkle_path(&proof.leaf_digest, root, depth, &proof.path_proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proved_hash::felt::Felt;
    use proved_hash::merkle;

    fn digest(seed: u64) -> Digest {
        Digest(core::array::from_fn(|i| {
            Felt::from_canonical_u64(seed + i as u64).unwrap()
        }))
    }

    /// Profondeur 2 : appartenance complète (feuille + chaînage), diff. vs merkle::root.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "AIR gaté : générer en --release")]
    fn appartenance_d2() {
        let cm = digest(1);
        let path = [digest(100), digest(200)];
        for index in [0b00u64, 0b01, 0b10, 0b11] {
            let (root, proof) = prove_membership(&cm, &path, index);
            assert_eq!(root, merkle::root(&cm, &path, index), "index={index:#b}");
            assert!(verify_membership(&root, path.len(), &proof));
        }
    }

    /// Profondeur 32 (consensus) : trace du chemin = 512 lignes. P1 à l'échelle.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "AIR gaté : générer en --release")]
    fn appartenance_profondeur_32() {
        let cm = digest(7);
        let path: Vec<Digest> = (0..32u64).map(|i| digest(1000 + i * 10)).collect();
        let index = 0xA5A5_A5A5;
        let (root, proof) = prove_membership(&cm, &path, index);
        assert_eq!(root, merkle::root(&cm, &path, index));
        assert!(verify_membership(&root, path.len(), &proof));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "AIR gaté : générer en --release")]
    fn racine_alteree_rejetee() {
        let cm = digest(3);
        let path = [digest(30), digest(40)];
        let (root, proof) = prove_membership(&cm, &path, 0b10);
        assert!(verify_membership(&root, path.len(), &proof));
        let mut faux = root;
        faux.0[0] = Felt::from_canonical_u64(faux.0[0].as_u64() ^ 1).unwrap();
        assert!(!verify_membership(&faux, path.len(), &proof));
    }
}
