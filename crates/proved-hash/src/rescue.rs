//! Hash prouvé Rescue-Prime hors-circuit : wrapper de `winter-crypto::Rp64_256`.
//!
//! La séparation de domaine = le préambule injectif de 3a0 (`sponge_preamble`,
//! `PAD_ONE` inclus), fourni comme entrée à `hash_elements`. Le rate-padding est
//! interne à Rp64_256. Ce chemin est HORS-CIRCUIT : l'égalité avec la version
//! prouvée en AIR est un livrable de 3a2 (validity-only jusque-là).

use crate::digest::{Digest, DIGEST_FELTS};
use crate::domain::{sponge_preamble, Domain};
use crate::felt::Felt;
use winter_crypto::hashers::Rp64_256;
use winter_crypto::ElementHasher;

/// Hash prouvé domaine-séparé d'une séquence de Felts.
pub fn hash(domain: Domain, payload: &[Felt]) -> Digest {
    let input: Vec<_> = sponge_preamble(domain, payload)
        .into_iter()
        .map(Felt::to_winter)
        .collect();
    let d = Rp64_256::hash_elements(&input);
    let elems = d.as_elements();
    let mut felts = [Felt::ZERO; DIGEST_FELTS];
    for (i, felt) in felts.iter_mut().enumerate() {
        *felt = Felt::from_winter(elems[i]).expect("digest winter canonique");
    }
    Digest(felts)
}

/// Compression 2->1 domaine-séparée (nœuds de Merkle) : `hash(domain, a ‖ b)`.
pub fn merge(domain: Domain, a: &Digest, b: &Digest) -> Digest {
    let mut payload = Vec::with_capacity(2 * DIGEST_FELTS);
    payload.extend_from_slice(&a.0);
    payload.extend_from_slice(&b.0);
    hash(domain, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn felt(x: u64) -> Felt {
        Felt::from_canonical_u64(x).unwrap()
    }

    #[test]
    fn hash_deterministe() {
        let p = [felt(1), felt(2), felt(3)];
        assert_eq!(hash(Domain::Owner, &p), hash(Domain::Owner, &p));
    }

    #[test]
    fn domaines_distincts_donnent_digests_distincts() {
        let p = [felt(1), felt(2)];
        assert_ne!(hash(Domain::Owner, &p), hash(Domain::Nk, &p));
    }

    #[test]
    fn merge_ordre_significatif() {
        let a = hash(Domain::NoteCommitment, &[felt(1)]);
        let b = hash(Domain::NoteCommitment, &[felt(2)]);
        assert_ne!(
            merge(Domain::MerkleNode, &a, &b),
            merge(Domain::MerkleNode, &b, &a)
        );
    }
}
