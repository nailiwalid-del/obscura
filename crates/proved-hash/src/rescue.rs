//! Hash prouvé Rescue-Prime hors-circuit : wrapper de `winter-crypto::Rp64_256`.
//!
//! La séparation de domaine = le préambule injectif de 3a0 (`sponge_preamble`,
//! `PAD_ONE` inclus), fourni comme entrée à `hash_elements`. Ce chemin est
//! HORS-CIRCUIT : l'égalité avec la version prouvée en AIR est un livrable de 3a2
//! (validity-only jusque-là).
//!
//! **Alignement du sponge (PAD_ZERO*, 3b4).** Le préambule logique est complété par
//! des zéros jusqu'à un nombre de blocs de rate qui soit une PUISSANCE DE 2
//! (`absorbed_len`). Deux raisons : (1) la longueur absorbée devient la capacité du
//! sponge, injective car `LEN` figure déjà dans le préambule ; (2) la trace STARK
//! correspondante (8 lignes/bloc) doit avoir une longueur puissance de 2. Pour tout
//! préambule dont le nombre de blocs est DÉJÀ une puissance de 2 (owner=1, nk=1,
//! nullifier=2, merge=2) le padding est un NO-OP → hachages inchangés. Seul le
//! commitment de note (13 Felts de payload → 17 → 3 blocs) est complété à 4 blocs.

use crate::digest::{Digest, DIGEST_FELTS};
use crate::domain::{sponge_preamble, Domain};
use crate::felt::Felt;
use winter_crypto::hashers::Rp64_256;
use winter_crypto::ElementHasher;

/// Largeur de rate de Rp64_256 (éléments absorbés par permutation).
pub const RATE_WIDTH: usize = 8;

/// Longueur absorbée après alignement PAD_ZERO* : plus petit multiple de `RATE_WIDTH`
/// `≥ preamble_len` dont le nombre de blocs est une PUISSANCE DE 2. No-op si le
/// nombre de blocs du préambule est déjà une puissance de 2 (cas owner/nk/nullifier/merge).
pub fn absorbed_len(preamble_len: usize) -> usize {
    let blocks = preamble_len.div_ceil(RATE_WIDTH);
    if blocks.is_power_of_two() {
        preamble_len
    } else {
        blocks.next_power_of_two() * RATE_WIDTH
    }
}

/// Hash prouvé domaine-séparé d'une séquence de Felts.
pub fn hash(domain: Domain, payload: &[Felt]) -> Digest {
    let mut preamble = sponge_preamble(domain, payload);
    preamble.resize(absorbed_len(preamble.len()), Felt::ZERO); // PAD_ZERO* (no-op sauf commitment)
    let input: Vec<_> = preamble.into_iter().map(Felt::to_winter).collect();
    let d = Rp64_256::hash_elements(&input);
    let elems = d.as_elements();
    let mut felts = [Felt::ZERO; DIGEST_FELTS];
    for (i, felt) in felts.iter_mut().enumerate() {
        *felt = Felt::from_winter(elems[i]).expect("digest winter canonique");
    }
    Digest(felts)
}

/// Payload canonique d'un commitment de note : `value ‖ owner ‖ rho ‖ r` (13 Felts).
/// `value < 2^60` (borné par le range-check P6).
pub fn note_commit_payload(value: u64, owner: &Digest, rho: &Digest, r: &Digest) -> Vec<Felt> {
    let mut p = Vec::with_capacity(1 + 3 * DIGEST_FELTS);
    p.push(Felt::from_canonical_u64(value).expect("value < p"));
    p.extend_from_slice(&owner.0);
    p.extend_from_slice(&rho.0);
    p.extend_from_slice(&r.0);
    p
}

/// Commitment de note prouvé (P7) : `cm = H_NoteCommitment(value ‖ owner ‖ rho ‖ r)`.
/// C'est le JUGE du différentiel avec la version prouvée en circuit.
pub fn note_commitment(value: u64, owner: &Digest, rho: &Digest, r: &Digest) -> Digest {
    hash(Domain::NoteCommitment, &note_commit_payload(value, owner, rho, r))
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

    /// `absorbed_len` : no-op quand le nombre de blocs est déjà une puissance de 2,
    /// arrondit sinon (le commitment, 3 blocs → 4).
    #[test]
    fn absorbed_len_arrondi_puissance_de_2() {
        assert_eq!(absorbed_len(6), 6); // owner : 1 bloc
        assert_eq!(absorbed_len(8), 8); // 1 bloc pile
        assert_eq!(absorbed_len(12), 12); // merge : 2 blocs
        assert_eq!(absorbed_len(16), 16); // nullifier : 2 blocs
        assert_eq!(absorbed_len(17), 32); // commitment : 3 blocs → 4
        assert_eq!(absorbed_len(24), 32); // 3 blocs → 4
        assert_eq!(absorbed_len(33), 64); // 5 blocs → 8
    }

    /// Commitment de note : déterministe, hiding (r change → cm change), binding
    /// (value/owner/rho changent → cm change).
    #[test]
    fn note_commitment_deterministe_et_sensible() {
        let owner = Digest([felt(10), felt(11), felt(12), felt(13)]);
        let rho = Digest([felt(20), felt(21), felt(22), felt(23)]);
        let r = Digest([felt(30), felt(31), felt(32), felt(33)]);
        let cm = note_commitment(42, &owner, &rho, &r);
        assert_eq!(cm, note_commitment(42, &owner, &rho, &r));
        // hiding : r différent → cm différent.
        let r2 = Digest([felt(30), felt(31), felt(32), felt(99)]);
        assert_ne!(cm, note_commitment(42, &owner, &rho, &r2));
        // binding : value différente → cm différent.
        assert_ne!(cm, note_commitment(43, &owner, &rho, &r));
    }
}
