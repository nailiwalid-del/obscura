//! Séparation de domaine des hachages prouvés : tags Felt distincts + préambule
//! versionné. L'alignement PAD_ZERO* sur le rate du sponge est fixé en 3a1 ;
//! 3a0 fige la séquence logique se terminant par PAD_ONE.

use crate::felt::Felt;

pub const ENCODING_VERSION: u32 = 1;
/// Tag 0 : réservé, JAMAIS utilisé pour hasher.
pub const RESERVED_TAG: u32 = 0;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Domain {
    Owner = 1,
    Nk = 2,
    NoteCommitment = 3,
    MerkleLeaf = 4,
    MerkleNode = 5,
    Nullifier = 6,
}

impl Domain {
    pub fn tag(self) -> u32 {
        self as u32
    }
    pub fn tag_felt(self) -> Felt {
        Felt::from_small(self as u32)
    }
    /// Tous les domaines (pour tests de distinction).
    pub const ALL: [Domain; 6] = [
        Domain::Owner,
        Domain::Nk,
        Domain::NoteCommitment,
        Domain::MerkleLeaf,
        Domain::MerkleNode,
        Domain::Nullifier,
    ];
}

/// Préambule logique v1 : `[VERSION, DOMAIN_TAG, LEN_FIELDS, payload..., PAD_ONE]`.
pub fn sponge_preamble(domain: Domain, payload: &[Felt]) -> Vec<Felt> {
    let mut v = Vec::with_capacity(payload.len() + 4);
    v.push(Felt::from_small(ENCODING_VERSION));
    v.push(domain.tag_felt());
    v.push(Felt::from_small(payload.len() as u32));
    v.extend_from_slice(payload);
    v.push(Felt::ONE); // PAD_ONE ; PAD_ZERO* jusqu'au rate = 3a1
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_distincts_et_non_nuls() {
        let tags: Vec<u32> = Domain::ALL.iter().map(|d| d.tag()).collect();
        assert_eq!(tags, vec![1, 2, 3, 4, 5, 6]); // vecteur figé
        assert!(tags.iter().all(|&t| t != RESERVED_TAG));
        // unicité
        let mut sorted = tags.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), tags.len());
    }

    #[test]
    fn preambules_distincts_par_domaine() {
        let payload = [Felt::from_small(99)];
        let mut seen = std::collections::HashSet::new();
        for d in Domain::ALL {
            let pre: Vec<u64> = sponge_preamble(d, &payload)
                .iter()
                .map(|f| f.as_u64())
                .collect();
            assert!(seen.insert(pre), "préambule dupliqué pour {:?}", d);
        }
    }

    #[test]
    fn preambule_structure_figee() {
        let pre = sponge_preamble(Domain::Owner, &[Felt::from_small(7), Felt::from_small(8)]);
        let got: Vec<u64> = pre.iter().map(|f| f.as_u64()).collect();
        // [VERSION=1, tag Owner=1, LEN=2, 7, 8, PAD_ONE=1]
        assert_eq!(got, vec![1, 1, 2, 7, 8, 1]);
    }
}
