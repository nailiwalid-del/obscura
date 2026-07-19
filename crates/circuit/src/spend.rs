//! 3b5b — Bundle de dépense (Spend) par COMPOSITION liée.
//!
//! Pour UNE note d'entrée, établit **P7ᵢₙ ∧ P1 ∧ P3 ∧ P6** en composant les preuves
//! déjà bâties, liées par des valeurs PUBLIQUES partagées :
//! - `cm_in = H_NoteCommitment(value ‖ owner ‖ rho ‖ r)`  (P7ᵢₙ)
//! - `cm_in ∈ arbre(root)`                                 (P1)
//! - `nf = H_nullifier(nk ‖ rho ‖ cm_in)`                  (P3)
//! - `value < 2^60`                                        (P6)
//!
//! **Décision d'archi (validity-only)** : composition, PAS de mini-monolithe. Un
//! STARK validity-only n'est pas witness-hiding (il fuit ses témoins) → garder
//! `cm_in` hors des entrées publiques ne le cache pas. L'unlinkability (cm_in caché)
//! et le circuit fusionné rejoignent la Phase 3z. Le SEUL témoin qui doit rester
//! caché ET partagé — le secret maître — est déjà traité dans une trace unique par
//! `prove_key` (3b5a). Ici, les valeurs partagées sont publiques, donc liables sans
//! trace commune : chaque sous-preuve EXPOSE ses positions partagées et `verify_spend`
//! passe la même valeur partout.
//!
//! ⚠️ **À générer en `--release`** (membership + range sont gatés).

use crate::{
    prove_membership, prove_range, prove_sponge, verify_membership, verify_range, verify_sponge,
    MembershipProof, ValidityProof,
};
use proved_hash::digest::{Digest, DIGEST_FELTS};
use proved_hash::domain::Domain;
use proved_hash::felt::Felt;
use proved_hash::rescue::note_commit_payload;
use proved_hash::merkle;

/// Note d'entrée (domaine prouvé). `value < 2^60`.
#[derive(Clone)]
pub struct SpendNote {
    pub value: u64,
    pub owner: Digest,
    pub rho: Digest,
    pub r: Digest,
}

/// Preuve composée d'une dépense. `cm_in`/`value`/`rho` sont des liaisons PUBLIQUES ;
/// `nullifier` est l'entrée publique du statement.
pub struct SpendProof {
    pub cm_in: Digest,
    pub value: u64,
    pub rho: Digest,
    pub nullifier: Digest,
    pub commit: ValidityProof,
    pub membership: MembershipProof,
    pub nf_proof: ValidityProof,
    pub range: ValidityProof,
}

// Payload commitment = [value, owner(4), rho(4), r(4)] ; positions partagées 0..9
// (value + owner + rho). `r` (9..13) reste témoin.
const COMMIT_PUBLIC: usize = 9;

/// Prouve la dépense de `note` (chemin `path`, position `index`) sous la clé `nk`.
/// Retourne la racine prouvée (le bundle vérifie `root == tx.root`) et la preuve.
pub fn prove_spend(
    note: &SpendNote,
    path: &[Digest],
    index: u64,
    nk: &Digest,
) -> (Digest, SpendProof) {
    // P7ᵢₙ : commitment, exposant value/owner/rho.
    let payload = note_commit_payload(note.value, &note.owner, &note.rho, &note.r);
    let commit_idx: Vec<usize> = (0..COMMIT_PUBLIC).collect();
    let (cm_in, commit) = prove_sponge(Domain::NoteCommitment, &payload, &commit_idx);

    // P1 : appartenance de cm_in à l'arbre.
    let (root, membership) = prove_membership(&cm_in, path, index);

    // P3 : nullifier = H(nk ‖ rho ‖ cm_in), tout exposé.
    let mut nf_payload = Vec::with_capacity(3 * DIGEST_FELTS);
    nf_payload.extend_from_slice(&nk.0);
    nf_payload.extend_from_slice(&note.rho.0);
    nf_payload.extend_from_slice(&cm_in.0);
    let nf_idx: Vec<usize> = (0..3 * DIGEST_FELTS).collect();
    let (nullifier, nf_proof) = prove_sponge(Domain::Nullifier, &nf_payload, &nf_idx);

    // P6 : range de la valeur.
    let range = prove_range(note.value);

    (
        root,
        SpendProof {
            cm_in,
            value: note.value,
            rho: note.rho,
            nullifier,
            commit,
            membership,
            nf_proof,
            range,
        },
    )
}

/// Vérifie une dépense contre le statement : arbre `root` (profondeur `depth`),
/// `owner` et `nk` (liés à la preuve de clé, 3b5a).
pub fn verify_spend(
    root: &Digest,
    owner: &Digest,
    nk: &Digest,
    depth: usize,
    spend: &SpendProof,
) -> bool {
    let value_felt = match Felt::from_canonical_u64(spend.value) {
        Ok(f) => f,
        Err(_) => return false,
    };

    // P7ᵢₙ : cm_in engage bien (value, owner, rho) publics (r caché).
    let mut commit_pub: Vec<(usize, Felt)> = Vec::with_capacity(COMMIT_PUBLIC);
    commit_pub.push((0, value_felt));
    for (i, f) in owner.0.iter().enumerate() {
        commit_pub.push((1 + i, *f));
    }
    for (i, f) in spend.rho.0.iter().enumerate() {
        commit_pub.push((1 + DIGEST_FELTS + i, *f));
    }
    let ok_commit = verify_sponge(
        Domain::NoteCommitment,
        1 + 3 * DIGEST_FELTS,
        &spend.cm_in,
        &commit_pub,
        &spend.commit,
    );

    // P1 : cm_in ∈ arbre(root). La liaison au cm_in public = le leaf recalculé.
    let ok_mem = verify_membership(root, depth, &spend.membership)
        && spend.membership.leaf_digest == merkle::leaf(&spend.cm_in);

    // P3 : nf engage (nk, rho, cm_in) — tous liés par ailleurs.
    let mut nf_pub: Vec<(usize, Felt)> = Vec::with_capacity(3 * DIGEST_FELTS);
    for (i, f) in nk.0.iter().enumerate() {
        nf_pub.push((i, *f));
    }
    for (i, f) in spend.rho.0.iter().enumerate() {
        nf_pub.push((DIGEST_FELTS + i, *f));
    }
    for (i, f) in spend.cm_in.0.iter().enumerate() {
        nf_pub.push((2 * DIGEST_FELTS + i, *f));
    }
    let ok_nf = verify_sponge(
        Domain::Nullifier,
        3 * DIGEST_FELTS,
        &spend.nullifier,
        &nf_pub,
        &spend.nf_proof,
    );

    // P6 : value < 2^60.
    let ok_range = verify_range(spend.value, &spend.range);

    ok_commit && ok_mem && ok_nf && ok_range
}

#[cfg(test)]
mod tests {
    use super::*;
    use proved_hash::rescue;

    fn digest(seed: u64) -> Digest {
        Digest(core::array::from_fn(|i| {
            Felt::from_canonical_u64(seed + i as u64).unwrap()
        }))
    }

    fn note() -> SpendNote {
        SpendNote {
            value: 4_200,
            owner: digest(10),
            rho: digest(20),
            r: digest(30),
        }
    }

    // Profondeur modeste pour la vitesse ; membership@32 est validé en 3b2c.
    const DEPTH: usize = 8;

    fn setup() -> (SpendNote, Vec<Digest>, u64, Digest, Digest) {
        let n = note();
        let path: Vec<Digest> = (0..DEPTH as u64).map(|i| digest(1000 + i * 7)).collect();
        let index = 0b1011;
        let nk = digest(500);
        let owner = n.owner;
        (n, path, index, nk, owner)
    }

    /// Différentiel/heureux : la dépense d'une note dans l'arbre est acceptée, et
    /// `cm_in`/`nf` coïncident avec les références hors-circuit.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "membership/range gatés : --release")]
    fn depense_valide() {
        let (n, path, index, nk, owner) = setup();
        let (root, spend) = prove_spend(&n, &path, index, &nk);

        // Différentiels hors-circuit.
        assert_eq!(spend.cm_in, rescue::note_commitment(n.value, &n.owner, &n.rho, &n.r));
        assert_eq!(root, merkle::root(&spend.cm_in, &path, index));
        let mut nf_payload = Vec::new();
        nf_payload.extend_from_slice(&nk.0);
        nf_payload.extend_from_slice(&n.rho.0);
        nf_payload.extend_from_slice(&spend.cm_in.0);
        assert_eq!(spend.nullifier, rescue::hash(Domain::Nullifier, &nf_payload));

        assert!(verify_spend(&root, &owner, &nk, DEPTH, &spend));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "membership/range gatés : --release")]
    fn mauvais_owner_rejete() {
        let (n, path, index, nk, _) = setup();
        let (root, spend) = prove_spend(&n, &path, index, &nk);
        assert!(!verify_spend(&root, &digest(999), &nk, DEPTH, &spend));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "membership/range gatés : --release")]
    fn mauvais_nk_rejete() {
        let (n, path, index, nk, owner) = setup();
        let (root, spend) = prove_spend(&n, &path, index, &nk);
        assert!(!verify_spend(&root, &owner, &digest(888), DEPTH, &spend));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "membership/range gatés : --release")]
    fn mauvaise_racine_rejete() {
        let (n, path, index, nk, owner) = setup();
        let (root, spend) = prove_spend(&n, &path, index, &nk);
        assert!(verify_spend(&root, &owner, &nk, DEPTH, &spend));
        assert!(!verify_spend(&digest(7), &owner, &nk, DEPTH, &spend));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "membership/range gatés : --release")]
    fn cm_in_ou_nullifier_falsifie_rejete() {
        let (n, path, index, nk, owner) = setup();
        let (root, mut spend) = prove_spend(&n, &path, index, &nk);
        // cm_in falsifié : casse à la fois le digest du commitment et le leaf.
        let mut faux = spend.cm_in;
        faux.0[0] = Felt::from_canonical_u64(faux.0[0].as_u64() ^ 1).unwrap();
        spend.cm_in = faux;
        assert!(!verify_spend(&root, &owner, &nk, DEPTH, &spend));
    }
}
