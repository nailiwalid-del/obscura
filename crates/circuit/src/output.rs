//! 3b5c — Bundle de sortie (Output) par composition.
//!
//! Une note de SORTIE n'a ni appartenance ni nullifier : seulement **P7 ∧ P6**.
//! - `oc = H_NoteCommitment(value ‖ owner ‖ rho ‖ r)`  (P7, `oc` public)
//! - `value < 2^60`                                     (P6)
//!
//! Contrairement à Spend, `owner`/`rho`/`r` de la sortie (celles du DESTINATAIRE)
//! ne se lient à rien d'autre → elles restent témoins ; seul `value` est exposé
//! (lié à l'équilibre du bundle).
//!
//! ⚠️ **À générer en `--release`** (range gaté). Réutilise `SpendNote` comme forme
//! générique de note prouvée.

use crate::{prove_range, prove_sponge, verify_range, verify_sponge, SpendNote, ValidityProof};
use proved_hash::digest::{Digest, DIGEST_FELTS};
use proved_hash::domain::Domain;
use proved_hash::felt::Felt;
use proved_hash::rescue::note_commit_payload;

/// Preuve composée d'une sortie. `value` est la liaison publique (équilibre) ; `oc`
/// (l'output_commitment) est l'entrée publique du statement.
pub struct OutputProof {
    pub value: u64,
    pub commit: ValidityProof,
    pub range: ValidityProof,
}

/// Prouve une note de sortie. Retourne son commitment `oc` et la preuve.
pub fn prove_output(note: &SpendNote) -> (Digest, OutputProof) {
    let payload = note_commit_payload(note.value, &note.owner, &note.rho, &note.r);
    // Expose uniquement `value` (idx 0) ; owner/rho/r restent témoins.
    let (oc, commit) = prove_sponge(Domain::NoteCommitment, &payload, &[0]);
    let range = prove_range(note.value);
    (
        oc,
        OutputProof {
            value: note.value,
            commit,
            range,
        },
    )
}

/// Vérifie une sortie contre son commitment public `oc` et sa valeur publique.
pub fn verify_output(oc: &Digest, value: u64, proof: &OutputProof) -> bool {
    let value_felt = match Felt::from_canonical_u64(value) {
        Ok(f) => f,
        Err(_) => return false,
    };
    // P7 : oc engage `value` (owner/rho/r cachés).
    let ok_commit = verify_sponge(
        Domain::NoteCommitment,
        1 + 3 * DIGEST_FELTS,
        oc,
        &[(0, value_felt)],
        &proof.commit,
    );
    // P6 : value < 2^60.
    let ok_range = verify_range(value, &proof.range);
    ok_commit && ok_range
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

    fn note(value: u64) -> SpendNote {
        SpendNote {
            value,
            owner: digest(40),
            rho: digest(50),
            r: digest(60),
        }
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "range gaté : --release")]
    fn sortie_valide() {
        let n = note(7_777);
        let (oc, proof) = prove_output(&n);
        assert_eq!(oc, rescue::note_commitment(n.value, &n.owner, &n.rho, &n.r));
        assert!(verify_output(&oc, n.value, &proof));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "range gaté : --release")]
    fn valeur_fausse_rejetee() {
        let n = note(1_000);
        let (oc, proof) = prove_output(&n);
        assert!(verify_output(&oc, 1_000, &proof));
        assert!(!verify_output(&oc, 1_001, &proof)); // mauvaise valeur publique
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "range gaté : --release")]
    fn oc_falsifie_rejete() {
        let n = note(42);
        let (oc, proof) = prove_output(&n);
        let mut faux = oc;
        faux.0[0] = Felt::from_canonical_u64(faux.0[0].as_u64() ^ 1).unwrap();
        assert!(!verify_output(&faux, n.value, &proof));
    }
}
