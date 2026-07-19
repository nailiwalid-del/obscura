//! 3b5d — Transaction prouvée (`ProvedTx`) : le validateur complet 2-in/2-out.
//!
//! DERNIÈRE brique de l'assemblage 3b5 (validity-only). Assemble `prove_key` (P2∧P4),
//! deux `prove_spend` (P1+P3+P6+P7ᵢₙ), deux `prove_output` (P7+P6), l'équilibre P5
//! (natif, montants publics) et le `tx_digest` (non-rejeu). `verify_tx` établit ainsi
//! **P1–P7 pour la transaction entière**, liée à `tx_digest`.
//!
//! Liaisons : `owner`/`nk` sortis de la clé sont passés à CHAQUE dépense (autorité +
//! clé de nullifier communes) ; les deux dépenses partagent la même racine ; les
//! nullifiers/commitments proviennent des sous-preuves. La signature hybride (côté
//! ledger, hors périmètre) signe `tx_digest`.
//!
//! ⚠️ **À générer en `--release`** (spends/outputs gatés). Forme figée 2-in/2-out ;
//! M-in/N-out + witness-hiding = Phase 3z.

use crate::{
    prove_key, prove_output, prove_spend, verify_key, verify_output, verify_spend, OutputProof,
    SpendNote, SpendProof, ValidityProof,
};
use crypto::hash::dual_hash;
use proved_hash::digest::{Digest, ShieldedSecret};

/// Une entrée à dépenser : la note, son chemin de Merkle et sa position.
pub struct ProvedInput {
    pub note: SpendNote,
    pub path: Vec<Digest>,
    pub index: u64,
}

/// Transaction prouvée 2-in/2-out. Les valeurs de liaison (owner/nk, cm_in/rho/value
/// dans les `SpendProof`, `output_commitments`, fee) sont publiques (validity-only).
pub struct ProvedTx {
    pub owner: Digest,
    pub nk: Digest,
    pub key: ValidityProof,
    pub spends: [SpendProof; 2],
    pub outputs: [OutputProof; 2],
    pub output_commitments: [Digest; 2],
    pub fee: u64,
    pub tx_digest: [u8; 64],
}

const TX_DOMAIN: &str = "obscura/proved-tx/v1";

/// Encodage canonique injectif (tailles fixes) de toutes les données publiques.
fn tx_digest_bytes(
    root: &Digest,
    spends: &[SpendProof; 2],
    output_commitments: &[Digest; 2],
    outputs: &[OutputProof; 2],
    owner: &Digest,
    nk: &Digest,
    fee: u64,
) -> [u8; 64] {
    let mut b = Vec::new();
    b.extend_from_slice(&root.to_bytes());
    for sp in spends {
        b.extend_from_slice(&sp.nullifier.to_bytes());
        b.extend_from_slice(&sp.cm_in.to_bytes());
        b.extend_from_slice(&sp.rho.to_bytes());
        b.extend_from_slice(&sp.value.to_le_bytes());
    }
    for (oc, op) in output_commitments.iter().zip(outputs) {
        b.extend_from_slice(&oc.to_bytes());
        b.extend_from_slice(&op.value.to_le_bytes());
    }
    b.extend_from_slice(&owner.to_bytes());
    b.extend_from_slice(&nk.to_bytes());
    b.extend_from_slice(&fee.to_le_bytes());
    dual_hash(TX_DOMAIN, &b)
}

/// Construit la transaction prouvée. Précondition : notes d'entrée possédées par
/// `secret` (même `owner`), chemins cohérents avec un même arbre, équilibre respecté,
/// montants `< 2^60`. Retourne la racine prouvée et la `ProvedTx`.
pub fn prove_tx(
    secret: &ShieldedSecret,
    inputs: [ProvedInput; 2],
    outputs: [SpendNote; 2],
    fee: u64,
) -> (Digest, ProvedTx) {
    let (owner, nk, key) = prove_key(secret);

    let (root0, sp0) = prove_spend(&inputs[0].note, &inputs[0].path, inputs[0].index, &nk);
    let (root1, sp1) = prove_spend(&inputs[1].note, &inputs[1].path, inputs[1].index, &nk);
    assert_eq!(root0, root1, "les deux entrées doivent appartenir au même arbre");

    let (oc0, op0) = prove_output(&outputs[0]);
    let (oc1, op1) = prove_output(&outputs[1]);

    let spends = [sp0, sp1];
    let outputs_p = [op0, op1];
    let output_commitments = [oc0, oc1];
    let tx_digest = tx_digest_bytes(
        &root0,
        &spends,
        &output_commitments,
        &outputs_p,
        &owner,
        &nk,
        fee,
    );

    (
        root0,
        ProvedTx {
            owner,
            nk,
            key,
            spends,
            outputs: outputs_p,
            output_commitments,
            fee,
            tx_digest,
        },
    )
}

/// Vérifie la transaction contre l'arbre public `root` (profondeur `depth`).
/// Établit P1–P7 pour toute la tx + la liaison `tx_digest`.
pub fn verify_tx(root: &Digest, depth: usize, tx: &ProvedTx) -> bool {
    // P2 ∧ P4 : owner et nk d'un même secret.
    if !verify_key(&tx.owner, &tx.nk, &tx.key) {
        return false;
    }
    // P1+P3+P6+P7ᵢₙ par entrée, owner/nk LIÉS à la clé.
    for sp in &tx.spends {
        if !verify_spend(root, &tx.owner, &tx.nk, depth, sp) {
            return false;
        }
    }
    // P7+P6 par sortie.
    for (oc, op) in tx.output_commitments.iter().zip(&tx.outputs) {
        if !verify_output(oc, op.value, op) {
            return false;
        }
    }
    // P5 (natif) : Σ entrées = Σ sorties + fee (montants publics < 2^60 → pas d'overflow u128).
    let sum_in = tx.spends[0].value as u128 + tx.spends[1].value as u128;
    let sum_out = tx.outputs[0].value as u128 + tx.outputs[1].value as u128 + tx.fee as u128;
    if sum_in != sum_out {
        return false;
    }
    // Non-rejeu : le tx_digest recalculé lie toutes les données publiques.
    let expected = tx_digest_bytes(
        root,
        &tx.spends,
        &tx.output_commitments,
        &tx.outputs,
        &tx.owner,
        &tx.nk,
        tx.fee,
    );
    expected == tx.tx_digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use proved_hash::felt::Felt;
    use proved_hash::merkle;
    use proved_hash::rescue;

    fn digest(seed: u64) -> Digest {
        Digest(core::array::from_fn(|i| {
            Felt::from_canonical_u64(seed + i as u64).unwrap()
        }))
    }

    const DEPTH: usize = 2;

    /// Arbre de profondeur 2 (4 feuilles) : `cm0` en index 0, `cm1` en index 3,
    /// deux feuilles muettes. Retourne (root, path0, path1) selon la convention `fold`.
    fn build_tree(cm0: &Digest, cm1: &Digest) -> (Digest, Vec<Digest>, Vec<Digest>) {
        let l0 = merkle::leaf(cm0);
        let l1 = merkle::leaf(&digest(9001)); // muette
        let l2 = merkle::leaf(&digest(9002)); // muette
        let l3 = merkle::leaf(cm1);
        let n_left = merkle::node(&l0, &l1);
        let n_right = merkle::node(&l2, &l3);
        let root = merkle::node(&n_left, &n_right);
        // index 0 (00) : sib niveau0 = l1, niveau1 = n_right.
        let path0 = vec![l1, n_right];
        // index 3 (11) : sib niveau0 = l2, niveau1 = n_left.
        let path1 = vec![l2, n_left];
        (root, path0, path1)
    }

    /// Deux notes d'entrée possédées par `secret`, équilibrées avec 2 sorties.
    fn valid_tx() -> (ShieldedSecret, Digest, ProvedTx) {
        let secret = ShieldedSecret::from_felts(core::array::from_fn(|i| {
            Felt::from_canonical_u64(700 + i as u64).unwrap()
        }));
        let owner = rescue::hash(proved_hash::domain::Domain::Owner, secret.as_felts());

        let n0 = SpendNote { value: 1_000, owner, rho: digest(20), r: digest(30) };
        let n1 = SpendNote { value: 500, owner, rho: digest(40), r: digest(50) };
        let cm0 = rescue::note_commitment(n0.value, &n0.owner, &n0.rho, &n0.r);
        let cm1 = rescue::note_commitment(n1.value, &n1.owner, &n1.rho, &n1.r);
        let (root, path0, path1) = build_tree(&cm0, &cm1);

        // Sorties (destinataires) : 900 + 580 + fee 20 = 1500 = 1000 + 500.
        let o0 = SpendNote { value: 900, owner: digest(60), rho: digest(61), r: digest(62) };
        let o1 = SpendNote { value: 580, owner: digest(70), rho: digest(71), r: digest(72) };

        let inputs = [
            ProvedInput { note: n0, path: path0, index: 0 },
            ProvedInput { note: n1, path: path1, index: 3 },
        ];
        let (proved_root, tx) = prove_tx(&secret, inputs, [o0, o1], 20);
        assert_eq!(proved_root, root);
        (secret, root, tx)
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn transaction_valide() {
        let (_s, root, tx) = valid_tx();
        assert!(verify_tx(&root, DEPTH, &tx));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn desequilibre_rejete() {
        let (_s, root, mut tx) = valid_tx();
        // Prétendre une sortie plus grosse : l'équilibre natif casse.
        tx.outputs[0].value += 1;
        assert!(!verify_tx(&root, DEPTH, &tx));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn nk_falsifie_rejete() {
        let (_s, root, mut tx) = valid_tx();
        tx.nk = digest(123); // la preuve de clé prouvait le vrai nk.
        assert!(!verify_tx(&root, DEPTH, &tx));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn output_commitment_falsifie_rejete() {
        let (_s, root, mut tx) = valid_tx();
        tx.output_commitments[0] = digest(321);
        assert!(!verify_tx(&root, DEPTH, &tx));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn tx_digest_falsifie_rejete() {
        let (_s, root, mut tx) = valid_tx();
        tx.tx_digest[0] ^= 1;
        assert!(!verify_tx(&root, DEPTH, &tx));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn racine_erronee_rejetee() {
        let (_s, root, tx) = valid_tx();
        assert!(verify_tx(&root, DEPTH, &tx));
        assert!(!verify_tx(&digest(1), DEPTH, &tx));
    }
}
