//! Bench d'une transaction prouvée complète (2-in/2-out) à profondeur consensus (32).
//!
//! Mesure le temps de génération/vérification et la taille d'une preuve `ProvedTx`
//! v3 (circuit P1–P7 monolithique) AVEC WITNESS-HIDING (lignes de blinding en AIR).
//! Trace étendue à 1024 lignes (vs 512 validity-only), blowup = 16.
//! Preuve unique remplace les ~219 Kio (15 preuves v1).
//! Lancer en RELEASE :
//!   cargo run --release --example tx_bench -p circuit

use std::time::Instant;

use circuit::{prove_tx, verify_tx, ProvedInput, ProvedTx, SpendNote, ValidityProof};
use proved_hash::digest::{Digest, ShieldedSecret};
use proved_hash::domain::Domain;
use proved_hash::felt::Felt;
use proved_hash::merkle::ProvedMerkleTree;
use proved_hash::rescue;

fn digest(seed: u64) -> Digest {
    Digest(core::array::from_fn(|i| {
        Felt::from_canonical_u64(seed + i as u64).unwrap()
    }))
}

fn proof_bytes(p: &ValidityProof) -> usize {
    p.0.to_bytes().len()
}

/// Taille de LA preuve monolithique unique (v2 : plus de sous-preuves à sommer).
fn total_proof_bytes(tx: &ProvedTx) -> usize {
    proof_bytes(&tx.proof)
}

fn main() {
    let depth = ProvedMerkleTree::consensus().depth(); // 32
    println!("== Bench ProvedTx 2-in/2-out, arbre profondeur {depth} ==");

    // Clé de dépense et deux notes d'entrée possédées par elle.
    let secret = ShieldedSecret::from_felts(core::array::from_fn(|i| {
        Felt::from_canonical_u64(700 + i as u64).unwrap()
    }));
    let owner = rescue::hash(Domain::Owner, secret.as_felts());
    let n0 = SpendNote { value: 1_000, owner, rho: digest(20), r: digest(30) };
    let n1 = SpendNote { value: 500, owner, rho: digest(40), r: digest(50) };
    let cm0 = rescue::note_commitment(n0.value, &n0.owner, &n0.rho, &n0.r);
    let cm1 = rescue::note_commitment(n1.value, &n1.owner, &n1.rho, &n1.r);

    // Arbre consensus contenant les deux commitments.
    let mut tree = ProvedMerkleTree::consensus();
    let i0 = tree.append(&cm0);
    let i1 = tree.append(&cm1);
    let root = tree.root();
    let path0 = tree.path(i0).unwrap();
    let path1 = tree.path(i1).unwrap();

    let o0 = SpendNote { value: 900, owner: digest(60), rho: digest(61), r: digest(62) };
    let o1 = SpendNote { value: 580, owner: digest(70), rho: digest(71), r: digest(72) };
    let inputs = [
        ProvedInput { note: n0, path: path0, index: i0 },
        ProvedInput { note: n1, path: path1, index: i1 },
    ];

    // Génération. VRAIS enc_notes : chiffrés KEM hybride + AEAD cascade vers deux
    // destinataires éphémères (l'exemple ne peut pas dépendre du crate `ledger` — au-
    // dessus de `circuit` — donc on inline le chiffrement via `crypto`, comme le fait
    // `ledger::proved_wallet::encrypt_note`). Tailles ainsi représentatives de la tx.
    let intent = crypto::sig::SigKeypair::generate();
    let enc_note_reel = |cm: &proved_hash::digest::Digest, note: &SpendNote| {
        let recipient = crypto::kem::KemKeypair::generate();
        let (kem_ct, ss) = crypto::kem::encapsulate(&recipient.public);
        let enc_note = crypto::aead::encrypt(&ss, &cm.to_bytes(), &note.to_bytes());
        circuit::EncNote { kem_ct: kem_ct.to_bytes(), enc_note }
    };
    let oc0 = rescue::note_commitment(o0.value, &o0.owner, &o0.rho, &o0.r);
    let oc1 = rescue::note_commitment(o1.value, &o1.owner, &o1.rho, &o1.r);
    let enc_notes = [enc_note_reel(&oc0, &o0), enc_note_reel(&oc1, &o1)];
    let t0 = Instant::now();
    let (proved_root, tx) = prove_tx(&secret, inputs, [o0, o1], 20, &intent, enc_notes);
    let prove_ms = t0.elapsed().as_secs_f64() * 1e3;
    assert_eq!(proved_root, root);

    // Vérification (moyenne sur quelques passes).
    const V: u32 = 5;
    let t1 = Instant::now();
    for _ in 0..V {
        assert!(verify_tx(&root, depth, &tx));
    }
    let verify_ms = t1.elapsed().as_secs_f64() * 1e3 / V as f64;

    let bytes = total_proof_bytes(&tx);
    println!("=== WITNESS-HIDING (3z-b1, blinding AIR) ===");
    println!("génération  : {prove_ms:8.1} ms");
    println!("vérification: {verify_ms:8.1} ms  (moy. sur {V})");
    println!("taille preuve totale : {bytes} o  ({:.1} Kio)", bytes as f64 / 1024.0);
    println!("  = 1 SEULE preuve STARK monolithique (P1–P7, trace 1024 lignes avec blinding)");
    println!();
    println!("=== BASELINE (3z-a, validity-only) ===");
    println!("génération  :    634.0 ms");
    println!("vérification:      1.5 ms");
    println!("taille preuve totale : 85.3 Kio (trace 512 lignes)");
    println!();
    println!("Δ facteur vs baseline: {:.2}× génération, {:.2}× vérification, {:.2}× taille",
        prove_ms / 634.0, verify_ms / 1.5, bytes as f64 / 1024.0 / 85.3);
}
