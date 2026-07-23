//! Dimensionne la PREUVE D'OUVERTURE d'une émission de bloc, en octets réels.
//!
//! Existe pour que le chiffre du critère de franchissement de l'ADR J2
//! (`docs/superpowers/specs/`) reste VÉRIFIABLE plutôt que recopié — même raison
//! que `dimensionner-quorum` pour l'ADR J1. Il décide si le champ `extension` du
//! bloc — réservé, verrouillé vide, et DANS l'identifiant — peut porter le
//! mécanisme d'émission sans nouveau `VERSION_BLOC`.
//!
//! **L'énoncé d'une émission est déjà écrit.** Une coinbase (ou un collecteur de
//! frais) doit prouver qu'un commitment ouvre sur une valeur PUBLIQUE `R(h)`,
//! bénéficiaire caché — soit `oc = H_NoteCommitment(value ‖ owner ‖ rho ‖ r)` avec
//! `value` public et `owner`/`rho`/`r` témoins. C'est exactement le bundle de
//! sortie 3b5c (`prove_output`), à ceci près que son range-check y est INUTILE :
//! `R(h)` étant publique, `R(h) < 2^60` se vérifie en clair, sans preuve. On mesure
//! donc les deux moitiés séparément.
//!
//! ⚠️⚠️ **CE N'EST PAS UNE MESURE DE CONSENSUS.** Deux écarts, tous deux dans le
//! sens de la sous-estimation, séparent ce chiffre d'un devis :
//!
//! 1. **Paramètres de DEV.** Les gadgets autonomes appellent `proof_options()` —
//!    32 requêtes, blowup 8. Le consensus utilise `proof_options_hi()` — 48
//!    requêtes, blowup 16 — parce qu'à 32 la sécurité PROUVÉE n'est que de 62 bits.
//!    Le durcissement du 2026-07-22 a coûté ~43 % de taille sur le monolithe.
//! 2. **Validity-only.** Les gadgets prouvent que l'énoncé est prouvable à cette
//!    taille, pas qu'il CACHE son témoin. Le masquage (équivalent de 3z-b1)
//!    s'ajoute, et rend la taille VARIABLE d'une preuve à l'autre (aléa frais) —
//!    à lire comme une bande, jamais comme une égalité.
//!
//! `proof_options_hi` étant `pub(crate)`, la mesure de consensus demande un test
//! de mesure DANS `crates/circuit`, sur le modèle de `mesure_formes`. Tant qu'il
//! n'existe pas, ce chiffre est un **plancher**, et l'ADR le dit.
//!
//! ```text
//! cargo run -p node --example dimensionner-ouverture --release --features circuit/dev-circuits
//! ```

use circuit::{prove_output, SpendNote};
use proved_hash::digest::{Digest, DIGEST_FELTS};

/// Digest déterministe — la taille de preuve ne dépend pas de sa valeur.
fn digest(seed: u8) -> Digest {
    Digest::from_bytes(&[seed; 32]).expect("digest canonique")
}

fn main() {
    let budget = ledger::bloc::MAX_OCTETS_BLOC;
    let surcout_vide = ledger::bloc::SURCOUT_BLOC_VIDE;

    let note = SpendNote {
        value: 50_000_000,
        owner: digest(1),
        rho: digest(2),
        r: digest(3),
    };

    let (_oc, sortie) = prove_output(&note);
    let n_commit = sortie.commit.0.to_bytes().len();
    let n_range = sortie.range.0.to_bytes().len();
    // Enveloppe du bénéficiaire : c'est la MÊME borne que celle qu'un bloc applique
    // déjà à une émission de genèse — chiffré KEM hybride (X25519 ‖ ML-KEM-768) plus
    // la note scellée. La calculer à la main sous-estimerait d'un ordre de grandeur.
    let n_enc = circuit::tx::KEM_CT_LEN + circuit::tx::MAX_ENC_NOTE_LEN;

    let pct = |n: usize| 100.0 * n as f64 / budget as f64;

    println!("=== preuve d'ouverture d'une émission (plancher validity-only) ===");
    println!("MAX_OCTETS_BLOC        = {budget} o");
    println!("SURCOUT_BLOC_VIDE      = {surcout_vide} o");
    println!("payload engagé         = {} felts", 1 + 3 * DIGEST_FELTS);
    println!();
    println!(
        "ouverture P7 seule     = {n_commit:>7} o   ({:>5.2} % du bloc)",
        pct(n_commit)
    );
    println!(
        "range-check P6         = {n_range:>7} o   ({:>5.2} % du bloc)   INUTILE : R(h) est publique",
        pct(n_range)
    );
    println!(
        "enveloppe bénéficiaire = {n_enc:>7} o   ({:>5.2} % du bloc)",
        pct(n_enc)
    );
    println!(
        "commitment             = {:>7} o",
        proved_hash::digest::DIGEST_BYTES
    );
    println!("                         ─────────");
    let total = n_commit + n_enc + proved_hash::digest::DIGEST_BYTES;
    println!(
        "ÉMISSION COMPLÈTE      = {total:>7} o   ({:>5.2} % du bloc)",
        pct(total)
    );
    println!();
    println!("Reste pour les transactions : {} o", budget - total);
}
