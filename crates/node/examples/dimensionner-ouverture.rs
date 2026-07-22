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
//! ⚠️ Ce que ce chiffre N'EST PAS. Les gadgets autonomes du crate sont
//! **validity-only** : ils prouvent que l'énoncé est prouvable à cette taille, pas
//! qu'il cache son témoin. Une émission de production exige le masquage
//! (l'équivalent de 3z-b1 pour le monolithe), dont le coût s'ajoute. Le chiffre
//! mesuré ici est donc un **plancher**, pas un devis.
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
