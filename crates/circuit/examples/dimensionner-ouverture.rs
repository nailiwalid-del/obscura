//! Dimensionne la PREUVE D'OUVERTURE d'une émission de bloc, en octets réels.
//!
//! Existe pour que le chiffre du critère de franchissement de l'ADR J2
//! (`docs/superpowers/specs/`) reste VÉRIFIABLE plutôt que recopié. Il décide si
//! le champ `extension` du bloc — réservé, verrouillé vide, et DANS
//! l'identifiant — peut porter le mécanisme d'émission sans nouveau
//! `VERSION_BLOC`.
//!
//! **L'énoncé d'une émission est déjà écrit.** Une coinbase (ou un collecteur de
//! frais) doit prouver qu'un commitment ouvre sur une valeur PUBLIQUE `R(h)`,
//! bénéficiaire caché — c'est-à-dire `oc = H_NoteCommitment(value ‖ owner ‖ rho ‖ r)`
//! avec `value` public et `owner`/`rho`/`r` témoins. C'est exactement
//! `prove_output`/`verify_output` (3b5c), à ceci près que le range-check y est
//! INUTILE : `R(h)` étant publique, `R(h) < 2^60` se vérifie en clair, sans
//! preuve. On mesure donc les deux moitiés séparément.
//!
//! ⚠️ Ce que ce chiffre N'EST PAS. Les gadgets autonomes du crate sont
//! **validity-only** : ils prouvent que l'énoncé est prouvable à cette taille, pas
//! qu'il cache son témoin. Une émission de production exige le masquage
//! (l'équivalent de 3z-b1 pour le monolithe), dont le coût s'ajoute à ce qui est
//! mesuré ici. Le chiffre est donc un PLANCHER.
//!
//! ```text
//! cargo run -p circuit --example dimensionner-ouverture --release --features dev-circuits
//! ```

use circuit::{prove_output, prove_sponge, SpendNote};
use proved_hash::digest::{Digest, DIGEST_FELTS};
use proved_hash::domain::Domain;
use proved_hash::rescue::note_commit_payload;

/// Digest déterministe — la taille de preuve ne dépend pas de sa valeur.
fn digest(seed: u8) -> Digest {
    Digest::from_bytes(&[seed; 32]).expect("digest canonique")
}

fn main() {
    // Budget : ce que `extension` peut porter. Un bloc plein tient déjà dans
    // MAX_OCTETS_BLOC ; l'émission doit y tenir EN PLUS, donc on la compare au
    // budget total et à ce que coûte une transaction.
    let budget = ledger::bloc::MAX_OCTETS_BLOC;

    let note = SpendNote {
        value: 50_000_000,
        owner: digest(1),
        rho: digest(2),
        r: digest(3),
    };

    // Preuve COMPLÈTE de sortie (P7 ∧ P6) : commitment + range.
    let (oc, sortie) = prove_output(&note);
    let n_commit = sortie.commit.0.to_bytes().len();
    let n_range = sortie.range.0.to_bytes().len();

    // La moitié qui compte pour une émission : le commitment seul, `value`
    // exposée à l'index 0 (owner/rho/r restent témoins). Re-prouvée directement
    // pour mesurer sans dépendre du champ `range`.
    let payload = note_commit_payload(note.value, &note.owner, &note.rho, &note.r);
    let (oc2, commit_seul) = prove_sponge(Domain::NoteCommitment, &payload, &[0]);
    assert_eq!(oc, oc2, "même énoncé, même commitment");
    let n_seul = commit_seul.0.to_bytes().len();

    let pct = |n: usize| 100.0 * n as f64 / budget as f64;

    println!("=== preuve d'ouverture d'une émission (plancher validity-only) ===");
    println!("MAX_OCTETS_BLOC          = {budget} o");
    println!("payload engagé           = {} felts", 1 + 3 * DIGEST_FELTS);
    println!();
    println!(
        "ouverture seule (P7)     = {n_seul:>7} o   ({:.2} % du bloc)",
        pct(n_seul)
    );
    println!(
        "  + range-check (P6)     = {n_range:>7} o   ({:.2} % du bloc)  — INUTILE ici",
        pct(n_range)
    );
    println!(
        "sortie complète (P7∧P6)  = {:>7} o   ({:.2} % du bloc)",
        n_commit + n_range,
        pct(n_commit + n_range)
    );
    println!();
    println!("Pour comparaison, une transaction 2/2 pèse ~96,9 Kio (99 226 o),");
    println!("soit ~9,5 % du bloc. Une émission par bloc coûte donc l'équivalent");
    println!(
        "de {:.2} transaction(s) de forme 2/2.",
        n_seul as f64 / 99_226.0
    );
}
