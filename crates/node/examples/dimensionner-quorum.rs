//! Dimensionne le CERTIFICAT DE QUORUM d'un consensus BFT, en octets réels.
//!
//! Existe pour que les chiffres de l'ADR J1 (`docs/superpowers/specs/`) restent
//! VÉRIFIABLES plutôt que recopiés. Ils commandent le choix du modèle de
//! consensus, et ils bougeront si la signature hybride change de taille — ce que
//! toute migration de backend PQ ferait.
//!
//! ⚠️ La contrainte qui rend ce calcul nécessaire est propre à la thèse du
//! projet : **il n'existe pas d'agrégation de signatures post-quantique**.
//! L'astuce qui rend les BFT modernes bon marché (agrégation BLS) repose sur des
//! couplages, cassés par Shor. Un quorum PQ porte donc ses signatures
//! LINÉAIREMENT, et la taille du comité est bornée par le budget du bloc.
//!
//! ```text
//! cargo run -p node --example dimensionner-quorum --release
//! ```

fn main() {
    println!("MAX_OCTETS_BLOC   = {}", ledger::bloc::MAX_OCTETS_BLOC);
    println!(
        "TAILLE_SCELLEMENT = {}",
        ledger::bloc::TAILLE_SCELLEMENT_MAX
    );
    println!("MAX_AUTORITES     = {}", ledger::bloc::MAX_AUTORITES);
    println!("SURCOUT_BLOC_VIDE = {}", ledger::bloc::SURCOUT_BLOC_VIDE);
    let k = crypto::sig::SigKeypair::generate();
    let sig = k.sign("x", b"y").to_bytes().len();
    println!("signature hybride = {sig}");
    for n in [4usize, 7, 10, 16, 31, 64] {
        let f = (n - 1) / 3;
        let q = 2 * f + 1;
        let o = q * sig;
        println!(
            "n={n:3} f={f:2} quorum={q:2} -> QC={o:7} o = {:.1} % du bloc",
            100.0 * o as f64 / ledger::bloc::MAX_OCTETS_BLOC as f64
        );
    }
}
