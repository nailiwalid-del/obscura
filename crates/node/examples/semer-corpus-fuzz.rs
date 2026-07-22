//! Sème le corpus de départ du fuzzing de `Bloc::from_bytes`.
//!
//! ```text
//! cargo run -p node --example semer-corpus-fuzz --release
//! ```
//!
//! # Pourquoi un corpus semé
//!
//! Le fuzzing est guidé par la couverture, donc libFuzzer **trouvera** l'octet de
//! version tout seul. Ce qu'il n'atteindra pas en un budget de quelques minutes,
//! ce sont les chemins PROFONDS du décodeur : une émission bien formée, dont le
//! commitment, le `kem_ct` et l'`enc_note` ont tous les longueurs exactes ; ou un
//! certificat dont le masque et le nombre de signatures CONCORDENT — cette
//! dernière contrainte à elle seule est hors de portée d'une mutation aveugle.
//!
//! Partir de blocs VALIDES change la nature de l'exploration : les mutations
//! deviennent des blocs presque valides, c'est-à-dire exactement la forme d'entrée
//! qu'un adversaire fabriquerait.
//!
//! Le corpus est VERSIONNÉ : un fuzzing qui repart de zéro à chaque exécution ne
//! capitalise rien, et deux exécutions ne se valent pas.
//!
//! ⚠️ Les graines n'incluent aucune transaction : à ~68 Kio pièce, elles
//! gonfleraient le dépôt pour un gain nul — le décodage d'une `ProvedTx` a sa
//! propre cible de fuzz (`proved_tx`).

use crypto::sig::SigKeypair;
use ledger::bloc::Bloc;
use std::path::PathBuf;

fn main() {
    let dossier = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/bloc");
    std::fs::create_dir_all(&dossier).expect("création du dossier de corpus");

    let a = SigKeypair::generate();
    let b = SigKeypair::generate();

    let mut graines: Vec<(&str, Vec<u8>)> = Vec::new();

    // 1. Genèse vide — le plus court bloc valide qui existe.
    let genese = Bloc::genese();
    graines.push(("genese-vide", genese.to_bytes()));

    // 2. Genèse à autorités — exerce la boucle de décodage des clés publiques.
    let genese_aut =
        Bloc::genese_avec_autorites(Vec::new(), vec![a.public.clone(), b.public.clone()])
            .expect("genèse à autorités");
    graines.push(("genese-autorites", genese_aut.to_bytes()));

    // 3. Bloc scellé, sans certificat — chemin `scellement présent, certificat absent`.
    let mut scelle = Bloc::sceller(&genese_aut.id(), 1, Vec::new()).expect("scellement");
    scelle.signer_scellement(&a);
    graines.push(("scelle-sans-certificat", scelle.to_bytes()));

    // 4. Bloc scellé ET certifié à UN votant — masque à un bit.
    let mut certifie1 = Bloc::sceller(&genese_aut.id(), 1, Vec::new()).expect("scellement");
    certifie1.signer_scellement(&a);
    certifie1.signer_vote(0, &a);
    graines.push(("certifie-1-votant", certifie1.to_bytes()));

    // 5. Bloc certifié à DEUX votants — masque à plusieurs bits, et surtout un
    //    nombre de signatures qui doit CONCORDER avec le masque. C'est la graine
    //    la plus précieuse : cette concordance est ce qu'une mutation aveugle ne
    //    produira jamais.
    let mut certifie2 = Bloc::sceller(&genese_aut.id(), 1, Vec::new()).expect("scellement");
    certifie2.signer_scellement(&a);
    certifie2.signer_vote(0, &a);
    certifie2.signer_vote(1, &b);
    graines.push(("certifie-2-votants", certifie2.to_bytes()));

    // 6. Bloc de VUE non nulle — le champ ajouté en 0x04.
    let mut vue3 = Bloc::sceller(&genese_aut.id(), 1, Vec::new()).expect("scellement");
    vue3.vue = 3;
    vue3.signer_scellement(&b);
    vue3.signer_vote(1, &b);
    graines.push(("vue-non-nulle", vue3.to_bytes()));

    let mut total = 0usize;
    for (nom, octets) in &graines {
        // AUTO-VÉRIFICATION : une graine indécodable ne semerait rien du tout, et
        // l'erreur ne se verrait qu'au prochain fuzzing — c'est-à-dire trop tard.
        Bloc::from_bytes(octets)
            .unwrap_or_else(|e| panic!("graine « {nom} » INDÉCODABLE : {e} (bug interne)"));
        let chemin = dossier.join(format!("{nom}.bin"));
        std::fs::write(&chemin, octets).expect("écriture de la graine");
        println!("{:<24} {:>7} o", nom, octets.len());
        total += octets.len();
    }
    println!("\n{} graines, {} o au total", graines.len(), total);
    println!("dossier : {}", dossier.display());
}
