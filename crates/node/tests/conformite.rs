//! FIXTURE DE CONFORMITÉ — la commande qu'un tiers rejoue.
//!
//! Le critère de la porte AUD est « un tiers vérifie un bloc de la chaîne en
//! n'ayant lu que `docs/` ». Tel quel, il est intestable. Cette fixture le rend
//! falsifiable en une exécution : soit la commande sort les identifiants et les
//! racines attendus, soit elle ne les sort pas.
//!
//! Contenu : une genèse à UNE autorité (donc une chaîne fermée, où le scellement
//! est obligatoire) et un bloc VIDE de hauteur 1, scellé par cette autorité.
//! Aucune transaction, donc aucune preuve STARK — la fixture reste petite et
//! rapide, tout en exerçant chaînage, élection de producteur, vérification de
//! scellement et avancée de la tête.
//!
//! Le générateur (`generer_la_fixture`, `#[ignore]`) produit les fichiers ; il
//! n'est lancé qu'à la main, et son résultat est versionné.

use crypto::sig::SigKeypair;
use ledger::bloc::Bloc;
use ledger::proved_state::ProvedLedgerState;
use std::path::PathBuf;

fn racine_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/fixtures/conformite-v1")
}

fn lire(nom: &str) -> Vec<u8> {
    let p = racine_fixture().join(nom);
    std::fs::read(&p).unwrap_or_else(|e| panic!("fixture illisible {} : {e}", p.display()))
}

/// Lit `attendu.txt` : des lignes `clé=valeur_hex`, `#` en commentaire.
fn attendus() -> std::collections::BTreeMap<String, String> {
    let texte = String::from_utf8(lire("attendu.txt")).expect("attendu.txt non UTF-8");
    let mut m = std::collections::BTreeMap::new();
    for ligne in texte.lines() {
        let ligne = ligne.trim();
        if ligne.is_empty() || ligne.starts_with('#') {
            continue;
        }
        let (cle, val) = ligne
            .split_once('=')
            .unwrap_or_else(|| panic!("ligne sans '=' : {ligne:?}"));
        m.insert(cle.trim().to_string(), val.trim().to_string());
    }
    m
}

#[test]
fn la_fixture_se_rejoue() {
    let att = attendus();

    // 1. La genèse se décode et son identifiant est celui qui est publié.
    let genese = Bloc::from_bytes(&lire("genese.bin")).expect("genèse indécodable");
    assert_eq!(
        hex::encode(genese.id()),
        att["genese_id"],
        "l'identifiant de genèse diffère de la valeur publiée"
    );

    // 2. Elle amorce, et la racine d'état est celle qui est publiée.
    let mut etat = ProvedLedgerState::depuis_genese(&genese).expect("genèse inamorçable");
    assert_eq!(
        hex::encode(etat.tree.root().to_bytes()),
        att["racine_apres_genese"],
        "racine après genèse différente"
    );
    assert_eq!(hex::encode(etat.tete()), att["genese_id"], "tête ≠ genèse");

    // 3. Le bloc 1 se décode, son identifiant est celui qui est publié, et son
    //    scellement est celui de l'autorité gravée dans la genèse.
    let bloc1 = Bloc::from_bytes(&lire("bloc-1.bin")).expect("bloc 1 indécodable");
    assert_eq!(hex::encode(bloc1.id()), att["bloc1_id"], "id du bloc 1");
    let autorite = etat
        .producteur_attendu(1)
        .expect("chaîne à autorités attendue")
        .clone();
    assert!(
        bloc1.verifier_scellement(&autorite),
        "le scellement du bloc 1 n'est pas celui de l'autorité du tour"
    );

    // 4. Il s'applique, et l'état avance exactement comme publié.
    etat.appliquer_bloc(&bloc1).expect("bloc 1 refusé");
    assert_eq!(
        hex::encode(etat.tete()),
        att["bloc1_id"],
        "la tête n'a pas avancé jusqu'au bloc 1"
    );
    assert_eq!(
        hex::encode(etat.tree.root().to_bytes()),
        att["racine_apres_bloc1"],
        "racine après bloc 1 différente"
    );
}

/// Génère la fixture. À lancer À LA MAIN, une fois :
///
/// ```text
/// cargo test -p node --test conformite -- --ignored generer_la_fixture --nocapture
/// ```
///
/// La clé d'autorité produite est JETABLE et publiée avec la fixture : elle
/// n'existe que pour rendre la genèse et le bloc reproductibles. Ne jamais s'en
/// servir ailleurs.
#[test]
#[ignore]
fn generer_la_fixture() {
    let dir = racine_fixture();
    std::fs::create_dir_all(&dir).expect("création du répertoire de fixture");

    let autorite = SigKeypair::generate();
    std::fs::write(dir.join("autorite.cle"), autorite.to_bytes_secret())
        .expect("écriture de la clé");

    let genese = Bloc::genese_avec_autorites(Vec::new(), vec![autorite.public.clone()])
        .expect("genèse refusée");
    std::fs::write(dir.join("genese.bin"), genese.to_bytes()).expect("écriture genèse");

    let mut etat = ProvedLedgerState::depuis_genese(&genese).expect("genèse inamorçable");
    let genese_id = hex::encode(genese.id());
    let racine_genese = hex::encode(etat.tree.root().to_bytes());

    let mut bloc1 = Bloc::sceller(&genese.id(), 1, Vec::new()).expect("scellement refusé");
    bloc1.signer_scellement(&autorite);
    std::fs::write(dir.join("bloc-1.bin"), bloc1.to_bytes()).expect("écriture bloc 1");

    let bloc1_id = hex::encode(bloc1.id());
    etat.appliquer_bloc(&bloc1).expect("bloc 1 refusé");
    let racine_bloc1 = hex::encode(etat.tree.root().to_bytes());

    let contenu = format!(
        "# Valeurs attendues — fixture de conformité v1.\n\
         # Produites par : cargo test -p node --test conformite -- --ignored generer_la_fixture\n\
         # Vérifiées par : cargo test -p node --test conformite\n\
         genese_id={genese_id}\n\
         racine_apres_genese={racine_genese}\n\
         bloc1_id={bloc1_id}\n\
         racine_apres_bloc1={racine_bloc1}\n"
    );
    std::fs::write(dir.join("attendu.txt"), &contenu).expect("écriture attendu.txt");
    println!("{contenu}");
}
