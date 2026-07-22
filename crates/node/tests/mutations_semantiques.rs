//! MUTATIONS SÉMANTIQUES — ce que le fuzzing d'octets ne peut pas atteindre.
//!
//! Défaut n°2 de la porte D. Les décodeurs sont fuzzés (`fuzz/fuzz_targets/`), mais
//! un fuzzer aléatoire **ne produira jamais une preuve STARK valide** : il s'arrête
//! au décodeur, et tout ce qui est DERRIÈRE — l'admission, la confrontation à l'état,
//! la vérification — n'est jamais exercé sur une entrée bien formée mais hostile.
//!
//! Ce test comble le trou par l'autre bout : il part d'une transaction **valide**,
//! mute un champ SÉMANTIQUE, et exige un refus **nommé**.
//!
//! # Ce qui est réellement vérifié, et pourquoi ça compte
//!
//! Pas seulement « c'est refusé ». Aussi **à quel prix**. L'asymétrie de coût est LE
//! vecteur de DoS du projet : ~4 ms de vérification STARK pour ~68 Kio envoyés. Les
//! cinq filtres O(1) existent précisément pour que l'attaquant ne puisse pas
//! déclencher la vérification à volonté. Un refus qui *pourrait* être prononcé à coût
//! nul mais qui ne l'est qu'après la preuve serait une régression invisible en test
//! fonctionnel — et un vecteur de DoS.
//!
//! `Refus::couteux()` distingue les deux, et chaque mutation déclare lequel elle
//! attend.
//!
//! # Ce que le test ne prétend pas être
//!
//! Ce n'est pas du fuzzing aléatoire : les mutations sont ÉNUMÉRÉES et
//! déterministes. C'est un choix — une mutation aléatoire d'un champ sémantique est
//! presque toujours rejetée pour la même raison, et n'apprendrait rien de plus. La
//! valeur est dans la couverture des CHAMPS, pas dans le volume.

use crypto::sig::SigKeypair;
use ledger::bloc::Bloc;
use ledger::mempool::{Mempool, Refus};
use ledger::proved_state::ProvedLedgerState;
use proved_hash::digest::ShieldedSecret;
use proved_hash::felt::Felt;
use proved_hash::merkle::CONSENSUS_DEPTH;
use proved_hash::rescue;
use wallet::Wallet;

/// Une mutation nommée : son étiquette, et la fonction qui l'applique.
type Mutation = (&'static str, fn(&mut circuit::ProvedTx));

fn secret(graine: u64) -> ShieldedSecret {
    ShieldedSecret::from_felts(core::array::from_fn(|i| {
        Felt::from_canonical_u64(graine + i as u64).unwrap()
    }))
}

fn genese_pour(w: &Wallet) -> Bloc {
    let valeur = 1_000u64;
    let note = circuit::SpendNote {
        value: valeur,
        owner: w.owner(),
        rho: rescue::hash(
            proved_hash::domain::Domain::Owner,
            &[Felt::from_canonical_u64(valeur).unwrap(); 4],
        ),
        r: rescue::hash(
            proved_hash::domain::Domain::Nk,
            &[Felt::from_canonical_u64(valeur).unwrap(); 4],
        ),
    };
    let cm = rescue::note_commitment(note.value, &note.owner, &note.rho, &note.r);
    let emission = ledger::proved_wallet::emission_vers(&w.adresse().kem, &cm, &note).unwrap();
    Bloc::genese_avec_autorites(vec![emission], vec![SigKeypair::generate().public])
        .expect("genèse bornée")
}

/// Retourne un bit du premier octet d'un digest — mutation minimale et localisée.
fn muter_digest(d: &mut proved_hash::digest::Digest) {
    let mut o = d.to_bytes();
    o[0] ^= 0x01;
    *d = proved_hash::digest::Digest::from_bytes(&o).expect("digest muté encodable");
}

/// Prépare l'état, le mempool et UNE transaction valide.
fn preparer() -> (ProvedLedgerState, Mempool, circuit::ProvedTx) {
    let mut payeur = Wallet::depuis_secret(secret(700), CONSENSUS_DEPTH);
    let beneficiaire = Wallet::depuis_secret(secret(900), CONSENSUS_DEPTH);
    let genese = genese_pour(&payeur);
    let etat = ProvedLedgerState::depuis_genese(&genese).expect("amorçage");
    let lot = wallet::synchro::MorceauHistorique::bloc_entier(
        0,
        0,
        etat.tree.root(),
        genese
            .emissions
            .iter()
            .map(ledger::historique::Sortie::from)
            .collect(),
    );
    payeur
        .synchroniser(std::slice::from_ref(&lot))
        .expect("rejeu");
    let tx = payeur
        .construire(&beneficiaire.adresse(), 300, 0)
        .expect("transaction valide");
    (etat, Mempool::new(), tx)
}

/// CONTRÔLE — sans cette assertion, tout le reste du fichier pourrait passer avec
/// une transaction qui n'était de toute façon pas admissible.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn la_transaction_temoin_est_admise() {
    let (etat, mut mp, tx) = preparer();
    assert_eq!(mp.admettre(&etat, tx), Ok(()), "le témoin doit être admis");
    assert_eq!(mp.len(), 1);
}

/// ANCRE mutée : refusée **à coût nul**. C'est la propriété la plus importante du
/// fichier — une ancre inconnue est le refus le moins cher, et il doit le rester.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn ancre_mutee_refusee_sans_verifier_la_preuve() {
    let (etat, mut mp, mut tx) = preparer();
    muter_digest(&mut tx.anchor);
    let refus = mp.admettre(&etat, tx).expect_err("ancre inconnue");
    assert_eq!(refus, Refus::AncreInconnue);
    assert!(
        !refus.couteux(),
        "REGRESSION DE DoS : une ancre inconnue doit être refusée AVANT la \
         vérification STARK. La faire passer par la preuve offrirait à un attaquant \
         ~4 ms de notre CPU pour ~68 Kio de sa bande passante."
    );
    assert_eq!(mp.len(), 0);
}

/// NULLIFIER muté : la preuve ne l'engage plus. Refus coûteux, et c'est normal —
/// aucun filtre O(1) ne peut le détecter, le nullifier muté n'étant ni connu de la
/// chaîne ni du mempool.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn nullifier_mute_refuse() {
    let (etat, mut mp, mut tx) = preparer();
    muter_digest(&mut tx.nullifiers[0]);
    let refus = mp.admettre(&etat, tx).expect_err("preuve invalide");
    assert_eq!(refus, Refus::PreuveInvalide);
    assert!(refus.couteux(), "il a bien fallu vérifier pour le savoir");
    assert_eq!(mp.len(), 0);
}

/// COMMITMENT DE SORTIE muté : c'est la substitution de bénéficiaire. Si elle
/// passait, un relais pourrait détourner un paiement en vol.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn commitment_de_sortie_mute_refuse() {
    let (etat, mut mp, mut tx) = preparer();
    muter_digest(&mut tx.output_commitments[0]);
    assert_eq!(
        mp.admettre(&etat, tx),
        Err(Refus::PreuveInvalide),
        "substituer un bénéficiaire doit être impossible"
    );
    assert_eq!(mp.len(), 0);
}

/// FRAIS mutés : c'est la création de valeur. Si elle passait, l'équilibre
/// `Σin = Σout + fee` serait rompu sans qu'aucune preuve ne le contredise.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn frais_mutes_refuses() {
    let (etat, mut mp, mut tx) = preparer();
    tx.fee = tx.fee.wrapping_add(1);
    assert_eq!(
        mp.admettre(&etat, tx),
        Err(Refus::PreuveInvalide),
        "modifier les frais rompt l'équilibre et doit être refusé"
    );
    assert_eq!(mp.len(), 0);
}

/// PREUVE mutée : le cas le plus direct, et celui qui doit rester bon marché à
/// REFUSER même s'il est coûteux à VÉRIFIER.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn preuve_mutee_refusee() {
    let (etat, mut mp, tx) = preparer();
    // `ValidityProof` est un newtype sur la preuve winterfell : on passe par
    // l'aller-retour WIRE de la transaction entière, seul chemin public — et le
    // seul par lequel un attaquant réel modifierait une preuve.
    let mut octets = tx.to_bytes();
    let n = octets.len();
    octets[n - 40] ^= 0x01;

    // ⚠️ Le mutant DOIT se décoder. S'il était refusé au décodage, ce test
    // passerait sans jamais exercer la vérification STARK — il deviendrait un
    // test de décodeur déguisé. L'assertion épingle donc la branche.
    let relu = circuit::ProvedTx::from_bytes(&octets)
        .expect("le mutant doit se DÉCODER, sinon la preuve n'est jamais vérifiée");
    assert_eq!(
        mp.admettre(&etat, relu),
        Err(Refus::PreuveInvalide),
        "une preuve altérée doit être refusée par la VÉRIFICATION"
    );
    assert_eq!(mp.len(), 0);
}

/// REJEU : la même transaction deux fois. Refus **à coût nul** — c'est le cas le
/// plus fréquent en propagation normale, et le faire passer par la preuve
/// coûterait 4 ms à chaque annonce redondante du réseau.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn rejeu_refuse_sans_verifier_la_preuve() {
    let (etat, mut mp, tx) = preparer();
    let copie = circuit::ProvedTx::from_bytes(&tx.to_bytes()).expect("aller-retour wire");
    mp.admettre(&etat, tx).expect("première admission");
    let refus = mp.admettre(&etat, copie).expect_err("doublon");
    assert_eq!(refus, Refus::DejaConnue);
    assert!(
        !refus.couteux(),
        "REGRESSION DE DoS : un doublon doit être refusé AVANT la vérification"
    );
    assert_eq!(mp.len(), 1);
}

/// TOUTE mutation doit survivre à l'ALLER-RETOUR WIRE sans panique.
///
/// C'est le point de jonction avec le fuzzing d'octets : un mutant sémantique
/// arrive par le réseau, donc il passe d'abord par `from_bytes`. Deux issues sont
/// acceptables — refus au décodage, ou refus à l'admission — et **aucune autre**.
/// Ce qui est interdit, c'est la panique et l'acceptation.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn les_mutants_traversent_le_fil_sans_panique() {
    let mutations: Vec<Mutation> = vec![
        ("ancre", |tx| muter_digest(&mut tx.anchor)),
        ("nullifier", |tx| muter_digest(&mut tx.nullifiers[0])),
        ("sortie", |tx| muter_digest(&mut tx.output_commitments[0])),
        ("frais", |tx| tx.fee = tx.fee.wrapping_add(1)),
        ("tx_digest", |tx| tx.tx_digest[0] ^= 0x01),
    ];

    for (nom, muter) in mutations {
        let (etat, mut mp, mut tx) = preparer();
        muter(&mut tx);
        let octets = tx.to_bytes();
        match circuit::ProvedTx::from_bytes(&octets) {
            // Refusé au décodage : le mutant n'atteint même pas l'admission.
            Err(_) => {}
            // Décodé : l'admission doit alors le refuser. Jamais l'accepter.
            Ok(relu) => {
                let r = mp.admettre(&etat, relu);
                assert!(
                    r.is_err(),
                    "mutation « {nom} » ACCEPTÉE après aller-retour wire — \
                     c'est une faille de consensus, pas un défaut de test"
                );
            }
        }
        assert_eq!(mp.len(), 0, "mutation « {nom} » : rien n'entre au mempool");
    }
}
