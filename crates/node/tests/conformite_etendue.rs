//! FIXTURE DE CONFORMITÉ ÉTENDUE — la commande qu'un tiers rejoue quand il veut
//! davantage qu'un chaînage.
//!
//! `conformite.rs` (v3) est le contrôle MINIMAL : une genèse à UNE autorité, un bloc
//! VIDE, aucune preuve. Il est petit, rapide, et s'exécute sans `--release` — c'est
//! sa raison d'être, et elle est délibérée. Mais il laisse deux réserves écrites noir
//! sur blanc dans `docs/CONFORMITE.md` : « aucune transaction ni preuve STARK » et
//! « quorum à un seul votant ». Un quorum à un votant ne prouve rien du quorum, et
//! une chaîne sans transaction ne prouve rien de la monnaie.
//!
//! Cette fixture-ci ferme les deux, et une troisième chose que ni l'une ni l'autre ne
//! disait : qu'un paiement confidentiel est RECOUVRABLE par son destinataire.
//!
//! Ce qu'elle contient, et ce que chaque pièce démontre :
//!
//! ```text
//!   genese.bin              4 autorités  → n = 4, f = 1, quorum ⌊2n/3⌋+1 = 3
//!                           1 émission   → de la monnaie existe, chiffrée vers le payeur
//!   bloc-1.bin              1 transaction confidentielle (300 sur 1000, frais 0)
//!                           certificat masque 0x07 → 3 votants DISTINCTS
//!   bloc-1-sous-quorum.bin  LE MÊME bloc, certificat masque 0x03 → 2 votants
//!   beneficiaire.wallet     le matériel du destinataire, état PRÉ-scan
//! ```
//!
//! Le rejeu positif fait passer la preuve STARK par `appliquer_bloc`, c'est-à-dire par
//! le CHEMIN DE CONSENSUS réel et pas par un vérifieur de test. Le rejeu négatif
//! MORD sur la frontière : deux votes sur trois requis, et le bloc est refusé par son
//! nom. Le recouvrement scanne réellement les sorties du bloc et retrouve 300.
//!
//! # Pourquoi une fixture séparée, et pas une v4
//!
//! Les numéros de version de `conformite-v{1,2,3}` tracent les BUMPS DE FORMAT de
//! bloc (`0x04`, puis `0x05`) : chaque bump invalide la fixture précédente *par
//! construction*, et la remplacer plutôt que l'écraser laisse le remplacement visible
//! dans l'historique. Ici le format ne bouge pas — c'est la COUVERTURE qui s'étend.
//! Un « v4 » mentirait sur la nature du changement. Le jour où le format bumpera, les
//! deux fixtures tomberont ensemble, et seront re-datées ensemble.
//!
//! # `--release`, et pourquoi v3 ne l'exige toujours pas
//!
//! Générer et vérifier une preuve STARK est gaté sur `--release` dans tout le dépôt.
//! Faire porter cette contrainte à v3 aurait coûté le seul contrôle de conformité
//! exécutable en build de dev. Deux artefacts, deux rôles : v3 reste le smoke-check
//! nu, celui-ci est la preuve profonde.
//!
//! # Déterminisme PAR COMMIT, pas par régénération
//!
//! Les octets sont produits UNE fois par `generer_la_fixture_etendue` (`#[ignore]`),
//! puis versionnés. Les rejeux les VÉRIFIENT et ne les régénèrent jamais : les
//! signatures sont hedgées et une taille de preuve STARK varie, donc relancer le
//! générateur donnerait un artefact différent — valide, mais différent. Seuls les
//! octets commités font foi. C'est le contrat déjà tenu par v3.

use crypto::sig::SigKeypair;
use ledger::bloc::Bloc;
use ledger::historique::Sortie;
use ledger::proved_state::{BlocRefus, ProvedLedgerState};
use proved_hash::digest::ShieldedSecret;
use proved_hash::felt::Felt;
use proved_hash::merkle::CONSENSUS_DEPTH;
use proved_hash::rescue;
use std::path::PathBuf;
use wallet::synchro::MorceauHistorique;
use wallet::Wallet;

/// Nombre d'autorités de la fixture. `n = 4` ⇒ `f = 1` ⇒ quorum `⌊2·4/3⌋ + 1 = 3` :
/// le plus petit comité où un quorum signifie réellement quelque chose.
const AUTORITES: usize = 4;

fn racine_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/fixtures/conformite-etendue")
}

fn lire(nom: &str) -> Vec<u8> {
    let p = racine_fixture().join(nom);
    std::fs::read(&p).unwrap_or_else(|e| panic!("fixture illisible {} : {e}", p.display()))
}

/// Lit `attendu.txt` : des lignes `clé=valeur`, `#` en commentaire.
///
/// Dupliqué depuis `conformite.rs` plutôt qu'extrait dans un module partagé : les
/// deux fixtures doivent pouvoir diverger (répertoire, jeu de clés, conventions de
/// type) sans qu'un changement de l'une ne touche l'autre — un artefact de
/// conformité qu'on ne peut pas relire seul n'est plus un artefact.
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

/// Secret de wallet déterministe (motif de `quorum_sockets.rs`).
fn secret(graine: u64) -> ShieldedSecret {
    ShieldedSecret::from_felts(core::array::from_fn(|i| {
        Felt::from_canonical_u64(graine + i as u64).unwrap()
    }))
}

/// Rejoue la genèse PUIS le bloc 1 dans `w`, depuis les seuls blocs publiés.
///
/// La genèse suit le motif de `quorum_sockets.rs` : ses sorties sont ses `emissions`.
/// Le bloc 1 est l'endroit délicat — ses sorties ne sont pas dans un champ dédié,
/// elles sont les `output_commitments`/`enc_notes` de ses TRANSACTIONS. Plutôt que de
/// les recoller à la main (donc de réimplémenter l'ordre d'insertion, avec le risque
/// d'index décalés que `wallet::synchro` décrit comme la panne la plus coûteuse du
/// protocole), on amorce l'état en ARCHIVANT : `appliquer_bloc` remplit alors la
/// tranche du bloc — plage de feuilles et racine de fin de bloc — exactement comme le
/// fait un nœud archiviste réel. Que ces sorties SOIENT celles que le bloc engage
/// n'est pas une supposition : `ledger` le vérifie mécaniquement
/// (`historique_est_exactement_ce_que_le_bloc_engage`).
///
/// L'ordre genèse → bloc 1 n'est pas cosmétique : `synchroniser` refuse tout lot qui
/// ne commence pas exactement là où le wallet s'est arrêté.
///
/// Retourne l'état, qui a donc appliqué le bloc 1 — preuve STARK vérifiée comprise.
fn rejouer_dans(w: &mut Wallet, genese: &Bloc, bloc1: &Bloc) -> ProvedLedgerState {
    let mut etat = ProvedLedgerState::depuis_genese_archivant(genese).expect("genèse inamorçable");
    let lot0 = MorceauHistorique::bloc_entier(
        0,
        0,
        etat.tree.root(),
        genese.emissions.iter().map(Sortie::from).collect(),
    );
    w.synchroniser(std::slice::from_ref(&lot0))
        .expect("rejeu de la genèse");

    etat.appliquer_bloc(bloc1).expect("bloc 1 refusé");
    let historique = etat.historique().expect("état amorcé ARCHIVANT");
    let tranche = historique.tranche(1).expect("tranche du bloc 1").clone();
    let sorties = historique
        .sorties_du_bloc(1)
        .expect("sorties du bloc 1")
        .to_vec();
    let lot1 = MorceauHistorique::bloc_entier(1, tranche.debut, tranche.racine_apres, sorties);
    w.synchroniser(std::slice::from_ref(&lot1))
        .expect("rejeu du bloc 1");
    etat
}

/// LE REJEU TIERS. Tout ce qui suit se lit depuis `docs/fixtures/conformite-etendue/`
/// et rien d'autre.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gardées par --release")]
fn la_fixture_etendue_se_rejoue() {
    let att = attendus();

    // 1. La genèse se décode, porte le comité et la monnaie annoncés, et son
    //    identifiant est celui qui est publié.
    let genese = Bloc::from_bytes(&lire("genese.bin")).expect("genèse indécodable");
    assert_eq!(
        genese.autorites.len(),
        AUTORITES,
        "la genèse doit graver QUATRE autorités : c'est ce qui fait du quorum 3 autre \
         chose qu'une auto-certification"
    );
    assert_eq!(
        genese.emissions.len(),
        1,
        "une émission, vers le payeur : sans monnaie, aucune transaction n'existe"
    );
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

    // 3. COHÉRENCE CLÉS ↔ GENÈSE. Les quatre clés publiées sont bien celles que la
    //    genèse grave, dans le même ORDRE — l'index d'un votant est une position dans
    //    cette liste, donc une permutation ferait vérifier le masque contre les
    //    mauvaises clés. Sans ce contrôle, l'artefact pourrait publier des clés
    //    étrangères sans que rien ne le dise.
    for i in 0..AUTORITES {
        let cle = SigKeypair::from_bytes_secret(&lire(&format!("autorite-{i}.cle")))
            .unwrap_or_else(|e| panic!("clé d'autorité {i} illisible : {e:?}"));
        assert_eq!(
            cle.public.to_bytes(),
            genese.autorites[i].to_bytes(),
            "la clé publiée {i} n'est pas l'autorité {i} de la genèse"
        );
    }

    // 4. Le bloc 1 se décode et déclare exactement ce que la fixture annonce : une
    //    transaction, aucune émission (ce serait de l'inflation), aucune
    //    reconfiguration (ce serait un autre scénario), vue 0.
    let bloc1 = Bloc::from_bytes(&lire("bloc-1.bin")).expect("bloc 1 indécodable");
    assert_eq!(bloc1.hauteur, 1, "hauteur 1");
    assert_eq!(bloc1.vue, 0, "vue 0 : nominal, aucun changement de vue ici");
    assert_eq!(
        bloc1.transactions.len(),
        1,
        "UNE transaction confidentielle — c'est elle qui porte la preuve STARK"
    );
    assert!(
        bloc1.emissions.is_empty(),
        "aucune émission hors genèse : ce serait de l'inflation"
    );
    assert!(
        bloc1.changement_autorites.is_none(),
        "aucune reconfiguration : le comité de la genèse est celui qui certifie"
    );
    assert_eq!(hex::encode(bloc1.id()), att["bloc1_id"], "id du bloc 1");

    // 5. Le scellement est celui de l'autorité DU TOUR — `autorites[(1−1+0) mod 4]`,
    //    donc l'autorité 0. « Qui scelle » est une règle, pas une course.
    let producteur = etat
        .producteur_attendu(1, 0)
        .expect("chaîne à autorités attendue")
        .clone();
    assert!(
        bloc1.verifier_scellement(&producteur),
        "le scellement du bloc 1 n'est pas celui de l'autorité du tour"
    );

    // 6. LE CERTIFICAT DE QUORUM, aux valeurs exactes. C'est la réserve §5 de
    //    `docs/CONFORMITE.md` qui tombe ici : trois votants DISTINCTS sur quatre
    //    autorités, pas une autorité unique se certifiant elle-même.
    assert_eq!(
        etat.quorum_requis(),
        att["quorum_requis"].parse::<usize>().expect("décimal"),
        "n = 4 ⇒ quorum ⌊2n/3⌋ + 1 = 3"
    );
    let cert = bloc1
        .certificat
        .as_ref()
        .expect("bloc 1 sans certificat de quorum");
    let masque_attendu = u64::from_str_radix(
        att["masque_certificat"]
            .trim_start_matches("0x")
            .trim_start_matches("0X"),
        16,
    )
    .expect("masque hexadécimal");
    assert_eq!(cert.masque, masque_attendu, "masque du certificat");
    assert_eq!(
        cert.masque, 0x0000_0000_0000_0007,
        "les bits 0, 1 et 2 : les autorités 0, 1 et 2 ont voté"
    );
    // La liste des votants n'est PAS publiée dans `attendu.txt` : elle est l'exacte
    // dérivation du masque, et la dupliquer aurait créé deux sources de vérité pour
    // une seule information. On l'affirme donc ici, où le lecteur voit la dérivation.
    assert_eq!(
        cert.votants().collect::<Vec<_>>(),
        vec![0, 1, 2],
        "un bit mis = une autorité qui a voté, dans l'ordre croissant des index"
    );
    assert_eq!(
        cert.nombre_de_votants(),
        att["nombre_de_votants"].parse::<usize>().expect("décimal"),
        "trois votants distincts"
    );

    // 7. LE BLOC S'APPLIQUE — et c'est ce geste, pas un vérifieur de test, qui fait
    //    passer la PREUVE STARK de la transaction par le chemin de consensus réel
    //    (`appliquer_bloc` → `apply_proved_tx` → `verify_tx`). L'état avance ensuite
    //    exactement comme publié : une racine différente signifierait que la
    //    transaction n'a pas inséré les mêmes sorties dans le même ordre.
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

/// LE DESTINATAIRE RECOUVRE SON PAIEMENT.
///
/// C'est la démonstration que ni v3 ni le rejeu positif ne font : une chaîne peut
/// avancer parfaitement, avec des racines justes et un quorum valide, tout en portant
/// un paiement que son destinataire ne peut pas lire. Le consensus ne l'attraperait
/// jamais — il ne regarde pas le clair.
///
/// Le bénéficiaire est rechargé depuis son matériel PUBLIÉ, à l'état PRÉ-scan (aucune
/// note, position de synchronisation à zéro), puis rejoue les deux blocs et retrouve
/// son montant en le DÉCHIFFRANT.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gardées par --release")]
fn le_beneficiaire_recouvre_son_paiement() {
    let att = attendus();
    let genese = Bloc::from_bytes(&lire("genese.bin")).expect("genèse indécodable");
    let bloc1 = Bloc::from_bytes(&lire("bloc-1.bin")).expect("bloc 1 indécodable");

    let mut beneficiaire =
        Wallet::from_bytes_secret(&lire("beneficiaire.wallet")).expect("wallet illisible");
    assert_eq!(
        beneficiaire.solde(),
        0,
        "le wallet publié est à l'état PRÉ-scan : c'est le tiers qui doit trouver la note, \
         pas la fixture qui la lui donne déjà trouvée"
    );
    // GARDE : le solde à 0 ne suffit pas à démontrer l'état PRÉ-scan — un wallet déjà
    // synchronisé et intégralement dépensé afficherait le même solde. Sans ce contrôle
    // sur la position de synchronisation elle-même, un `beneficiaire.wallet` un jour
    // republié à `prochaine_hauteur = 1` ferait renvoyer au lot de genèse
    // `Ok(Statut::DejaApplique)` (voir `wallet::synchro::Wallet::synchroniser`) au lieu
    // d'une erreur : `rejouer_dans` réussirait quand même, silencieusement, et ce test
    // resterait vert sans avoir démontré un recouvrement DEPUIS ZÉRO.
    assert_eq!(
        beneficiaire.prochaine_hauteur(),
        0,
        "le wallet publié doit être à l'état PRÉ-scan : position de synchronisation à zéro"
    );
    assert!(
        beneficiaire.notes().is_empty(),
        "le wallet publié doit être à l'état PRÉ-scan : aucune note déjà connue"
    );

    rejouer_dans(&mut beneficiaire, &genese, &bloc1);

    assert_eq!(
        beneficiaire.solde(),
        att["solde_beneficiaire"].parse::<u64>().expect("décimal"),
        "le bénéficiaire doit DÉCHIFFRER exactement le montant payé"
    );
    assert_eq!(
        beneficiaire.notes().len(),
        1,
        "une seule sortie lui revient : l'autre est la monnaie rendue au payeur, \
         chiffrée vers une clé qu'il n'a pas"
    );
}

/// LA FRONTIÈRE DE QUORUM MORD : deux votes sur trois requis, et le bloc est refusé.
///
/// Sans ce test, la fixture ne constaterait qu'un bloc accepté — ce qui ne dit rien
/// du seuil. Ici le bloc est le MÊME (même identifiant, donc même parent, même
/// hauteur, même transaction) : seule la taille du certificat change. Un quorum qui
/// ne serait pas réellement appliqué se verrait ici, et nulle part ailleurs.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gardées par --release")]
fn un_quorum_de_deux_est_refuse() {
    let att = attendus();
    let genese = Bloc::from_bytes(&lire("genese.bin")).expect("genèse indécodable");
    // État FRAIS : le bloc doit être refusé sur une chaîne qui l'attend, sinon le
    // refus pourrait venir du chaînage et non du quorum.
    let mut etat = ProvedLedgerState::depuis_genese(&genese).expect("genèse inamorçable");

    let sous_quorum =
        Bloc::from_bytes(&lire("bloc-1-sous-quorum.bin")).expect("bloc sous-quorum indécodable");

    // MÊME IDENTIFIANT que le bloc plein — et c'est une propriété, pas une
    // coïncidence : ni le scellement ni le certificat n'entrent dans le corps
    // canonique, donc recueillir un vote de plus ne change pas l'`id` et n'invalide
    // pas les votes déjà donnés.
    assert_eq!(
        hex::encode(sous_quorum.id()),
        att["bloc1_id"],
        "le certificat n'entre pas dans l'identifiant : le bloc réduit doit porter le MÊME id"
    );
    let cert = sous_quorum
        .certificat
        .as_ref()
        .expect("le bloc sous-quorum porte quand même un certificat, simplement trop court");
    assert_eq!(cert.masque, 0x0000_0000_0000_0003, "les autorités 0 et 1");
    assert_eq!(cert.nombre_de_votants(), 2);

    // Le refus est NOMMÉ, et ses deux champs sont exacts : « obtenu 2, requis 3 ».
    // Un refus générique laisserait un opérateur incapable de distinguer un comité
    // en retard d'un bloc invalide pour tout le monde.
    match etat.appliquer_bloc(&sous_quorum) {
        Err(BlocRefus::QuorumInsuffisant { obtenu, requis }) => {
            assert_eq!(obtenu, 2, "deux votes obtenus");
            assert_eq!(requis, 3, "trois votes requis à n = 4");
        }
        Err(autre) => panic!("refus attendu QuorumInsuffisant, obtenu : {autre}"),
        Ok(_) => panic!(
            "FAILLE DE SÛRETÉ : un bloc à 2 votes sur 4 autorités a été APPLIQUÉ. \
             Deux quorums de cette taille peuvent ne pas se recouper — divergence définitive."
        ),
    }
    // Et l'état n'a pas bougé d'un octet : un bloc refusé ne laisse rien derrière lui.
    assert_eq!(
        hex::encode(etat.tete()),
        att["genese_id"],
        "la tête doit être restée sur la genèse"
    );
    assert_eq!(
        hex::encode(etat.tree.root().to_bytes()),
        att["racine_apres_genese"],
        "la racine doit être restée celle de la genèse"
    );
}

/// Génère la fixture. À lancer À LA MAIN, une fois :
///
/// ```text
/// cargo test -p node --test conformite_etendue --release -- --ignored \
///     generer_la_fixture_etendue --nocapture
/// ```
///
/// ⚠️ **TOUT le matériel secret produit ici est JETABLE et PUBLIÉ** : les quatre clés
/// d'autorité comme le wallet du bénéficiaire. `autorite-{i}.cle` donne le droit de
/// sceller et de voter sur cette chaîne-là ; `beneficiaire.wallet` donne l'autorité de
/// DÉPENSE sur les fonds qu'il détient. C'est assumé et sans conséquence : la chaîne
/// n'existe que dans ce répertoire et sa monnaie n'a aucune valeur. Ne jamais s'en
/// servir ailleurs, et ne jamais reprendre ce motif pour une chaîne réelle.
#[test]
#[ignore]
fn generer_la_fixture_etendue() {
    let dir = racine_fixture();
    std::fs::create_dir_all(&dir).expect("création du répertoire de fixture");

    // 1. LE COMITÉ. Quatre clés, écrites avant tout le reste : c'est d'elles que la
    //    genèse dépend, et un tiers doit pouvoir refaire le lien dans les deux sens.
    let cles: Vec<SigKeypair> = (0..AUTORITES).map(|_| SigKeypair::generate()).collect();
    for (i, cle) in cles.iter().enumerate() {
        std::fs::write(dir.join(format!("autorite-{i}.cle")), cle.to_bytes_secret())
            .expect("écriture de la clé d'autorité");
    }

    // 2. LES DEUX WALLETS. Profondeur CONSENSUS (32) — pas la profondeur réduite des
    //    tests rapides : un artefact de conformité qui prouverait un chemin de Merkle
    //    à 4 niveaux ne dirait rien du chemin réel.
    let mut payeur = Wallet::depuis_secret(secret(700), CONSENSUS_DEPTH);
    let beneficiaire = Wallet::depuis_secret(secret(900), CONSENSUS_DEPTH);

    // 3. LE WALLET DU BÉNÉFICIAIRE EST ÉCRIT ICI, avant toute synchronisation.
    //    `to_bytes_secret` inclut la POSITION de synchronisation : écrit après un
    //    scan, le fichier publierait un wallet déjà à jour, qui refuserait de rejouer
    //    la genèse (`HauteurHorsSequence`) — le tiers ne trouverait rien et le test de
    //    recouvrement ne démontrerait plus rien.
    std::fs::write(
        dir.join("beneficiaire.wallet"),
        beneficiaire.to_bytes_secret(),
    )
    .expect("écriture du wallet bénéficiaire");

    // 4. LA GENÈSE : quatre autorités, une émission de 1000 vers le payeur.
    let valeur = 1_000u64;
    let note = circuit::SpendNote {
        value: valeur,
        owner: payeur.owner(),
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
    let emission = ledger::proved_wallet::emission_vers(&payeur.adresse().kem, &cm, &note).unwrap();
    let genese = Bloc::genese_avec_autorites(
        vec![emission],
        cles.iter().map(|k| k.public.clone()).collect(),
    )
    .expect("genèse bornée");
    std::fs::write(dir.join("genese.bin"), genese.to_bytes()).expect("écriture genèse");

    // 5. LE PAYEUR SE SYNCHRONISE puis construit la transaction. Sans rejeu, il ne
    //    connaît pas l'INDEX de sa note, donc aucun chemin de Merkle, donc aucune
    //    dépense possible.
    let etat = ProvedLedgerState::depuis_genese(&genese).expect("genèse inamorçable");
    let genese_id = hex::encode(genese.id());
    let racine_genese = hex::encode(etat.tree.root().to_bytes());
    let lot0 = MorceauHistorique::bloc_entier(
        0,
        0,
        etat.tree.root(),
        genese.emissions.iter().map(Sortie::from).collect(),
    );
    payeur
        .synchroniser(std::slice::from_ref(&lot0))
        .expect("rejeu de la genèse");
    let tx = payeur
        .construire(&beneficiaire.adresse(), 300, 0)
        .expect("transaction constructible");
    // Conservés pour rebâtir la MÊME transaction dans le bloc sous-quorum :
    // `ProvedTx` n'est pas `Clone`, et l'aller-retour WIRE est de toute façon le
    // chemin qu'emprunterait un pair qui reçoit ce bloc.
    let tx_octets = tx.to_bytes();

    // 6. LE BLOC 1, SCELLÉ ET CERTIFIÉ. Le producteur du tour est `autorites[(1−1+0)
    //    mod 4]`, donc l'autorité 0 — vérifié plutôt que supposé. Les votes sont
    //    signés APRÈS le scellement : ni l'un ni l'autre n'entre dans l'identifiant,
    //    donc l'ordre des deux gestes ne change pas `bloc1_id`.
    let producteur = etat
        .producteur_attendu(1, 0)
        .expect("chaîne à autorités")
        .clone();
    assert_eq!(
        producteur.to_bytes(),
        cles[0].public.to_bytes(),
        "le producteur de la hauteur 1 en vue 0 doit être l'autorité 0"
    );
    let mut bloc1 = Bloc::sceller(&genese.id(), 1, vec![tx]).expect("scellement refusé");
    bloc1.signer_scellement(&cles[0]);
    for (i, cle) in cles.iter().enumerate().take(3) {
        bloc1.signer_vote(i, cle);
    }
    std::fs::write(dir.join("bloc-1.bin"), bloc1.to_bytes()).expect("écriture bloc 1");
    let bloc1_id = hex::encode(bloc1.id());

    // 7. LE MÊME BLOC, RÉDUIT À DEUX VOTES. Même parent, même hauteur, même
    //    transaction : seul le certificat change, donc l'identifiant est identique.
    let tx_bis = circuit::ProvedTx::from_bytes(&tx_octets).expect("aller-retour wire");
    let mut sous_quorum = Bloc::sceller(&genese.id(), 1, vec![tx_bis]).expect("scellement refusé");
    sous_quorum.signer_scellement(&cles[0]);
    for (i, cle) in cles.iter().enumerate().take(2) {
        sous_quorum.signer_vote(i, cle);
    }
    assert_eq!(
        sous_quorum.id(),
        bloc1.id(),
        "le certificat n'entre pas dans l'identifiant : les deux blocs doivent le partager"
    );
    std::fs::write(dir.join("bloc-1-sous-quorum.bin"), sous_quorum.to_bytes())
        .expect("écriture bloc sous-quorum");

    // 8. LES VALEURS ATTENDUES. Le bloc est appliqué sur un état archivant, sur lequel
    //    une COPIE du bénéficiaire — rechargée depuis les octets qu'on vient de
    //    publier, donc exactement ce qu'un tiers lira — rejoue les deux blocs. Relire
    //    le fichier plutôt que réutiliser l'objet en mémoire est délibéré : c'est ce
    //    qui garantit que le wallet publié est réellement exploitable.
    let mut copie = Wallet::from_bytes_secret(
        &std::fs::read(dir.join("beneficiaire.wallet")).expect("relecture du wallet publié"),
    )
    .expect("wallet publié illisible");
    let etat_final = rejouer_dans(&mut copie, &genese, &bloc1);
    let racine_bloc1 = hex::encode(etat_final.tree.root().to_bytes());
    let solde = copie.solde();
    assert_eq!(solde, 300, "le bénéficiaire doit recouvrer le paiement");

    let quorum = etat.quorum_requis();
    let cert = bloc1.certificat.as_ref().expect("certificat");
    let masque = cert.masque;
    let votants = cert.nombre_de_votants();

    let contenu = format!(
        "# Identifiants et racines : HEX. Compteurs et montants : DÉCIMAL. Masque : HEX (u64).\n\
         # Valeurs attendues — fixture de conformité ÉTENDUE (quorum n=4, transaction STARK).\n\
         # Produites par : cargo test -p node --test conformite_etendue --release -- --ignored generer_la_fixture_etendue\n\
         # Vérifiées par : cargo test -p node --test conformite_etendue --release\n\
         genese_id={genese_id}\n\
         racine_apres_genese={racine_genese}\n\
         bloc1_id={bloc1_id}\n\
         racine_apres_bloc1={racine_bloc1}\n\
         quorum_requis={quorum}\n\
         masque_certificat=0x{masque:016x}\n\
         nombre_de_votants={votants}\n\
         solde_beneficiaire={solde}\n"
    );
    std::fs::write(dir.join("attendu.txt"), &contenu).expect("écriture attendu.txt");
    println!("{contenu}");
}
