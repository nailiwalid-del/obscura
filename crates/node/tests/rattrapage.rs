//! RATTRAPAGE DE BLOC sur de vraies sockets : un nœud qui a manqué une hauteur la
//! redemande, et rejoint la chaîne.
//!
//! # Ce que ce fichier ferme
//!
//! `finalite.rs` montre deux nœuds qui convergent quand ils reçoivent TOUS les blocs.
//! Le trou était juste à côté : un nœud qui en manque UN refuse ensuite tous les
//! suivants (l'état est append-only, rien ne se rattrape) et reste figé **pour
//! toujours**.
//!
//! Ce n'est pas une simple indisponibilité. Un nœud figé sert un historique plus
//! court mais parfaitement COHÉRENT — racine valide, tête valide, transactions
//! acceptées contre son ancre. Tout wallet qui s'y synchronise conclut à tort qu'il
//! est à jour, et ne voit jamais les paiements scellés depuis. C'est pour cela que le
//! rattrapage est un prérequis et non un confort.
//!
//! # Ce que les tests exigent
//!
//! Pas « la demande est partie » — un message qui voyage ne prouve rien. Ils exigent
//! que le nœud en retard finisse avec la **même racine de Merkle** et la **même tête**
//! que le nœud en avance, et que deux nœuds qui ne peuvent PAS se rattraper cessent
//! de se parler au lieu de boucler.

use crypto::sig::SigKeypair;
use ledger::bloc::Bloc;
use ledger::proved_state::ProvedLedgerState;
use node::message::Message;
use node::orchestration::Noeud;
use node::runtime::Runtime;
use proved_hash::digest::ShieldedSecret;
use proved_hash::felt::Felt;
use proved_hash::rescue;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use wallet::Wallet;

const PROFONDEUR: usize = 4;

fn secret(graine: u64) -> ShieldedSecret {
    ShieldedSecret::from_felts(core::array::from_fn(|i| {
        Felt::from_canonical_u64(graine + i as u64).unwrap()
    }))
}

/// Construit LA genèse : deux notes émises vers `w`. Une seule est fabriquée puis
/// PARTAGÉE entre les nœuds — deux nœuds sont d'accord parce qu'ils partent du même
/// bloc 0, pas parce qu'ils rejouent les mêmes gestes.
fn genese_pour(w: &Wallet) -> Bloc {
    let emissions = [1_000u64, 500]
        .iter()
        .map(|valeur| {
            let note = circuit::SpendNote {
                value: *valeur,
                owner: w.owner(),
                rho: rescue::hash(
                    proved_hash::domain::Domain::Owner,
                    &[Felt::from_canonical_u64(*valeur).unwrap(); 4],
                ),
                r: rescue::hash(
                    proved_hash::domain::Domain::Nk,
                    &[Felt::from_canonical_u64(*valeur).unwrap(); 4],
                ),
            };
            let cm = rescue::note_commitment(note.value, &note.owner, &note.rho, &note.r);
            ledger::proved_wallet::emission_vers(&w.adresse().kem, &cm, &note)
        })
        .collect();
    Bloc::genese_avec(emissions).expect("genèse bornée")
}

/// Amorce un état sur `genese` et fait découvrir à `w` ce qui lui revient (par scan).
fn amorcer_sur(genese: &Bloc, w: &mut Wallet) -> ProvedLedgerState {
    let etat = ProvedLedgerState::depuis_genese_depth(genese, PROFONDEUR).expect("amorçage");
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
    w.synchroniser(&[lot]).expect("rejeu de la genèse");
    etat
}

/// Identifiant de pair quelconque : sert à injecter un bloc par le chemin NORMAL de
/// réception, sans monter une troisième socket.
fn pair_fictif() -> net::pairs::PeerId {
    net::pairs::PeerId::depuis_identite(&SigKeypair::generate().public)
}

fn boucler_jusqua<F: FnMut() -> bool>(mut c: F, delai: Duration) -> bool {
    let t = Instant::now();
    while t.elapsed() < delai {
        if c() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    c()
}

/// UN NŒUD QUI A MANQUÉ UN BLOC LE REDEMANDE ET RATTRAPE.
///
/// Scénario, sur de vraies sockets et un canal chiffré :
///
/// 1. A scelle le bloc 1 (une transaction prouvée) alors que B n'est pas connecté :
///    B le manque, et rien dans son état ne le lui dira jamais.
/// 2. A et B se connectent.
/// 3. A applique et diffuse un bloc 2. B ne peut pas l'enchaîner.
///
/// À partir de là tout doit se faire seul : B demande la hauteur 1, l'applique par le
/// chemin NORMAL, constate qu'il est encore en retard, demande la hauteur 2, et
/// rejoint A.
///
/// La propriété exigée n'est pas « B a reçu quelque chose » : c'est l'égalité de la
/// RACINE et de la TÊTE. Deux nœuds aux racines différentes se rejettent
/// mutuellement tout ce qui suit pour « ancre inconnue », sans que rien ne désigne la
/// cause.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn un_noeud_qui_a_manque_un_bloc_rattrape() {
    let mut payeur = Wallet::depuis_secret(secret(700), PROFONDEUR);
    let genese = genese_pour(&payeur);
    let etat_a = amorcer_sur(&genese, &mut payeur);
    let beneficiaire = Wallet::depuis_secret(secret(900), PROFONDEUR);

    // B part de LA MÊME genèse (aucune synchronisation d'historique n'existe).
    let mut miroir = Wallet::depuis_secret(secret(700), PROFONDEUR);
    let etat_b = amorcer_sur(&genese, &mut miroir);
    assert_eq!(etat_a.tree.root(), etat_b.tree.root(), "même genèse");

    let tx = payeur
        .construire(&beneficiaire.adresse(), 300, 20)
        .expect("transaction constructible");
    let nullifier = tx.nullifiers[0];

    let mut a = Runtime::new(Noeud::new(SigKeypair::generate(), etat_a, [1u8; 32]));

    // 1. A scelle le bloc 1 AVANT toute connexion : B ne le verra jamais passer.
    a.noeud_mut().soumettre(tx, 0).expect("admission locale");
    let (bloc1, _actions) = a.noeud_mut().sceller().expect("un bloc à sceller");
    assert_eq!(a.noeud().etat.hauteur(), 1);
    assert_eq!(a.noeud().archive().len(), 1, "A peut resservir le bloc 1");

    // 2. Connexion.
    let ecoute = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let adresse_b = ecoute.local_addr().unwrap();
    let identite_b = SigKeypair::generate();
    let hauteur_b = Arc::new(AtomicU64::new(0));
    let vue_b = Arc::clone(&hauteur_b);

    let serveur = std::thread::spawn(move || {
        let mut rt = Runtime::new(Noeud::new(SigKeypair::generate(), etat_b, [3u8; 32]));
        let (flux, _) = ecoute.accept().unwrap();
        rt.accepter(flux, &identite_b).expect("handshake");
        let rattrape = boucler_jusqua(
            || {
                rt.pomper(0);
                vue_b.store(rt.noeud().etat.hauteur(), Ordering::SeqCst);
                rt.noeud().etat.hauteur() == 2
            },
            Duration::from_secs(60),
        );
        (
            rattrape,
            rt.noeud().etat.tree.root(),
            rt.noeud().etat.tete(),
            rt.noeud().etat.is_spent(&nullifier),
            rt.noeud().blocs_desaccordes(),
        )
    });

    let _pair_b = a.connecter(adresse_b, &SigKeypair::generate()).expect("handshake");

    // 3. Un bloc 2 arrive chez A et repart vers B. Il est VIDE : `sceller` n'en
    //    produit pas (une chaîne au repos ne doit pas s'allonger), mais le protocole
    //    en accepte — c'est le plus court moyen de faire avancer A d'une hauteur
    //    sans fabriquer une seconde preuve STARK. Il joue exactement le rôle du
    //    « bloc suivant » que B ne saura pas enchaîner.
    let bloc2 = Bloc::sceller(&a.noeud().etat.tete(), 2, Vec::new());
    let id2 = bloc2.id();
    let actions = a
        .noeud_mut()
        .traiter(pair_fictif(), Message::Bloc(Box::new(bloc2)), 0);
    a.executer(actions);
    assert_eq!(a.noeud().etat.hauteur(), 2);
    assert_eq!(a.noeud().archive().len(), 2, "A peut resservir 1 ET 2");

    // A doit continuer à POMPER : c'est lui qui répond aux demandes de rattrapage.
    let fini = boucler_jusqua(
        || {
            a.pomper(0);
            hauteur_b.load(Ordering::SeqCst) == 2
        },
        Duration::from_secs(60),
    );
    assert!(fini, "B n'a pas rattrapé dans le délai imparti");

    let (rattrape, racine_b, tete_b, depense_b, desaccords_b) = serveur.join().expect("thread B");

    assert!(rattrape, "B doit avoir APPLIQUÉ les deux blocs manquants");
    assert_eq!(
        racine_b,
        a.noeud().etat.tree.root(),
        "LA propriété : après rattrapage, les deux nœuds voient le même arbre"
    );
    assert_eq!(tete_b, a.noeud().etat.tete(), "et la même tête de chaîne");
    assert_eq!(tete_b, id2);
    assert!(
        depense_b,
        "le nullifier du bloc MANQUÉ est dépensé chez B : il a bien rejoué le bloc 1, \
         pas seulement sauté à la hauteur 2"
    );
    assert_eq!(
        desaccords_b, 1,
        "un seul désaccord — celui qui a déclenché le rattrapage ; \
         davantage signalerait des demandes qui tournent à vide"
    );
    assert_ne!(
        bloc1.id(),
        id2,
        "les deux blocs sont bien distincts (garde-fou du scénario)"
    );
}

/// DEUX NŒUDS QUI NE PEUVENT PAS SE RATTRAPER CESSENT DE SE PARLER.
///
/// Le rattrapage crée un risque que l'immobilité n'avait pas : deux nœuds désaccordés
/// pourraient se demander mutuellement des blocs indéfiniment, chacun servant des
/// hauteurs que l'autre ne peut pas enchaîner. Un amplificateur de trafic construit
/// de nos propres mains.
///
/// Le scénario est le pire cas : A est en avance de plusieurs hauteurs sur une chaîne
/// que B ne peut PAS rejoindre. B demande donc la hauteur manquante, reçoit un bloc
/// qui ne s'enchaîne pas — et doit s'arrêter là.
///
/// L'observable est `blocs_desaccordes` : il compte chaque bloc refusé. S'il se
/// stabilise, l'échange s'est éteint ; s'il monte sans fin, la boucle existe. Le seuil
/// est volontairement généreux (10) pour ne mesurer que la différence entre « borné »
/// et « emballé », pas un nombre exact d'allers-retours.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn deux_noeuds_desaccordes_ne_bouclent_pas() {
    // B scelle SA chaîne : un bloc 1 contenant une transaction prouvée.
    //
    // Une transaction est ici indispensable et non décorative : deux blocs VIDES de
    // même parent et même hauteur sont bit à bit identiques (le scellement est
    // déterministe), donc impossibles à faire diverger. C'est le contenu qui sépare
    // les chaînes.
    let mut payeur = Wallet::depuis_secret(secret(700), PROFONDEUR);
    let genese = genese_pour(&payeur);
    let etat_b = amorcer_sur(&genese, &mut payeur);
    let beneficiaire = Wallet::depuis_secret(secret(900), PROFONDEUR);
    let tx = payeur
        .construire(&beneficiaire.adresse(), 300, 20)
        .expect("transaction constructible");

    let mut noeud_b = Noeud::new(SigKeypair::generate(), etat_b, [3u8; 32]);
    noeud_b.soumettre(tx, 0).expect("admission locale");
    let (bloc_b1, _) = noeud_b.sceller().expect("bloc");
    assert_eq!(noeud_b.etat.hauteur(), 1);

    // A a une AUTRE chaîne, de trois hauteurs, faite de blocs vides.
    let mut noeud_a = Noeud::new(
        SigKeypair::generate(),
        ProvedLedgerState::with_depth(PROFONDEUR),
        [1u8; 32],
    );
    let fictif = pair_fictif();
    for h in 1..=3u64 {
        let b = Bloc::sceller(&noeud_a.etat.tete(), h, Vec::new());
        let _ = noeud_a.traiter(fictif, Message::Bloc(Box::new(b)), 0);
    }
    assert_eq!(noeud_a.etat.hauteur(), 3);
    assert_ne!(
        noeud_a.etat.tete(),
        bloc_b1.id(),
        "les deux chaînes sont bien distinctes (garde-fou du scénario)"
    );

    let ecoute = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let adresse_b = ecoute.local_addr().unwrap();
    let identite_b = SigKeypair::generate();
    let desaccords_b = Arc::new(AtomicU64::new(0));
    let vue = Arc::clone(&desaccords_b);

    let serveur = std::thread::spawn(move || {
        let mut rt = Runtime::new(noeud_b);
        let (flux, _) = ecoute.accept().unwrap();
        rt.accepter(flux, &identite_b).expect("handshake");
        let debut = Instant::now();
        while debut.elapsed() < Duration::from_secs(3) {
            rt.pomper(0);
            vue.store(rt.noeud().blocs_desaccordes(), Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(2));
        }
        (rt.noeud().blocs_desaccordes(), rt.noeud().etat.hauteur())
    });

    let mut a = Runtime::new(noeud_a);
    a.connecter(adresse_b, &SigKeypair::generate()).expect("handshake");

    // A diffuse sa tête : c'est ce qui met B en position de vouloir rattraper.
    let tete = Bloc::from_bytes(a.noeud().archive().octets_a(3).expect("hauteur 3")).unwrap();
    a.executer(vec![node::orchestration::Action::Diffuser(Message::Bloc(
        Box::new(tete),
    ))]);

    let debut = Instant::now();
    while debut.elapsed() < Duration::from_secs(3) {
        a.pomper(0);
        std::thread::sleep(Duration::from_millis(2));
    }

    let (desaccords, hauteur_b) = serveur.join().expect("thread B");
    assert_eq!(hauteur_b, 1, "B n'a pas pu rejoindre la chaîne de A, et c'est correct");
    assert!(
        desaccords <= 10,
        "l'échange doit s'ÉTEINDRE : {desaccords} blocs refusés en 3 s trahit une boucle"
    );
    assert_eq!(
        desaccords_b.load(Ordering::SeqCst),
        desaccords,
        "le compteur s'est stabilisé avant la fin de la fenêtre"
    );
}

/// Une demande pour une hauteur INCONNUE, sur de vraies sockets : ni réponse, ni
/// sanction, ni panique.
///
/// Le silence est la bonne réponse — l'archive est bornée, une hauteur trop ancienne
/// ou d'une autre chaîne est un cas légitime. Répondre par une erreur pénalisante
/// rendrait le rattrapage plus risqué que l'immobilité : un nœud en retard serait
/// banni pour avoir essayé de se réparer.
#[test]
fn demande_de_hauteur_inconnue_reste_sans_reponse_sur_socket() {
    let ecoute = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let adresse_b = ecoute.local_addr().unwrap();
    let identite_b = SigKeypair::generate();

    let serveur = std::thread::spawn(move || {
        let mut rt = Runtime::new(Noeud::new(
            SigKeypair::generate(),
            ProvedLedgerState::with_depth(PROFONDEUR),
            [3u8; 32],
        ));
        let (flux, adresse_client) = ecoute.accept().unwrap();
        let pair = rt.accepter(flux, &identite_b).expect("handshake");
        // `accepter` n'inscrit pas le pair dans la table (c'est `connecter` qui le
        // fait, pour l'anti-eclipse). On l'y met à la main : sans entrée, le score
        // serait inobservable et l'assertion « aucune sanction » vide de sens.
        rt.noeud_mut().pairs.ajouter(pair, adresse_client);
        let debut = Instant::now();
        while debut.elapsed() < Duration::from_secs(2) {
            rt.pomper(0);
            std::thread::sleep(Duration::from_millis(2));
        }
        (
            rt.noeud().pairs.get(&pair).map(|p| p.score).unwrap_or(0),
            rt.liens_ouverts(),
        )
    });

    let mut a = Runtime::new(Noeud::new(
        SigKeypair::generate(),
        ProvedLedgerState::with_depth(PROFONDEUR),
        [1u8; 32],
    ));
    let pair_b = a.connecter(adresse_b, &SigKeypair::generate()).expect("handshake");

    // Hauteurs qu'aucune chaîne au repos ne possède, dont les bornes du domaine.
    for hauteur in [0u64, 1, 12_345, u64::MAX] {
        a.executer(vec![node::orchestration::Action::Envoyer(
            pair_b,
            Message::DemandeBloc { hauteur },
        )]);
    }

    let debut = Instant::now();
    let mut recus = 0;
    while debut.elapsed() < Duration::from_secs(2) {
        recus += a.pomper(0);
        std::thread::sleep(Duration::from_millis(2));
    }

    let (score, liens) = serveur.join().expect("thread B");
    assert_eq!(recus, 0, "silence : aucune réponse ne doit revenir");
    assert_eq!(score, 0, "demander une hauteur inconnue n'est PAS une faute");
    assert_eq!(liens, 1, "et le lien reste ouvert — le nœud n'a pas coupé");
}
