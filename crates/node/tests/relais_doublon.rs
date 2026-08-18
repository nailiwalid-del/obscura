//! RELAIS D'UN BLOC SAIN, sur de vraies sockets : le doublon qui revient ne doit PAS
//! passer le statut en « préoccupant ».
//!
//! # Le défaut que ce fichier ferme
//!
//! `blocs_desaccordes` existe pour une seule chose : rendre visible un nœud FIGÉ, qui
//! — en retard — refuse des hauteurs qu'il n'a pas encore (cf. `archive.rs`). Dès qu'il
//! est non nul, le statut du nœud devient « préoccupant » (`journal.rs`).
//!
//! Or, dans une chaîne saine, un bloc appliqué est RELAYÉ. Le relais revient vers celui
//! qui l'a scellé, qui a déjà avancé sa tête : le bloc échoue alors à se rechaîner
//! (`ParentInattendu`) — mais à une hauteur qu'il tient DÉJÀ. Rien ne diverge. Compter
//! ce doublon comme un désaccord teintait en permanence le statut d'un réseau qui
//! fonctionne exactement comme prévu.
//!
//! # Ce que le test exige
//!
//! Pas « le bloc a voyagé » : les deux nœuds finissent à la **même hauteur**, la
//! **même tête** et la **même racine** — et `blocs_desaccordes` reste **nul des deux
//! côtés**, malgré le bloc qui a fait l'aller-retour du relais.
//!
//! # Pourquoi une chaîne OUVERTE et un bloc VIDE
//!
//! Le défaut est dans la comptabilité du chaînage, en amont de tout quorum et de toute
//! preuve. Une chaîne ouverte (sans autorités) accepte un bloc vide sans certificat ni
//! scellement ni STARK : c'est le plus court chemin pour faire circuler un vrai bloc
//! entre deux nœuds, et il tourne en test `debug` sans être gaté par `--release`.

use crypto::sig::SigKeypair;
use ledger::bloc::Bloc;
use ledger::proved_state::ProvedLedgerState;
use node::message::Message;
use node::orchestration::{Action, Noeud};
use node::runtime::Runtime;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const PROFONDEUR: usize = 4;

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

/// UNE CHAÎNE SAINE À DEUX NŒUDS GARDE `blocs_desaccordes == 0` APRÈS RELAIS.
///
/// Scénario, sur de vraies sockets et un canal chiffré, calqué sur l'atelier local :
///
/// 1. A et B partent de LA MÊME genèse (chaîne ouverte, genèse déterministe).
/// 2. A applique le bloc 1 et le diffuse à B.
/// 3. B l'applique et le RELAIE — il revient donc vers A, qui est déjà à cette hauteur.
///
/// Ce dernier aller-retour est précisément le doublon bénin. La propriété exigée : les
/// deux nœuds convergent (hauteur, tête, racine) ET aucun des deux ne compte de
/// désaccord.
#[test]
fn chaine_saine_a_deux_noeuds_ne_compte_aucun_desaccord() {
    // Deux états issus de la même genèse ouverte : `with_depth` est déterministe, donc
    // A et B partagent la tête de genèse — condition sine qua non du chaînage.
    let etat_a = ProvedLedgerState::with_depth(PROFONDEUR);
    let etat_b = ProvedLedgerState::with_depth(PROFONDEUR);
    assert_eq!(etat_a.tree.root(), etat_b.tree.root(), "même genèse");
    assert_eq!(etat_a.tete(), etat_b.tete());

    // Le bloc 1 : vide, bien chaîné sur la genèse. Fabriqué avant de déplacer `etat_b`.
    let bloc1 = Bloc::sceller(&etat_a.tete(), 1, Vec::new(), 0).unwrap();
    let id1 = bloc1.id();

    // B écoute ; il applique le bloc reçu, le relaie, et ne s'arrête qu'à la fin.
    let ecoute = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let adresse_b = ecoute.local_addr().unwrap();
    let identite_b = SigKeypair::generate();
    let hauteur_b = Arc::new(AtomicU64::new(0));
    let vue_b = Arc::clone(&hauteur_b);
    let (fin_tx, fin_rx) = std::sync::mpsc::channel::<()>();

    let serveur = std::thread::spawn(move || {
        let mut rt = Runtime::new(Noeud::new(SigKeypair::generate(), etat_b, [3u8; 32]));
        let (flux, _) = ecoute.accept().unwrap();
        rt.accepter(flux, &identite_b).expect("handshake");
        let _ = boucler_jusqua(
            || {
                rt.pomper(0);
                vue_b.store(rt.noeud().etat.hauteur(), Ordering::SeqCst);
                fin_rx.try_recv().is_ok()
            },
            Duration::from_secs(60),
        );
        rt.pomper(0);
        (
            rt.noeud().etat.hauteur(),
            rt.noeud().etat.tete(),
            rt.noeud().etat.tree.root(),
            rt.noeud().blocs_desaccordes(),
        )
    });

    let mut a = Runtime::new(Noeud::new(SigKeypair::generate(), etat_a, [1u8; 32]));
    a.connecter(adresse_b, &SigKeypair::generate())
        .expect("handshake");

    // A applique le bloc 1 par le chemin NORMAL de réception : le succès rend une action
    // de diffusion, que le runtime pousse vers B.
    let actions = a
        .noeud_mut()
        .traiter(pair_fictif(), Message::Bloc(Box::new(bloc1)), 0);
    assert!(
        matches!(actions.as_slice(), [Action::Diffuser(Message::Bloc(_))]),
        "l'application d'un bloc sain doit produire un relais"
    );
    a.executer(actions);
    assert_eq!(a.noeud().etat.hauteur(), 1, "A a appliqué le bloc 1");

    // B rattrape la hauteur 1 (il l'applique et la relaie).
    let b_applique = boucler_jusqua(
        || {
            a.pomper(0);
            hauteur_b.load(Ordering::SeqCst) == 1
        },
        Duration::from_secs(60),
    );
    assert!(
        b_applique,
        "B doit appliquer le bloc 1 dans le délai imparti"
    );

    // Laisser le RELAIS de B revenir vers A et être traité comme doublon.
    let _ = boucler_jusqua(
        || {
            a.pomper(0);
            false
        },
        Duration::from_secs(2),
    );
    let _ = fin_tx.send(());

    let (hauteur_b, tete_b, racine_b, desaccords_b) = serveur.join().expect("thread B");

    // Convergence : les deux nœuds voient la même chaîne.
    assert_eq!(a.noeud().etat.hauteur(), 1);
    assert_eq!(hauteur_b, 1, "B est à la même hauteur que A");
    assert_eq!(
        a.noeud().etat.tete(),
        id1,
        "la tête de A est bien le bloc 1"
    );
    assert_eq!(tete_b, a.noeud().etat.tete(), "même tête des deux côtés");
    assert_eq!(racine_b, a.noeud().etat.tree.root(), "même arbre");

    // LA propriété : le doublon de relais n'a teinté le statut d'AUCUN des deux nœuds.
    assert_eq!(
        a.noeud().blocs_desaccordes(),
        0,
        "A a reçu son propre bloc en relais — un doublon bénin, PAS un désaccord"
    );
    assert_eq!(
        desaccords_b, 0,
        "B n'a fait qu'appliquer un bloc sain : aucun désaccord non plus"
    );
    assert!(
        !node::journal::Statut {
            hauteur: a.noeud().etat.hauteur(),
            pairs: 1,
            liens: 1,
            mempool: 0,
            desaccords: a.noeud().blocs_desaccordes(),
            hauteurs_calees: 0,
        }
        .preoccupant(),
        "une chaîne saine ne doit pas afficher un statut préoccupant"
    );
}
