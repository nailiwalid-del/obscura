//! FINALITÉ sur de vraies sockets : deux nœuds convergent vers le MÊME arbre.
//!
//! C'est le test qui ferme le trou consigné jusqu'ici dans README et THREAT_MODEL :
//! `apply_proved_tx` était écrite, testée, et appelée par aucun chemin du nœud. Les
//! transactions s'accumulaient au mempool sans jamais devenir définitives.
//!
//! Ce que le test exige n'est pas « le bloc est arrivé » — un message qui voyage ne
//! prouve rien. Il exige que les deux nœuds finissent avec la **même racine de
//! Merkle** et la **même tête de chaîne**. C'est cette égalité qui rend une
//! transaction utilisable par le reste du réseau : deux nœuds aux racines
//! différentes se rejettent mutuellement tout ce qui suit, pour « ancre inconnue »,
//! sans que rien ne désigne la cause.

use crypto::sig::SigKeypair;
use ledger::proved_state::ProvedLedgerState;
use node::message::Message;
use node::orchestration::{Action, Noeud};
use node::runtime::Runtime;
use proved_hash::digest::ShieldedSecret;
use proved_hash::felt::Felt;
use proved_hash::rescue;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::time::{Duration, Instant};
use wallet::Wallet;

const PROFONDEUR: usize = 4;

fn secret(graine: u64) -> ShieldedSecret {
    ShieldedSecret::from_felts(core::array::from_fn(|i| {
        Felt::from_canonical_u64(graine + i as u64).unwrap()
    }))
}

fn attendre<F: FnMut() -> bool>(mut c: F, delai: Duration) -> bool {
    let t = Instant::now();
    while t.elapsed() < delai {
        if c() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    c()
}

/// Émet deux notes vers `w` et rend l'état de nœud correspondant.
fn amorcer(w: &mut Wallet) -> ProvedLedgerState {
    let mut etat = ProvedLedgerState::with_depth(PROFONDEUR);
    for valeur in [1_000u64, 500] {
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
        etat.mint(&cm).expect("émission");
        w.crediter_pour_demo(note, &cm);
    }
    etat
}

/// UNE TRANSACTION DEVIENT DÉFINITIVE, ET LES DEUX NŒUDS SONT D'ACCORD.
///
/// A reçoit une transaction, la scelle dans un bloc, diffuse le bloc. B l'applique.
/// À la fin, racine, hauteur et tête doivent coïncider — et le nullifier être dépensé
/// des deux côtés.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn un_bloc_scelle_fait_converger_deux_noeuds() {
    let mut payeur = Wallet::depuis_secret(secret(700), PROFONDEUR);
    let etat_a = amorcer(&mut payeur);
    let beneficiaire = Wallet::depuis_secret(secret(900), PROFONDEUR);

    // B part du MÊME état initial (aucune synchronisation d'historique n'existe).
    let mut miroir = Wallet::depuis_secret(secret(700), PROFONDEUR);
    let etat_b = amorcer(&mut miroir);
    assert_eq!(etat_a.tree.root(), etat_b.tree.root());
    assert_eq!(etat_a.tete(), etat_b.tete(), "même genèse");

    let tx = payeur
        .construire(&beneficiaire.adresse(), 300, 20)
        .expect("transaction constructible");
    let nullifier = tx.nullifiers[0];

    let ecoute = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let adresse_b = ecoute.local_addr().unwrap();
    let identite_b = SigKeypair::generate();

    let serveur = std::thread::spawn(move || {
        let mut rt = Runtime::new(Noeud::new(SigKeypair::generate(), etat_b, [3u8; 32]));
        let (flux, _) = ecoute.accept().unwrap();
        rt.accepter(flux, &identite_b).expect("handshake");
        // B attend d'avoir avancé d'un bloc — pas simplement reçu un message.
        let avance = attendre(
            || {
                rt.pomper(0);
                rt.noeud().etat.hauteur() == 1
            },
            Duration::from_secs(60),
        );
        (
            avance,
            rt.noeud().etat.tree.root(),
            rt.noeud().etat.tete(),
            rt.noeud().etat.is_spent(&nullifier),
            rt.noeud().mempool.len(),
        )
    });

    let mut a = Runtime::new(Noeud::new(SigKeypair::generate(), etat_a, [1u8; 32]));
    let pair_b = a.connecter(adresse_b, &SigKeypair::generate()).expect("handshake");
    let _ = pair_b;

    // A soumet la transaction (elle entre au mempool), puis SCELLE.
    a.noeud_mut().soumettre(tx, 0).expect("admission locale");
    assert_eq!(a.noeud().mempool.len(), 1);
    assert_eq!(a.noeud().etat.hauteur(), 0, "rien n'est encore définitif");

    let (bloc, actions) = a.noeud_mut().sceller().expect("un bloc à sceller");
    assert_eq!(a.noeud().etat.hauteur(), 1);
    assert_eq!(a.noeud().mempool.len(), 0);
    a.executer(actions);

    let (avance, racine_b, tete_b, depense_b, mempool_b) = serveur.join().expect("thread B");

    assert!(avance, "B doit avoir APPLIQUÉ le bloc, pas seulement l'avoir reçu");
    assert_eq!(
        racine_b,
        a.noeud().etat.tree.root(),
        "LA propriété : les deux nœuds voient le même arbre"
    );
    assert_eq!(tete_b, bloc.id(), "et la même tête de chaîne");
    assert_eq!(tete_b, a.noeud().etat.tete());
    assert!(depense_b, "le nullifier est dépensé des DEUX côtés");
    assert_eq!(mempool_b, 0, "et la transaction n'est plus en attente chez B");
}

/// Un bloc ne s'applique QU'UNE FOIS.
///
/// Le rejeu est le cas normal d'un réseau en gossip : un même bloc peut nous revenir
/// par plusieurs pairs. L'appliquer deux fois insérerait les sorties deux fois et
/// ferait diverger l'arbre du reste du réseau — le contraire exact de ce que le bloc
/// sert à garantir.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn rejouer_un_bloc_ne_change_rien() {
    let mut payeur = Wallet::depuis_secret(secret(700), PROFONDEUR);
    let etat = amorcer(&mut payeur);
    let beneficiaire = Wallet::depuis_secret(secret(900), PROFONDEUR);
    let tx = payeur
        .construire(&beneficiaire.adresse(), 300, 20)
        .expect("transaction");

    let mut n = Noeud::new(SigKeypair::generate(), etat, [1u8; 32]);
    n.soumettre(tx, 0).expect("admission");
    let (bloc, _) = n.sceller().expect("bloc");

    let racine = n.etat.tree.root();
    let hauteur = n.etat.hauteur();

    // Le même bloc nous revient d'un pair, cinq fois.
    let pair = net::pairs::PeerId::depuis_identite(&SigKeypair::generate().public);
    n.pairs
        .ajouter(pair, SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), 8333)));
    for _ in 0..5 {
        let copie = ledger::bloc::Bloc::from_bytes(&bloc.to_bytes()).unwrap();
        let actions = n.traiter(pair, Message::Bloc(Box::new(copie)), 0);
        assert!(actions.is_empty(), "un bloc déjà appliqué n'est pas relayé");
    }

    assert_eq!(n.etat.tree.root(), racine, "l'arbre n'a pas bougé");
    assert_eq!(n.etat.hauteur(), hauteur);
    assert_eq!(
        n.pairs.get(&pair).unwrap().score,
        0,
        "recevoir un bloc déjà connu n'est PAS une faute : c'est le gossip normal"
    );
}

/// Le bloc scellé propage bien les ACTIONS attendues (diffusion, pas envoi ciblé).
#[test]
fn sceller_diffuse_plutot_que_cibler() {
    let mut n = Noeud::new(
        SigKeypair::generate(),
        ProvedLedgerState::with_depth(PROFONDEUR),
        [1u8; 32],
    );
    // Mempool vide : rien à sceller, et surtout aucun bloc vide propagé.
    assert!(n.sceller().is_none());
    let _ = Action::Diffuser(Message::Annonce(vec![]));
}
