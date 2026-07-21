//! Testnet local : propagation d'une transaction PROUVÉE à travers plusieurs nœuds
//! réels, sur de vraies sockets.
//!
//! C'est la validation de bout en bout de toute la pile — circuit STARK, ledger,
//! transport post-quantique, cadrage, pairs, mempool, Dandelion++, orchestration,
//! runtime. Chaque brique a été éprouvée isolément ; ici elles doivent CONVERGER.
//!
//! # Ce que ce test attrape et que les autres ne peuvent pas
//!
//! Une transaction n'est admise que si son ANCRE est une racine récente connue du
//! nœud récepteur. Trois nœuds n'y parviennent que s'ils partagent le même état
//! initial — c'est-à-dire si la construction déterministe de l'état, la
//! sérialisation de la transaction, le transport et l'admission s'accordent TOUS.
//! Un désaccord sur n'importe lequel bloque la propagation sans erreur explicite.

use crypto::sig::SigKeypair;
use ledger::proved_state::ProvedLedgerState;
use node::message::Message;
use node::orchestration::{Action, Noeud};
use node::runtime::Runtime;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::time::{Duration, Instant};

const DEPTH: usize = 4;

/// État initial DÉTERMINISTE, identique sur tous les nœuds, plus la transaction
/// valide qui le dépense.
///
/// Le déterminisme est essentiel : sans lui les nœuds auraient des racines
/// différentes et rejetteraient la transaction pour « ancre inconnue ».
fn etat_partage_et_transaction() -> (ProvedLedgerState, circuit::ProvedTx) {
    use circuit::{prove_tx, ProvedInput, SpendNote};
    use ledger::proved_wallet::encrypt_note;
    use proved_hash::digest::{Digest, ShieldedSecret};
    use proved_hash::domain::Domain;
    use proved_hash::felt::Felt;
    use proved_hash::{merkle, rescue};

    let d = |seed: u64| {
        Digest(core::array::from_fn(|i| {
            Felt::from_canonical_u64(seed + i as u64).unwrap()
        }))
    };
    let secret = ShieldedSecret::from_felts(core::array::from_fn(|i| {
        Felt::from_canonical_u64(700 + i as u64).unwrap()
    }));
    let owner = rescue::hash(Domain::Owner, secret.as_felts());
    let n0 = SpendNote { value: 1_000, owner, rho: d(20), r: d(30) };
    let n1 = SpendNote { value: 500, owner, rho: d(40), r: d(50) };
    let cm0 = rescue::note_commitment(n0.value, &n0.owner, &n0.rho, &n0.r);
    let cm1 = rescue::note_commitment(n1.value, &n1.owner, &n1.rho, &n1.r);

    // La monnaie n'existe QUE par la genèse : les deux notes d'entrée sont des
    // émissions du bloc 0, insérées dans l'ordre (donc index 0 et 1).
    let genese = ledger::bloc::Bloc::genese_avec(vec![
        ledger::proved_wallet::emission_factice(&cm0),
        ledger::proved_wallet::emission_factice(&cm1),
    ])
    .expect("genèse bornée");
    let etat = ProvedLedgerState::depuis_genese_depth(&genese, DEPTH).expect("amorçage");
    let mut arbre = merkle::ProvedMerkleTree::new(DEPTH);
    arbre.append(&cm0);
    arbre.append(&cm1);
    let (i0, i1) = (0u64, 1u64);

    let o0 = SpendNote { value: 900, owner: d(60), rho: d(61), r: d(62) };
    let o1 = SpendNote { value: 580, owner: d(70), rho: d(71), r: d(72) };
    let oc0 = rescue::note_commitment(o0.value, &o0.owner, &o0.rho, &o0.r);
    let oc1 = rescue::note_commitment(o1.value, &o1.owner, &o1.rho, &o1.r);
    let (r0, r1) = (
        crypto::kem::KemKeypair::generate(),
        crypto::kem::KemKeypair::generate(),
    );
    let enc = [
        encrypt_note(&r0.public, &oc0, &o0),
        encrypt_note(&r1.public, &oc1, &o1),
    ];
    let inputs = [
        ProvedInput { note: n0, path: arbre.path(i0).unwrap(), index: i0 },
        ProvedInput { note: n1, path: arbre.path(i1).unwrap(), index: i1 },
    ];
    let intent = SigKeypair::generate();
    let (_root, tx) = prove_tx(&secret, inputs, [o0, o1], 20, &intent, enc);
    (etat, tx)
}

/// Le même état, reconstruit à l'identique (pour un autre nœud).
fn etat_partage() -> ProvedLedgerState {
    etat_partage_et_transaction().0
}

fn attendre<F: FnMut() -> bool>(mut condition: F, delai: Duration) -> bool {
    let debut = Instant::now();
    while debut.elapsed() < delai {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    condition()
}

/// PROPAGATION DE BOUT EN BOUT : une transaction injectée dans le nœud A parvient
/// au nœud B à travers une vraie socket, après vérification STARK complète.
///
/// Le chemin exercé : sérialisation → cadrage → chiffrement → socket → déchiffrement
/// → décodage → admission (5 filtres O(1) puis vérification STARK) → mempool.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn transaction_se_propage_entre_deux_noeuds() {
    let (etat_a, tx) = etat_partage_et_transaction();
    let digest = tx.tx_digest;

    let id_a = SigKeypair::generate();
    let id_b = SigKeypair::generate();
    let ecoute = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let adresse = ecoute.local_addr().unwrap();

    // Nœud B : reçoit et doit finir par détenir la transaction.
    let b = std::thread::spawn(move || {
        let mut rt = Runtime::new(Noeud::new(SigKeypair::generate(), etat_partage(), [2u8; 32]));
        let (flux, _) = ecoute.accept().unwrap();
        rt.accepter(flux, &id_b).expect("handshake");
        let recu = attendre(
            || {
                rt.pomper(0);
                rt.noeud().mempool.contient(&digest)
            },
            Duration::from_secs(30),
        );
        assert!(recu, "B doit finir par détenir la transaction");
        assert_eq!(rt.noeud().mempool.len(), 1);
    });

    // Nœud A : détient la transaction et l'annonce.
    let mut a = Runtime::new(Noeud::new(SigKeypair::generate(), etat_a, [1u8; 32]));
    let pair_b = a.connecter(adresse, &id_a).expect("handshake");
    assert!(
        a.noeud_mut().soumettre(tx, 0).is_ok(),
        "A admet sa propre transaction"
    );

    a.executer(vec![Action::Envoyer(pair_b, Message::Annonce(vec![digest]))]);

    // A doit répondre à la DEMANDE de B en envoyant la transaction : on pompe.
    assert!(
        attendre(|| a.pomper(0) > 0, Duration::from_secs(30)),
        "A doit recevoir la demande de B"
    );

    b.join().expect("nœud B");
}

/// L'ancre fait foi : un nœud dont l'état DIFFÈRE rejette la transaction, sans
/// jamais atteindre la vérification STARK (refus bon marché « ancre inconnue »).
///
/// Ce test protège une propriété de sécurité facile à perdre : accepter une
/// transaction contre un état qu'on ne connaît pas reviendrait à faire confiance
/// au pair.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn noeud_a_l_etat_different_rejette_l_ancre() {
    use ledger::mempool::{Mempool, Refus};

    let (_etat, tx) = etat_partage_et_transaction();
    // Un état VIERGE : il ne connaît pas la racine contre laquelle la tx prouve.
    let etranger = ProvedLedgerState::with_depth(DEPTH);
    let mut m = Mempool::new();
    assert_eq!(
        m.admettre(&etranger, tx),
        Err(Refus::AncreInconnue),
        "une transaction ancrée sur un état inconnu doit être rejetée"
    );
    assert!(
        !Refus::AncreInconnue.couteux(),
        "et ce refus doit être GRATUIT : aucune vérification STARK gaspillée"
    );
}

/// TROIS NŒUDS : la transaction traverse un intermédiaire. C'est le premier
/// scénario où le relais — et non le simple échange — est exercé.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn transaction_traverse_un_intermediaire() {
    let (etat_a, tx) = etat_partage_et_transaction();
    let digest = tx.tx_digest;

    let id_a = SigKeypair::generate();
    let id_b1 = SigKeypair::generate();
    let id_b2 = SigKeypair::generate();
    let id_c = SigKeypair::generate();

    let ecoute_b = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let adr_b = ecoute_b.local_addr().unwrap();
    let ecoute_c = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let adr_c = ecoute_c.local_addr().unwrap();

    // Nœud C : terminal, doit finir par détenir la transaction.
    let c = std::thread::spawn(move || {
        let mut rt = Runtime::new(Noeud::new(SigKeypair::generate(), etat_partage(), [3u8; 32]));
        let (flux, _) = ecoute_c.accept().unwrap();
        rt.accepter(flux, &id_c).expect("handshake C");
        let recu = attendre(
            || {
                rt.pomper(0);
                rt.noeud().mempool.contient(&digest)
            },
            Duration::from_secs(60),
        );
        assert!(recu, "C doit recevoir la transaction VIA B");
    });

    // Nœud B : intermédiaire. Accepte A, se connecte à C, et relaie.
    let b = std::thread::spawn(move || {
        let mut rt = Runtime::new(Noeud::new(SigKeypair::generate(), etat_partage(), [2u8; 32]));
        let (flux, _) = ecoute_b.accept().unwrap();
        rt.accepter(flux, &id_b1).expect("handshake B←A");
        let vers_c = rt.connecter(adr_c, &id_b2).expect("handshake B→C");

        // Dès que B détient la transaction, il l'annonce à C.
        let obtenue = attendre(
            || {
                rt.pomper(0);
                rt.noeud().mempool.contient(&digest)
            },
            Duration::from_secs(45),
        );
        assert!(obtenue, "B doit d'abord obtenir la transaction de A");
        rt.executer(vec![Action::Envoyer(vers_c, Message::Annonce(vec![digest]))]);

        // Puis répondre à la demande de C.
        assert!(
            attendre(|| rt.pomper(0) > 0, Duration::from_secs(45)),
            "B doit recevoir la demande de C"
        );
    });

    // Nœud A : origine.
    let mut a = Runtime::new(Noeud::new(SigKeypair::generate(), etat_a, [1u8; 32]));
    let pair_b = a.connecter(adr_b, &id_a).expect("handshake A→B");
    assert!(a.noeud_mut().soumettre(tx, 0).is_ok());
    a.executer(vec![Action::Envoyer(pair_b, Message::Annonce(vec![digest]))]);
    assert!(
        attendre(|| a.pomper(0) > 0, Duration::from_secs(45)),
        "A doit recevoir la demande de B"
    );

    b.join().expect("nœud B");
    c.join().expect("nœud C");
}
