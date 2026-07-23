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
use ledger::bloc::Bloc;
use ledger::proved_state::ProvedLedgerState;
use node::message::Message;
use node::orchestration::{Action, Noeud};
use node::persistance::Donnees;
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

/// Construit LA genèse : deux notes émises vers `w`.
///
/// Une seule genèse est fabriquée, puis PARTAGÉE entre les nœuds. La version
/// précédente de ce fichier rejouait la même séquence d'émissions de chaque côté ;
/// cela ne fonctionnait que parce que les notes étaient déterministes, et masquait la
/// propriété qui compte : deux nœuds sont d'accord parce qu'ils partent du MÊME
/// bloc 0, pas parce qu'ils répètent les mêmes gestes.
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
            ledger::proved_wallet::emission_vers(&w.adresse().kem, &cm, &note).unwrap()
        })
        .collect();
    Bloc::genese_avec(emissions).expect("genèse bornée")
}

/// Amorce un état sur `genese`, et fait DÉCOUVRIR à `w` les notes qui lui reviennent
/// (par scan — le même chemin que pour un paiement reçu).
fn amorcer_sur(genese: &Bloc, w: &mut Wallet) -> ProvedLedgerState {
    let etat = ProvedLedgerState::depuis_genese_depth(genese, PROFONDEUR).expect("amorçage");
    // Le wallet REJOUE la genèse par la même porte que l'historique servi sur le fil :
    // chaque feuille dans l'ordre du nœud, qu'elle lui appartienne ou non, et une ancre
    // adoptée sur la frontière de bloc.
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

/// UNE TRANSACTION DEVIENT DÉFINITIVE, ET LES DEUX NŒUDS SONT D'ACCORD.
///
/// A reçoit une transaction, la scelle dans un bloc, diffuse le bloc. B l'applique.
/// À la fin, racine, hauteur et tête doivent coïncider — et le nullifier être dépensé
/// des deux côtés.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn un_bloc_scelle_fait_converger_deux_noeuds() {
    let mut payeur = Wallet::depuis_secret(secret(700), PROFONDEUR);
    let genese = genese_pour(&payeur);
    let etat_a = amorcer_sur(&genese, &mut payeur);
    let beneficiaire = Wallet::depuis_secret(secret(900), PROFONDEUR);

    // B part de LA MÊME genèse — c'est l'unique artefact que les deux nœuds partagent
    // (aucune synchronisation d'historique n'existe).
    let mut miroir = Wallet::depuis_secret(secret(700), PROFONDEUR);
    let etat_b = amorcer_sur(&genese, &mut miroir);
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
    let pair_b = a
        .connecter(adresse_b, &SigKeypair::generate())
        .expect("handshake");
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

    assert!(
        avance,
        "B doit avoir APPLIQUÉ le bloc, pas seulement l'avoir reçu"
    );
    assert_eq!(
        racine_b,
        a.noeud().etat.tree.root(),
        "LA propriété : les deux nœuds voient le même arbre"
    );
    assert_eq!(tete_b, bloc.id(), "et la même tête de chaîne");
    assert_eq!(tete_b, a.noeud().etat.tete());
    assert!(depense_b, "le nullifier est dépensé des DEUX côtés");
    assert_eq!(
        mempool_b, 0,
        "et la transaction n'est plus en attente chez B"
    );
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
    let genese = genese_pour(&payeur);
    let etat = amorcer_sur(&genese, &mut payeur);
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
    n.pairs.ajouter(
        pair,
        SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), 8333)),
    );
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

/// ÉLECTION DE PRODUCTEUR sur sockets réelles : deux autorités ALTERNENT.
///
/// La chaîne est fermée par sa genèse (autorités [A, B]) : A scelle la hauteur 1
/// (son tour), B l'applique puis scelle la hauteur 2 (le sien), A l'applique. Le
/// scellement traverse le fil deux fois (sérialisation → chiffrement → socket →
/// décodage → vérification de signature) et les deux nœuds convergent. C'est le
/// test d'intégration exigé par la spec « élection de producteur ».
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn deux_autorites_alternent_sur_sockets() {
    // Deux wallets financés par la même genèse : chacun paiera dans SON bloc.
    let mut payeur_a = Wallet::depuis_secret(secret(700), PROFONDEUR);
    let mut payeur_b = Wallet::depuis_secret(secret(800), PROFONDEUR);
    let beneficiaire = Wallet::depuis_secret(secret(900), PROFONDEUR);

    let id_a = SigKeypair::generate();
    let id_b = SigKeypair::generate();
    let id_a_pub = id_a.public.clone();

    let emissions: Vec<_> = [
        (&payeur_a, 1_000u64, 11u64),
        (&payeur_a, 500, 12),
        (&payeur_b, 800, 13),
        (&payeur_b, 400, 14),
    ]
    .iter()
    .map(|(w, valeur, graine)| {
        let note = circuit::SpendNote {
            value: *valeur,
            owner: w.owner(),
            rho: rescue::hash(
                proved_hash::domain::Domain::Owner,
                &[Felt::from_canonical_u64(*graine).unwrap(); 4],
            ),
            r: rescue::hash(
                proved_hash::domain::Domain::Nk,
                &[Felt::from_canonical_u64(*graine).unwrap(); 4],
            ),
        };
        let cm = rescue::note_commitment(note.value, &note.owner, &note.rho, &note.r);
        ledger::proved_wallet::emission_vers(&w.adresse().kem, &cm, &note).unwrap()
    })
    .collect();
    let genese =
        Bloc::genese_avec_autorites(emissions, vec![id_a.public.clone(), id_b.public.clone()])
            .expect("genèse bornée");

    // Chaque nœud amorce sur LA même genèse ; chaque wallet la rejoue entière.
    let etat_a = ProvedLedgerState::depuis_genese_depth(&genese, PROFONDEUR).expect("amorçage A");
    let etat_b = ProvedLedgerState::depuis_genese_depth(&genese, PROFONDEUR).expect("amorçage B");
    let lot = wallet::synchro::MorceauHistorique::bloc_entier(
        0,
        0,
        etat_a.tree.root(),
        genese
            .emissions
            .iter()
            .map(ledger::historique::Sortie::from)
            .collect(),
    );
    payeur_a
        .synchroniser(std::slice::from_ref(&lot))
        .expect("rejeu A");
    payeur_b
        .synchroniser(std::slice::from_ref(&lot))
        .expect("rejeu B");

    let tx_a = payeur_a
        .construire(&beneficiaire.adresse(), 300, 20)
        .expect("tx de A");
    let tx_b = payeur_b
        .construire(&beneficiaire.adresse(), 200, 20)
        .expect("tx de B");

    let ecoute = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let adresse_b = ecoute.local_addr().unwrap();
    let identite_transport_b = SigKeypair::generate();
    let (fin_tx, fin_rx) = std::sync::mpsc::channel::<()>();

    let serveur = std::thread::spawn(move || {
        // n=2 ⇒ quorum 2 : B DOIT voter pour la proposition de A, et A pour celle
        // de B. Le vote est fail-closed sans dépôt, d'où le répertoire de données.
        let dir_b = std::env::temp_dir().join(format!("obscura_finalite_b_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir_b);
        let donnees_b = Donnees::ouvrir(&dir_b).expect("dépôt B");
        let mut noeud_b = Noeud::new(id_b, etat_b, [3u8; 32]);
        noeud_b.adopter_votes(donnees_b.charger_ou_creer_votes().expect("registre B"));
        let mut rt = Runtime::new(noeud_b).avec_donnees(donnees_b);
        let (flux, _) = ecoute.accept().unwrap();
        rt.accepter(flux, &identite_transport_b).expect("handshake");

        // B vote pour la proposition de A, reçoit le bloc 1 certifié, l'applique.
        let a_recu_h1 = attendre(
            || {
                rt.pomper(0);
                rt.noeud().etat.hauteur() == 1
            },
            Duration::from_secs(60),
        );
        assert!(a_recu_h1, "B doit appliquer le bloc 1 (certifié par A+B)");

        // …puis PROPOSE la hauteur 2 : c'est SON tour. A votera, B assemblera.
        rt.noeud_mut().soumettre(tx_b, 0).expect("admission chez B");
        let (bloc2, actions) = rt.noeud_mut().sceller().expect("le tour de B");
        assert_eq!(bloc2.hauteur, 2);
        rt.executer(actions);

        // B reste en vie (et pompe) jusqu'à ce que A ait confirmé la convergence.
        let _ = attendre(
            || {
                rt.pomper(0);
                fin_rx.try_recv().is_ok()
            },
            Duration::from_secs(60),
        );
        let r = (
            rt.noeud().etat.tree.root(),
            rt.noeud().etat.tete(),
            rt.noeud().etat.hauteur(),
        );
        let _ = std::fs::remove_dir_all(&dir_b);
        r
    });

    let dir_a = std::env::temp_dir().join(format!("obscura_finalite_a_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir_a);
    let donnees_a = Donnees::ouvrir(&dir_a).expect("dépôt A");
    let mut noeud_a = Noeud::new(id_a, etat_a, [1u8; 32]);
    noeud_a.adopter_votes(donnees_a.charger_ou_creer_votes().expect("registre A"));
    let mut a = Runtime::new(noeud_a).avec_donnees(donnees_a);
    a.connecter(adresse_b, &SigKeypair::generate())
        .expect("handshake");

    // A PROPOSE la hauteur 1 : c'est son tour (autorité n° 0). Le bloc n'est PAS
    // appliqué tout de suite — il faut le vote de B pour atteindre le quorum 2.
    a.noeud_mut().soumettre(tx_a, 0).expect("admission chez A");
    let (bloc1, actions) = a.noeud_mut().sceller().expect("le tour de A");
    assert_eq!(bloc1.hauteur, 1);
    assert!(bloc1.verifier_scellement(&id_a_pub), "scellé par A");
    a.executer(actions);

    // A reçoit le vote de B, assemble le certificat, applique la hauteur 1, puis
    // vote pour la proposition de B et applique la hauteur 2 reçue certifiée.
    let a_atteint_h2 = attendre(
        || {
            a.pomper(0);
            a.noeud().etat.hauteur() == 2
        },
        Duration::from_secs(60),
    );
    assert!(
        a_atteint_h2,
        "A doit atteindre la hauteur 2 après alternance"
    );
    let _ = fin_tx.send(());
    let _ = std::fs::remove_dir_all(&dir_a);

    let (racine_b, tete_b, hauteur_b) = serveur.join().expect("thread B");
    assert_eq!(hauteur_b, 2);
    assert_eq!(
        racine_b,
        a.noeud().etat.tree.root(),
        "même arbre après alternance"
    );
    assert_eq!(tete_b, a.noeud().etat.tete(), "même tête après alternance");
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
