//! LE MENSONGE PAR OMISSION, ET CE QUI LE REND DÉTECTABLE.
//!
//! # Le défaut que ce fichier ferme
//!
//! Un wallet qui prend son historique ET ses racines de bloc au MÊME nœud n'a rien
//! vérifié. Le nœud servant peut TAIRE une sortie : il annonce alors la racine de
//! l'arbre amputé, le wallet insère les feuilles qu'on lui donne, recalcule cette
//! même racine et la trouve conforme. La chaîne est parfaitement close, aucune
//! erreur n'apparaît nulle part — et le paiement omis reste invisible pour
//! toujours. C'est écrit depuis le début dans docs/THREAT_MODEL.md comme une
//! limite ; ce n'était pas une limite fermable par plus de contrôles locaux.
//!
//! Ce qu'il faut est *par nature* extérieur : un identifiant de bloc venu
//! d'AILLEURS. C'est ce que fait le TÉMOIN — un second nœud, interrogé sur la même
//! hauteur, dont on ne retient QUE la racine de fin de bloc.
//!
//! # Ce que le témoin change, et ce qu'il ne change pas
//!
//! Il ne rend pas le nœud servant honnête : il exige que **deux** nœuds mentent de
//! la même façon. C'est tout, et c'est le maximum atteignable sans autorité
//! extérieure — mais la différence est celle entre « indétectable » et « demande
//! une collusion ».
//!
//! ⚠️ Deux nœuds ne suffisent pas s'ils sont le même opérateur. Le témoin n'a de
//! valeur que choisi INDÉPENDAMMENT — ce que le protocole ne peut pas vérifier.

use crypto::sig::SigKeypair;
use ledger::bloc::Bloc;
use ledger::proved_state::ProvedLedgerState;
use net::Connexion;
use node::client::Arret;
use node::orchestration::Noeud;
use node::runtime::Runtime;
use proved_hash::digest::Digest;
use proved_hash::felt::Felt;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use wallet::Wallet;

const PROFONDEUR: usize = 10;
/// La chaîne honnête porte ce nombre de sorties ; le menteur en tait une.
const SORTIES: u64 = 8;

fn commitment(n: u64) -> Digest {
    Digest(core::array::from_fn(|i| {
        Felt::from_canonical_u64(9_000 + n * 64 + i as u64).unwrap()
    }))
}

/// Une genèse de `combien` émissions factices. Le contenu déchiffrable n'importe
/// pas : ce qui est testé est la RACINE, et deux ensembles de feuilles différents
/// en donnent deux différentes.
fn genese_de(combien: u64) -> Bloc {
    let emissions = (0..combien)
        .map(|n| ledger::proved_wallet::emission_factice(&commitment(n)))
        .collect();
    Bloc::genese_avec(emissions).expect("genèse bornée")
}

/// Lance un nœud qui écoute une connexion et pompe jusqu'à l'arrêt.
///
/// `archiviste` distingue les deux rôles : un nœud non archiviste répond au
/// SILENCE à toute demande d'historique — c'est le témoin muet, un cas normal (il
/// n'a pas activé `--archiver`, ou son crédit d'étranglement est épuisé).
fn serveur(
    genese: Bloc,
    ecoute: TcpListener,
    fini: Arc<AtomicBool>,
    archiviste: bool,
) -> std::thread::JoinHandle<()> {
    let identite = SigKeypair::generate();
    std::thread::spawn(move || {
        let etat = if archiviste {
            ProvedLedgerState::depuis_genese_depth_archivant(&genese, PROFONDEUR)
        } else {
            ProvedLedgerState::depuis_genese_depth(&genese, PROFONDEUR)
        }
        .expect("amorçage");
        let mut rt = Runtime::new(Noeud::new(SigKeypair::generate(), etat, [5u8; 32]));
        let (flux, _) = ecoute.accept().unwrap();
        rt.accepter(flux, &identite).expect("handshake");
        while !fini.load(Ordering::SeqCst) {
            rt.pomper(0);
            std::thread::sleep(Duration::from_millis(2));
        }
    })
}

/// Un nœud écoutant sur un port libre, et son adresse.
fn lancer(
    genese: Bloc,
    archiviste: bool,
) -> (SocketAddr, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let ecoute = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let adresse = ecoute.local_addr().unwrap();
    let fini = Arc::new(AtomicBool::new(false));
    let h = serveur(genese, ecoute, Arc::clone(&fini), archiviste);
    (adresse, fini, h)
}

/// Se connecte comme un wallet : transport chiffré éphémère, échéance de lecture
/// courte — c'est elle qui définit le SILENCE.
fn client(adresse: SocketAddr) -> Connexion<TcpStream> {
    let flux = TcpStream::connect(adresse).expect("connexion");
    flux.set_read_timeout(Some(Duration::from_millis(800)))
        .unwrap();
    flux.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    Connexion::connecter(flux, &SigKeypair::generate()).expect("handshake")
}

/// UN NŒUD QUI TAIT UNE SORTIE EST DÉMASQUÉ PAR LE TÉMOIN.
///
/// Le serveur amputé est *cohérent avec lui-même* : sa racine est bien celle de son
/// arbre, et le wallet ne peut rien lui reprocher localement. C'est le témoin, et
/// lui seul, qui apporte l'information manquante — la vraie racine de la hauteur 0.
///
/// Exigence forte : le wallet ne doit RIEN appliquer. Détecter après coup ne
/// servirait à rien, puisque l'arbre porterait déjà des index faux.
#[test]
fn une_sortie_taie_est_demasquee_par_le_temoin() {
    let (menteur, fini_m, h_m) = lancer(genese_de(SORTIES - 1), true);
    let (temoin, fini_t, h_t) = lancer(genese_de(SORTIES), true);

    let mut w = Wallet::nouveau(PROFONDEUR);
    let mut c = client(menteur);
    let mut t = client(temoin);
    let resume = node::client::synchroniser_avec_temoin(
        &mut c,
        Some(&mut t),
        &mut w,
        Duration::ZERO,
        |_, _| Ok(()),
    );

    for f in [&fini_m, &fini_t] {
        f.store(true, Ordering::SeqCst);
    }
    h_m.join().expect("menteur");
    h_t.join().expect("témoin");

    match resume.arret {
        Arret::Desaccord(raison) => assert!(
            raison.contains("hauteur 0"),
            "le désaccord doit nommer la hauteur : {raison}"
        ),
        autre => panic!("désaccord attendu, obtenu {autre:?}"),
    }
    assert_eq!(resume.blocs_rejoues, 0, "rien ne doit être appliqué");
    assert_eq!(
        w.prochaine_hauteur(),
        0,
        "la position du wallet ne bouge pas"
    );
}

/// DEUX NŒUDS D'ACCORD : la synchronisation se déroule normalement.
///
/// Sans ce test, le précédent serait satisfait par un témoin qui refuse TOUT.
#[test]
fn deux_noeuds_daccord_laissent_passer() {
    let (servant, fini_s, h_s) = lancer(genese_de(SORTIES), true);
    let (temoin, fini_t, h_t) = lancer(genese_de(SORTIES), true);

    let mut w = Wallet::nouveau(PROFONDEUR);
    let mut c = client(servant);
    let mut t = client(temoin);
    let resume = node::client::synchroniser_avec_temoin(
        &mut c,
        Some(&mut t),
        &mut w,
        Duration::ZERO,
        |_, _| Ok(()),
    );

    for f in [&fini_s, &fini_t] {
        f.store(true, Ordering::SeqCst);
    }
    h_s.join().expect("servant");
    h_t.join().expect("témoin");

    assert!(
        matches!(resume.arret, Arret::AJour),
        "arrêt inattendu : {:?}",
        resume.arret
    );
    assert_eq!(resume.blocs_rejoues, 1);
    assert_eq!(resume.entrees, SORTIES);
    assert_eq!(w.prochaine_hauteur(), 1);
}

/// UN TÉMOIN MUET N'EST PAS UN ACCORD.
///
/// Le cas est ORDINAIRE : un nœud qui n'archive pas, ou dont le crédit
/// d'étranglement est épuisé, se tait. La tentation serait de continuer en le
/// signalant — ce serait un placebo, puisque l'opérateur croirait avoir corroboré.
/// La boucle s'arrête donc, sans appliquer, avec un arrêt qui le NOMME. Relancer
/// plus tard (ou changer de témoin) reprend là où on s'est arrêté.
#[test]
fn un_temoin_muet_arrete_la_boucle_sans_appliquer() {
    let (servant, fini_s, h_s) = lancer(genese_de(SORTIES), true);
    // Témoin sur la même chaîne, mais SANS archive : il se tait.
    let (temoin, fini_t, h_t) = lancer(genese_de(SORTIES), false);

    let mut w = Wallet::nouveau(PROFONDEUR);
    let mut c = client(servant);
    let mut t = client(temoin);
    let resume = node::client::synchroniser_avec_temoin(
        &mut c,
        Some(&mut t),
        &mut w,
        Duration::ZERO,
        |_, _| Ok(()),
    );

    for f in [&fini_s, &fini_t] {
        f.store(true, Ordering::SeqCst);
    }
    h_s.join().expect("servant");
    h_t.join().expect("témoin");

    assert!(
        matches!(resume.arret, Arret::TemoinMuet),
        "arrêt inattendu : {:?}",
        resume.arret
    );
    assert_eq!(resume.blocs_rejoues, 0, "rien appliqué sans corroboration");
    assert_eq!(w.prochaine_hauteur(), 0);
}
