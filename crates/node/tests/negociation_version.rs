//! Négociation de version (J3) sur de VRAIES sockets.
//!
//! Quatre scénarios, et un seul coupe :
//!
//! - deux nœuds À JOUR échangent `Version` en tête et dialoguent normalement ;
//! - un pair qui n'envoie JAMAIS `Version` (un nœud d'avant J3) est servi comme les
//!   autres : ni banni, ni pénalisé, ni mis en attente ;
//! - un pair annonçant `protocole = 0` (sous le minimum) est déconnecté POUR DE BON,
//!   et **sans la moindre sanction de score** ;
//! - un CLIENT qui n'annonce pas ne reçoit AUCUNE `Version` ; s'il annonce, il
//!   reçoit UNE réponse et pas deux.
//!
//! # L'invariant tenu ici : la coexistence, dans les DEUX sens
//!
//! Un déploiement de la négociation ne doit pas forker le réseau. Il faut donc que
//! le nouveau n'exige rien de l'ancien (scénario 2, exercé sur socket), et que
//! l'ancien ne condamne pas le nouveau (le message part avec un tag AU-DELÀ de la
//! frontière connue d'avant J3 : chez lui c'est un message « du futur », ignoré sans
//! pénalité — cf. `message::tests::tag_version_est_une_version_future_pour_un_noeud_davant_j3`
//! et l'assertion sur le premier octet ci-dessous).
//!
//! # La règle est ASYMÉTRIQUE
//!
//! Seul le CONNECTEUR annonce spontanément ; l'ACCEPTEUR ne répond que s'il a reçu
//! une annonce, et une seule fois. Un client qui n'annonce pas ne reçoit donc AUCUNE
//! `Version` — ce qui supprime l'écriture SYSTÉMATIQUE en tête de lien, c'est-à-dire
//! le cas « toujours » de la perte silencieuse d'un « j'envoie et je raccroche » (un
//! `RST` de fermeture fait jeter au nœud son tampon de réception, transaction
//! comprise). La négociation nœud↔nœud ne perd rien : tout nœud se connecte en
//! sortant.
//!
//! ⚠️ Ce que ces tests ne prouvent PAS, et ce que personne ne doit leur faire dire :
//! que le nœud n'écrit JAMAIS rien de non sollicité. `Action::Diffuser` atteint tous
//! les liens ouverts, entrants compris, pour des causes indépendantes du client
//! (embargo Dandelion++ expiré, scellement, relais de bloc, proposition de changement
//! d'autorités) — cf. `synchronisation.rs::une_diffusion_pendant_la_synchronisation_ne_lavorte_pas`.
//! Ici aucune de ces causes n'est déclenchée ; le silence observé est donc celui de
//! la NÉGOCIATION, pas celui du trafic.
//!
//! # Pourquoi un pair BRUT plutôt qu'un second `Runtime`
//!
//! Un `Runtime` qui se connecte annonce toujours sa version : il ne peut donc pas
//! jouer l'ancien nœud. Le pair est monté directement sur `net::Connexion` — le même
//! transport chiffré, sans la politique applicative. C'est aussi ce qui permet
//! d'inspecter les octets RÉELLEMENT reçus, plutôt que de croire une structure Rust.

use crypto::sig::SigKeypair;
use ledger::proved_state::ProvedLedgerState;
use node::message::{Message, VERSION_PROTOCOLE};
use node::orchestration::Noeud;
use node::runtime::Runtime;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

/// Dernier tag applicatif attribué AVANT J3 (`TAG_VOTE`). Un nœud de cette époque
/// classe tout tag supérieur en « version future » : ignoré, jamais sanctionné.
const DERNIER_TAG_AVANT_J3: u8 = 9;

fn noeud(secret: u8) -> Noeud {
    Noeud::new(
        SigKeypair::generate(),
        ProvedLedgerState::with_depth(4),
        [secret; 32],
    )
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

/// Écoute sur un port libre — les tests s'exécutent alors en parallèle sans
/// collision.
fn ecoute() -> (TcpListener, SocketAddr) {
    let l = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let a = l.local_addr().unwrap();
    (l, a)
}

/// Un pair BRUT : transport chiffré réel, aucune politique applicative. Échéance de
/// lecture posée pour qu'un test ne puisse pas se figer indéfiniment.
fn pair_brut(ecoute: &TcpListener) -> net::Connexion<TcpStream> {
    let (flux, _) = ecoute.accept().unwrap();
    flux.set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    flux.set_write_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    net::Connexion::accepter(flux, &SigKeypair::generate()).expect("handshake côté pair brut")
}

/// SCÉNARIO 1 — deux nœuds à jour : chacun apprend la version de l'autre, et le
/// trafic ordinaire passe ensuite comme avant.
///
/// ⚠️ Les deux côtés se tiennent la main jusqu'à la fin des vérifications : un
/// `Runtime` qui tombe ferme sa socket, et le lien d'en face avec — ce qui ferait
/// échouer l'assertion « le lien reste ouvert » pour une raison qui n'a rien à voir
/// avec la négociation.
#[test]
fn deux_noeuds_a_jour_echangent_leur_version() {
    let (l, adresse) = ecoute();
    let (pret_tx, pret_rx) = std::sync::mpsc::channel::<()>();
    let (fin_tx, fin_rx) = std::sync::mpsc::channel::<()>();

    let client = std::thread::spawn(move || {
        let mut rt = Runtime::new(noeud(2));
        let pair = rt
            .connecter(adresse, &SigKeypair::generate())
            .expect("handshake");
        let vu = attendre(
            || {
                rt.pomper(0);
                rt.noeud().version_annoncee(&pair).is_some()
            },
            Duration::from_secs(30),
        );
        assert!(vu, "le client doit apprendre la version du serveur");
        assert_eq!(
            rt.noeud().version_annoncee(&pair),
            Some(VERSION_PROTOCOLE),
            "la version annoncée est celle que nous parlons"
        );
        assert_eq!(rt.liens_ouverts(), 1, "le lien reste ouvert");

        // TRAFIC ORDINAIRE après la négociation : rien n'a changé pour le reste du
        // protocole. C'est ce que « fonctionnent normalement » veut dire.
        rt.executer(vec![node::orchestration::Action::Diffuser(
            Message::Annonce(vec![[9u8; 64]]),
        )]);
        // Le serveur répond par une Demande (mempool vide). Le seul effet observable
        // d'ici est NÉGATIF : aucune fermeture ne doit en découler. On pompe donc un
        // nombre BORNÉ de fois puis on constate — `attendre(|| liens == 1)` serait
        // vrai dès le premier appel, avant tout traitement, et n'affirmerait rien.
        // (Que la `Demande` soit bien produite est vérifié sur le fil par le
        // scénario 2 et par `deux_noeuds::annonce_declenche_une_demande_sur_le_fil`.)
        for _ in 0..100 {
            rt.pomper(0);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            rt.liens_ouverts(),
            1,
            "le lien survit à l'échange ordinaire"
        );
        pret_tx.send(()).expect("signal");
        // Tenir le lien ouvert pendant les vérifications d'en face.
        let _ = fin_rx.recv_timeout(Duration::from_secs(30));
    });

    let mut rt = Runtime::new(noeud(1));
    let (flux, _) = l.accept().unwrap();
    let pair = rt
        .accepter(flux, &SigKeypair::generate())
        .expect("handshake");
    let vu = attendre(
        || {
            rt.pomper(0);
            rt.noeud().version_annoncee(&pair).is_some()
        },
        Duration::from_secs(30),
    );
    assert!(vu, "le serveur doit apprendre la version du client");
    assert_eq!(rt.noeud().version_annoncee(&pair), Some(VERSION_PROTOCOLE));

    // Puis l'annonce du client, traitée comme n'importe quelle autre.
    let echange = attendre(
        || {
            rt.pomper(0);
            pret_rx.try_recv().is_ok()
        },
        Duration::from_secs(30),
    );
    assert!(echange, "l'échange ordinaire doit aboutir des deux côtés");
    assert_eq!(rt.liens_ouverts(), 1, "aucune coupure sur un pair à jour");
    fin_tx.send(()).expect("signal");
    client.join().expect("thread client");
}

/// SCÉNARIO 2 — COEXISTENCE : un pair qui n'annonce JAMAIS sa version est présumé
/// parler la version de base. Il est servi, son score reste intact, aucun blocage.
///
/// C'est le nœud d'AVANT J3. Le test vérifie aussi ce qu'il REÇOIT de nous : un
/// message dont le tag dépasse sa frontière connue, donc classé « version future »
/// chez lui — ignoré sans pénalité.
#[test]
fn un_pair_sans_version_nest_ni_banni_ni_penalise() {
    let (l, adresse) = ecoute();
    let (servi_tx, servi_rx) = std::sync::mpsc::channel::<()>();
    let (fin_tx, fin_rx) = std::sync::mpsc::channel::<()>();

    let ancien = std::thread::spawn(move || {
        let mut c = pair_brut(&l);

        // Ce que le NOUVEAU nous envoie spontanément, en tête.
        let octets = c.recevoir().expect("premier message applicatif");
        assert_eq!(
            octets.first().copied(),
            Some(10u8),
            "le premier message applicatif est la Version"
        );
        assert!(
            octets[0] > DERNIER_TAG_AVANT_J3,
            "tag au-delà de la frontière d'avant J3 : « version future », donc ignoré \
             sans sanction par un nœud en arrière"
        );

        // L'ancien nœud, lui, n'annonce RIEN : il parle directement.
        c.envoyer(&Message::Annonce(vec![[3u8; 64]]).to_bytes())
            .expect("envoi");

        // Et il est servi normalement : le nouveau lui demande la transaction.
        let reponse = c.recevoir().expect("réponse du nouveau nœud");
        match Message::from_bytes(&reponse).expect("réponse décodable") {
            Message::Demande(d) => assert_eq!(d, vec![[3u8; 64]]),
            _ => panic!("le pair sans version doit être servi comme les autres"),
        }
        servi_tx.send(()).expect("signal");
        // Tenir le lien ouvert : un pair qui raccroche fermerait la socket, et
        // l'assertion « aucune déconnexion » d'en face perdrait tout son sens.
        let _ = fin_rx.recv_timeout(Duration::from_secs(30));
    });

    let mut rt = Runtime::new(noeud(1));
    let pair = rt
        .connecter(adresse, &SigKeypair::generate())
        .expect("handshake");
    let servi = attendre(
        || {
            rt.pomper(0);
            servi_rx.try_recv().is_ok()
        },
        Duration::from_secs(30),
    );
    assert!(servi, "le pair muet doit être servi normalement");

    assert_eq!(
        rt.noeud().version_annoncee(&pair),
        None,
        "aucune version annoncée : présumé version de base, jamais exigé"
    );
    let p = rt.noeud().pairs.get(&pair).expect("pair sortant connu");
    assert_eq!(p.score, 0, "AUCUNE pénalité pour un pair qui se tait");
    assert!(!p.banni());
    assert_eq!(rt.liens_ouverts(), 1, "aucune déconnexion");
    fin_tx.send(()).expect("signal");
    ancien.join().expect("thread pair ancien");
}

/// Échéance de lecture du scénario 4.
///
/// Elle sert DEUX usages opposés : attendre une réponse (qui arrive en
/// millisecondes sur boucle locale) et constater une ABSENCE (qui coûte l'échéance
/// entière, deux fois). D'où une valeur unique et courte — la régler en cours de
/// route par un clone du flux ne fonctionne pas partout, `SO_RCVTIMEO` n'étant pas
/// garanti partagé entre descripteurs dupliqués.
const COURT: Duration = Duration::from_secs(3);

/// SCÉNARIO 4 — LA RÈGLE ASYMÉTRIQUE, vérifiée sur le fil dans ses trois moments.
///
/// 1. Un client qui n'annonce rien ne reçoit **aucune `Version`** — et, ce nœud-ci ne
///    diffusant rien, rien du tout. C'est ce qui supprime l'écriture SYSTÉMATIQUE en
///    tête de lien, donc le cas « toujours » de la perte silencieuse d'un « j'envoie
///    et je raccroche » : fermer une socket portant des octets non lus provoque un
///    `RST`, et un `RST` fait jeter au nœud son tampon de réception — donc la
///    transaction qu'on venait de lui envoyer.
///
///    ⚠️ Ce que ce point NE dit pas : que le nœud n'écrira jamais rien. Une
///    `Action::Diffuser` atteint tous les liens ouverts, entrants compris, pour des
///    causes indépendantes du client. Le silence observé ici est celui d'un nœud qui
///    n'a rien à diffuser, pas une garantie de protocole.
/// 2. S'il annonce, il reçoit la version du nœud en réponse : la négociation reste
///    complète pour qui la demande.
/// 3. S'il réannonce, il ne reçoit **plus rien** : la réponse est unique. Sans cela,
///    un pair obtiendrait une réponse gratuite par annonce (amplification), et deux
///    nœuds se répondraient indéfiniment.
#[test]
fn un_client_qui_nannonce_pas_ne_recoit_aucune_version() {
    let (l, adresse) = ecoute();
    let (fini_tx, fini_rx) = std::sync::mpsc::channel::<()>();

    let serveur = std::thread::spawn(move || {
        let mut rt = Runtime::new(noeud(1));
        let (flux, _) = l.accept().unwrap();
        let pair = rt
            .accepter(flux, &SigKeypair::generate())
            .expect("handshake");
        // `accepter` n'inscrit pas le pair dans la table (c'est le rôle de
        // `connecter`, pour l'anti-eclipse) : sans entrée, le score serait
        // inobservable et « aucune sanction » ne voudrait rien dire.
        rt.noeud_mut()
            .pairs
            .ajouter(pair, SocketAddr::from((Ipv4Addr::LOCALHOST, 1)));
        while fini_rx.try_recv().is_err() {
            rt.pomper(0);
            std::thread::sleep(Duration::from_millis(2));
        }
        (
            rt.noeud().pairs.get(&pair).map(|p| p.score).unwrap_or(0),
            rt.liens_ouverts(),
            rt.noeud().version_annoncee(&pair),
        )
    });

    let flux = TcpStream::connect(adresse).expect("connexion");
    flux.set_read_timeout(Some(COURT)).unwrap();
    flux.set_write_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let mut c = net::Connexion::connecter(flux, &SigKeypair::generate()).expect("handshake");

    // 1. AUCUNE `Version` (et ce nœud ne diffusant rien, aucune trame).
    assert!(
        matches!(
            c.recevoir(),
            Err(net::NetError::Io(
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ))
        ),
        "un client qui n'annonce pas ne doit recevoir AUCUNE Version spontanée"
    );

    // 2. Qui annonce obtient une réponse.
    c.envoyer(
        &Message::Version {
            protocole: VERSION_PROTOCOLE,
        }
        .to_bytes(),
    )
    .expect("envoi de notre version");
    let octets = c.recevoir().expect("réponse à notre annonce");
    assert!(
        matches!(
            Message::from_bytes(&octets),
            Ok(Message::Version { protocole }) if protocole == VERSION_PROTOCOLE
        ),
        "l'accepteur répond sa version à qui lui annonce la sienne"
    );

    // 3. Une seule réponse, jamais deux.
    c.envoyer(
        &Message::Version {
            protocole: VERSION_PROTOCOLE,
        }
        .to_bytes(),
    )
    .expect("seconde annonce");
    assert!(
        matches!(
            c.recevoir(),
            Err(net::NetError::Io(
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ))
        ),
        "la réponse est UNIQUE : réannoncer n'obtient rien (ni rebond, ni amplification)"
    );

    fini_tx.send(()).expect("signal");
    let (score, liens, vue) = serveur.join().expect("thread serveur");
    assert_eq!(score, 0, "annoncer — ou se taire — n'est jamais une faute");
    assert_eq!(liens, 1, "aucune coupure");
    assert_eq!(
        vue,
        Some(VERSION_PROTOCOLE),
        "le nœud a bien retenu la version annoncée"
    );
}

/// SCÉNARIO 3 — un pair annonçant une version SOUS le minimum est déconnecté, et le
/// lien est coupé POUR DE BON (les deux sens), sans aucune sanction de score.
#[test]
fn un_pair_trop_ancien_est_deconnecte_sans_sanction() {
    let (l, adresse) = ecoute();

    let (fin_tx, fin_rx) = std::sync::mpsc::channel::<bool>();
    let trop_ancien = std::thread::spawn(move || {
        let mut c = pair_brut(&l);
        let _ = c.recevoir().expect("la Version du nouveau nœud");
        // Version 0 : sous VERSION_MIN_ACCEPTEE.
        c.envoyer(&Message::Version { protocole: 0 }.to_bytes())
            .expect("envoi");
        // Le lien doit être VRAIMENT coupé. Une simple erreur ne suffirait pas à le
        // prouver : l'échéance de lecture en produit une aussi, et le test passerait
        // pour un nœud qui se contente de SE TAIRE. On exige donc une erreur qui
        // n'est PAS une échéance — c'est-à-dire une socket réellement fermée.
        let coupe = match c.recevoir() {
            Err(net::NetError::Io(
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut,
            )) => false,
            Err(_) => true,
            Ok(_) => false,
        };
        let _ = fin_tx.send(coupe);
    });

    let mut rt = Runtime::new(noeud(1));
    let pair = rt
        .connecter(adresse, &SigKeypair::generate())
        .expect("handshake");
    let ferme = attendre(
        || {
            rt.pomper(0);
            rt.liens_ouverts() == 0
        },
        Duration::from_secs(30),
    );
    assert!(ferme, "un pair trop ancien doit être déconnecté");

    let p = rt.noeud().pairs.get(&pair).expect("pair sortant connu");
    assert_eq!(
        p.score, 0,
        "REFUSER n'est pas CONDAMNER : le score reste intact"
    );
    assert!(
        !p.banni(),
        "le pair doit pouvoir revenir dès qu'il est à jour"
    );
    assert_eq!(
        rt.noeud().version_annoncee(&pair),
        None,
        "rien n'est retenu d'un pair avec qui on ne dialogue pas"
    );

    let coupe = fin_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("le pair doit constater la coupure");
    assert!(
        coupe,
        "la coupure doit être RÉELLE : sinon le pair continuerait de nous parler"
    );
    trop_ancien.join().expect("thread pair trop ancien");
}
