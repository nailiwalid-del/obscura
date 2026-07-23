//! Deux nœuds RÉELS sur une vraie socket TCP.
//!
//! Toutes les briques ont été testées isolément et sans réseau. Ce test est le
//! premier à les faire fonctionner ENSEMBLE sur un vrai socket : handshake
//! post-quantique, cadrage, protocole applicatif, orchestration, exécution.
//!
//! C'est le test qui échouerait si deux couches, individuellement correctes,
//! s'accordaient mal — la classe de défaut que les tests unitaires ne voient pas.
//!
//! # Ce que ces tests n'assertent PLUS
//!
//! « `pomper(0) > 0` » — « au moins un événement est arrivé » — ne prouve rien depuis
//! que la négociation de version (J3) fait circuler un message spontané en tête de
//! lien : le connecteur annonce sa `Version`, l'accepteur lui répond la sienne. Cet
//! événement-là satisfait la condition indépendamment de ce que le test prétend
//! observer, et il arrive TOUJOURS EN PREMIER. Chaque attente porte donc ici sur
//! l'EFFET réel — la `Demande` reçue et décodée, le score effectivement descendu.

use crypto::sig::SigKeypair;
use node::message::{Message, VERSION_PROTOCOLE};
use node::orchestration::{Noeud, PENALITE_MESSAGE_INVALIDE};
use node::runtime::Runtime;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

fn noeud(secret: u8) -> Noeud {
    Noeud::new(
        SigKeypair::generate(),
        ledger::proved_state::ProvedLedgerState::with_depth(4),
        [secret; 32],
    )
}

/// Attend qu'une condition devienne vraie, avec échéance — évite les `sleep`
/// arbitraires, qui rendent les tests soit lents soit instables.
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

/// HANDSHAKE ET ÉCHANGE sur une vraie socket, dans les DEUX sens.
///
/// L'effet observé est la version APPRISE de part et d'autre : le client annonce la
/// sienne (il est le connecteur), le serveur lui RÉPOND la sienne. Chacun asserte
/// donc qu'un message de l'autre est bien arrivé, décodé et traité — et non « un
/// événement quelconque a été pompé ».
///
/// Le port 0 laisse l'OS attribuer un port libre : le test peut donc s'exécuter en
/// parallèle d'autres sans collision.
#[test]
fn deux_noeuds_se_connectent_et_echangent() {
    let id_serveur = SigKeypair::generate();
    let id_client = SigKeypair::generate();

    let ecoute = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let adresse = ecoute.local_addr().unwrap();

    // Serveur : accepte une connexion dans un thread.
    let serveur = std::thread::spawn(move || {
        let mut rt = Runtime::new(noeud(1));
        let (flux, _) = ecoute.accept().unwrap();
        let pair = rt
            .accepter(flux, &id_serveur)
            .expect("handshake côté serveur");
        // L'EFFET du message du client : sa version est apprise.
        assert!(
            attendre(
                || {
                    rt.pomper(0);
                    rt.noeud().version_annoncee(&pair).is_some()
                },
                Duration::from_secs(10)
            ),
            "le serveur doit recevoir et TRAITER le message du client"
        );
        assert_eq!(rt.noeud().version_annoncee(&pair), Some(VERSION_PROTOCOLE));
        (pair, rt.liens_ouverts())
    });

    // Client : se connecte et envoie une annonce (message le plus simple).
    let mut rt_client = Runtime::new(noeud(2));
    let pair_serveur = rt_client
        .connecter(adresse, &id_client)
        .expect("handshake côté client");
    assert_eq!(rt_client.liens_ouverts(), 1);

    // L'identité authentifiée par le client est bien celle du serveur.
    assert_eq!(
        rt_client
            .noeud()
            .pairs
            .get(&pair_serveur)
            .map(|p| p.adresse),
        Some(adresse),
        "le pair sortant est mémorisé avec son adresse (sélection anti-eclipse)"
    );

    rt_client.executer(vec![node::orchestration::Action::Envoyer(
        pair_serveur,
        Message::Annonce(vec![[7u8; 64]]),
    )]);

    // Sens RETOUR : le serveur a répondu à notre annonce de version, et le client
    // l'apprend. C'est l'effet réel d'un message reçu, pas un compteur d'événements.
    assert!(
        attendre(
            || {
                rt_client.pomper(0);
                rt_client.noeud().version_annoncee(&pair_serveur).is_some()
            },
            Duration::from_secs(10)
        ),
        "le client doit recevoir et TRAITER la réponse du serveur"
    );

    let (_pair_vu, liens) = serveur.join().expect("thread serveur");
    assert_eq!(liens, 1, "le serveur a bien un lien ouvert");
}

/// PROPAGATION RÉELLE : le client annonce une transaction inconnue, le serveur la
/// DEMANDE. C'est l'aller-retour du protocole applicatif, de bout en bout, chiffré.
///
/// # Pourquoi le client est ici une `net::Connexion` brute
///
/// Parce que ce test doit DÉCODER la `Demande` reçue. Un `Runtime` n'expose pas les
/// messages qu'il a traités : côté client, une `Demande` pour une transaction qu'on
/// n'a pas ne laisse aucune trace observable, et la seule attente possible serait
/// « au moins un événement » — c'est-à-dire, désormais, rien du tout. Le pair brut
/// parle le MÊME transport chiffré ; il n'a simplement pas de politique applicative,
/// ce qui permet d'affirmer sur les octets plutôt que de les supposer.
///
/// C'est le test qui doit redevenir ROUGE si la production de la `Demande`
/// disparaît de `Noeud::sur_annonce`.
#[test]
fn annonce_declenche_une_demande_sur_le_fil() {
    let id_serveur = SigKeypair::generate();

    let ecoute = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let adresse = ecoute.local_addr().unwrap();

    let (fini_tx, fini_rx) = std::sync::mpsc::channel::<()>();
    let serveur = std::thread::spawn(move || {
        let mut rt = Runtime::new(noeud(1));
        let (flux, _) = ecoute.accept().unwrap();
        rt.accepter(flux, &id_serveur).expect("handshake");
        // Pomper jusqu'à ce que le client ait CONSTATÉ la demande — pas jusqu'au
        // premier événement venu.
        while fini_rx.try_recv().is_err() {
            rt.pomper(0);
            std::thread::sleep(Duration::from_millis(2));
        }
        rt.liens_ouverts()
    });

    let flux = TcpStream::connect(adresse).expect("connexion");
    flux.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    flux.set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut client =
        net::Connexion::connecter(flux, &SigKeypair::generate()).expect("handshake client");

    // Le client annonce une transaction que le serveur n'a pas.
    client
        .envoyer(&Message::Annonce(vec![[42u8; 64]]).to_bytes())
        .expect("envoi de l'annonce");

    // Le serveur doit répondre par une DEMANDE portant exactement ce digest. Rien
    // d'autre ne doit précéder : ce client n'annonce pas sa version, donc le nœud ne
    // lui envoie rien de non sollicité (règle asymétrique J3).
    let octets = client.recevoir().expect("le serveur doit répondre");
    match Message::from_bytes(&octets).expect("réponse décodable") {
        Message::Demande(d) => assert_eq!(
            d,
            vec![[42u8; 64]],
            "la demande doit porter le digest annoncé"
        ),
        _ => panic!("réponse inattendue à une annonce : une Demande était attendue"),
    }

    fini_tx.send(()).expect("signal de fin");
    assert_eq!(serveur.join().expect("thread serveur"), 1);
}

/// Un pair qui envoie une MALFORMATION est pénalisé, sans faire tomber le nœud : la
/// surface réseau reste hostile jusqu'au bout de la chaîne.
///
/// ⚠️ Politique AFFINÉE : un tag applicatif inconnu ne pénalise plus. Il est
/// indissociable d'un message d'une version FUTURE du protocole, et le pénaliser
/// ferait bannir les nœuds d'une autre version en une centaine de secondes — avec eux
/// s'effondrerait la diversité de groupes réseau dont dépend l'anti-eclipse, donc
/// l'anonymat de Dandelion++. On sanctionne donc les malformations DANS une version
/// connue (troncature, borne dépassée), jamais l'inconnu.
#[test]
fn message_indecodable_penalise_sans_faire_tomber_le_noeud() {
    let id_serveur = SigKeypair::generate();
    let id_client = SigKeypair::generate();

    let ecoute = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let adresse = ecoute.local_addr().unwrap();

    let serveur = std::thread::spawn(move || {
        let mut rt = Runtime::new(noeud(1));
        let (flux, _) = ecoute.accept().unwrap();
        let pair = rt.accepter(flux, &id_serveur).expect("handshake");
        rt.noeud_mut()
            .pairs
            .ajouter(pair, SocketAddr::from((Ipv4Addr::LOCALHOST, 1)));
        // L'EFFET attendu est la SANCTION, pas « un événement quelconque » : on pompe
        // jusqu'à ce que le score descende. Sans cela, le test passait dès la
        // première trame reçue — donc avant même que le bruit ne soit traité.
        let sanctionne = attendre(
            || {
                rt.pomper(0);
                rt.noeud().pairs.get(&pair).map(|p| p.score).unwrap_or(0) < 0
            },
            Duration::from_secs(10),
        );
        // Le nœud est toujours debout, et le pair a été pénalisé.
        let score = rt.noeud().pairs.get(&pair).map(|p| p.score).unwrap_or(0);
        assert!(
            sanctionne,
            "un message indécodable doit pénaliser (score {score})"
        );
        assert_eq!(
            score, PENALITE_MESSAGE_INVALIDE,
            "une malformation, une sanction — exactement"
        );
    });

    let mut client = Runtime::new(noeud(2));
    let pair = client.connecter(adresse, &id_client).expect("handshake");
    // Une ANNONCE TRONQUÉE : tag connu (1), longueur annoncée mais octets absents.
    // C'est une malformation dans une version que nous comprenons — donc une faute.
    client.envoyer_octets_bruts(pair, &[1, 2, 0, 0, 0]);

    serveur.join().expect("thread serveur");
}

/// Un tag applicatif INCONNU ne pénalise pas : c'est un message d'une version future.
///
/// Le pénaliser ferait qu'une mise à jour de réseau partitionne le testnet toute
/// seule — chaque nœud bannissant ceux qui parlent la version qu'il ne connaît pas
/// encore, et dégradant au passage sa propre défense anti-eclipse.
///
/// # Le MARQUEUR : une malformation envoyée APRÈS
///
/// « Le score vaut 0 » est vrai avant même que le bruit n'ait été lu : l'assertion ne
/// vaut donc que si l'on sait que le message inconnu a bien été TRAITÉ. On envoie
/// derrière lui une malformation, qui elle pénalise ; l'ordre sur un lien est
/// préservé (file d'envoi unique, flux unique), donc voir la sanction prouve que le
/// tag inconnu est déjà passé. Le score final doit alors valoir EXACTEMENT une
/// pénalité : si le tag inconnu avait sanctionné, il en vaudrait deux.
#[test]
fn tag_inconnu_ne_penalise_pas() {
    let id_serveur = SigKeypair::generate();
    let id_client = SigKeypair::generate();

    let ecoute = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let adresse = ecoute.local_addr().unwrap();

    let serveur = std::thread::spawn(move || {
        let mut rt = Runtime::new(noeud(1));
        let (flux, _) = ecoute.accept().unwrap();
        let pair = rt.accepter(flux, &id_serveur).expect("handshake");
        rt.noeud_mut()
            .pairs
            .ajouter(pair, SocketAddr::from((Ipv4Addr::LOCALHOST, 1)));
        let marqueur = attendre(
            || {
                rt.pomper(0);
                rt.noeud().pairs.get(&pair).map(|p| p.score).unwrap_or(0) < 0
            },
            Duration::from_secs(10),
        );
        assert!(
            marqueur,
            "le marqueur (malformation) doit être traité — sinon rien n'est prouvé"
        );
        assert_eq!(
            rt.noeud().pairs.get(&pair).map(|p| p.score),
            Some(PENALITE_MESSAGE_INVALIDE),
            "une seule sanction : celle du marqueur. Un tag d'une version future ne \
             doit PAS pénaliser"
        );
    });

    let mut client = Runtime::new(noeud(2));
    let pair = client.connecter(adresse, &id_client).expect("handshake");
    // Tag hors de toute version connue : à ignorer.
    client.envoyer_octets_bruts(pair, &[0xFF, 0xFF, 0xFF]);
    // MARQUEUR : annonce tronquée — tag connu (1), longueur annoncée, octets absents.
    client.envoyer_octets_bruts(pair, &[1, 2, 0, 0, 0]);

    serveur.join().expect("thread serveur");
}
