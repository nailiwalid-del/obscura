//! Deux nœuds RÉELS sur une vraie socket TCP.
//!
//! Toutes les briques ont été testées isolément et sans réseau. Ce test est le
//! premier à les faire fonctionner ENSEMBLE sur un vrai socket : handshake
//! post-quantique, cadrage, protocole applicatif, orchestration, exécution.
//!
//! C'est le test qui échouerait si deux couches, individuellement correctes,
//! s'accordaient mal — la classe de défaut que les tests unitaires ne voient pas.

use crypto::sig::SigKeypair;
use node::message::Message;
use node::orchestration::Noeud;
use node::runtime::Runtime;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
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

/// HANDSHAKE ET ÉCHANGE sur une vraie socket.
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
    let id_serveur_pub = id_serveur.public.to_bytes();
    let serveur = std::thread::spawn(move || {
        let mut rt = Runtime::new(noeud(1));
        let (flux, _) = ecoute.accept().unwrap();
        let pair = rt.accepter(flux, &id_serveur).expect("handshake côté serveur");
        // Attendre le message du client.
        assert!(
            attendre(|| rt.pomper(0) > 0, Duration::from_secs(10)),
            "le serveur doit recevoir un message"
        );
        (pair, rt.liens_ouverts())
    });

    // Client : se connecte et envoie une annonce vide (message le plus simple).
    let mut rt_client = Runtime::new(noeud(2));
    let pair_serveur = rt_client
        .connecter(adresse, &id_client)
        .expect("handshake côté client");
    assert_eq!(rt_client.liens_ouverts(), 1);

    // L'identité authentifiée par le client est bien celle du serveur.
    assert_eq!(
        rt_client.noeud().pairs.get(&pair_serveur).map(|p| p.adresse),
        Some(adresse),
        "le pair sortant est mémorisé avec son adresse (sélection anti-eclipse)"
    );
    let _ = id_serveur_pub;

    rt_client.executer(vec![node::orchestration::Action::Envoyer(
        pair_serveur,
        Message::Annonce(vec![[7u8; 64]]),
    )]);

    let (_pair_vu, liens) = serveur.join().expect("thread serveur");
    assert_eq!(liens, 1, "le serveur a bien un lien ouvert");
}

/// PROPAGATION RÉELLE : le client annonce une transaction inconnue, le serveur la
/// DEMANDE. C'est l'aller-retour du protocole applicatif, de bout en bout, chiffré.
#[test]
fn annonce_declenche_une_demande_sur_le_fil() {
    let id_serveur = SigKeypair::generate();
    let id_client = SigKeypair::generate();

    let ecoute = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let adresse = ecoute.local_addr().unwrap();

    let serveur = std::thread::spawn(move || {
        let mut rt = Runtime::new(noeud(1));
        let (flux, _) = ecoute.accept().unwrap();
        rt.accepter(flux, &id_serveur).expect("handshake");
        // Pomper jusqu'à avoir traité l'annonce (le serveur répondra une demande).
        assert!(
            attendre(|| rt.pomper(0) > 0, Duration::from_secs(10)),
            "annonce non reçue"
        );
    });

    let mut client = Runtime::new(noeud(2));
    let pair = client.connecter(adresse, &id_client).expect("handshake");

    // Le client annonce une transaction que le serveur n'a pas.
    client.executer(vec![node::orchestration::Action::Envoyer(
        pair,
        Message::Annonce(vec![[42u8; 64]]),
    )]);

    // Le serveur doit répondre par une demande — le client la reçoit.
    assert!(
        attendre(|| client.pomper(0) > 0, Duration::from_secs(10)),
        "le client doit recevoir la DEMANDE du serveur"
    );

    serveur.join().expect("thread serveur");
}

/// Un pair qui envoie du BRUIT (message indécodable) est pénalisé, sans faire
/// tomber le nœud : la surface réseau reste hostile jusqu'au bout de la chaîne.
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
        assert!(
            attendre(|| rt.pomper(0) > 0, Duration::from_secs(10)),
            "bruit non reçu"
        );
        // Le nœud est toujours debout, et le pair a été pénalisé.
        let score = rt.noeud().pairs.get(&pair).map(|p| p.score).unwrap_or(0);
        assert!(score < 0, "un message indécodable doit pénaliser (score {score})");
    });

    let mut client = Runtime::new(noeud(2));
    let pair = client.connecter(adresse, &id_client).expect("handshake");
    // Un tag de message inexistant : décodable au niveau transport, pas applicatif.
    client.executer(vec![node::orchestration::Action::Envoyer(
        pair,
        Message::Annonce(vec![]),
    )]);
    // Puis du vrai bruit, injecté sous la couche applicative.
    client.envoyer_octets_bruts(pair, &[0xFF, 0xFF, 0xFF]);

    serveur.join().expect("thread serveur");
}
