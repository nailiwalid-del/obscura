//! SYNCHRONISATION DU WALLET sur de vraies sockets : le nœud SERT son historique.
//!
//! # Ce que ce fichier ferme
//!
//! Le nœud CONSERVAIT l'historique des sorties depuis la brique précédente, mais rien
//! ne l'exposait : aucun message de protocole, donc aucun wallet capable de RECEVOIR.
//! Un wallet ne connaît pas l'index de ses notes dans l'arbre tant que quelqu'un ne le
//! lui dit pas, et sans index il n'y a ni chemin de Merkle ni dépense possible.
//!
//! # Pourquoi le client de ce test n'est PAS un nœud
//!
//! Il se connecte avec `net::Connexion` et rien d'autre. C'est délibéré : un wallet
//! n'a ni mempool, ni état de consensus, ni table de pairs, et exiger qu'il en ait un
//! ferait de la synchronisation un privilège d'opérateur de nœud. Le test montre que
//! le service se consomme avec le seul transport.
//!
//! # Ce que les tests exigent
//!
//! Pas « un message est parti » : que les COMMITMENTS reçus soient exactement ceux que
//! le bloc a insérés, **dans l'ordre**, avec leur plage absolue et la racine de fin de
//! bloc. Un ordre inversé ou un index décalé ne produit aucune erreur — il produit un
//! chemin de Merkle faux, et la transaction du wallet est refusée bien plus tard pour
//! « ancre inconnue », sans que rien ne désigne la cause.

use crypto::sig::SigKeypair;
use ledger::bloc::Bloc;
use ledger::proved_state::ProvedLedgerState;
use net::Connexion;
use node::message::Message;
use node::orchestration::Noeud;
use node::runtime::Runtime;
use proved_hash::digest::Digest;
use proved_hash::felt::Felt;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const PROFONDEUR: usize = 10;
/// Assez de sorties pour que l'ORDRE soit une propriété observable (deux entrées ne
/// suffisent pas à distinguer « préservé » de « inversé par hasard »).
const SORTIES: u64 = 16;

fn commitment(n: u64) -> Digest {
    Digest(core::array::from_fn(|i| {
        Felt::from_canonical_u64(5_000 + n * 64 + i as u64).unwrap()
    }))
}

/// Une genèse de [`SORTIES`] émissions FACTICES : le contenu déchiffrable n'a aucune
/// importance ici — ce qui est testé est le transport de la liste, dans l'ordre.
fn genese() -> Bloc {
    let emissions = (0..SORTIES)
        .map(|n| ledger::proved_wallet::emission_factice(&commitment(n)))
        .collect();
    Bloc::genese_avec(emissions).expect("genèse bornée")
}

fn noeud_archiviste(genese: &Bloc) -> Noeud {
    Noeud::new(
        SigKeypair::generate(),
        ProvedLedgerState::depuis_genese_depth_archivant(genese, PROFONDEUR).expect("amorçage"),
        [3u8; 32],
    )
}

/// Lance un nœud archiviste qui écoute et pompe jusqu'à ce qu'on lui dise d'arrêter.
fn serveur_archiviste(
    genese: Bloc,
    ecoute: TcpListener,
    fini: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    let identite = SigKeypair::generate();
    std::thread::spawn(move || {
        let mut rt = Runtime::new(noeud_archiviste(&genese));
        let (flux, _) = ecoute.accept().unwrap();
        rt.accepter(flux, &identite).expect("handshake");
        while !fini.load(Ordering::SeqCst) {
            rt.pomper(0);
            std::thread::sleep(Duration::from_millis(2));
        }
    })
}

/// Se connecte comme un WALLET : transport chiffré, rien d'autre.
fn client(adresse: SocketAddr) -> Connexion<TcpStream> {
    let flux = TcpStream::connect(adresse).expect("connexion");
    flux.set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    flux.set_write_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    Connexion::connecter(flux, &SigKeypair::generate()).expect("handshake")
}

/// UN WALLET OBTIENT LES SORTIES D'UN BLOC, DANS L'ORDRE, AVEC SON ANCRE.
///
/// Le chemin complet est exercé : `Message::to_bytes` → cadrage → cascade AEAD →
/// socket → déchiffrement → `Message::from_bytes` → `ReponseHistorique`.
///
/// Trois propriétés sont exigées, et chacune répare un manque distinct :
///
/// - les COMMITMENTS, dans l'ordre d'insertion — sans quoi les index divergent et tous
///   les chemins de Merkle du wallet deviennent faux, en silence ;
/// - la PLAGE ABSOLUE (`debut`, `fin`), qui dit à quel index ranger la première
///   feuille — un décalage est indétectable côté wallet ;
/// - la RACINE DE FIN DE BLOC, l'ancre à publier. Sur une frontière de bloc, tous les
///   wallets à jour partagent la même ancre ; à la feuille près, chacun publierait un
///   `ProvedTx::anchor` quasi unique, c'est-à-dire un pseudonyme permanent.
#[test]
fn un_wallet_obtient_les_sorties_dun_bloc_dans_lordre() {
    let g = genese();
    let racine_attendue = ProvedLedgerState::depuis_genese_depth_archivant(&g, PROFONDEUR)
        .expect("amorçage")
        .tree
        .root();

    let ecoute = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let adresse = ecoute.local_addr().unwrap();
    let fini = Arc::new(AtomicBool::new(false));
    let serveur = serveur_archiviste(g, ecoute, Arc::clone(&fini));

    // AUCUN message spontané n'est attendu du nœud : la règle de négociation J3 est
    // asymétrique (seul le connecteur annonce, et un wallet n'annonce pas). La
    // première trame reçue est donc bien la réponse à NOTRE demande.
    let mut c = client(adresse);
    c.envoyer(&Message::DemandeHistorique { hauteur: 0 }.to_bytes())
        .expect("envoi");
    let octets = c.recevoir().expect("réponse");
    fini.store(true, Ordering::SeqCst);
    serveur.join().expect("thread serveur");

    match Message::from_bytes(&octets).expect("réponse décodable") {
        Message::Historique(r) => {
            assert_eq!(r.hauteur, 0);
            assert_eq!((r.debut, r.fin), (0, SORTIES), "plage absolue du bloc");
            assert_eq!(r.decalage, 0);
            assert_eq!((r.morceau, r.morceaux), (0, 1));
            assert_eq!(r.hauteur_tete, 0, "la tête que le serveur peut servir");
            assert_eq!(
                r.racine_apres.to_bytes(),
                racine_attendue.to_bytes(),
                "l'ancre servie est celle de l'arbre, pas une valeur inventée"
            );
            let recus: Vec<[u8; 32]> = r.sorties.iter().map(|s| s.commitment.to_bytes()).collect();
            let attendus: Vec<[u8; 32]> = (0..SORTIES).map(|n| commitment(n).to_bytes()).collect();
            assert_eq!(
                recus, attendus,
                "les commitments doivent arriver dans l'ORDRE D'INSERTION : \
                 un ordre inversé décale tous les index sans produire la moindre erreur"
            );
        }
        _ => panic!("attendu une réponse d'historique"),
    }
}

/// DEUX WALLETS À LA MÊME POSITION SONT INDISCERNABLES SUR LE FIL.
///
/// C'est la raison pour laquelle la demande ne porte que la position : tout autre champ
/// choisi par le client (un `max` d'entrées, une plage) serait une empreinte stable qui
/// survit à l'identité de transport éphémère. Le nœud séparerait les wallets par leur
/// paramètre, puis suivrait chacun par sa position — un pseudonyme reconstruit
/// exactement là où le projet s'échine à n'en laisser aucun.
///
/// Le test compare le CLAIR applicatif (le chiffré diffère toujours : nonces frais et
/// compteur de séquence en AAD, ce qui est précisément ce qu'on veut).
#[test]
fn deux_wallets_a_la_meme_position_emettent_les_memes_octets() {
    let a = Message::DemandeHistorique { hauteur: 12 }.to_bytes();
    let b = Message::DemandeHistorique { hauteur: 12 }.to_bytes();
    assert_eq!(a, b);
    assert_eq!(a.len(), 9, "tag + hauteur, rien d'autre");
}

/// UNE HAUTEUR HOSTILE NE FAIT NI PANIQUER NI RÉPONDRE — sur de vraies sockets.
///
/// `u64::MAX`, la hauteur juste après la tête, une hauteur absurde : chacune traverse
/// le décodage réseau puis `HistoriqueSorties::tranche`, qui la ramène dans le repère
/// local par `checked_sub` + `usize::try_from` + `get(..)`. Une indexation directe
/// donnerait ici une panique du thread de service — ou, pire, la tranche d'une AUTRE
/// hauteur, servie en silence à un wallet qui la croirait.
///
/// Le silence, et surtout AUCUNE sanction : demander son historique est le comportement
/// normal d'un wallet, et le score gouverne la sélection sortante — pénaliser ici
/// dégraderait notre propre anti-eclipse.
#[test]
fn hauteurs_hostiles_ne_font_ni_paniquer_ni_repondre() {
    let ecoute = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let adresse = ecoute.local_addr().unwrap();
    let g = genese();
    let identite = SigKeypair::generate();

    let serveur = std::thread::spawn(move || {
        let mut rt = Runtime::new(noeud_archiviste(&g));
        let (flux, adresse_client) = ecoute.accept().unwrap();
        let pair = rt.accepter(flux, &identite).expect("handshake");
        // `accepter` n'inscrit volontairement pas le pair dans la table anti-eclipse.
        // On l'y met à la main : sans entrée, le score serait inobservable et
        // l'assertion « aucune sanction » serait vide de sens.
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

    let mut c = client(adresse);
    // La tête servie est 0 : tout le reste doit rendre le silence, y compris les
    // valeurs qui feraient déborder une soustraction naïve.
    for hauteur in [1u64, 2, SORTIES, SORTIES + 1, u64::MAX, u64::MAX - 1] {
        c.envoyer(&Message::DemandeHistorique { hauteur }.to_bytes())
            .expect("envoi");
    }
    // Une seule lecture, avec échéance : rien ne doit revenir.
    let recu = c.recevoir();
    let (score, liens) = serveur.join().expect("thread serveur");

    assert!(
        matches!(recu, Err(net::NetError::Io(_))),
        "silence attendu : RIEN ne doit revenir — ni réponse à une hauteur inconnue, \
         ni message spontané (le nœud n'annonce sa version qu'à qui l'annonce)"
    );
    assert_eq!(
        score, 0,
        "demander une hauteur qu'on n'a pas n'est PAS une faute"
    );
    assert_eq!(
        liens, 1,
        "et le lien reste ouvert — le nœud n'a ni coupé ni paniqué"
    );
}
