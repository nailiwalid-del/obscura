//! LE CYCLE COMPLET DE LA MONNAIE, sur de vraies sockets : payer → sceller →
//! recevoir → redépenser.
//!
//! C'est le test qui prouve que la monnaie CIRCULE. Chaque brique a été éprouvée
//! séparément — le wallet construit une preuve, le nœud scelle un bloc, le service
//! d'historique sert les sorties, le rejeu retrouve les index — mais rien jusqu'ici ne
//! les enchaînait de bout en bout à travers la BOUCLE de synchronisation du client.
//!
//! Le scénario ferme le cycle que le projet visait :
//!
//! 1. Alice est financée par la genèse (deux notes) ; Bob l'est aussi (une note).
//! 2. Alice se SYNCHRONISE (boucle client réelle), découvre ses notes, paie Bob.
//! 3. Un nœud SCELLE le bloc contenant le paiement.
//! 4. Bob se SYNCHRONISE et voit son paiement — la RÉCEPTION, longtemps impossible.
//! 5. Alice se synchronise et RETROUVE SA MONNAIE RENDUE (sortie de sa vue à la
//!    dépense, faute d'index ; elle revient par le rejeu).
//! 6. Bob DÉPENSE ce qu'il a reçu (sa note de genèse + le paiement d'Alice) et le nœud
//!    l'admet — donc scelle un second bloc.
//!
//! Il doit ÉCHOUER si n'importe quel maillon casse : un index décalé au rejeu, une
//! ancre à mi-bloc, une monnaie rendue jamais retrouvée, une note reçue non
//! dépensable — chacun coupe la chaîne à un endroit différent, et aucune erreur
//! intermédiaire ne le dirait.

use crypto::sig::SigKeypair;
use ledger::bloc::Bloc;
use ledger::proved_state::ProvedLedgerState;
use net::connexion::Connexion;
use node::message::Message;
use node::orchestration::Noeud;
use node::runtime::Runtime;
use proved_hash::digest::ShieldedSecret;
use proved_hash::domain::Domain;
use proved_hash::felt::Felt;
use proved_hash::rescue;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use wallet::{Adresse, Wallet};

// Profondeur telle que `16·D` soit une puissance de 2 (contrainte du circuit de preuve
// de chemin Merkle) : `D = 4` donne 16 feuilles, largement assez pour ce scénario.
const PROFONDEUR: usize = 4;

fn secret(graine: u64) -> ShieldedSecret {
    ShieldedSecret::from_felts(core::array::from_fn(|i| {
        Felt::from_canonical_u64(graine + i as u64).unwrap()
    }))
}

/// Une émission de genèse VERS `w`, d'une valeur donnée, avec un sel qui rend son
/// commitment distinct des autres (deux notes de même valeur auraient sinon le même
/// commitment, donc la même feuille — l'arbre les confondrait).
fn emission_pour(w: &Wallet, valeur: u64, sel: u64) -> ledger::bloc::Emission {
    let note = circuit::SpendNote {
        value: valeur,
        owner: w.owner(),
        rho: rescue::hash(Domain::Owner, &[Felt::from_canonical_u64(sel).unwrap(); 4]),
        r: rescue::hash(Domain::Nk, &[Felt::from_canonical_u64(sel + 7).unwrap(); 4]),
    };
    let cm = rescue::note_commitment(note.value, &note.owner, &note.rho, &note.r);
    ledger::proved_wallet::emission_vers(&w.adresse().kem, &cm, &note).unwrap()
}

/// Se connecte comme un WALLET : transport chiffré éphémère, échéance de lecture courte
/// (c'est elle qui définit le SILENCE sur lequel la boucle s'arrête).
fn client(adresse: SocketAddr) -> Connexion<TcpStream> {
    let flux = TcpStream::connect(adresse).expect("connexion");
    flux.set_read_timeout(Some(Duration::from_millis(800)))
        .unwrap();
    flux.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    Connexion::connecter(flux, &SigKeypair::generate()).expect("handshake")
}

/// Synchronise `w` par la BOUCLE CLIENT réelle, en repartant à chaque fois d'une
/// connexion neuve (identité de transport éphémère — comme le fait `obscura-wallet`).
///
/// Retourne le nombre de notes reçues sur l'invocation.
fn synchroniser(w: &mut Wallet, adresse: SocketAddr) -> usize {
    let mut c = client(adresse);
    let resume = node::client::synchroniser_par_connexion(&mut c, w, Duration::ZERO, |_, _| Ok(()));
    resume.notes_recues
}

/// Un nœud ARCHIVISTE qui écoute plusieurs connexions successives, pompe, et SCELLE dès
/// qu'une transaction entre au mempool. La hauteur courante est publiée dans un compteur
/// partagé pour que le test puisse attendre un scellement sans fouiller l'état du thread.
fn serveur(
    genese: Bloc,
    ecoute: TcpListener,
    fini: Arc<AtomicBool>,
    hauteur: Arc<AtomicU64>,
) -> std::thread::JoinHandle<()> {
    let identite = SigKeypair::generate();
    std::thread::spawn(move || {
        ecoute.set_nonblocking(true).expect("non bloquant");
        let etat = ProvedLedgerState::depuis_genese_depth_archivant(&genese, PROFONDEUR)
            .expect("amorçage archivant");
        let mut rt = Runtime::new(Noeud::new(SigKeypair::generate(), etat, [3u8; 32]));
        while !fini.load(Ordering::SeqCst) {
            // Accepter les entrants sans bloquer la boucle.
            match ecoute.accept() {
                Ok((flux, _)) => {
                    // Le socket accepté peut hériter du mode non bloquant du listener
                    // (notamment sous Windows) : on le repasse en bloquant, sans quoi le
                    // handshake lirait WouldBlock et le lien serait avorté.
                    flux.set_nonblocking(false).expect("mode bloquant");
                    let _ = rt.accepter(flux, &identite);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => {}
            }
            rt.pomper(0);
            // Sceller dès qu'il y a de quoi : c'est ce qui donne la FINALITÉ. Sans
            // producteur élu, n'importe quel nœud peut le faire (testnet local).
            if !rt.noeud().mempool.is_empty() {
                if let Some((_bloc, actions)) = rt.noeud_mut().sceller() {
                    rt.executer(actions);
                }
            }
            hauteur.store(rt.noeud().etat.hauteur(), Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(2));
        }
    })
}

fn attendre_hauteur(hauteur: &AtomicU64, cible: u64, delai: Duration) -> bool {
    let t = Instant::now();
    while t.elapsed() < delai {
        if hauteur.load(Ordering::SeqCst) >= cible {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    hauteur.load(Ordering::SeqCst) >= cible
}

/// Soumet une transaction comme `obscura-wallet envoyer` : connexion éphémère, une
/// seule trame applicative.
fn soumettre(adresse: SocketAddr, tx: circuit::ProvedTx) {
    let mut c = client(adresse);
    c.envoyer(&Message::Transaction(Box::new(tx)).to_bytes())
        .expect("envoi de la transaction");
    // Rien à drainer : sous la règle asymétrique J3, un client qui n'annonce pas sa
    // version ne reçoit rien de non sollicité. La socket se ferme sans octets non lus,
    // donc sans `RST`, donc sans faire jeter au nœud son tampon de réception.
}

/// LE CYCLE : payer → sceller → recevoir → retrouver sa monnaie → redépenser.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn le_cycle_complet_de_la_monnaie() {
    let mut alice = Wallet::depuis_secret(secret(700), PROFONDEUR);
    let bob = Wallet::depuis_secret(secret(900), PROFONDEUR);

    // GENÈSE : Alice reçoit deux notes (elle pourra construire une tx 2-entrées), Bob
    // une note (il lui en faudra une seconde, le paiement d'Alice, pour dépenser).
    let genese = Bloc::genese_avec(vec![
        emission_pour(&alice, 1_000, 10),
        emission_pour(&alice, 500, 20),
        emission_pour(&bob, 700, 30),
    ])
    .expect("genèse bornée");

    let ecoute = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let adresse = ecoute.local_addr().unwrap();
    let fini = Arc::new(AtomicBool::new(false));
    let hauteur = Arc::new(AtomicU64::new(0));
    let serveur = serveur(genese, ecoute, Arc::clone(&fini), Arc::clone(&hauteur));

    // 1. ALICE SE SYNCHRONISE (genèse) et découvre ses deux notes.
    let recues = synchroniser(&mut alice, adresse);
    assert_eq!(recues, 2, "Alice doit reconnaître ses deux notes de genèse");
    assert_eq!(alice.solde(), 1_500);
    assert_eq!(
        alice.prochaine_hauteur(),
        1,
        "genèse rejouée, position avancée"
    );

    // 2. ALICE PAIE BOB. Le paiement s'ancre sur la frontière de bloc de la genèse.
    let texte = bob.adresse().encoder();
    let destinataire = Adresse::decoder(&texte).expect("adresse valide");
    let tx = alice
        .construire(&destinataire, 300, 20)
        .expect("transaction constructible");
    // Alice OUBLIE ses notes dépensées : la monnaie rendue sort de sa vue ici, et ne
    // reviendra qu'à la synchronisation.
    assert_eq!(alice.oublier_depensees(&tx), 2);
    soumettre(adresse, tx);
    assert_eq!(alice.solde(), 0, "les deux notes de genèse sont dépensées");

    // 3. LE NŒUD SCELLE le bloc 1.
    assert!(
        attendre_hauteur(&hauteur, 1, Duration::from_secs(60)),
        "le nœud doit sceller le paiement d'Alice dans un bloc"
    );

    // 4. BOB SE SYNCHRONISE et VOIT SON PAIEMENT — la réception longtemps impossible.
    let mut bob = bob;
    let recues_bob = synchroniser(&mut bob, adresse);
    assert_eq!(
        recues_bob, 2,
        "Bob reçoit sa note de genèse ET le paiement d'Alice"
    );
    assert_eq!(bob.solde(), 700 + 300, "genèse + paiement");
    assert_eq!(bob.prochaine_hauteur(), 2, "genèse et bloc 1 rejoués");

    // 5. ALICE SE SYNCHRONISE et RETROUVE SA MONNAIE RENDUE.
    let recues_alice = synchroniser(&mut alice, adresse);
    assert_eq!(recues_alice, 1, "la monnaie rendue revient par le rejeu");
    assert_eq!(
        alice.solde(),
        1_500 - 300 - 20,
        "solde = fonds initiaux − paiement − frais"
    );

    // 6. BOB DÉPENSE ce qu'il a reçu ; le nœud l'admet, donc scelle un bloc 2.
    let cible = Wallet::depuis_secret(secret(1_234), PROFONDEUR);
    let tx_bob = bob
        .construire(&cible.adresse(), 100, 10)
        .expect("Bob peut dépenser ses deux notes");
    soumettre(adresse, tx_bob);
    assert!(
        attendre_hauteur(&hauteur, 2, Duration::from_secs(60)),
        "le paiement de Bob doit être ADMIS et scellé — la monnaie reçue est dépensable"
    );

    fini.store(true, Ordering::SeqCst);
    serveur.join().expect("thread serveur");
}
