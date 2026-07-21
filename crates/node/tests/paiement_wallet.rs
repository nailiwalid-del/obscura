//! Le chemin de paiement d'un WALLET, de l'adresse partagée jusqu'au mempool d'un
//! nœud réel.
//!
//! C'est le chemin qu'emprunte `obscura-wallet envoyer`, exercé ici sans passer par
//! le binaire. Il traverse trois frontières que les tests unitaires éprouvent
//! séparément mais jamais ensemble :
//!
//! ```text
//!   adresse encodée (texte) → décodée → preuve STARK → handshake PQ
//!     → socket → mempool du nœud → le destinataire DÉCHIFFRE son paiement
//! ```
//!
//! La dernière étape est la seule qui compte vraiment pour un payeur : une adresse
//! qui traverse l'encodage en perdant un bit de sa clé de réception donnerait une
//! transaction parfaitement VALIDE dont le destinataire ne pourrait rien tirer. Le
//! consensus ne peut pas attraper cela — ce test, si.

use crypto::sig::SigKeypair;
use ledger::bloc::Bloc;
use ledger::proved_state::ProvedLedgerState;
use net::connexion::Connexion;
use node::message::Message;
use node::orchestration::Noeud;
use node::runtime::Runtime;
use proved_hash::digest::ShieldedSecret;
use proved_hash::felt::Felt;
use proved_hash::rescue;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};
use wallet::{Adresse, Wallet};

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
/// Une seule genèse est fabriquée puis PARTAGÉE : wallet et nœud doivent voir les
/// mêmes commitments dans le même ordre, sinon les index divergent et la transaction
/// est rejetée pour « ancre inconnue ».
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
            ledger::proved_wallet::emission_vers(&w.adresse().kem, &cm, &note)
        })
        .collect();
    Bloc::genese_avec(emissions).expect("genèse bornée")
}

/// Amorce un état sur `genese` et fait découvrir à `w` ce qui lui revient (par scan).
fn amorcer_sur(genese: &Bloc, w: &mut Wallet) -> ProvedLedgerState {
    let etat = ProvedLedgerState::depuis_genese_depth(genese, PROFONDEUR).expect("amorçage");
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

/// PAIEMENT DE BOUT EN BOUT — via l'adresse TEXTUELLE.
///
/// Le destinataire n'est connu du payeur que par la chaîne `obs1…` : c'est la seule
/// chose qu'un humain échange réellement. Si l'encodage abîmait quoi que ce soit, la
/// dernière assertion (le destinataire déchiffre son paiement) tomberait.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuve gatée : --release")]
fn paiement_via_adresse_textuelle_jusqu_au_mempool() {
    let mut payeur = Wallet::depuis_secret(secret(700), PROFONDEUR);
    let genese = genese_pour(&payeur);
    let etat_payeur = amorcer_sur(&genese, &mut payeur);
    let beneficiaire = Wallet::depuis_secret(secret(900), PROFONDEUR);

    // Le seul lien entre les deux : une chaîne de caractères.
    let texte = beneficiaire.adresse().encoder();
    let destinataire = Adresse::decoder(&texte).expect("adresse valide");

    let tx = payeur
        .construire(&destinataire, 300, 20)
        .expect("transaction constructible");
    let digest = tx.tx_digest;

    // Nœud receveur : amorcé sur LA MÊME genèse que le payeur (pas de chaîne à
    // synchroniser).
    let mut noeud_receveur = Wallet::depuis_secret(secret(700), PROFONDEUR);
    let etat_noeud = amorcer_sur(&genese, &mut noeud_receveur);
    assert_eq!(
        etat_noeud.tree.root(),
        etat_payeur.tree.root(),
        "payeur et nœud doivent partager la même ancre"
    );

    let ecoute = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let adresse_noeud = ecoute.local_addr().unwrap();
    let identite_noeud = SigKeypair::generate();

    let serveur = std::thread::spawn(move || {
        let mut rt = Runtime::new(Noeud::new(SigKeypair::generate(), etat_noeud, [3u8; 32]));
        let (flux, _) = ecoute.accept().unwrap();
        rt.accepter(flux, &identite_noeud).expect("handshake");
        attendre(
            || {
                rt.pomper(0);
                rt.noeud().mempool.contient(&digest)
            },
            Duration::from_secs(60),
        )
    });

    // Soumission comme le fait `obscura-wallet envoyer` : identité de transport
    // ÉPHÉMÈRE, une seule trame applicative.
    let flux = TcpStream::connect(adresse_noeud).expect("connexion");
    let mut connexion =
        Connexion::connecter(flux, &SigKeypair::generate()).expect("handshake post-quantique");
    let octets = Message::Transaction(Box::new(tx)).to_bytes();
    connexion.envoyer(&octets).expect("envoi");

    assert!(
        serveur.join().expect("thread nœud"),
        "la transaction doit être ADMISE par le nœud (preuve vérifiée)"
    );

    // CE QUI COMPTE POUR LE PAYEUR : le bénéficiaire peut lire son paiement. Une
    // clé de réception abîmée par l'encodage d'adresse produirait une transaction
    // valide et pourtant inutilisable — défaut invisible au consensus.
    let tx = match Message::from_bytes(&octets).expect("réencodage") {
        Message::Transaction(tx) => tx,
        _ => panic!("mauvais type"),
    };
    let mut beneficiaire = beneficiaire;
    let index = beneficiaire.observer(&tx.output_commitments[0]);
    assert!(
        beneficiaire.scanner(&tx.output_commitments[0], &tx.enc_notes[0], index),
        "le bénéficiaire doit RECONNAÎTRE la sortie qui lui est destinée"
    );
    assert_eq!(
        beneficiaire.solde(),
        300,
        "le bénéficiaire doit déchiffrer exactement le montant payé"
    );

    // Et il ne reconnaît PAS la monnaie rendue, chiffrée vers le payeur.
    assert!(
        !beneficiaire.scanner(&tx.output_commitments[1], &tx.enc_notes[1], 1),
        "la monnaie du payeur ne doit pas être lisible par le bénéficiaire"
    );

    // Et le payeur ne détient plus les notes consommées.
    assert_eq!(payeur.oublier_depensees(&tx), 2);
    assert_eq!(payeur.solde(), 0);
}
