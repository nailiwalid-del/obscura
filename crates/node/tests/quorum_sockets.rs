//! QUORUM sur de vraies sockets : quatre autorités, `f = 1`, quorum 3.
//!
//! C'est le test qui prouve que J1-b1 tient : une chaîne à `n ≥ 4` produisait plus
//! aucun bloc depuis J1-a (l'auto-vote ne suffit pas au quorum). Ici les votes
//! circulent réellement — cadrage, chiffrement, threads de lecture et d'écriture
//! découplés — et le bloc atteint la finalité.
//!
//! # Ce que le test exige
//!
//! Pas « la proposition est arrivée » : un message qui voyage ne prouve rien. Il
//! exige que les quatre nœuds finissent à la **même hauteur**, la **même tête** et
//! la **même racine**, et que le bloc appliqué porte un certificat d'au moins
//! `2f+1` votants **distincts**. C'est la discipline de `finalite.rs`.
//!
//! # Pourquoi chaque nœud a son répertoire de données
//!
//! Le vote est persisté AVANT d'être émis, et le runtime est **fail-closed** : sans
//! dépôt branché, il n'émet pas le vote du tout. Un nœud sans disque ne participe
//! donc pas au consensus — ce qui est le comportement voulu, et ce test le montre
//! en le respectant.

use crypto::sig::SigKeypair;
use ledger::bloc::Bloc;
use ledger::proved_state::ProvedLedgerState;
use node::orchestration::Noeud;
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

fn repertoire(nom: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("obscura_quorum_{}_{}", nom, std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

/// Genèse à quatre autorités, avec une note émise vers `w`.
fn genese_pour(w: &Wallet, autorites: &[SigKeypair]) -> Bloc {
    let valeur = 1_000u64;
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
    let emission = ledger::proved_wallet::emission_vers(&w.adresse().kem, &cm, &note).unwrap();
    Bloc::genese_avec_autorites(
        vec![emission],
        autorites.iter().map(|k| k.public.clone()).collect(),
    )
    .expect("genèse bornée")
}

/// Prépare un nœud voteur : état amorcé, registre chargé, dépôt branché.
fn voteur(identite: SigKeypair, genese: &Bloc, dir: std::path::PathBuf, graine: u8) -> Runtime {
    let donnees = Donnees::ouvrir(&dir).expect("dépôt");
    let etat = ProvedLedgerState::depuis_genese_depth(genese, PROFONDEUR).expect("amorçage");
    let mut noeud = Noeud::new(identite, etat, [graine; 32]);
    noeud.adopter_votes(donnees.charger_ou_creer_votes().expect("registre"));
    Runtime::new(noeud).avec_donnees(donnees)
}

/// Quatre autorités, une transaction, un bloc qui atteint le quorum et s'applique
/// partout.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn quatre_autorites_atteignent_le_quorum_sur_sockets() {
    let cles: Vec<SigKeypair> = (0..4).map(|_| SigKeypair::generate()).collect();
    let producteur_pub = cles[0].public.clone();

    let mut payeur = Wallet::depuis_secret(secret(700), PROFONDEUR);
    let beneficiaire = Wallet::depuis_secret(secret(900), PROFONDEUR);
    let genese = genese_pour(&payeur, &cles);

    // Le wallet rejoue la genèse : sans index, aucune preuve d'appartenance.
    let etat_amorce =
        ProvedLedgerState::depuis_genese_depth(&genese, PROFONDEUR).expect("amorçage");
    let lot = wallet::synchro::MorceauHistorique::bloc_entier(
        0,
        0,
        etat_amorce.tree.root(),
        genese
            .emissions
            .iter()
            .map(ledger::historique::Sortie::from)
            .collect(),
    );
    payeur
        .synchroniser(std::slice::from_ref(&lot))
        .expect("rejeu");
    let tx = payeur
        .construire(&beneficiaire.adresse(), 300, 0)
        .expect("transaction");

    // Trois voteurs à l'écoute. Le producteur (autorité 0) se connectera à eux.
    let mut adresses = Vec::new();
    let mut fins = Vec::new();
    let mut threads = Vec::new();
    for (i, cle) in cles.iter().enumerate().skip(1) {
        let ecoute = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        adresses.push(ecoute.local_addr().unwrap());
        let identite = SigKeypair::from_bytes_secret(&cle.to_bytes_secret()).unwrap();
        let genese_c = Bloc::from_bytes(&genese.to_bytes()).unwrap();
        let dir = repertoire(&format!("voteur{i}"));
        let transport = SigKeypair::generate();
        let (fin_tx, fin_rx) = std::sync::mpsc::channel::<()>();
        fins.push(fin_tx);
        threads.push(std::thread::spawn(move || {
            let mut rt = voteur(identite, &genese_c, dir.clone(), i as u8);
            let (flux, _) = ecoute.accept().unwrap();
            rt.accepter(flux, &transport).expect("handshake");
            // Pompe jusqu'à la fin : ce nœud vote puis applique le bloc certifié.
            let _ = attendre(
                || {
                    rt.pomper(0);
                    fin_rx.try_recv().is_ok()
                },
                Duration::from_secs(120),
            );
            rt.pomper(0);
            let r = (
                rt.noeud().etat.hauteur(),
                rt.noeud().etat.tete(),
                rt.noeud().etat.tree.root(),
            );
            let _ = std::fs::remove_dir_all(&dir);
            r
        }));
    }

    // Le PRODUCTEUR : autorité 0, donc producteur de la hauteur 1 (vue 0).
    let dir_p = repertoire("producteur");
    let identite_p = SigKeypair::from_bytes_secret(&cles[0].to_bytes_secret()).unwrap();
    let mut p = voteur(identite_p, &genese, dir_p.clone(), 0);
    for adresse in &adresses {
        p.connecter(*adresse, &SigKeypair::generate())
            .expect("handshake");
    }

    p.noeud_mut().soumettre(tx, 0).expect("admission");
    let (propose, actions) = p.noeud_mut().sceller().expect("notre tour");
    assert_eq!(propose.hauteur, 1);
    assert_eq!(propose.vue, 0, "vue 0 : le changement de vue est J1-b2");
    p.executer(actions);

    // Les votes reviennent, le quorum est atteint, le bloc s'applique chez nous.
    let applique = attendre(
        || {
            p.pomper(0);
            p.noeud().etat.hauteur() == 1
        },
        Duration::from_secs(120),
    );
    assert!(
        applique,
        "le producteur doit atteindre le quorum et appliquer le bloc"
    );

    // Laisser le bloc certifié se diffuser avant de couper.
    let _ = attendre(
        || {
            p.pomper(0);
            false
        },
        Duration::from_secs(3),
    );
    for f in fins {
        let _ = f.send(());
    }

    let racine_p = p.noeud().etat.tree.root();
    let tete_p = p.noeud().etat.tete();
    for (i, t) in threads.into_iter().enumerate() {
        let (hauteur, tete, racine) = t.join().expect("thread voteur");
        assert_eq!(hauteur, 1, "le voteur {} doit appliquer le bloc", i + 1);
        assert_eq!(tete, tete_p, "même tête que le producteur");
        assert_eq!(racine, racine_p, "même arbre que le producteur");
    }

    // Le bloc appliqué porte bien un quorum de votants DISTINCTS.
    let octets = p
        .noeud()
        .archive()
        .octets_a(1)
        .expect("le bloc 1 est dans l'archive");
    let certifie = Bloc::from_bytes(octets).expect("bloc archivé décodable");
    let cert = certifie
        .certificat
        .as_ref()
        .expect("le bloc appliqué est CERTIFIÉ");
    assert!(
        cert.nombre_de_votants() >= 3,
        "au moins 2f+1 = 3 votants distincts, obtenu {}",
        cert.nombre_de_votants()
    );
    assert!(
        certifie.verifier_scellement(&producteur_pub),
        "scellé par le producteur du tour"
    );

    let _ = std::fs::remove_dir_all(&dir_p);
}
