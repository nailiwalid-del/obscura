//! LIVENESS sur sockets : le producteur du tour est ABSENT, la chaîne avance.
//!
//! 4 autorités, quorum 3. L'autorité 0 — producteur de `(1, 0)` — n'est JAMAIS
//! démarrée. Les délais de vue des trois autres expirent, elles passent à la vue 1
//! dont le producteur est `autorites[1]` ; celle-ci propose, les trois votent, et
//! le bloc 1 en **vue 1** se certifie et s'applique partout.
//!
//! C'est le critère de sortie de J1-b2 : depuis J1-b1, une autorité absente figeait
//! la chaîne. Ici elle est contournée.
//!
//! # Le temps est INJECTÉ
//!
//! Aucun `sleep` ne pilote le changement de vue. Chaque nœud avance une horloge
//! `maintenant_ms` qu'il passe à `tick`, franchissant le délai de vue de façon
//! déterministe. Seule l'attente des E/S socket utilise l'horloge réelle.

use crypto::sig::SigKeypair;
use ledger::bloc::Bloc;
use ledger::proved_state::ProvedLedgerState;
use node::orchestration::Noeud;
use node::persistance::Donnees;
use node::runtime::Runtime;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::time::{Duration, Instant};

const PROFONDEUR: usize = 4;

/// Uptime injecté qui franchit largement le délai de vue de base (3 × 5 s = 15 s).
const APRES_DELAI_MS: u64 = 30_000;

fn repertoire(nom: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("obscura_vue_{}_{}", nom, std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

/// Attend une condition, en pompant les sockets ET en tiquant l'horloge injectée à
/// `maintenant_ms` — c'est le tick qui déclenche le changement de vue.
fn attendre_en_tiquant<F: FnMut(&mut Runtime) -> bool>(
    rt: &mut Runtime,
    maintenant_ms: u64,
    mut pret: F,
    delai_reel: Duration,
) -> bool {
    let t = Instant::now();
    while t.elapsed() < delai_reel {
        rt.pomper(maintenant_ms);
        rt.tick(maintenant_ms);
        if pret(rt) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    pret(rt)
}

fn voteur(identite: SigKeypair, genese: &Bloc, dir: &std::path::PathBuf, graine: u8) -> Runtime {
    let donnees = Donnees::ouvrir(dir).expect("dépôt");
    let etat = ProvedLedgerState::depuis_genese_depth(genese, PROFONDEUR).expect("amorçage");
    let mut noeud = Noeud::new(identite, etat, [graine; 32]);
    noeud.adopter_votes(donnees.charger_ou_creer_votes().expect("registre"));
    Runtime::new(noeud).avec_donnees(donnees)
}

#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn producteur_absent_la_chaine_avance() {
    let cles: Vec<SigKeypair> = (0..4).map(|_| SigKeypair::generate()).collect();
    // Genèse VIDE d'allocations : aucun wallet, aucune transaction — le bloc 1 sera
    // vide (le battement suffit à prouver la liveness).
    let genese =
        Bloc::genese_avec_autorites(Vec::new(), cles.iter().map(|k| k.public.clone()).collect())
            .expect("genèse");
    let producteur_vue1 = cles[1].public.clone();

    // Autorités 2 et 3 écoutent ; l'autorité 1 (producteur de la vue 1) se connecte
    // à elles, collecte les votes, assemble. L'autorité 0 n'existe pas.
    let mut adresses = Vec::new();
    let mut fins = Vec::new();
    let mut threads = Vec::new();
    for i in [2usize, 3] {
        let ecoute = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        adresses.push(ecoute.local_addr().unwrap());
        let identite = SigKeypair::from_bytes_secret(&cles[i].to_bytes_secret()).unwrap();
        let genese_c = Bloc::from_bytes(&genese.to_bytes()).unwrap();
        let dir = repertoire(&format!("aut{i}"));
        let transport = SigKeypair::generate();
        let (fin_tx, fin_rx) = std::sync::mpsc::channel::<()>();
        fins.push(fin_tx);
        threads.push(std::thread::spawn(move || {
            let mut rt = voteur(identite, &genese_c, &dir, i as u8);
            let (flux, _) = ecoute.accept().unwrap();
            rt.accepter(flux, &transport).expect("handshake");
            // On tique jusqu'à la fin : ce nœud passe à la vue 1, vote pour la
            // proposition de l'autorité 1, reçoit le bloc certifié, l'applique.
            let _ = attendre_en_tiquant(
                &mut rt,
                APRES_DELAI_MS,
                |rt| rt.noeud().etat.hauteur() == 1 && fin_rx.try_recv().is_ok(),
                Duration::from_secs(120),
            );
            rt.pomper(APRES_DELAI_MS);
            let r = (
                rt.noeud().etat.hauteur(),
                rt.noeud().etat.tete(),
                rt.noeud().etat.tree.root(),
                rt.noeud().vue_courante(),
            );
            let _ = std::fs::remove_dir_all(&dir);
            r
        }));
    }

    // L'AUTORITÉ 1 : producteur de la vue 1. Elle se connecte aux deux voteuses.
    let dir1 = repertoire("aut1");
    let identite1 = SigKeypair::from_bytes_secret(&cles[1].to_bytes_secret()).unwrap();
    let mut rt1 = voteur(identite1, &genese, &dir1, 1);
    for adresse in &adresses {
        rt1.connecter(*adresse, &SigKeypair::generate())
            .expect("handshake");
    }

    // Le producteur de (1,0) est absent : le délai de vue de l'autorité 1 expire,
    // elle passe à la vue 1, propose, collecte les votes de 2 et 3, applique.
    let atteint = attendre_en_tiquant(
        &mut rt1,
        APRES_DELAI_MS,
        |rt| rt.noeud().etat.hauteur() == 1,
        Duration::from_secs(120),
    );
    assert!(
        atteint,
        "l'autorité 1 doit produire le bloc 1 en vue 1 malgré l'absence de l'autorité 0"
    );

    // Laisser le bloc certifié se diffuser aux voteuses.
    let _ = attendre_en_tiquant(&mut rt1, APRES_DELAI_MS, |_| false, Duration::from_secs(3));
    for f in fins {
        let _ = f.send(());
    }

    let racine1 = rt1.noeud().etat.tree.root();
    let tete1 = rt1.noeud().etat.tete();
    for t in threads {
        let (hauteur, tete, racine, _vue) = t.join().expect("thread voteur");
        assert_eq!(hauteur, 1, "la voteuse doit appliquer le bloc 1");
        assert_eq!(tete, tete1, "même tête que le producteur de la vue 1");
        assert_eq!(racine, racine1, "même arbre");
    }

    // Le bloc appliqué est en VUE 1, scellé par l'autorité 1, certifié à 3 votants.
    let octets = rt1.noeud().archive().octets_a(1).expect("bloc 1 archivé");
    let bloc = Bloc::from_bytes(octets).expect("bloc décodable");
    assert_eq!(
        bloc.vue, 1,
        "le bloc a été produit en VUE 1 (changement de vue)"
    );
    assert!(
        bloc.verifier_scellement(&producteur_vue1),
        "scellé par le producteur de la vue 1 = autorites[1]"
    );
    assert!(
        bloc.certificat.as_ref().unwrap().nombre_de_votants() >= 3,
        "quorum de 3 votants distincts"
    );

    let _ = std::fs::remove_dir_all(&dir1);
}
