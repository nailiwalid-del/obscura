//! CRITÈRE DE SORTIE J1-c : une reconfiguration d'autorités ANNONCÉE se certifie par
//! le quorum de l'ANCIENNE liste (partie sockets), puis BASCULE à `h+K` où le NOUVEAU
//! comité prend la main (partie in-process déterministe).
//!
//! Deux tests, deux registres de preuve :
//!
//! - `reconfiguration_certifiee_sur_sockets` : l'annonce et sa certification par
//!   l'ancien quorum passent sur de VRAIES sockets (la spec l'exige). Temps INJECTÉ,
//!   aucun `sleep` ne pilote le consensus — exactement comme `vue_sockets.rs`.
//! - `reconfiguration_bascule_a_h_plus_k` : le basculement effectif à `h+K` est prouvé
//!   par un driver in-process déterministe qui route les `Action` entre 5 `Noeud` sur 9
//!   hauteurs — plus fiable qu'un test socket 5-nœuds/9-blocs, et le transport est déjà
//!   prouvé ailleurs (`quorum_sockets.rs`, `cycle_wallet.rs`). ⚠️ Ce test prouve la
//!   bascule et distingue le site height-aware du VOTEUR (`notre_index_a`) : « E vote /
//!   D non » à h+K (et, symétriquement, à h=6) échoue si ce fix est reverté. Les sites
//!   producteur et assemblage restent COMMUNS aux index partagés ici, la taille du
//!   comité restant 4→4 — c'est le test suivant qui les sépare.
//! - `reconfiguration_change_de_taille_a_h_plus_k` : un changement de TAILLE de comité
//!   (n=4 → n=7) déroulé jusqu'à `h+K` sur 8 `Noeud`. C'est ce que le test précédent ne
//!   pouvait pas faire : distinguer les DEUX sites height-aware restants. À h+K le
//!   producteur vient du NOUVEAU comité (index de vote `% 7`, site producteur) et le
//!   quorum de 5 se referme sur des positions de comité (3, 4) qui n'existent PAS dans
//!   l'ancien comité de 4 (clés retrouvées par `autorites_a_hauteur(9).get`, site
//!   assemblage). Sans ces deux fix, le bloc 9 ne se certifierait pas et la chaîne
//!   stallerait — donc le seul fait qu'elle atteigne h+K partout les prouve.

use crypto::sig::SigKeypair;
use ledger::bloc::Bloc;
use ledger::proved_state::{ProvedLedgerState, DELAI_CHANGEMENT_AUTORITES};
use net::pairs::PeerId;
use node::message::Message;
use node::orchestration::{Action, Noeud};
use node::persistance::Donnees;
use node::runtime::Runtime;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::time::{Duration, Instant};

const PROFONDEUR: usize = 4;

/// Uptime injecté SOUS le délai de vue de base (3 × 5 s = 15 s) : le producteur de
/// `(1, 0)` est présent et propose immédiatement, aucun changement de vue ne doit se
/// déclencher — sans quoi les voteuses quitteraient la vue 0 et rejetteraient sa
/// proposition.
const T_MS: u64 = 1_000;

fn repertoire(nom: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("obscura_reconf_{}_{}", nom, std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

/// Attend une condition, en pompant les sockets ET en tiquant l'horloge injectée à
/// `maintenant_ms`. Calqué sur `vue_sockets.rs`.
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

// ───────────────────────── Test A — SOCKET ─────────────────────────

#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn reconfiguration_certifiee_sur_sockets() {
    // 4 autorités [A, B, C, D] (cles 0..3) ; E (cle 4) n'est pas encore autorité.
    let cles: Vec<SigKeypair> = (0..5).map(|_| SigKeypair::generate()).collect();
    let comite_genese: Vec<_> = (0..4).map(|i| cles[i].public.clone()).collect();
    // Genèse VIDE d'allocations → bloc 1 vide, aucune preuve STARK.
    let genese = Bloc::genese_avec_autorites(Vec::new(), comite_genese).expect("genèse");
    // Nouveau comité : D (index 3) remplacé par E (cle 4).
    let nouveau: Vec<_> = vec![
        cles[0].public.clone(),
        cles[1].public.clone(),
        cles[2].public.clone(),
        cles[4].public.clone(),
    ];
    let e_bytes = cles[4].public.to_bytes();
    let d_bytes = cles[3].public.to_bytes();
    let hk = 1 + DELAI_CHANGEMENT_AUTORITES;

    // Les autorités 1, 2, 3 (B, C, D) écoutent et votent ; l'autorité 0 (A), producteur
    // de (1, 0), se connecte à elles et ANNONCE le changement.
    let mut adresses = Vec::new();
    let mut threads = Vec::new();
    for i in [1usize, 2, 3] {
        let ecoute = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        adresses.push(ecoute.local_addr().unwrap());
        let identite = SigKeypair::from_bytes_secret(&cles[i].to_bytes_secret()).unwrap();
        let genese_c = Bloc::from_bytes(&genese.to_bytes()).unwrap();
        let dir = repertoire(&format!("aut{i}"));
        let transport = SigKeypair::generate();
        threads.push(std::thread::spawn(move || {
            let mut rt = voteur(identite, &genese_c, &dir, i as u8);
            let (flux, _) = ecoute.accept().unwrap();
            rt.accepter(flux, &transport).expect("handshake");
            // On tique jusqu'à appliquer le bloc 1 certifié (le changement d'autorités).
            let _ = attendre_en_tiquant(
                &mut rt,
                T_MS,
                |rt| rt.noeud().etat.hauteur() == 1,
                Duration::from_secs(120),
            );
            rt.pomper(T_MS);
            // Le comité ACTIF à h+K vu par cette voteuse (liste height-aware).
            let actives_hk: Vec<Vec<u8>> = rt
                .noeud()
                .etat
                .autorites_a_hauteur(hk)
                .iter()
                .map(|k| k.to_bytes())
                .collect();
            let r = (
                rt.noeud().etat.hauteur(),
                rt.noeud().etat.tete(),
                rt.noeud().etat.tree.root(),
                rt.noeud().etat.quorum_a(hk),
                actives_hk,
            );
            let _ = std::fs::remove_dir_all(&dir);
            r
        }));
    }

    // L'AUTORITÉ 0 (A) : producteur de (1, 0). Elle se connecte aux trois voteuses puis
    // déclenche `proposer_changement` — l'ancien quorum (3 sur 4) doit certifier.
    let dir0 = repertoire("aut0");
    let identite0 = SigKeypair::from_bytes_secret(&cles[0].to_bytes_secret()).unwrap();
    let mut rt0 = voteur(identite0, &genese, &dir0, 0);
    for adresse in &adresses {
        rt0.connecter(*adresse, &SigKeypair::generate())
            .expect("handshake");
    }

    // Les liens sont établis (handshakes synchrones) : la proposition atteint les trois.
    assert!(
        rt0.proposer_changement(nouveau.clone(), T_MS),
        "A est producteur de (1,0) sur une chaîne à autorités : la proposition est émise"
    );

    // A collecte les votes de l'ancien comité, assemble le bloc 1 certifié, se
    // l'applique et le diffuse.
    let atteint = attendre_en_tiquant(
        &mut rt0,
        T_MS,
        |rt| rt.noeud().etat.hauteur() == 1,
        Duration::from_secs(120),
    );
    assert!(
        atteint,
        "A doit certifier le bloc 1 de reconfiguration par l'ancien quorum"
    );

    // Laisser le bloc certifié se diffuser aux voteuses.
    let _ = attendre_en_tiquant(&mut rt0, T_MS, |_| false, Duration::from_secs(3));

    let racine0 = rt0.noeud().etat.tree.root();
    let tete0 = rt0.noeud().etat.tete();
    for t in threads {
        let (hauteur, tete, racine, quorum_hk, actives_hk) = t.join().expect("thread voteur");
        assert_eq!(hauteur, 1, "la voteuse applique le bloc 1");
        assert_eq!(tete, tete0, "même tête que le producteur A");
        assert_eq!(racine, racine0, "même arbre");
        // Vu de chaque voteuse : à h+K, D est remplacée par E et le quorum est 3.
        assert_eq!(quorum_hk, 3, "quorum du nouveau comité à h+K");
        assert!(
            actives_hk.contains(&e_bytes),
            "E est autorité active à h+K (chez la voteuse)"
        );
        assert!(
            !actives_hk.contains(&d_bytes),
            "D ne l'est plus à h+K (chez la voteuse)"
        );
    }

    // Le bloc 1 archivé porte le changement et un certificat de l'ancien quorum.
    let octets = rt0.noeud().archive().octets_a(1).expect("bloc 1 archivé");
    let bloc = Bloc::from_bytes(octets).expect("bloc décodable");
    let annonce = bloc
        .changement_autorites
        .as_ref()
        .expect("le bloc 1 annonce un changement d'autorités");
    let annonce_bytes: Vec<Vec<u8>> = annonce.iter().map(|k| k.to_bytes()).collect();
    let attendu_bytes: Vec<Vec<u8>> = nouveau.iter().map(|k| k.to_bytes()).collect();
    assert_eq!(
        annonce_bytes, attendu_bytes,
        "le bloc annonce exactement [A, B, C, E]"
    );
    assert!(
        bloc.certificat.as_ref().unwrap().nombre_de_votants() >= 3,
        "certifié par >= 3 votants de l'ANCIEN comité"
    );

    // Chez A aussi, le comité height-aware à h+K est le nouveau (D remplacée par E),
    // quorum 3. (`producteur_attendu(h+K, 0)` vaut A — index (h+K−1) mod 4 = 0 — non E ;
    // ce que l'on prouve ici est le REMPLACEMENT effectif de D par E dans la liste
    // active, pas l'ordre de rotation.)
    let actives_a: Vec<Vec<u8>> = rt0
        .noeud()
        .etat
        .autorites_a_hauteur(hk)
        .iter()
        .map(|k| k.to_bytes())
        .collect();
    assert_eq!(rt0.noeud().etat.quorum_a(hk), 3, "quorum 3 à h+K (chez A)");
    assert!(actives_a.contains(&e_bytes), "E est autorité active à h+K");
    assert!(!actives_a.contains(&d_bytes), "D ne l'est plus à h+K");

    let _ = std::fs::remove_dir_all(&dir0);
}

// ───────────────────────── Test B — IN-PROCESS ─────────────────────────

/// Applique une file d'actions `(source, action)` sur les 5 nœuds jusqu'au point fixe :
/// `Diffuser` → tous les AUTRES nœuds ; `Envoyer(peer)` → le nœud ciblé ; `PersisterVotes`
/// ignoré (pas de disque en test). Chaque `traiter` peut produire de nouvelles actions,
/// enfilées à leur tour. Déterministe : aucun réseau, aucun temps réel.
///
/// Renvoie l'ensemble des INDEX de nœuds ayant ÉMIS un `Message::Vote` pendant ce
/// routage — indépendant de l'ordre de livraison (un vote émis est capturé même si le
/// quorum se referme avant qu'il n'atteigne le producteur). C'est ce qui prouve, sans
/// dépendre du hasard de la file, quel comité a effectivement voté à une hauteur.
fn router(
    noeuds: &mut [Noeud],
    pids: &[PeerId],
    depart: Vec<(usize, Action)>,
    t: u64,
) -> std::collections::BTreeSet<usize> {
    let mut voteurs = std::collections::BTreeSet::new();
    let mut file: VecDeque<(usize, Action)> = depart.into_iter().collect();
    let mut garde = 0usize;
    while let Some((src, action)) = file.pop_front() {
        garde += 1;
        assert!(
            garde < 100_000,
            "boucle de routage — point fixe non atteint"
        );
        let de = pids[src]; // `PeerId` est `Copy`
        match action {
            Action::PersisterVotes(_) => {}
            // Une déconnexion ne produit AUCUN trafic : rien à router ici. Ce
            // simulateur n'a pas de liens à fermer — les nœuds de ce scénario sont
            // tous à jour, et le cas est couvert sur sockets par
            // `negociation_version.rs`.
            Action::Deconnecter { .. } => {}
            Action::Diffuser(msg) => {
                // `Message` n'est pas `Clone` : on le duplique par son encodage de fil
                // canonique (le MÊME que sur socket), une fois par destinataire.
                let octets = msg.to_bytes();
                for (j, n) in noeuds.iter_mut().enumerate() {
                    if j == src {
                        continue;
                    }
                    let copie = Message::from_bytes(&octets).expect("message re-décodable");
                    for a in n.traiter(de, copie, t) {
                        if let Action::Envoyer(_, Message::Vote(_)) = &a {
                            voteurs.insert(j);
                        }
                        file.push_back((j, a));
                    }
                }
            }
            Action::Envoyer(cible, msg) => {
                if let Some(j) = pids.iter().position(|p| *p == cible) {
                    for a in noeuds[j].traiter(de, msg, t) {
                        if let Action::Envoyer(_, Message::Vote(_)) = &a {
                            voteurs.insert(j);
                        }
                        file.push_back((j, a));
                    }
                }
            }
        }
    }
    voteurs
}

#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn reconfiguration_bascule_a_h_plus_k() {
    // 5 nœuds : A, B, C, D (comité de genèse) + E (pas encore autorité). Genèse VIDE
    // d'allocations → blocs vides, aucune preuve STARK.
    let cles: Vec<SigKeypair> = (0..5).map(|_| SigKeypair::generate()).collect(); // 0..4 = A..E
    let comite_genese: Vec<_> = (0..4).map(|i| cles[i].public.clone()).collect(); // A, B, C, D
    let genese = Bloc::genese_avec_autorites(Vec::new(), comite_genese).expect("genèse");
    // Nouveau comité : D (index 3) remplacé par E (index 4).
    let nouveau: Vec<_> = vec![
        cles[0].public.clone(),
        cles[1].public.clone(),
        cles[2].public.clone(),
        cles[4].public.clone(),
    ];

    let mut noeuds: Vec<Noeud> = (0..5)
        .map(|i| {
            let etat =
                ProvedLedgerState::depuis_genese_depth(&genese, PROFONDEUR).expect("amorçage");
            let id = SigKeypair::from_bytes_secret(&cles[i].to_bytes_secret()).unwrap();
            Noeud::new(id, etat, [i as u8; 32])
        })
        .collect();
    let pids: Vec<PeerId> = noeuds
        .iter()
        .map(|n| PeerId::depuis_identite(&n.identite.public))
        .collect();

    let t = 1_000u64;

    // Index du producteur de `(hauteur, vue 0)` selon le comité height-aware (n'importe
    // quel nœud à jour donne la même réponse).
    let producteur = |noeuds: &[Noeud], hauteur: u64| -> usize {
        let pk = noeuds[0]
            .etat
            .producteur_attendu(hauteur, 0)
            .unwrap()
            .to_bytes();
        (0..5)
            .find(|&i| noeuds[i].identite.public.to_bytes() == pk)
            .unwrap()
    };

    // HAUTEUR 1 : le producteur ANNONCE le changement (proposer_changement).
    let p1 = producteur(&noeuds, 1);
    let (_, actions) = noeuds[p1]
        .proposer_changement(nouveau.clone(), t)
        .expect("annonce");
    router(
        &mut noeuds,
        &pids,
        actions.into_iter().map(|a| (p1, a)).collect(),
        t,
    );
    for n in &noeuds {
        assert_eq!(n.etat.hauteur(), 1, "tous appliquent le bloc 1");
    }

    // HAUTEURS 2..=9 : chaque producteur du tour SCELLE un bloc vide (battement), le
    // comité vote, le bloc se certifie et s'applique partout. On retient les VOTEURS de
    // la dernière hauteur (h+K) — c'est là que le nouveau comité doit avoir pris la main
    // — ET ceux de h=6 (comité ANCIEN), le miroir AVANT bascule.
    //
    // h=6 est choisi plutôt que h=8 : le producteur de (6, 0) est [A,B,C,D][(6-1)%4] =
    // index 1 = B, donc D y est VOTEUSE non-productrice — contrairement à h=8, où D
    // ([A,B,C,D][(8-1)%4] = index 3) serait productrice et « D a voté » y serait trivial
    // (le producteur signe toujours son propre vote).
    let mut voteurs_hk = std::collections::BTreeSet::new();
    let mut voteurs_h6 = std::collections::BTreeSet::new();
    for h in 2..=(1 + DELAI_CHANGEMENT_AUTORITES) {
        let p = producteur(&noeuds, h);
        let (_, actions) = noeuds[p].sceller().expect("scellement du battement");
        voteurs_hk = router(
            &mut noeuds,
            &pids,
            actions.into_iter().map(|a| (p, a)).collect(),
            t,
        );
        if h == 6 {
            voteurs_h6 = voteurs_hk.clone();
        }
        for n in &noeuds {
            assert_eq!(n.etat.hauteur(), h, "tous appliquent le bloc {h}");
        }
    }

    // AVANT la bascule (h=6, comité ANCIEN [A,B,C,D]) : D (nœud 3) est encore autorité et
    // vote ; E (nœud 4) n'en est pas encore une et ne vote pas. Miroir exact de
    // l'assertion h+K plus bas — c'est le CONTRASTE avant/après qui prouve que le
    // basculement change effectivement quelque chose, et pas seulement qu'après h+K le
    // nouveau comité est en place.
    assert!(
        voteurs_h6.contains(&3),
        "D (nœud 3, encore autorité avant bascule) vote à h=6 — voteurs = {voteurs_h6:?}"
    );
    assert!(
        !voteurs_h6.contains(&4),
        "E (nœud 4, pas encore autorité) ne vote pas à h=6 — voteurs = {voteurs_h6:?}"
    );

    // À h+K = 9 : le NOUVEAU comité a pris la main. Vérifier la bascule.
    let hk = 1 + DELAI_CHANGEMENT_AUTORITES;
    for n in &noeuds {
        assert_eq!(n.etat.hauteur(), hk);
        // La liste committée est le NOUVEAU comité (D remplacé par E).
        let actives: Vec<_> = n.etat.autorites().iter().map(|k| k.to_bytes()).collect();
        assert_eq!(actives.len(), 4);
        assert!(
            actives.contains(&cles[4].public.to_bytes()),
            "E est désormais autorité"
        );
        assert!(
            !actives.contains(&cles[3].public.to_bytes()),
            "D ne l'est plus"
        );
    }

    // Le bloc h+K est certifié par le NOUVEAU comité. On relit le bloc archivé chez son
    // producteur : le certificat réunit au moins le quorum du nouveau comité.
    let ph = producteur(&noeuds, hk);
    let octets = noeuds[ph].archive().octets_a(hk).expect("bloc h+K archivé");
    let bloc = Bloc::from_bytes(octets).expect("décodable");
    let cert = bloc.certificat.as_ref().expect("certificat");
    assert!(cert.nombre_de_votants() >= 3, "quorum du nouveau comité");
    // Que le bloc se soit APPLIQUÉ partout (égalité des hauteurs ci-dessus) prouve déjà
    // que `appliquer_bloc` a validé ce certificat SOUS le nouveau comité.
    //
    // La BASCULE elle-même — E vote désormais, D remplacée ne vote plus — est prouvée
    // par les VOTEURS effectifs de la ronde h+K, capturés par le routeur AVANT que le
    // quorum ne se referme (donc indépendamment de l'ordre de livraison, contrairement
    // au contenu du certificat qui, lui, s'arrête au premier quorum atteint).
    assert!(
        voteurs_hk.contains(&4),
        "E (nœud 4, désormais autorité) a voté à h+K — voteurs = {voteurs_hk:?}"
    );
    assert!(
        !voteurs_hk.contains(&3),
        "D (nœud 3, remplacée) ne vote plus à h+K — voteurs = {voteurs_hk:?}"
    );
}

// ───────────────────────── Test C — REDÉMARRAGE ─────────────────────────

/// REDÉMARRAGE : un nœud qui a enregistré un changement en attente le retrouve après
/// rechargement — sinon il raterait le basculement et divergerait.
///
/// `Donnees` n'expose pas de chemin d'état direct (pas de `chemin_etat()`) : on passe
/// par l'API RÉELLE de persistance, `enregistrer_etat`/`charger_ou_amorcer_etat` (cf.
/// `crates/node/src/persistance.rs`), celle qu'utilisent aussi `runtime` et les
/// binaires — donc le chemin effectivement exercé en production, pas un raccourci de
/// test qui contournerait `verifier_genese`.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn le_pendant_survit_au_redemarrage() {
    let cles: Vec<SigKeypair> = (0..1).map(|_| SigKeypair::generate()).collect();
    let genese = Bloc::genese_avec_autorites(Vec::new(), vec![cles[0].public.clone()]).unwrap();
    let dir = repertoire("redemarrage");
    let neuve = SigKeypair::generate().public;
    // Amorcer, proposer un changement (n=1, auto-appliqué : quorum 1), sauvegarder.
    {
        let donnees = Donnees::ouvrir(&dir).unwrap();
        let etat = ProvedLedgerState::depuis_genese_depth(&genese, PROFONDEUR).unwrap();
        let mut noeud = Noeud::new(
            SigKeypair::from_bytes_secret(&cles[0].to_bytes_secret()).unwrap(),
            etat,
            [5u8; 32],
        );
        noeud
            .proposer_changement(vec![neuve.clone()], 0)
            .expect("reconfig n=1");
        assert_eq!(noeud.etat.hauteur(), 1);
        // Persister via le chemin RÉEL du nœud (identique à `runtime`/aux binaires).
        donnees.enregistrer_etat(&noeud.etat).unwrap();
    }
    // REDÉMARRAGE : rouvrir le répertoire et recharger l'état depuis la genèse.
    {
        let donnees = Donnees::ouvrir(&dir).unwrap();
        let etat = donnees.charger_ou_amorcer_etat(&genese).unwrap();
        assert_eq!(etat.hauteur(), 1);
        assert_eq!(
            etat.producteur_attendu(1 + DELAI_CHANGEMENT_AUTORITES, 0)
                .map(|k| k.to_bytes()),
            Some(neuve.to_bytes()),
            "après redémarrage, le producteur à h+K est la nouvelle autorité"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ──────────────── Test D — CHANGEMENT DE TAILLE (sites producteur & assemblage) ────────────────

/// Un changement de TAILLE de comité (n=4 → n=7) déroulé jusqu'à `h+K`. Là où
/// `reconfiguration_bascule_a_h_plus_k` distingue le site height-aware du VOTEUR
/// (`notre_index_a`), ce test distingue les DEUX sites restants — que SEUL un changement
/// de taille sépare, l'ancien et le nouveau comité ne partageant plus tous leurs index :
///
/// - **Site PRODUCTEUR** (l'index du vote que le producteur signe lui-même,
///   `orchestration.rs` : `(prochaine − 1 + vue) % autorites_a_hauteur(prochaine).len()`).
///   À h+K le producteur est `new[(9−1) % 7] = new[1] = B`. Son index de vote est sa
///   POSITION dans le nouveau comité, 1. Sans le fix (`% 4`), il vaudrait `8 % 4 = 0`
///   (la position de A) : `appliquer_bloc` opposerait alors la clé de A à la signature
///   de B → `VoteInvalide`. Que le bloc 9 se certifie et s'applique le prouve.
/// - **Site ASSEMBLAGE** (la clé de vérification retrouvée par
///   `autorites_a_hauteur(h+1).get(vote.index)`). Le quorum de 5 se referme sur les 5
///   plus petites POSITIONS de comité {0,1,2,3,4} = A,B,C,E,F. Les positions 3 et 4
///   (E, F) N'EXISTENT PAS dans l'ancien comité de 4 : sans le fix, `get(3)` rendrait D
///   (clé fausse → `VoteInvalide`) et `get(4)` serait hors liste (`VotantInconnu`) → le
///   certificat ne validerait pas et la chaîne stallerait à h=9.
///
/// ⚠️ Ne PAS confondre POSITION DE COMITÉ et INDEX DE NŒUD. Dans le nouveau comité
/// [A,B,C,E,F,G,H], E est en position 3 et F en position 4 ; mais les NŒUDS E, F sont aux
/// index 4, 5 dans `noeuds`/`cles` (D, retirée, garde l'index de nœud 3). Les voteurs
/// capturés sont indexés par NŒUD.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn reconfiguration_change_de_taille_a_h_plus_k() {
    // 8 nœuds : A,B,C,D (comité de genèse) + E,F,G,H (pas encore autorités). Genèse VIDE
    // d'allocations → blocs vides, aucune preuve STARK.
    let cles: Vec<SigKeypair> = (0..8).map(|_| SigKeypair::generate()).collect(); // 0..7 = A..H
    let comite_genese: Vec<_> = (0..4).map(|i| cles[i].public.clone()).collect(); // A, B, C, D
    let genese = Bloc::genese_avec_autorites(Vec::new(), comite_genese).expect("genèse");
    // Nouveau comité : D (index de nœud 3) RETIRÉE, E,F,G,H (index de nœud 4..8) AJOUTÉS.
    // Taille 4 → 7. Positions de comité : A=0, B=1, C=2, E=3, F=4, G=5, H=6.
    let nouveau: Vec<_> = vec![
        cles[0].public.clone(),
        cles[1].public.clone(),
        cles[2].public.clone(),
        cles[4].public.clone(),
        cles[5].public.clone(),
        cles[6].public.clone(),
        cles[7].public.clone(),
    ];

    let mut noeuds: Vec<Noeud> = (0..8)
        .map(|i| {
            let etat =
                ProvedLedgerState::depuis_genese_depth(&genese, PROFONDEUR).expect("amorçage");
            let id = SigKeypair::from_bytes_secret(&cles[i].to_bytes_secret()).unwrap();
            Noeud::new(id, etat, [i as u8; 32])
        })
        .collect();
    let pids: Vec<PeerId> = noeuds
        .iter()
        .map(|n| PeerId::depuis_identite(&n.identite.public))
        .collect();

    let t = 1_000u64;

    // Index de NŒUD du producteur de `(hauteur, vue 0)` selon le comité height-aware
    // (n'importe quel nœud à jour donne la même réponse). Calqué sur le test précédent,
    // étendu à 8 nœuds.
    let producteur = |noeuds: &[Noeud], hauteur: u64| -> usize {
        let pk = noeuds[0]
            .etat
            .producteur_attendu(hauteur, 0)
            .unwrap()
            .to_bytes();
        (0..8)
            .find(|&i| noeuds[i].identite.public.to_bytes() == pk)
            .unwrap()
    };

    // HAUTEUR 1 : le producteur du tour (A, sous l'ANCIEN comité) ANNONCE le nouveau
    // comité de 7. Certifié par l'ancien quorum (3 de [A,B,C,D]).
    let p1 = producteur(&noeuds, 1);
    let (_, actions) = noeuds[p1]
        .proposer_changement(nouveau.clone(), t)
        .expect("annonce");
    router(
        &mut noeuds,
        &pids,
        actions.into_iter().map(|a| (p1, a)).collect(),
        t,
    );
    for n in &noeuds {
        assert_eq!(n.etat.hauteur(), 1, "tous appliquent le bloc 1");
    }

    // HAUTEURS 2..=9 : chaque producteur du tour SCELLE un bloc vide (battement), le
    // comité vote, le bloc se certifie et s'applique partout. On retient les VOTEURS de
    // la dernière hauteur (h+K) — c'est là que le NOUVEAU comité de 7 prend la main.
    let mut voteurs_hk = std::collections::BTreeSet::new();
    for h in 2..=(1 + DELAI_CHANGEMENT_AUTORITES) {
        let p = producteur(&noeuds, h);
        let (_, actions) = noeuds[p].sceller().expect("scellement du battement");
        voteurs_hk = router(
            &mut noeuds,
            &pids,
            actions.into_iter().map(|a| (p, a)).collect(),
            t,
        );
        for n in &noeuds {
            assert_eq!(n.etat.hauteur(), h, "tous appliquent le bloc {h}");
        }
    }

    let hk = 1 + DELAI_CHANGEMENT_AUTORITES; // = 9

    // (1) Les 8 nœuds atteignent h+K, et (2) le comité committé est le NOUVEAU (taille 7 :
    // E,F,G,H présents, D absente). Que le bloc 9 se soit APPLIQUÉ partout prouve DÉJÀ les
    // sites producteur et assemblage : sans eux, `appliquer_bloc` aurait rejeté le
    // certificat sous le nouveau comité et la chaîne aurait stallé à h=9.
    for n in &noeuds {
        assert_eq!(n.etat.hauteur(), hk);
        let actives: Vec<_> = n.etat.autorites().iter().map(|k| k.to_bytes()).collect();
        assert_eq!(actives.len(), 7, "le comité committé est de taille 7");
        for (i, cle) in cles.iter().enumerate().take(8).skip(4) {
            assert!(
                actives.contains(&cle.public.to_bytes()),
                "le membre neuf (nœud {i}) est désormais autorité"
            );
        }
        assert!(
            !actives.contains(&cles[3].public.to_bytes()),
            "D (nœud 3) n'est plus autorité"
        );
        // (3) Le quorum du nouveau comité de 7 est ⌊2·7/3⌋ + 1 = 5.
        assert_eq!(n.etat.quorum_a(hk), 5, "quorum du comité de taille 7 à h+K");
    }

    // À h+K le producteur est `new[(9−1) % 7] = new[1] = B` (nœud 1), issu du NOUVEAU
    // comité — c'est le prérequis du site producteur (son index de vote est `% 7`).
    let ph = producteur(&noeuds, hk);
    assert_eq!(
        ph, 1,
        "à h+K le producteur est new[(9-1)%7] = new[1] = B (nœud 1)"
    );

    // (4) Le bloc h+K archivé porte un certificat du NOUVEAU comité : au moins 5 votants.
    // Le certificat canonique retient les 5 plus petites positions {0,1,2,3,4} =
    // A,B,C,E,F ; les positions 3 et 4 (E, F) ne se vérifient que sous
    // `autorites_a_hauteur(9)` — c'est le site assemblage.
    let octets = noeuds[ph].archive().octets_a(hk).expect("bloc h+K archivé");
    let bloc = Bloc::from_bytes(octets).expect("décodable");
    let cert = bloc.certificat.as_ref().expect("certificat");
    assert!(
        cert.nombre_de_votants() >= 5,
        "quorum du nouveau comité (≥ 5 votants) — votants = {}",
        cert.nombre_de_votants()
    );

    // (5) BASCULE prouvée par les VOTEURS effectifs de la ronde h+K, capturés AVANT que
    // le quorum ne se referme (donc indépendamment de l'ordre de livraison). E (nœud 4,
    // position de comité 3) et F (nœud 5, position de comité 4) sont les membres neufs
    // ESSENTIELS — leurs positions figurent dans les 5 plus petites que le certificat
    // canonique retient. Leur vote passe par `notre_index_a(9)` height-aware (site
    // voteur) ; D (nœud 3), retirée, ne vote plus.
    assert!(
        voteurs_hk.contains(&4),
        "E (nœud 4, position de comité 3, membre neuf essentiel) a voté à h+K — voteurs = {voteurs_hk:?}"
    );
    assert!(
        voteurs_hk.contains(&5),
        "F (nœud 5, position de comité 4, membre neuf essentiel) a voté à h+K — voteurs = {voteurs_hk:?}"
    );
    assert!(
        !voteurs_hk.contains(&3),
        "D (nœud 3, retirée) ne vote plus à h+K — voteurs = {voteurs_hk:?}"
    );
}
