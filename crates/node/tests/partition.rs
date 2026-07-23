//! PARTITION (J3, chantier 1) : la minorité s'arrête sans forker, la majorité
//! avance, et au retour la minorité rattrape la MÊME tête.
//!
//! # Ce que ce test ÉNONCE
//!
//! La sûreté sous partition n'est pas un mécanisme ajouté : elle DÉCOULE du quorum
//! BFT sur un état append-only. Un côté qui ne réunit pas `2f+1` votes ne certifie
//! aucun bloc, donc n'en applique aucun, donc ne crée aucune branche concurrente à
//! réconcilier. La propriété était implicite ; ce fichier la rend EXPLICITE et
//! non-régressable.
//!
//! Il est donc NORMAL que ce test passe d'emblée : il ne construit rien, il prouve.
//!
//! # Le montage
//!
//! Quatre autorités (`n = 4`, `f = 1`, quorum 3) sur de VRAIES sockets, toutes dans
//! le fil principal — un `Runtime` par nœud, pompé à tour de rôle, ce qui rend
//! l'ordonnancement déterministe. La partition est l'ABSENCE de lien : `{1, 2, 3}`
//! sont en maille complète, l'autorité `0` n'est reliée à personne. Rien n'est
//! simulé au niveau transport, et `crates/net` n'est pas touché (invariant : `net` =
//! pur transport).
//!
//! Le côté isolé est délibérément **le producteur du tour** : `producteur_attendu(1,
//! 0) = autorites[0]`. La majorité doit donc d'abord le CONTOURNER par changement de
//! vue — c'est le cas réel d'une partition, où le côté coupé emporte parfois le
//! producteur — puis produire ses hauteurs suivantes en vue 0.
//!
//! La guérison est un lien de plus, et le déclencheur du rattrapage est un bloc
//! VRAIMENT NEUF (hauteur 4, produite par une autorité restée en majorité) : aucun
//! message n'est fabriqué par le test. Le chemin emprunté est le chemin NORMAL —
//! `Message::Bloc` en avance refusé → `DemandeBloc` → bloc servi depuis l'archive →
//! `appliquer_bloc` — un bloc par échange, sans raccourci.
//!
//! # Le temps est INJECTÉ
//!
//! Aucun `sleep` ne pilote le consensus. La majorité vit à une horloge CONSTANTE,
//! choisie au-delà du délai de vue de base : le premier `tick` la fait passer en vue
//! 1 (contournement du producteur isolé), et plus jamais ensuite — chaque avancée de
//! hauteur réarme `debut_vue_ms` sur cette même valeur. La minorité, elle, avance son
//! horloge : ses délais expirent, elle monte de vue, et ne conclut toujours rien.

use crypto::sig::SigKeypair;
use ledger::bloc::Bloc;
use ledger::proved_state::ProvedLedgerState;
use node::orchestration::Noeud;
use node::persistance::Donnees;
use node::runtime::Runtime;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::time::{Duration, Instant};

const PROFONDEUR: usize = 4;

/// Horloge de la majorité, CONSTANTE et au-delà du délai de vue de base
/// (`3 × 5 s = 15 s`). Le premier `tick` franchit donc le délai et fait passer en vue
/// 1 ; ensuite `maintenant − debut_vue_ms` reste nul, puisque chaque avancée de
/// hauteur réarme le timer sur cette même valeur. Une seule montée de vue, voulue.
const HORLOGE_MAJORITE: u64 = 30_000;

/// Bond d'horloge de la minorité : franchit largement le délai de vue, backoff
/// plafonné compris (60 s). Un bond = une vue de plus.
const BOND_MINORITE_MS: u64 = 120_000;

/// Délai RÉEL accordé aux échanges de sockets (le consensus, lui, est en temps injecté).
const PATIENCE: Duration = Duration::from_secs(120);

fn repertoire(nom: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("obscura_partition_{}_{}", nom, std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

/// Prépare un nœud-autorité : état amorcé, registre de votes chargé, dépôt branché.
///
/// Le dépôt n'est pas décoratif : le runtime est **fail-closed**, un nœud sans disque
/// n'émet aucun vote. Il ne participerait donc pas au consensus, et le test
/// prouverait autre chose que ce qu'il annonce.
fn autorite(identite: SigKeypair, genese: &Bloc, dir: &std::path::Path, graine: u8) -> Runtime {
    let donnees = Donnees::ouvrir(dir).expect("dépôt");
    let etat = ProvedLedgerState::depuis_genese_depth(genese, PROFONDEUR).expect("amorçage");
    let mut noeud = Noeud::new(identite, etat, [graine; 32]);
    noeud.adopter_votes(donnees.charger_ou_creer_votes().expect("registre"));
    Runtime::new(noeud).avec_donnees(donnees)
}

/// Relie deux nœuds par une VRAIE socket TCP, handshake PQ compris.
///
/// Le handshake est en trois passes BLOQUANTES : les deux côtés doivent s'exécuter en
/// même temps. On prête donc l'accepteur à un thread de PORTÉE le temps de
/// l'établissement, puis on le récupère — tout le reste du test pilote les quatre
/// nœuds depuis le fil principal. La partition devient alors observable comme une
/// simple absence d'appel à cette fonction.
fn relier(accepteur: &mut Runtime, appelant: &mut Runtime) {
    let ecoute = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("écoute");
    let adresse = ecoute.local_addr().expect("adresse liée");
    let transport_entrant = SigKeypair::generate();
    let transport_sortant = SigKeypair::generate();
    std::thread::scope(|s| {
        let accepte = s.spawn(|| {
            let (flux, _) = ecoute.accept().expect("connexion entrante");
            accepteur
                .accepter(flux, &transport_entrant)
                .expect("handshake entrant");
        });
        appelant
            .connecter(adresse, &transport_sortant)
            .expect("handshake sortant");
        accepte.join().expect("thread d'acceptation");
    });
}

/// Un battement : chaque nœud pompe ses sockets et tique son horloge.
fn battre(majorite: &mut [&mut Runtime], minorite: &mut Runtime, t_minorite: u64) {
    for rt in majorite.iter_mut() {
        rt.pomper(HORLOGE_MAJORITE);
        rt.tick(HORLOGE_MAJORITE);
    }
    minorite.pomper(t_minorite);
    minorite.tick(t_minorite);
}

/// Bat jusqu'à ce que toute la majorité ait atteint `cible`, ou expiration du délai réel.
fn attendre_majorite(
    majorite: &mut [&mut Runtime],
    minorite: &mut Runtime,
    t_minorite: u64,
    cible: u64,
) -> bool {
    attendre(majorite, minorite, t_minorite, |maj, _| {
        maj.iter().all(|rt| rt.noeud().etat.hauteur() == cible)
    })
}

fn attendre(
    majorite: &mut [&mut Runtime],
    minorite: &mut Runtime,
    t_minorite: u64,
    mut pret: impl FnMut(&[&mut Runtime], &Runtime) -> bool,
) -> bool {
    let debut = Instant::now();
    loop {
        battre(majorite, minorite, t_minorite);
        if pret(majorite, minorite) {
            return true;
        }
        if debut.elapsed() >= PATIENCE {
            return pret(majorite, minorite);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// La majorité produit `hauteur` en vue 0 : le producteur du tour propose (chemin
/// OPÉRATEUR, `sceller`), les deux autres votent, le quorum de 3 est atteint, le bloc
/// certifié se diffuse et s'applique partout.
fn majorite_produit(
    majorite: &mut [&mut Runtime],
    minorite: &mut Runtime,
    t_minorite: u64,
    tour: usize,
    hauteur: u64,
) {
    let (bloc, actions) = majorite[tour]
        .noeud_mut()
        .sceller()
        .expect("le producteur du tour propose");
    assert_eq!(bloc.hauteur, hauteur, "la hauteur proposée est la suivante");
    assert_eq!(
        bloc.vue, 0,
        "hauteur avancée = timer réarmé : plus de changement de vue"
    );
    majorite[tour].executer(actions);
    assert!(
        attendre_majorite(majorite, minorite, t_minorite, hauteur),
        "les trois nœuds majoritaires doivent atteindre la hauteur {hauteur}"
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn minorite_sarrete_majorite_avance_puis_convergence() {
    let cles: Vec<SigKeypair> = (0..4).map(|_| SigKeypair::generate()).collect();
    // Genèse SANS allocation : les blocs sont vides (le battement suffit — ce test
    // porte sur le consensus, pas sur les transactions).
    let genese =
        Bloc::genese_avec_autorites(Vec::new(), cles.iter().map(|k| k.public.clone()).collect())
            .expect("genèse à quatre autorités");
    assert_eq!(
        ProvedLedgerState::depuis_genese_depth(&genese, PROFONDEUR)
            .expect("amorçage")
            .quorum_a(1),
        3,
        "n = 4 ⇒ f = 1 ⇒ quorum 2f+1 = 3 : un nœud SEUL ne peut pas l'atteindre"
    );

    let dirs: Vec<std::path::PathBuf> = (0..4).map(|i| repertoire(&format!("aut{i}"))).collect();
    let mut runtimes: Vec<Runtime> = cles
        .iter()
        .zip(dirs.iter())
        .enumerate()
        .map(|(i, (cle, dir))| {
            let identite = SigKeypair::from_bytes_secret(&cle.to_bytes_secret()).expect("identité");
            autorite(identite, &genese, dir, i as u8)
        })
        .collect();
    // L'ISOLÉE est l'autorité 0 — le producteur de (1, 0). La majorité devra donc la
    // contourner avant de pouvoir produire quoi que ce soit.
    let mut m3 = runtimes.pop().expect("autorité 3");
    let mut m2 = runtimes.pop().expect("autorité 2");
    let mut m1 = runtimes.pop().expect("autorité 1");
    let mut isolee = runtimes.pop().expect("autorité 0");

    // ---------- LA PARTITION ----------
    // Maille complète du côté majoritaire : chaque producteur du tour doit pouvoir
    // recueillir les votes des deux autres. L'autorité 0 n'est reliée à PERSONNE :
    // c'est là, et nulle part ailleurs, que la partition est faite.
    relier(&mut m1, &mut m2);
    relier(&mut m2, &mut m3);
    relier(&mut m3, &mut m1);
    assert_eq!(
        isolee.liens_ouverts(),
        0,
        "la minorité est isolée : aucun lien, aucune simulation"
    );

    let mut majorite: [&mut Runtime; 3] = [&mut m1, &mut m2, &mut m3];
    let t_min_gele = 0u64;

    // ---------- LA MAJORITÉ CONTOURNE, PUIS AVANCE ----------
    // Hauteur 1 : le producteur de la vue 0 est l'isolée. Les délais de vue de la
    // majorité expirent, elle passe en vue 1 dont le producteur est `autorites[1]`,
    // qui propose. Rien n'est déclenché à la main : c'est `tick` qui décide.
    assert!(
        attendre_majorite(&mut majorite, &mut isolee, t_min_gele, 1),
        "la majorité doit contourner le producteur isolé par changement de vue"
    );
    let octets1 = majorite[0]
        .noeud()
        .archive()
        .octets_a(1)
        .expect("bloc 1 archivé")
        .to_vec();
    let bloc1_majorite = Bloc::from_bytes(&octets1).expect("bloc 1 décodable");
    assert_eq!(
        bloc1_majorite.vue, 1,
        "la hauteur 1 a été produite en VUE 1 : le producteur de la vue 0 est du côté coupé"
    );

    // Hauteurs 2 et 3, en vue 0 : `producteur_attendu(h, 0) = autorites[(h−1) mod 4]`
    // vaut `autorites[1]` puis `autorites[2]` — toutes deux en majorité.
    majorite_produit(&mut majorite, &mut isolee, t_min_gele, 0, 2);
    majorite_produit(&mut majorite, &mut isolee, t_min_gele, 1, 3);

    let tete_majorite = majorite[0].noeud().etat.tete();
    let racine_majorite = majorite[0].noeud().etat.tree.root();
    for rt in majorite.iter() {
        assert_eq!(rt.noeud().etat.hauteur(), 3, "majorité à la hauteur 3");
        assert_eq!(rt.noeud().etat.tete(), tete_majorite, "même tête");
        assert_eq!(rt.noeud().etat.tree.root(), racine_majorite, "même arbre");
    }
    // Chacun de ces blocs porte un quorum de votants DISTINCTS : le côté majoritaire
    // a conclu par le protocole, pas par autorité solitaire.
    for hauteur in 1..=3u64 {
        let octets = majorite[0]
            .noeud()
            .archive()
            .octets_a(hauteur)
            .expect("bloc archivé");
        let bloc = Bloc::from_bytes(octets).expect("bloc décodable");
        assert!(
            bloc.certificat
                .as_ref()
                .expect("bloc appliqué = bloc CERTIFIÉ")
                .nombre_de_votants()
                >= 3,
            "quorum de 3 votants distincts à la hauteur {hauteur}"
        );
    }

    // ---------- LA MINORITÉ N'AVANCE PAS, ET NE FORKE PAS ----------
    // Elle n'est pas passive : elle est le producteur LÉGITIME de (1, 0). Elle scelle
    // donc pour de bon — signature de scellement, son propre vote, proposition — et
    // n'applique rien : son vote unique reste à 1 sur les 3 exigés.
    let (propose, actions) = isolee
        .noeud_mut()
        .sceller()
        .expect("l'isolée EST le producteur de (1, 0) : elle scelle");
    assert_eq!(propose.hauteur, 1);
    assert_eq!(propose.vue, 0);
    assert_ne!(
        propose.id(),
        bloc1_majorite.id(),
        "ce bloc EST un concurrent de celui de la majorité : appliqué, il ferait une \
         divergence DÉFINITIVE sur un état append-only. C'est bien un fork qui est \
         évité, pas une coïncidence de contenu"
    );
    isolee.executer(actions);
    assert_eq!(
        isolee.noeud().etat.hauteur(),
        0,
        "LA PROPRIÉTÉ : sous quorum, la minorité n'APPLIQUE rien — même quand elle est \
         le producteur légitime du tour"
    );

    // Et le temps ne l'aide pas : ses délais expirent, elle monte de vue, encore rien.
    let mut t_min = 0u64;
    for _ in 0..4 {
        t_min += BOND_MINORITE_MS;
        isolee.pomper(t_min);
        isolee.tick(t_min);
    }
    assert!(
        isolee.noeud().vue_courante() >= 3,
        "les vues de la minorité défilent (obtenu {})",
        isolee.noeud().vue_courante()
    );
    assert_eq!(
        isolee.noeud().etat.hauteur(),
        0,
        "quatre vues plus tard : toujours aucun bloc appliqué"
    );
    assert_eq!(
        isolee.noeud().etat.tete(),
        genese.id(),
        "sa tête est restée la GENÈSE : aucune branche concurrente n'existe"
    );
    for hauteur in 1..=3u64 {
        assert!(
            isolee.noeud().archive().octets_a(hauteur).is_none(),
            "AUCUN bloc concurrent à la hauteur {hauteur} : rien à réconcilier plus tard"
        );
    }
    assert_eq!(
        isolee.liens_ouverts(),
        0,
        "toujours isolée : ce qui précède ne doit rien au réseau"
    );

    // Horloge de la minorité GELÉE à partir d'ici : `debut_vue_ms` vaut `t_min`, donc
    // plus aucun délai n'expire. Le rattrapage qui suit ne doit rien au temps.
    let t_gel = t_min;

    // ---------- GUÉRISON ----------
    // Un lien de plus, dans le sens naturel : c'est celui qui rejoint qui appelle.
    relier(majorite[0], &mut isolee);
    assert_eq!(
        isolee.liens_ouverts(),
        1,
        "la minorité a retrouvé le réseau"
    );

    // La chaîne continue : la hauteur 4 revient à `autorites[3]`, restée en majorité.
    // C'est ce bloc NEUF — relayé par le voisin de l'isolée après application — qui
    // lui apprend son retard. Aucun message n'est fabriqué par le test.
    majorite_produit(&mut majorite, &mut isolee, t_gel, 2, 4);

    // ---------- CONVERGENCE PAR LE CHEMIN NORMAL ----------
    // Bloc en avance refusé → `DemandeBloc{1}` → bloc 1 servi depuis l'archive →
    // appliqué → `DemandeBloc{2}` → … Un bloc par échange, jusqu'à la tête.
    let tete_finale = majorite[0].noeud().etat.tete();
    let racine_finale = majorite[0].noeud().etat.tree.root();
    let converge = attendre(&mut majorite, &mut isolee, t_gel, |_, min| {
        min.noeud().etat.hauteur() == 4
    });
    assert!(
        converge,
        "à la guérison, la minorité doit rattraper par le chemin normal (DemandeBloc), \
         obtenu hauteur {}",
        isolee.noeud().etat.hauteur()
    );
    assert_eq!(
        isolee.noeud().etat.tete(),
        tete_finale,
        "MÊME IDENTIFIANT DE TÊTE que la majorité : la chaîne est UNE"
    );
    assert_eq!(
        isolee.noeud().etat.tree.root(),
        racine_finale,
        "et le MÊME arbre — convergence, pas simple égalité de hauteur"
    );
    assert_eq!(
        isolee.noeud().vue_courante(),
        0,
        "la hauteur a avancé : la vue est remise à 0, la minorité est REDEVENUE \
         participante à part entière"
    );
    for rt in majorite.iter() {
        assert_eq!(
            rt.noeud().etat.tete(),
            tete_finale,
            "la majorité n'a pas bougé pendant le rattrapage"
        );
    }

    for dir in &dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}
