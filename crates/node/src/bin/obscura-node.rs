//! `obscura-node` — nœud Obscura autonome.
//!
//! ```text
//! obscura-node --ecoute 127.0.0.1:9333 [--pair 127.0.0.1:9334]...
//! ```
//!
//! L'identité et l'état SURVIVENT aux redémarrages (répertoire `--donnees`) : sans
//! cela les pairs ne reconnaîtraient pas le nœud d'un lancement à l'autre, et un
//! nœud malveillant se blanchirait en redémarrant.
//!
//! ⚠️ **Prototype non audité.** Le mempool, lui, n'est PAS persisté (les
//! transactions en attente sont perdues au redémarrage — sans gravité : elles sont
//! réannoncées par les pairs). Le fichier d'identité contient du matériel de clé
//! EN CLAIR, protégé par les permissions du système de fichiers seulement.

use crypto::sig::SigKeypair;
use node::journal::{Journal, Statut};
use node::orchestration::Noeud;
use node::runtime::Runtime;
use std::net::{SocketAddr, TcpListener};
use std::time::{Duration, Instant};

/// Période de rotation d'époque Dandelion++ (ms). Un successeur trop stable finit
/// par être identifié ; trop volatil, il laisse apprendre la topologie.
const EPOQUE_MS: u64 = 600_000; // 10 min

/// Intervalle d'enregistrement de l'état sur disque (ms).
const SAUVEGARDE_MS: u64 = 30_000;

/// Cadence de scellement par défaut si `--sceller` est demandé sans valeur.
const SCELLEMENT_MS_DEFAUT: u64 = 10_000;

/// Intervalle de la ligne de STATUT (ms).
///
/// 30 s : assez espacé pour ne pas noyer le journal d'un nœud au repos, assez
/// fréquent pour qu'un opérateur voie une dérive avant qu'elle ne devienne une
/// panne. C'est la seule ligne qu'un nœud sain écrit en régime permanent.
const STATUT_MS: u64 = 30_000;

fn usage() -> ! {
    eprintln!("usage : obscura-node --ecoute <adresse> [--pair <adresse>]... [--donnees <rep>]");
    eprintln!();
    eprintln!("  --ecoute  <adresse>  adresse d'écoute (ex. 127.0.0.1:9333)");
    eprintln!("  --pair    <adresse>  pair à contacter (répétable)");
    eprintln!("  --donnees <rep>      répertoire de données (défaut : ./donnees-obscura)");
    eprintln!("  --genese  <fichier>  bloc de genèse (défaut : genèse VIDE, testnet local)");
    eprintln!("  --sceller <ms>       SCELLER des blocs toutes les <ms> (défaut : off)");
    eprintln!("  --archiver           conserver l'HISTORIQUE des sorties (défaut : off)");
    eprintln!("  --identite           IMPRIMER la clé publique de ce nœud, et sortir");
    eprintln!("                       (à publier pour devenir autorité de scellement)");
    eprintln!();
    eprintln!("⚠️  --archiver est un rôle d'OPÉRATEUR, pas une obligation de consensus.");
    eprintln!("    Un nœud qui ne l'active pas est parfaitement valide — il ne peut");
    eprintln!("    simplement pas amorcer de wallet. Le coût est réel : ≈1,4 Kio par");
    eprintln!("    sortie, soit ≈1,4 Mio par bloc plein, et l'archive n'est jamais");
    eprintln!("    élaguée. Elle doit être activée DÈS L'AMORÇAGE : rien ne sait");
    eprintln!("    reconstruire un préfixe manquant.");
    eprintln!();
    eprintln!("⚠️  La genèse fixe la monnaie initiale ET la tête de départ. Deux nœuds");
    eprintln!("    amorcés sur des genèses différentes se refusent tous leurs blocs.");
    eprintln!("    L'identifiant imprimé au démarrage est fait pour être COMPARÉ.");
    eprintln!();
    eprintln!("⚠️  --sceller : sur une chaîne dont la genèse déclare des AUTORITÉS, le");
    eprintln!("    nœud ne scelle qu'à SON tour (tour de rôle par hauteur, bloc signé,");
    eprintln!("    équivocation = faute prouvable). Sur une chaîne OUVERTE (genèse sans");
    eprintln!("    autorités, le défaut), tout nœud qui l'active fabrique des blocs :");
    eprintln!("    ordre CONVENU, pas DÉFENDU — testnet local uniquement.");
    eprintln!("    ⚠️  LIVENESS (option A assumée) : une autorité absente FIGE la chaîne");
    eprintln!("    à son tour ; les transactions attendent au mempool, rien n'est perdu.");
    std::process::exit(2)
}

fn main() {
    // Journal d'abord : tout ce qui suit doit pouvoir écrire, et le niveau doit
    // être appliqué avant la première ligne — pas après.
    let journal = Journal::demarrer();
    let (_niveau, valeur_invalide) = node::journal::depuis_environnement();
    if let Some(v) = valeur_invalide {
        // Une faute de frappe dans OBSCURA_LOG ne doit pas faire TAIRE le nœud :
        // on retombe sur INFO et on le dit, plutôt que de laisser l'opérateur
        // croire à un filtre qui ne s'applique pas.
        journal.avert(&format!(
            "OBSCURA_LOG=« {v} » n'est pas un niveau connu (erreur|avert|info|debug) \
             — niveau INFO appliqué"
        ));
    }

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut ecoute: Option<SocketAddr> = None;
    let mut pairs: Vec<SocketAddr> = Vec::new();
    let mut donnees = String::from("./donnees-obscura");
    let mut genese_fichier: Option<String> = None;
    // Scellement DÉSACTIVÉ par défaut : produire des blocs est une décision
    // d'opérateur, pas un comportement qu'un nœud adopte de lui-même.
    let mut sceller_ms: Option<u64> = None;
    // Archivage DÉSACTIVÉ par défaut, pour la même raison : conserver l'historique
    // des sorties est un rôle d'opérateur, à un coût qui croît sans borne.
    let mut archiver = false;
    // Interrogation, pas démarrage : on imprime la clé publique et on sort. Sans
    // elle, `obscura-genese --autorite-hex` — la voie recommandée pour monter une
    // fédération, celle où personne ne transmet son fichier d'identité — n'avait
    // aucune source d'entrée.
    let mut imprimer_identite = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--archiver" => {
                archiver = true;
                i += 1;
            }
            "--identite" => {
                imprimer_identite = true;
                i += 1;
            }
            "--donnees" => {
                let Some(v) = args.get(i + 1) else { usage() };
                donnees = v.clone();
                i += 2;
            }
            "--genese" => {
                let Some(v) = args.get(i + 1) else { usage() };
                genese_fichier = Some(v.clone());
                i += 2;
            }
            "--sceller" => {
                let Some(v) = args.get(i + 1) else { usage() };
                let Ok(ms) = v.parse::<u64>() else {
                    eprintln!("cadence de scellement invalide : {v}");
                    std::process::exit(2);
                };
                sceller_ms = Some(if ms == 0 { SCELLEMENT_MS_DEFAUT } else { ms });
                i += 2;
            }
            "--ecoute" | "--pair" => {
                let Some(valeur) = args.get(i + 1) else {
                    usage()
                };
                let Ok(adresse) = valeur.parse::<SocketAddr>() else {
                    eprintln!("adresse invalide : {valeur}");
                    std::process::exit(2);
                };
                if args[i] == "--ecoute" {
                    ecoute = Some(adresse);
                } else {
                    pairs.push(adresse);
                }
                i += 2;
            }
            _ => usage(),
        }
    }
    // `--identite` court-circuite TOUT le démarrage : pas de genèse, pas d'état, pas
    // de socket. C'est une interrogation, et elle doit répondre à un opérateur qui
    // n'a encore ni chaîne ni pairs — c'est justement l'ordre des choses, puisque sa
    // clé doit être connue AVANT que la genèse ne soit fabriquée.
    if imprimer_identite {
        let stockage = match node::persistance::Donnees::ouvrir(&donnees) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("répertoire de données inutilisable ({donnees}) : {e}");
                std::process::exit(1);
            }
        };
        let (identite, neuve) = match stockage.charger_ou_creer_identite() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("identité illisible : {e}");
                std::process::exit(1);
            }
        };
        if neuve {
            eprintln!("identité CRÉÉE dans {donnees} — c'est désormais celle de ce nœud.");
        }
        eprintln!("clé publique à publier (--autorite-hex de obscura-genese) :");
        // La clé seule sur stdout : elle doit pouvoir se rediriger vers un fichier
        // sans emporter de prose. Tout le reste part sur stderr.
        println!("{}", node::autorite::encoder(&identite.public));
        eprintln!();
        eprintln!("⚠️  Cette clé n'a de valeur d'autorité que si le fichier d'identité");
        eprintln!("    ({donnees}/identite.cle) SURVIT : le perdre, c'est perdre le");
        eprintln!("    tour de scellement, et la liste des autorités est figée dans");
        eprintln!("    l'identifiant de la chaîne — elle ne se corrige pas.");
        return;
    }

    let Some(adresse_ecoute) = ecoute else {
        usage()
    };

    // GENÈSE d'abord, AVANT de toucher au répertoire de données : un démarrage qui
    // échoue ici ne doit rien laisser derrière lui (une identité créée pour un nœud
    // qui n'a jamais démarré).
    //
    // Elle fixe la monnaie initiale ET la tête de départ. Un nœud amorcé sur
    // la mauvaise genèse est indiscernable d'un nœud neuf en bonne santé — il refuse
    // tout bloc en silence et reste à la hauteur 0. D'où : échec FRANC si le fichier
    // demandé manque, et affichage explicite quand on retombe sur le défaut.
    let genese = match &genese_fichier {
        Some(chemin) => match node::persistance::charger_genese(chemin) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("genèse illisible ({chemin}) : {e}");
                eprintln!("aucun repli n'est tenté : un nœud amorcé sur la mauvaise");
                eprintln!("genèse refuse tous les blocs sans que rien ne le dise.");
                std::process::exit(1);
            }
        },
        None => {
            journal.avert(
                "aucune --genese : GENÈSE VIDE par défaut (testnet local) — \
                 aucune monnaie n'existe sur cette chaîne",
            );
            ledger::bloc::Bloc::genese()
        }
    };
    let id_genese = genese.id();

    // Identité et état RECHARGÉS s'ils existent — c'est ce qui fait qu'un nœud reste
    // le même pair d'un lancement à l'autre.
    let stockage = match node::persistance::Donnees::ouvrir(&donnees) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("répertoire de données inutilisable ({donnees}) : {e}");
            std::process::exit(1);
        }
    };
    let (identite, neuve) = match stockage.charger_ou_creer_identite() {
        Ok(v) => v,
        Err(e) => {
            // On NE régénère PAS en silence : perdre son identité doit être une
            // décision de l'opérateur, pas un effet de bord d'un fichier corrompu.
            eprintln!("identité illisible : {e}");
            eprintln!("supprimez le fichier pour en générer une nouvelle (le nœud");
            eprintln!("changera alors de pair aux yeux du réseau).");
            std::process::exit(1);
        }
    };
    // Chargement de l'état. Avec `--archiver`, on tente d'ADOPTER l'archive et, si elle
    // manque ou ne concorde pas, on tombe en mode DÉGRADÉ — bruyamment, et sans rien
    // réparer. Servir un historique qu'on n'a pas pu corroborer serait pire que de ne
    // rien servir : un wallet en tirerait des index faux sans qu'aucune erreur ne le
    // dise, et sa monnaie deviendrait invisible.
    let etat = if archiver {
        match stockage.charger_ou_amorcer_archive(&genese) {
            Ok(e) => {
                journal.info(&format!(
                    "archivage ACTIVÉ — {} sorties conservées (≈{} Kio)",
                    e.historique().map(|h| h.len()).unwrap_or(0),
                    e.historique().map(|h| h.octets() / 1024).unwrap_or(0)
                ));
                e
            }
            Err(err) => {
                journal.erreur(&format!("ARCHIVE INUTILISABLE : {err}"));
                journal.erreur(
                    "le nœud démarre en mode DÉGRADÉ, SANS archive : il reste \
                     parfaitement valide mais ne peut plus amorcer de wallet. \
                     Aucun fichier n'a été tronqué ni effacé.",
                );
                match stockage.charger_ou_amorcer_etat(&genese) {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("état illisible ou genèse inapplicable : {e}");
                        std::process::exit(1);
                    }
                }
            }
        }
    } else {
        match stockage.charger_ou_amorcer_etat(&genese) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("état illisible ou genèse inapplicable : {e}");
                std::process::exit(1);
            }
        }
    };
    journal.info(&format!(
        "identité {} — chaîne à la hauteur {} ({} notes)",
        if neuve { "CRÉÉE" } else { "rechargée" },
        etat.hauteur(),
        etat.tree.len()
    ));
    // Une LIGNE à comparer entre opérateurs. Elle vaut mieux qu'un diagnostic
    // a posteriori sur « pourquoi mes blocs sont refusés ».
    journal.info(&format!(
        "genèse {} ({} émissions) — tête courante {}",
        hex::encode(&id_genese[..8]),
        genese.emissions.len(),
        hex::encode(&etat.tete()[..8])
    ));
    // ÉLECTION DE PRODUCTEUR : sur une chaîne à autorités, dire tout de suite qui
    // nous sommes — découvrir au premier tour de scellement qu'on n'est pas
    // autorité serait un silence inexplicable.
    let notre_rang = etat
        .autorites()
        .iter()
        .position(|pk| pk.to_bytes() == identite.public.to_bytes());
    if !etat.autorites().is_empty() {
        match notre_rang {
            Some(i) => journal.info(&format!(
                "chaîne à {} autorités — cette identité est l'autorité n° {i}",
                etat.autorites().len()
            )),
            None => journal.avert(&format!(
                "chaîne à {} autorités — cette identité N'EN EST PAS une",
                etat.autorites().len()
            )),
        }
    }
    match sceller_ms {
        Some(ms) => {
            journal.info(&format!("scellement ACTIVÉ toutes les {ms} ms"));
            if etat.autorites().is_empty() {
                journal.avert(
                    "chaîne OUVERTE, aucune élection de producteur : ordre convenu, pas défendu",
                );
            } else if notre_rang.is_none() {
                // AVERT et non INFO : l'opérateur a demandé quelque chose que le nœud
                // ne fera JAMAIS. Le dire en INFO le laisserait attendre des blocs qui
                // ne viendront pas.
                journal.avert(
                    "--sceller sans être autorité : AUCUN bloc ne sera produit (le nœud refuse \
                     de sceller hors de son tour, et il n'a pas de tour)",
                );
            } else {
                journal.info("élection par tour de rôle : ce nœud ne scelle qu'à son tour");
            }
        }
        None => journal.info("scellement désactivé (--sceller <ms> pour l'activer)"),
    }

    let mut secret_dandelion = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut secret_dandelion);

    // Le Noeud reçoit l'identité PERSISTANTE (recopiée), pas une identité jetable :
    // c'est elle qui signe les scellements, et une autorité qui signerait d'une clé
    // neuve à chaque démarrage ne serait jamais reconnue.
    let identite_noeud = match SigKeypair::from_bytes_secret(&identite.to_bytes_secret()) {
        Ok(k) => k,
        Err(_) => {
            eprintln!("recopie de l'identité impossible (bug interne)");
            std::process::exit(1);
        }
    };
    let mut rt = Runtime::new(Noeud::new(identite_noeud, etat, secret_dandelion));

    let listener = match TcpListener::bind(adresse_ecoute) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("écoute impossible sur {adresse_ecoute} : {e}");
            std::process::exit(1);
        }
    };
    // Non bloquant : la boucle doit pouvoir traiter les messages même sans nouvelle
    // connexion entrante — sinon le nœud se fige en attendant un visiteur.
    if let Err(e) = listener.set_nonblocking(true) {
        eprintln!("mode non bloquant indisponible : {e}");
        std::process::exit(1);
    }
    journal.info(&format!("écoute sur {adresse_ecoute}"));

    for p in &pairs {
        match rt.connecter(*p, &identite) {
            Ok(_) => journal.info(&format!("connecté à {p}")),
            Err(e) => journal.avert(&format!("échec de connexion à {p} : {e}")),
        }
    }

    let depart = Instant::now();
    let mut derniere_epoque = u64::MAX;
    let mut derniere_sauvegarde = 0u64;
    let mut dernier_scellement = 0u64;
    let mut dernier_statut = 0u64;
    loop {
        let maintenant = depart.elapsed().as_millis() as u64;

        // Rotation d'époque Dandelion++ : re-choisit le successeur de tige.
        let epoque = maintenant / EPOQUE_MS;
        if epoque != derniere_epoque {
            derniere_epoque = epoque;
            let table = std::mem::take(&mut rt.noeud_mut().pairs);
            rt.noeud_mut().dandelion.nouvelle_epoque(epoque, &table);
            rt.noeud_mut().pairs = table;
        }

        // Connexions entrantes (non bloquant).
        match listener.accept() {
            Ok((flux, distant)) => match rt.accepter(flux, &identite) {
                Ok(_) => journal.info(&format!("connexion entrante de {distant}")),
                Err(e) => journal.avert(&format!("handshake échoué avec {distant} : {e}")),
            },
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => journal.avert(&format!("accept : {e}")),
        }

        rt.pomper(maintenant);
        rt.tick(maintenant);

        // Scellement : ce qui rend les transactions DÉFINITIVES. Sans lui, le mempool
        // ne se vide jamais et rien n'entre dans l'arbre.
        if let Some(cadence) = sceller_ms {
            if maintenant.saturating_sub(dernier_scellement) >= cadence {
                dernier_scellement = maintenant;
                if let Some((bloc, actions)) = rt.noeud_mut().sceller() {
                    journal.info(&format!(
                        "bloc {} scellé à la hauteur {} ({} transactions)",
                        hex::encode(&bloc.id()[..8]),
                        bloc.hauteur,
                        bloc.transactions.len()
                    ));
                    rt.executer(actions);
                }
            }
        }

        // STATUT : la ligne qu'un opérateur surveille. Un nœud isolé (aucun lien)
        // ou qui décroche (blocs refusés pour chaînage) passe en AVERT — sans quoi
        // il resterait indiscernable d'un nœud au repos, en servant un historique
        // cohérent mais tronqué.
        if maintenant.saturating_sub(dernier_statut) >= STATUT_MS {
            dernier_statut = maintenant;
            let statut = Statut {
                hauteur: rt.noeud().etat.hauteur(),
                pairs: rt.noeud().pairs.len(),
                liens: rt.liens_ouverts(),
                mempool: rt.noeud().mempool.len(),
                desaccords: rt.noeud().blocs_desaccordes(),
            };
            if statut.preoccupant() {
                journal.avert(&statut.ligne());
            } else {
                journal.info(&statut.ligne());
            }
        }

        // Sauvegarde périodique de l'état (écriture atomique : un arrêt brutal
        // laisse la version précédente intacte, jamais un fichier à moitié écrit).
        if maintenant.saturating_sub(derniere_sauvegarde) >= SAUVEGARDE_MS {
            derniere_sauvegarde = maintenant;
            if let Err(e) = stockage.enregistrer_etat(&rt.noeud().etat) {
                // ERREUR et non AVERT : un état non sauvegardé signifie que le
                // prochain redémarrage repartira d'un point ANTÉRIEUR.
                journal.erreur(&format!("sauvegarde de l'état impossible : {e}"));
            }
        }

        // Le protocole est piloté par les événements ; sans cette pause la boucle
        // consommerait un cœur entier à ne rien faire.
        std::thread::sleep(Duration::from_millis(10));
    }
}
