//! `obscura-wallet` — wallet en ligne de commande.
//!
//! ```text
//! obscura-wallet creer        --fichier mon.wallet
//! obscura-wallet adresse      --fichier mon.wallet
//! obscura-wallet synchroniser --fichier mon.wallet --noeud 127.0.0.1:9333
//! obscura-wallet solde        --fichier mon.wallet
//! obscura-wallet envoyer      --fichier mon.wallet --a obs1… --montant 300 --frais 20 \
//!                             --noeud 127.0.0.1:9333 [--noeud-synchro 127.0.0.1:9444]
//! ```
//!
//! # Ce wallet sait RECEVOIR
//!
//! `synchroniser` rejoue l'historique des sorties servi par un nœud : le wallet
//! retrouve les INDEX de ses notes (sans lesquels ni chemin de Merkle ni dépense),
//! découvre les paiements reçus, et récupère sa propre monnaie rendue — qui sort de sa
//! vue à chaque dépense faute d'index et n'y revient que par le rejeu. La boucle demande
//! `hauteur + 1` après chaque bloc vérifié, s'arrête au premier silence, et BORNE son
//! travail par invocation (cf. [`node::client`]).
//!
//! ## ⚠️ Ce que le nœud servant apprend, et ce qu'il peut cacher
//!
//! Le nœud qui sert l'historique voit notre IP, la CADENCE de nos demandes et notre
//! POSITION de chaîne. Il peut aussi MENTIR PAR OMISSION : taire une sortie donne une
//! chaîne parfaitement close dont la racine est celle qu'il annonce, et le paiement omis
//! reste invisible. S'en prémunir exige des identifiants de blocs venus d'AILLEURS
//! (plusieurs nœuds, point de contrôle hors bande) — cf. docs/THREAT_MODEL.md.
//!
//! ⚠️ **Prototype non audité.** Le fichier de wallet contient l'AUTORITÉ DE DÉPENSE,
//! chiffrée au repos sous une phrase de passe (Argon2id + cascade AEAD) — ou EN CLAIR
//! si `OBSCURA_WALLET_SANS_CHIFFREMENT=1` l'a explicitement demandé
//! (cf. `wallet::persistance`).

use crypto::sig::SigKeypair;
use net::connexion::Connexion;
use node::client::{synchroniser_par_connexion, Arret, ResumeSynchro};
use node::message::Message;
use proved_hash::merkle::CONSENSUS_DEPTH;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;
use wallet::Adresse;
use wallet::Wallet;

/// Échéance de lecture d'une connexion de synchronisation : elle DÉFINIT le silence sur
/// lequel la boucle s'arrête (« le nœud n'a plus rien à cette hauteur »). Trop courte,
/// on renoncerait à un nœud lent ; trop longue, le dernier tour ferait attendre pour
/// rien à chaque invocation.
const DELAI_SILENCE: Duration = Duration::from_secs(5);

/// Échéance d'écriture : un pair qui n'absorbe plus nos octets ne doit pas nous figer.
const DELAI_ECRITURE: Duration = Duration::from_secs(20);

/// Cadence minimale entre deux demandes d'historique — le SEUL levier de débit côté
/// client (aucun champ sur le fil ne le porte).
const CADENCE_DEMANDES: Duration = Duration::from_millis(50);


/// Protection du fichier de wallet, résolue UNE SEULE FOIS par invocation.
///
/// La résolution est PARESSEUSE (première utilisation) puis mémorisée : `creer` peut
/// ainsi refuser d'écraser un fichier AVANT toute saisie, et surtout la phrase n'est
/// jamais redemandée en cours de commande. Sans cela, `synchroniser` la redemandait à
/// CHAQUE bloc enregistré — et une frappe différente à mi-course aurait ré-enregistré
/// le wallet sous une AUTRE phrase que celle du début, silencieusement.
struct ProtectionCli(std::cell::OnceCell<wallet::persistance::Protection>);

impl ProtectionCli {
    fn nouvelle() -> Self {
        ProtectionCli(std::cell::OnceCell::new())
    }

    fn get(&self) -> &wallet::persistance::Protection {
        self.0.get_or_init(resoudre_protection)
    }
}

/// Protection du fichier de wallet, résolue SANS valeur par défaut silencieuse.
///
/// 1. `OBSCURA_WALLET_PHRASE` si définie (voie scriptable / CI) ;
/// 2. sinon `OBSCURA_WALLET_SANS_CHIFFREMENT=1` pour écrire EN CLAIR — choix qui doit
///    être posé explicitement, jamais subi ;
/// 3. sinon saisie sur l'entrée standard.
///
/// ⚠️ La saisie est ÉCHOÏQUE : masquer la frappe demande un accès TTY (crate dédiée),
/// volontairement non introduit ici. Sur un poste partagé, préférer la variable.
///
/// Sort du processus plutôt que de propager : sans protection résolue, aucune commande
/// de wallet n'a de sens, et un `Result` remonté ici n'ajouterait qu'du bruit.
fn resoudre_protection() -> wallet::persistance::Protection {
    use wallet::persistance::Protection;
    if let Ok(p) = std::env::var("OBSCURA_WALLET_PHRASE") {
        if !p.is_empty() {
            return Protection::Phrase(p);
        }
    }
    if std::env::var("OBSCURA_WALLET_SANS_CHIFFREMENT").as_deref() == Ok("1") {
        eprintln!("⚠️  wallet NON chiffré au repos (OBSCURA_WALLET_SANS_CHIFFREMENT=1)");
        return Protection::Aucune;
    }
    eprint!("phrase de passe du wallet (la frappe est visible) : ");
    use std::io::Write;
    std::io::stderr().flush().ok();
    let mut ligne = String::new();
    if std::io::stdin().read_line(&mut ligne).is_err() {
        eprintln!("erreur : lecture de la phrase de passe impossible");
        std::process::exit(2);
    }
    let phrase = ligne.trim().to_string();
    if phrase.is_empty() {
        eprintln!(
            "erreur : phrase vide. Définissez OBSCURA_WALLET_PHRASE, ou              OBSCURA_WALLET_SANS_CHIFFREMENT=1 pour écrire en clair."
        );
        std::process::exit(2);
    }
    Protection::Phrase(phrase)
}

fn usage() -> ! {
    eprintln!("usage : obscura-wallet <commande> [options]");
    eprintln!();
    eprintln!("  creer        --fichier <f>                   crée un wallet (refuse d'écraser)");
    eprintln!("  adresse      --fichier <f>                   affiche l'adresse à communiquer");
    eprintln!("  synchroniser --fichier <f> --noeud <ip:port> rejoue l'historique, se met à jour");
    eprintln!("  solde        --fichier <f>                   affiche le solde connu");
    eprintln!("  consolider   --fichier <f> --noeud <ip:port>  regroupe ses notes en une seule");
    eprintln!("  envoyer      --fichier <f> --a <adresse> \\");
    eprintln!("               --montant <n> [--frais <n>] --noeud <ip:port> \\");
    eprintln!("               [--noeud-synchro <ip:port>]");
    std::process::exit(2)
}

/// Sortie en erreur avec un message lisible. Un wallet qui panique laisse
/// l'utilisateur devant un « thread panicked » et aucune idée de la marche à suivre.
fn abandon(message: &str) -> ! {
    eprintln!("erreur : {message}");
    std::process::exit(1)
}

struct Options {
    fichier: Option<PathBuf>,
    destinataire: Option<String>,
    montant: Option<u64>,
    frais: u64,
    noeud: Option<SocketAddr>,
    noeud_synchro: Option<SocketAddr>,
}

fn lire_options(args: &[String]) -> Options {
    let mut o = Options {
        fichier: None,
        destinataire: None,
        montant: None,
        frais: 0,
        noeud: None,
        noeud_synchro: None,
    };
    let mut i = 0;
    while i < args.len() {
        let Some(valeur) = args.get(i + 1) else { usage() };
        match args[i].as_str() {
            "--fichier" => o.fichier = Some(PathBuf::from(valeur)),
            "--a" => o.destinataire = Some(valeur.clone()),
            "--montant" => {
                o.montant = Some(
                    valeur
                        .parse()
                        .unwrap_or_else(|_| abandon(&format!("montant invalide : {valeur}"))),
                )
            }
            "--frais" => {
                o.frais = valeur
                    .parse()
                    .unwrap_or_else(|_| abandon(&format!("frais invalides : {valeur}")))
            }
            "--noeud" => {
                o.noeud = Some(
                    valeur
                        .parse()
                        .unwrap_or_else(|_| abandon(&format!("adresse de nœud invalide : {valeur}"))),
                )
            }
            "--noeud-synchro" => {
                o.noeud_synchro = Some(valeur.parse().unwrap_or_else(|_| {
                    abandon(&format!("adresse de nœud de synchro invalide : {valeur}"))
                }))
            }
            autre => {
                eprintln!("option inconnue : {autre}");
                usage()
            }
        }
        i += 2;
    }
    o
}

fn charger(chemin: &Path, protection: &ProtectionCli) -> Wallet {
    use wallet::persistance::{Protection, WalletFichierError};
    match Wallet::charger(chemin, protection.get()) {
        Ok(w) => w,
        // Fichier EN CLAIR alors qu'une phrase est fournie : jamais lu en silence
        // (un repli implicite permettrait de substituer un wallet en clair à un
        // wallet chiffré sans que rien ne le signale). La migration est un GESTE :
        // `OBSCURA_WALLET_MIGRER=1` relit le clair et réenregistre sous la phrase.
        Err(WalletFichierError::FichierEnClair) => {
            if std::env::var("OBSCURA_WALLET_MIGRER").as_deref() != Ok("1") {
                abandon(&format!(
                    "{} est EN CLAIR alors qu'une phrase de passe est fournie.\n\
                     \x20        Si c'est bien votre wallet d'avant le chiffrement, migrez-le\n\
                     \x20        explicitement : relancez avec OBSCURA_WALLET_MIGRER=1 (il sera\n\
                     \x20        réenregistré chiffré sous votre phrase). Sinon, quelqu'un a\n\
                     \x20        peut-être REMPLACÉ votre fichier : n'allez pas plus loin.",
                    chemin.display()
                ));
            }
            let w = Wallet::charger(chemin, &Protection::Aucune).unwrap_or_else(|e| {
                abandon(&format!("wallet illisible ({}) : {e}", chemin.display()))
            });
            if let Err(e) = w.enregistrer(chemin, protection.get()) {
                abandon(&format!("migration impossible ({}) : {e}", chemin.display()));
            }
            eprintln!("wallet migré : désormais chiffré sous votre phrase de passe.");
            w
        }
        Err(e) => abandon(&format!(
            "wallet illisible ({}) : {e}\n\
             \x20        Ce fichier n'est PAS remplacé automatiquement : un wallet écrasé\n\
             \x20        est irrécupérable. Restaurez une sauvegarde.",
            chemin.display()
        )),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(commande) = args.first().cloned() else { usage() };
    let o = lire_options(&args[1..]);
    let Some(fichier) = o.fichier.clone() else {
        eprintln!("--fichier est obligatoire");
        usage()
    };
    let protection = ProtectionCli::nouvelle();

    match commande.as_str() {
        "creer" => creer(&fichier, &protection),
        "adresse" => println!("{}", charger(&fichier, &protection).adresse().encoder()),
        "synchroniser" => synchroniser(&fichier, &o, &protection),
        "solde" => solde(&fichier, &protection),
        "envoyer" => envoyer(&fichier, &o, &protection),
        "consolider" => consolider(&fichier, &o, &protection),
        _ => usage(),
    }
}

/// Crée un wallet — et REFUSE d'écraser un fichier existant.
///
/// C'est le garde-fou le plus important du binaire : `creer` sur un wallet garni
/// détruirait des fonds sans recours possible. Aucune option ne force l'écrasement,
/// délibérément.
fn creer(fichier: &Path, protection: &ProtectionCli) {
    if fichier.exists() {
        abandon(&format!(
            "{} existe déjà — refus d'écraser un wallet.\n\
             \x20        Si vous voulez vraiment repartir de zéro, déplacez ce fichier\n\
             \x20        vous-même, après vous être assuré qu'il ne contient pas de fonds.",
            fichier.display()
        ));
    }
    let w = Wallet::nouveau(CONSENSUS_DEPTH);
    if let Err(e) = w.enregistrer(fichier, protection.get()) {
        abandon(&format!("écriture impossible : {e}"));
    }
    println!("wallet créé : {}", fichier.display());
    println!();
    println!("adresse à communiquer au payeur :");
    println!("{}", w.adresse().encoder());
    println!();
    match protection.get() {
        wallet::persistance::Protection::Aucune => {
            println!("⚠️  Ce fichier contient l'autorité de dépense, EN CLAIR et non chiffrée.");
            println!("    Sauvegardez-le : il n'existe nulle part ailleurs.");
        }
        wallet::persistance::Protection::Phrase(_) => {
            println!("Ce fichier contient l'autorité de dépense, chiffrée sous votre phrase.");
            println!("⚠️  Sauvegardez-le ET retenez la phrase : sans elle il est illisible,");
            println!("    et il n'existe nulle part ailleurs.");
        }
    }
    println!();
    println!("Un wallet neuf ne connaît encore aucune note : lancez `synchroniser`");
    println!("contre un nœud archiviste pour découvrir les paiements reçus.");
}

fn solde(fichier: &Path, protection: &ProtectionCli) {
    let w = charger(fichier, protection);
    println!("solde connu : {} unités ({} notes)", w.solde(), w.notes().len());
    println!("position de synchronisation : prochaine hauteur {}", w.prochaine_hauteur());
    if w.prochaine_hauteur() == 0 {
        println!(
            "⚠️  Ce wallet n'a JAMAIS été synchronisé : il ne peut pas encore connaître\n\
             \x20   les paiements reçus. Lancez `synchroniser --noeud <ip:port>`."
        );
    } else {
        println!(
            "⚠️  Ce solde est celui du dernier bloc rejoué. Un paiement plus récent\n\
             \x20   n'apparaîtra qu'après une nouvelle `synchroniser`. Et le nœud servant\n\
             \x20   l'historique peut MENTIR PAR OMISSION : un paiement tu reste invisible."
        );
    }
}

/// Ouvre une connexion de transport ÉPHÉMÈRE vers un nœud (identité neuve à chaque
/// commande — une identité stable relierait entre elles toutes nos requêtes).
fn connecter(noeud: SocketAddr, delai_lecture: Duration) -> Connexion<TcpStream> {
    let identite = SigKeypair::generate();
    let flux = TcpStream::connect(noeud)
        .unwrap_or_else(|e| abandon(&format!("connexion à {noeud} impossible : {e}")));
    flux.set_read_timeout(Some(delai_lecture))
        .unwrap_or_else(|e| abandon(&format!("échéance de lecture impossible : {e}")));
    flux.set_write_timeout(Some(DELAI_ECRITURE))
        .unwrap_or_else(|e| abandon(&format!("échéance d'écriture impossible : {e}")));
    Connexion::connecter(flux, &identite)
        .unwrap_or_else(|e| abandon(&format!("handshake post-quantique échoué : {e:?}")))
}

/// Rejoue l'historique auprès d'un nœud jusqu'à être à jour, puis enregistre.
///
/// La boucle vit dans [`node::client`] ; ce qui suit n'est que le câblage : une
/// connexion éphémère, l'enregistrement APRÈS chaque bloc (la position entre dans le
/// fichier 0x02), et le compte rendu.
fn synchroniser(fichier: &Path, o: &Options, protection: &ProtectionCli) {
    let Some(noeud) = o.noeud else {
        eprintln!("--noeud est obligatoire pour synchroniser");
        usage()
    };
    let mut w = charger(fichier, protection);
    let depart = w.prochaine_hauteur();
    println!("synchronisation depuis la hauteur {depart} auprès de {noeud}…");

    let mut connexion = connecter(noeud, DELAI_SILENCE);
    let resume = synchroniser_par_connexion(&mut connexion, &mut w, CADENCE_DEMANDES, |p, w| {
        // Enregistrement APRÈS chaque bloc rejoué : la position est dans le fichier, et
        // un crash entre deux blocs doit laisser le wallet exactement à son dernier bloc,
        // jamais en avance sur le disque.
        w.enregistrer(fichier, protection.get()).map_err(|e| e.to_string())?;
        if p.entrees > 0 || p.notes_recues > 0 {
            println!(
                "  bloc {} : {} sorties, {} pour vous — solde {}",
                p.hauteur, p.entrees, p.notes_recues, p.solde
            );
        }
        Ok(())
    });

    rapporter_synchro(&w, &resume, depart);
}

fn rapporter_synchro(w: &Wallet, resume: &ResumeSynchro, depart: u64) {
    println!();
    println!(
        "{} blocs rejoués (hauteurs {}..{}), {} paiements reçus — solde {}",
        resume.blocs_rejoues,
        depart,
        w.prochaine_hauteur(),
        resume.notes_recues,
        w.solde()
    );
    match &resume.arret {
        Arret::AJour => println!("à jour."),
        Arret::LimiteAtteinte => println!(
            "⚠️  limite de travail atteinte pour cette invocation : relancez\n\
             \x20   `synchroniser` pour continuer."
        ),
        Arret::Incoherent(raison) => abandon(&format!(
            "le nœud a servi une réponse incohérente : {raison}\n\
             \x20        Les blocs déjà rejoués sont enregistrés. Réessayez, au besoin\n\
             \x20        contre un autre nœud."
        )),
        Arret::Persistance(e) => abandon(&format!(
            "enregistrement du wallet impossible : {e}\n\
             \x20        La position en mémoire a avancé mais le fichier ne l'a pas suivie."
        )),
    }
}

fn envoyer(fichier: &Path, o: &Options, protection: &ProtectionCli) {
    let (Some(dest), Some(montant), Some(noeud)) = (&o.destinataire, o.montant, o.noeud) else {
        eprintln!("--a, --montant et --noeud sont obligatoires pour envoyer");
        usage()
    };
    let destinataire = Adresse::decoder(dest).unwrap_or_else(|e| {
        abandon(&format!(
            "adresse du destinataire refusée : {e}\n\
             \x20        Rien n'a été envoyé. Un paiement vers une adresse abîmée serait\n\
             \x20        définitivement perdu — c'est pourquoi le contrôle est fait ici."
        ))
    });

    let mut w = charger(fichier, protection);

    // Synchronisation optionnelle AVANT l'envoi, contre un nœud DISTINCT. C'est le seul
    // câblage qui rend la séparation possible sans deux commandes séparées — et il
    // avertit fort quand les deux nœuds coïncident.
    if let Some(noeud_synchro) = o.noeud_synchro {
        if noeud_synchro == noeud {
            println!(
                "⚠️  --noeud-synchro est ÉGAL à --noeud : le même nœud verra que vous avez\n\
                 \x20   téléchargé l'historique PUIS soumis une transaction, à quelques\n\
                 \x20   secondes d'intervalle. Cela vous DÉSIGNE comme l'émetteur — un relais\n\
                 \x20   Dandelion++ ne vient jamais de se synchroniser. Utilisez deux nœuds\n\
                 \x20   distincts."
            );
        }
        println!("synchronisation préalable auprès de {noeud_synchro}…");
        let mut connexion = connecter(noeud_synchro, DELAI_SILENCE);
        let depart = w.prochaine_hauteur();
        let resume =
            synchroniser_par_connexion(&mut connexion, &mut w, CADENCE_DEMANDES, |_, w| {
                w.enregistrer(fichier, protection.get()).map_err(|e| e.to_string())
            });
        rapporter_synchro(&w, &resume, depart);
    }

    // REFUS si le wallet n'a jamais été synchronisé. Enchaîner une synchro et un envoi
    // depuis la MÊME IP relierait trivialement les deux : `soumettre` fait justement
    // partir la transaction en TIGE Dandelion++ pour qu'un observateur ne distingue pas
    // l'émetteur d'un relais — or un relais ne vient jamais de télécharger l'historique.
    if w.prochaine_hauteur() == 0 {
        abandon(
            "wallet non synchronisé : il ne connaît aucun index de note et ne peut rien\n\
             \x20        prouver. Lancez d'abord `synchroniser`, IDÉALEMENT contre un nœud\n\
             \x20        DIFFÉRENT de celui d'envoi (voir --noeud-synchro) : synchroniser puis\n\
             \x20        envoyer depuis la même IP relie les deux et vous désigne comme\n\
             \x20        l'émetteur.",
        );
    }

    // Avertissement INCONDITIONNEL — pas seulement quand --noeud-synchro == --noeud.
    // Le flux le plus naturel est en DEUX commandes (`synchroniser` puis `envoyer`),
    // et l'outil ne mémorise pas d'une invocation à l'autre quel nœud a servi
    // l'historique : il ne PEUT pas détecter la corrélation, seulement la rappeler.
    // Se taire sur ce chemin laisserait croire que la protection existe.
    println!(
        "⚠️  rappel : si ce nœud (ou son opérateur) a AUSSI servi votre synchronisation,\n\
         \x20   il voit un téléchargement d'historique suivi d'une soumission depuis la\n\
         \x20   même IP — ce qui vous désigne comme l'émetteur, un relais Dandelion++ ne\n\
         \x20   venant jamais de se synchroniser. Synchronisez et envoyez via des nœuds\n\
         \x20   distincts (--noeud-synchro), voire des réseaux distincts."
    );

    println!("construction de la preuve (plusieurs secondes)…");
    let debut = std::time::Instant::now();
    let tx = w
        .construire(&destinataire, montant, o.frais)
        .unwrap_or_else(|e| abandon(&format!("transaction impossible : {e}")));
    println!(
        "preuve générée en {:.1} s ({:.1} Kio) — forme {}-in/{}-out",
        debut.elapsed().as_secs_f64(),
        tx.to_bytes().len() as f64 / 1024.0,
        tx.m(),
        tx.n(),
    );

    let mut connexion = connecter(noeud, DELAI_ECRITURE);

    // On ENVOIE avant d'oublier les notes. L'ordre inverse perdrait des notes jamais
    // dépensées si l'envoi échouait ; dans ce sens-ci, le pire cas est un renvoi que
    // le réseau rejettera comme doublon.
    let octets = Message::Transaction(Box::new(tx)).to_bytes();
    if let Err(e) = connexion.envoyer(&octets) {
        abandon(&format!(
            "envoi échoué : {e:?} — aucune note n'a été marquée comme dépensée"
        ));
    }
    println!("transaction soumise à {noeud}");

    let tx = match Message::from_bytes(&octets) {
        Ok(Message::Transaction(tx)) => tx,
        _ => abandon("réencodage de la transaction impossible (bug interne)"),
    };
    let consommees = w.oublier_depensees(&tx);
    if let Err(e) = w.enregistrer(fichier, protection.get()) {
        abandon(&format!(
            "transaction ENVOYÉE mais wallet non enregistré : {e}\n\
             \x20        Relancer `envoyer` retenterait les mêmes notes."
        ));
    }

    println!("{consommees} notes retirées de la réserve — solde connu : {}", w.solde());
    let monnaie = tx.output_commitments.len().saturating_sub(1);
    if monnaie > 0 {
        println!();
        println!("ℹ️  La MONNAIE RENDUE n'est pas re-créditée immédiatement : son index");
        println!("    dans l'arbre du consensus n'existera qu'une fois la transaction");
        println!("    scellée dans un bloc. Elle REVIENDRA au solde à la prochaine");
        println!("    `synchroniser` — elle est chiffrée vers vous, donc reconnue au scan.");
    }
}

/// `consolider` : regroupe les notes du wallet en UNE seule (M-in/1-out), pour
/// pouvoir ensuite payer un montant qu'aucune paire de notes ne couvrait.
///
/// ⚠️ Produit une forme rare (M/1), donc distinctive au regard d'un observateur —
/// la forme d'une transaction est publique. C'est un geste VOLONTAIRE, dont
/// l'alternative (ne pas pouvoir dépenser) est pire ; l'avertissement le rappelle.
fn consolider(fichier: &Path, o: &Options, protection: &ProtectionCli) {
    let Some(noeud) = o.noeud else {
        eprintln!("--noeud est obligatoire pour consolider");
        usage()
    };
    let mut w = charger(fichier, protection);
    if w.prochaine_hauteur() == 0 {
        abandon("wallet non synchronisé : lancez d'abord `synchroniser`.");
    }
    println!(
        "⚠️  consolider produit une transaction de forme M-in/1-out, plus rare donc
             plus distinctive qu'un paiement 2/2 (la forme est publique). À n'utiliser
             que si vos notes sont trop éparpillées pour payer autrement."
    );
    println!("construction de la preuve (plusieurs secondes)…");
    let tx = w
        .consolider(o.frais)
        .unwrap_or_else(|e| abandon(&format!("consolidation impossible : {e}")));
    println!("preuve générée — forme {}-in/1-out", tx.m());

    let mut connexion = connecter(noeud, DELAI_ECRITURE);
    let octets = Message::Transaction(Box::new(tx)).to_bytes();
    if let Err(e) = connexion.envoyer(&octets) {
        abandon(&format!("envoi échoué : {e:?} — aucune note marquée dépensée"));
    }
    println!("transaction soumise à {noeud}");

    let tx = match Message::from_bytes(&octets) {
        Ok(Message::Transaction(tx)) => tx,
        _ => abandon("réencodage impossible (bug interne)"),
    };
    let consommees = w.oublier_depensees(&tx);
    if let Err(e) = w.enregistrer(fichier, protection.get()) {
        abandon(&format!("transaction ENVOYÉE mais wallet non enregistré : {e}"));
    }
    println!("{consommees} notes regroupées — solde connu : {}", w.solde());
    println!();
    println!("ℹ️  La note consolidée REVIENDRA au solde à la prochaine `synchroniser`");
    println!("    (chiffrée vers vous, reconnue au scan, comme la monnaie rendue).");
}
