//! `obscura-wallet` — wallet en ligne de commande.
//!
//! ```text
//! obscura-wallet creer   --fichier mon.wallet
//! obscura-wallet adresse --fichier mon.wallet
//! obscura-wallet solde   --fichier mon.wallet
//! obscura-wallet envoyer --fichier mon.wallet --a obs1… --montant 300 --frais 20 \
//!                        --noeud 127.0.0.1:9333
//! ```
//!
//! # Ce que ce wallet ne sait PAS encore faire : RECEVOIR
//!
//! Un wallet doit rejouer, dans l'ordre, tous les commitments insérés dans l'arbre
//! du consensus : c'est ce qui lui donne les index et les chemins de Merkle qu'exigent
//! ses preuves de dépense. Or aucun nœud ne sert aujourd'hui cet historique — il n'en
//! conserve pas (`MerkleFrontier` = bord droit seulement), et rien ne l'applique :
//! `ProvedLedgerState::apply_proved_tx` existe et est testé, mais AUCUN chemin du
//! nœud ne l'appelle. Les transactions s'accumulent dans le mempool sans jamais être
//! finalisées.
//!
//! Conséquences concrètes, à ne pas découvrir en route :
//!
//! - `solde` ne montre que ce que ce fichier a déjà observé, jamais un paiement reçu ;
//! - `envoyer` soumet bien la transaction, mais la MONNAIE RENDUE disparaît de la vue
//!   du wallet : sa note existe, son INDEX dans l'arbre n'existera qu'une fois la
//!   transaction appliquée, et rien ne le rapporte.
//!
//! Ce n'est pas un défaut de ce binaire : il manque au protocole une notion de
//! FINALITÉ (ordre convenu entre nœuds) et un moyen pour un wallet de rejouer
//! l'historique. La commande `envoyer` le dit à l'utilisateur au lieu de le laisser
//! le déduire d'un solde qui a fondu.
//!
//! ⚠️ **Prototype non audité.** Le fichier de wallet contient l'AUTORITÉ DE DÉPENSE
//! en clair (cf. `wallet::persistance`).

use crypto::sig::SigKeypair;
use net::connexion::Connexion;
use node::message::Message;
use proved_hash::merkle::CONSENSUS_DEPTH;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use wallet::Adresse;
use wallet::Wallet;

fn usage() -> ! {
    eprintln!("usage : obscura-wallet <commande> [options]");
    eprintln!();
    eprintln!("  creer   --fichier <f>                     crée un wallet (refuse d'écraser)");
    eprintln!("  adresse --fichier <f>                     affiche l'adresse à communiquer");
    eprintln!("  solde   --fichier <f>                     affiche le solde observé");
    eprintln!("  envoyer --fichier <f> --a <adresse> \\");
    eprintln!("          --montant <n> [--frais <n>] --noeud <ip:port>");
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
}

fn lire_options(args: &[String]) -> Options {
    let mut o = Options {
        fichier: None,
        destinataire: None,
        montant: None,
        frais: 0,
        noeud: None,
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
            autre => {
                eprintln!("option inconnue : {autre}");
                usage()
            }
        }
        i += 2;
    }
    o
}

fn charger(chemin: &Path) -> Wallet {
    Wallet::charger(chemin).unwrap_or_else(|e| {
        abandon(&format!(
            "wallet illisible ({}) : {e}\n\
             \x20        Ce fichier n'est PAS remplacé automatiquement : un wallet écrasé\n\
             \x20        est irrécupérable. Restaurez une sauvegarde.",
            chemin.display()
        ))
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(commande) = args.first().cloned() else { usage() };
    let o = lire_options(&args[1..]);
    let Some(fichier) = o.fichier.clone() else {
        eprintln!("--fichier est obligatoire");
        usage()
    };

    match commande.as_str() {
        "creer" => creer(&fichier),
        "adresse" => println!("{}", charger(&fichier).adresse().encoder()),
        "solde" => solde(&fichier),
        "envoyer" => envoyer(&fichier, &o),
        _ => usage(),
    }
}

/// Crée un wallet — et REFUSE d'écraser un fichier existant.
///
/// C'est le garde-fou le plus important du binaire : `creer` sur un wallet garni
/// détruirait des fonds sans recours possible. Aucune option ne force l'écrasement,
/// délibérément.
fn creer(fichier: &Path) {
    if fichier.exists() {
        abandon(&format!(
            "{} existe déjà — refus d'écraser un wallet.\n\
             \x20        Si vous voulez vraiment repartir de zéro, déplacez ce fichier\n\
             \x20        vous-même, après vous être assuré qu'il ne contient pas de fonds.",
            fichier.display()
        ));
    }
    let w = Wallet::nouveau(CONSENSUS_DEPTH);
    if let Err(e) = w.enregistrer(fichier) {
        abandon(&format!("écriture impossible : {e}"));
    }
    println!("wallet créé : {}", fichier.display());
    println!();
    println!("adresse à communiquer au payeur :");
    println!("{}", w.adresse().encoder());
    println!();
    println!("⚠️  Ce fichier contient l'autorité de dépense, EN CLAIR et non chiffrée.");
    println!("    Sauvegardez-le : il n'existe nulle part ailleurs.");
}

fn solde(fichier: &Path) {
    let w = charger(fichier);
    println!("solde observé : {} unités ({} notes)", w.solde(), w.notes().len());
    println!(
        "⚠️  « observé » au sens strict : ce wallet ne peut pas encore apprendre les\n\
         \x20   paiements reçus (aucun nœud ne sert l'historique des commitments)."
    );
}

fn envoyer(fichier: &Path, o: &Options) {
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

    let mut w = charger(fichier);
    println!("construction de la preuve (plusieurs secondes)…");
    let debut = std::time::Instant::now();
    let tx = w
        .construire(&destinataire, montant, o.frais)
        .unwrap_or_else(|e| abandon(&format!("transaction impossible : {e}")));
    println!(
        "preuve générée en {:.1} s ({:.1} Kio)",
        debut.elapsed().as_secs_f64(),
        tx.to_bytes().len() as f64 / 1024.0
    );

    // Identité de transport ÉPHÉMÈRE : une identité stable permettrait au nœud de
    // relier entre elles toutes les soumissions de ce wallet — la même raison qui
    // fait tirer une clé d'intention neuve par transaction.
    let identite = SigKeypair::generate();
    let flux = TcpStream::connect(noeud)
        .unwrap_or_else(|e| abandon(&format!("connexion à {noeud} impossible : {e}")));
    let mut connexion = Connexion::connecter(flux, &identite)
        .unwrap_or_else(|e| abandon(&format!("handshake post-quantique échoué : {e:?}")));

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
    if let Err(e) = w.enregistrer(fichier) {
        abandon(&format!(
            "transaction ENVOYÉE mais wallet non enregistré : {e}\n\
             \x20        Relancer `envoyer` retenterait les mêmes notes."
        ));
    }

    println!("{consommees} notes retirées de la réserve — solde observé : {}", w.solde());
    let monnaie = tx.output_commitments.len().saturating_sub(1);
    if monnaie > 0 {
        println!();
        println!("⚠️  La MONNAIE RENDUE n'est pas re-créditée à ce solde.");
        println!("    Elle existe dans la transaction, mais son index dans l'arbre du");
        println!("    consensus n'existera qu'une fois la transaction appliquée — et rien");
        println!("    ne le rapporte au wallet aujourd'hui. Tant que la synchronisation");
        println!("    wallet ↔ nœud n'existe pas, dépenser fait perdre la monnaie de vue.");
    }
}
