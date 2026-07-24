//! `obscura-genese` — fabrique le bloc 0 d'une chaîne Obscura.
//!
//! ```text
//! obscura-genese --sortie genese.bin \
//!     --autorite donnees-a/identite.cle --autorite-hex 01ab... \
//!     --allocation obs1…:1000000
//! ```
//!
//! # Pourquoi un outil, et pas un script
//!
//! La genèse est **l'artefact le moins rattrapable du projet**. Elle fixe la
//! monnaie initiale, la liste des autorités de scellement et la tête de départ ;
//! son identifiant devient l'identité de la chaîne, et deux nœuds amorcés sur des
//! genèses différentes se refusent *tous* leurs blocs — sans que rien ne désigne la
//! cause. La fabriquer par un bout de Rust jetable, c'est accepter qu'un octet de
//! travers devienne définitif.
//!
//! Trois garde-fous, tous délibérés :
//!
//! 1. **Refus d'écraser.** Une genèse remplacée, c'est une chaîne perdue. Aucune
//!    option ne force — comme `obscura-wallet creer`.
//! 2. **Auto-vérification.** Le fichier écrit est RELU, réamorcé, et son
//!    identifiant recalculé. Un artefact que son propre auteur ne sait pas relire
//!    ne doit jamais atteindre un opérateur.
//! 3. **L'identifiant est imprimé pour être COMPARÉ** entre opérateurs, avant tout
//!    démarrage. C'est le seul contrôle qui détecte une chaîne divergente *avant*
//!    qu'elle ne diverge.
//!
//! ⚠️ **Les allocations sont VISIBLES dans la genèse** — pas leurs montants (les
//! notes sont engagées et chiffrées), mais leur NOMBRE l'est, et il est public à
//! jamais. Une allocation unique désigne son bénéficiaire par sa seule position.

use ledger::bloc::{Bloc, MAX_AUTORITES, MAX_EMISSIONS_PAR_BLOC};
use proved_hash::digest::Digest;
use proved_hash::felt::Felt;

/// Borne d'un montant alloué : `2^60`, la borne de range-check du circuit
/// (`RANGE_BITS`). Au-delà, la note existerait dans la genèse mais serait
/// INDÉPENSABLE — aucune preuve ne pourrait l'établir. Refuser ici plutôt que de
/// laisser découvrir le blocage à la première dépense.
const MONTANT_MAX: u64 = 1 << 60;

fn usage() -> ! {
    eprintln!("usage : obscura-genese --sortie <fichier> [options]");
    eprintln!();
    eprintln!("  --sortie <fichier>         fichier de genèse à écrire (obligatoire)");
    eprintln!("  --autorite <identite.cle>  autorité de scellement, depuis un fichier");
    eprintln!("                             d'identité de nœud (répétable)");
    eprintln!("  --autorite-hex <hex>       idem, depuis une clé publique hexadécimale");
    eprintln!("                             (obtenue par : obscura-node --identite)");
    eprintln!("  --allocation <adr>:<n>     alloue <n> unités à l'adresse obs1… (répétable)");
    eprintln!();
    eprintln!("⚠️  SANS --autorite, la chaîne est OUVERTE : n'importe quel nœud peut");
    eprintln!("    sceller. Ordre CONVENU entre participants coopératifs, jamais");
    eprintln!("    DÉFENDU contre un adversaire — testnet local uniquement.");
    eprintln!();
    eprintln!("⚠️  AVEC --autorite, la liste INITIALE entre dans l'identifiant de la chaîne");
    eprintln!("    (l'ancre de genèse ne change jamais). Mais la liste reste");
    eprintln!("    RECONFIGURABLE sur la MÊME chaîne (J1-c : ajout/retrait/remplacement");
    eprintln!("    certifié par le quorum de l'ANCIENNE liste). Et une autorité absente");
    eprintln!("    est CONTOURNÉE par changement de vue (J1-b2) : la chaîne continue.");
    eprintln!();
    eprintln!("⚠️  Le NOMBRE d'allocations est public à jamais. Les montants et les");
    eprintln!("    bénéficiaires ne le sont pas — mais une allocation unique désigne");
    eprintln!("    son bénéficiaire par sa seule position.");
    std::process::exit(2)
}

fn abandon(message: &str) -> ! {
    eprintln!("erreur : {message}");
    std::process::exit(1)
}

/// Lit une clé publique d'autorité, depuis un fichier d'identité de nœud OU depuis
/// une chaîne hexadécimale.
///
/// ⚠️ Un fichier d'identité contient le SECRET du nœud. On n'en extrait que la
/// moitié publique, et on ne la recopie nulle part — mais fournir ce fichier
/// suppose de l'avoir sous la main, donc d'être soi-même l'opérateur du nœud.
/// Pour une fédération, `--autorite-hex` est la bonne voie : chaque opérateur
/// publie sa clé publique (`obscura-node --identite --donnees <rep>`), personne ne
/// transmet son fichier.
fn lire_autorite_fichier(chemin: &str) -> crypto::sig::SigPublicKey {
    let octets = std::fs::read(chemin)
        .unwrap_or_else(|e| abandon(&format!("identité illisible ({chemin}) : {e}")));
    let paire = crypto::sig::SigKeypair::from_bytes_secret(&octets).unwrap_or_else(|e| {
        abandon(&format!(
            "identité indécodable ({chemin}) : {e:?}\n\
             \x20        Un fichier d'une version d'algorithme périmée est refusé par\n\
             \x20        son nom plutôt que réinterprété."
        ))
    });
    paire.public
}

/// L'autre moitié de `obscura-node --identite`, et c'est délibérément le MÊME code
/// (`node::autorite`) : ce qu'un nœud imprime doit être exactement ce qu'on relit
/// ici, sous peine de découvrir la dérive au moment de graver une chaîne.
fn lire_autorite_hex(h: &str) -> crypto::sig::SigPublicKey {
    node::autorite::decoder(h).unwrap_or_else(|e| abandon(&format!("clé d'autorité : {e}")))
}

/// `adresse:montant`. Le séparateur est le DERNIER `:` — une adresse `obs1…` n'en
/// contient pas, mais autant ne pas en dépendre.
fn lire_allocation(arg: &str) -> (wallet::Adresse, u64) {
    let Some((adr, montant)) = arg.rsplit_once(':') else {
        abandon("allocation : forme attendue « obs1…:montant »")
    };
    let adresse = wallet::Adresse::decoder(adr).unwrap_or_else(|e| {
        abandon(&format!(
            "adresse d'allocation refusée : {e}\n\
             \x20        Une allocation vers une adresse abîmée serait DÉFINITIVEMENT\n\
             \x20        perdue : aucun secret ne correspondrait au owner altéré."
        ))
    });
    let montant: u64 = montant
        .trim()
        .parse()
        .unwrap_or_else(|_| abandon(&format!("montant invalide : {montant}")));
    if montant == 0 {
        abandon("montant nul : une allocation de 0 n'alloue rien et occupe une feuille");
    }
    if montant >= MONTANT_MAX {
        abandon(&format!(
            "montant {montant} hors bornes (< 2^60) : la note serait INDÉPENSABLE,\n\
             \x20        aucune preuve ne pourrait l'établir (range-check du circuit)."
        ));
    }
    (adresse, montant)
}

/// Aléa de note (`rho`, `r`) : deux digests tirés d'`OsRng`.
///
/// `rho` entre dans le nullifier et `r` masque le commitment ; les tirer au hasard
/// est ce qui rend deux allocations de même montant vers la même adresse
/// INDISTINGUABLES l'une de l'autre sur la chaîne.
fn digest_aleatoire() -> Digest {
    Digest(core::array::from_fn(|_| loop {
        let mut b = [0u8; 8];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
        // Rejet des valeurs hors du corps : un Felt non canonique serait refusé
        // plus loin, et le rejet est ici gratuit.
        if let Ok(f) = Felt::from_canonical_u64(u64::from_le_bytes(b)) {
            break f;
        }
    }))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut sortie: Option<String> = None;
    let mut autorites: Vec<crypto::sig::SigPublicKey> = Vec::new();
    let mut allocations: Vec<(wallet::Adresse, u64)> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let Some(valeur) = args.get(i + 1) else {
            usage()
        };
        match args[i].as_str() {
            "--sortie" => sortie = Some(valeur.clone()),
            "--autorite" => autorites.push(lire_autorite_fichier(valeur)),
            "--autorite-hex" => autorites.push(lire_autorite_hex(valeur)),
            "--allocation" => allocations.push(lire_allocation(valeur)),
            autre => {
                eprintln!("option inconnue : {autre}");
                usage()
            }
        }
        i += 2;
    }

    let Some(sortie) = sortie else {
        eprintln!("--sortie est obligatoire");
        usage()
    };

    // REFUS D'ÉCRASER, avant tout travail : une genèse remplacée est une chaîne
    // perdue, et aucune option ne force. Même garde-fou que `obscura-wallet creer`.
    if std::path::Path::new(&sortie).exists() {
        abandon(&format!(
            "{sortie} existe déjà — refus d'écraser une genèse.\n\
             \x20        Une genèse remplacée, c'est une chaîne perdue : les nœuds déjà\n\
             \x20        amorcés sur l'ancienne refuseront tous les blocs de la nouvelle.\n\
             \x20        Déplacez ce fichier vous-même si vous savez ce que vous faites."
        ));
    }

    if autorites.len() > MAX_AUTORITES {
        abandon(&format!(
            "{} autorités (borne : {MAX_AUTORITES})",
            autorites.len()
        ));
    }
    if allocations.len() > MAX_EMISSIONS_PAR_BLOC {
        abandon(&format!(
            "{} allocations (borne : {MAX_EMISSIONS_PAR_BLOC})",
            allocations.len()
        ));
    }

    // Émissions : une note par allocation, chiffrée vers son bénéficiaire. Il la
    // découvrira par SCAN, exactement comme un paiement reçu — aucun chemin
    // particulier n'existe pour la genèse.
    let emissions: Vec<_> = allocations
        .iter()
        .map(|(adresse, montant)| {
            let note = circuit::SpendNote {
                value: *montant,
                owner: adresse.owner,
                rho: digest_aleatoire(),
                r: digest_aleatoire(),
            };
            let cm =
                proved_hash::rescue::note_commitment(note.value, &note.owner, &note.rho, &note.r);
            ledger::proved_wallet::emission_vers(&adresse.kem, &cm, &note)
                .unwrap_or_else(|e| abandon(&format!("chiffrement de l'allocation : {e:?}")))
        })
        .collect();

    let genese = Bloc::genese_avec_autorites(emissions, autorites.clone())
        .unwrap_or_else(|e| abandon(&format!("genèse refusée : {e}")));
    let identifiant = genese.id();
    let octets = genese.to_bytes();

    // AUTO-VÉRIFICATION avant écriture : on relit ce qu'on s'apprête à produire, et
    // on l'AMORCE. Un artefact que son propre auteur ne sait pas relire ne doit
    // jamais atteindre un opérateur — il découvrirait le défaut au démarrage, sur
    // une chaîne que d'autres ont peut-être déjà adoptée.
    let relu = Bloc::from_bytes(&octets)
        .unwrap_or_else(|e| abandon(&format!("genèse produite INDÉCODABLE : {e} (bug interne)")));
    if relu.id() != identifiant {
        abandon("identifiant instable après aller-retour (bug interne)");
    }
    let etat = ledger::proved_state::ProvedLedgerState::depuis_genese(&relu)
        .unwrap_or_else(|e| abandon(&format!("genèse INAMORÇABLE : {e} (bug interne)")));

    if let Err(e) = std::fs::write(&sortie, &octets) {
        abandon(&format!("écriture impossible ({sortie}) : {e}"));
    }

    println!("genèse écrite : {sortie} ({} octets)", octets.len());
    println!();
    println!("  identifiant : {}", hex::encode(identifiant));
    println!("  court       : {}", hex::encode(&identifiant[..8]));
    println!("  allocations : {}", genese.emissions.len());
    println!("  autorités   : {}", autorites.len());
    println!(
        "  racine      : {}",
        hex::encode(etat.tree.root().to_bytes())
    );
    println!();
    if autorites.is_empty() {
        println!("⚠️  Chaîne OUVERTE : aucune autorité. N'importe quel nœud lancé avec");
        println!("    --sceller produira des blocs. Ordre convenu, pas défendu.");
    } else {
        println!("Ordre de scellement (tour de rôle par hauteur) :");
        for (rang, pk) in autorites.iter().enumerate() {
            let empreinte = crypto::hash::dual_hash("obscura/genese/autorite/v1", &pk.to_bytes());
            println!("  n° {rang} — {}", hex::encode(&empreinte[..8]));
        }
        println!();
        println!("⚠️  Une autorité absente est CONTOURNÉE par changement de vue (J1-b2) :");
        println!("    passé un délai, les autres passent à la vue suivante, la chaîne continue.");
    }
    println!();
    println!("COMPAREZ l'identifiant COMPLET (128 hex) entre opérateurs AVANT de démarrer.");
    println!("(La forme courte ci-dessus n'est qu'un repère visuel rapide, jamais l'ancre.)");
    println!("Deux nœuds amorcés sur des genèses différentes se refusent tous leurs");
    println!("blocs, et rien dans les messages d'erreur ne désigne la cause.");
}
