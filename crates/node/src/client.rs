//! Boucle de SYNCHRONISATION d'un wallet, côté client.
//!
//! Le nœud CONSERVE l'historique des sorties ([`ledger::historique`]) et le SERT sur le
//! fil ([`crate::synchro`], [`crate::orchestration`]) ; le wallet REJOUE un bloc à la
//! fois ([`wallet::synchro`]). Il manquait la BOUCLE : demander une hauteur, rassembler
//! ses morceaux, la rejouer, avancer — jusqu'au premier silence. Ce module est cette
//! boucle, et rien d'autre.
//!
//! # Ce que la boucle envoie, et ce qu'elle NE fait pas
//!
//! Elle émet `Message::DemandeHistorique { hauteur: w.prochaine_hauteur() }` et **rien
//! d'autre** : pas de `max`, pas de plage, aucun champ choisi par le client. Un tel
//! champ serait une empreinte qui survit à l'identité de transport éphémère (cf.
//! docs/THREAT_MODEL.md). Le seul levier de débit est la FRÉQUENCE des demandes —
//! `cadence`, appliquée ici, jamais un champ sur le fil.
//!
//! # Elle n'avance QU'APRÈS un bloc rejoué, et s'arrête au premier silence
//!
//! La position (`prochaine_hauteur`) n'appartient qu'au wallet, et n'avance que sur un
//! `Statut::Applique`. La boucle ne consulte JAMAIS `hauteur_tete` — que le wallet ne
//! voit même pas : un nœud qui annonce une tête gonflée ne peut au pire que provoquer
//! une demande à laquelle il ne répond pas, donc un silence, donc un arrêt.
//!
//! `DejaApplique` n'est PAS un progrès : un nœud qui redélivre le passé ferait tourner
//! la boucle sans fin si on comptait ce cas comme un pas. On s'arrête.
//!
//! # Le travail est BORNÉ par invocation
//!
//! Une boucle qui suit aveuglément un nœud servant une chaîne sans fin (blocs vides à
//! l'infini) ne rendrait jamais la main. [`MAX_BLOCS_PAR_INVOCATION`] plafonne le
//! nombre de blocs rejoués en un appel : au-delà, la boucle S'ARRÊTE en le disant
//! ([`Arret::LimiteAtteinte`]) plutôt que de tourner. L'utilisateur relance pour
//! continuer — un abandon nommé, pas une boucle infinie.

use crate::message::Message;
use net::connexion::Connexion;
use std::io::{Read, Write};
use std::time::Duration;
use wallet::synchro::{MorceauHistorique, Progression, Statut};
use wallet::Wallet;

/// Nombre maximal de blocs rejoués en UNE invocation.
///
/// Ce n'est pas une limite de la chaîne mais une limite du TRAVAIL qu'on accepte de
/// faire sans rendre la main : un nœud hostile peut servir des blocs vides à l'infini,
/// chacun `Applique`, chacun déclenchant une écriture disque. Sans ce plafond, la
/// commande ne se terminerait jamais.
pub const MAX_BLOCS_PAR_INVOCATION: u64 = 100_000;

/// Nombre maximal de morceaux qu'on accepte d'attendre pour UN bloc.
///
/// `morceaux` est déterminé canoniquement par la plage du bloc et vérifié au décodage
/// ([`crate::synchro`]) ; mais avant même de rejouer, la collecte réserve un tampon de
/// cette taille. Un bloc plein en tient 2 aux paramètres de consensus — ce plafond, très
/// large, ne borne que l'aberration : un nœud annonçant des millions de morceaux.
/// Un bloc de consensus est plafonné à `MAX_TX_PAR_BLOC × 2` sorties (1 024), soit AU
/// PLUS 2 morceaux de `MAX_SORTIES_PAR_REPONSE` (≈739) — plus la genèse, du même
/// ordre. La borne laisse une marge de 4×, pas de 2000× : la version initiale (4 096)
/// « ne bornait que l'aberration », mais l'aberration qu'elle laissait passer était
/// précisément une réservation de ~4 Gio de RAM chez le wallet, décidée par le nœud
/// interrogé — que le modèle de menace traite comme hostile. À ~1 Mio par cadre, 8
/// morceaux plafonnent le tampon de collecte à ~8 Mio.
pub const MAX_MORCEAUX_PAR_BLOC: u32 = 8;

// La borne doit laisser passer un bloc PLEIN (sinon un wallet honnête ne peut plus se
// synchroniser sur une chaîne chargée) : consigné à la compilation.
const _: () = assert!(
    (MAX_MORCEAUX_PAR_BLOC as usize) * crate::synchro::MAX_SORTIES_PAR_REPONSE
        >= ledger::bloc::MAX_TX_PAR_BLOC * 2
);

/// Pourquoi la boucle s'est arrêtée.
///
/// La distinction compte : un wallet à jour, un travail plafonné, un nœud incohérent et
/// un échec d'enregistrement demandent des suites différentes, et les confondre sous un
/// « fini » muet cacherait un nœud fautif ou une perte de position.
#[derive(Debug)]
pub enum Arret {
    /// Silence après une demande : le nœud n'a plus rien à servir à cette hauteur. Le
    /// cas normal d'un wallet à jour — mais aussi celui d'un nœud qui ment par omission
    /// (indétectable auprès d'un nœud unique, cf. docs/THREAT_MODEL.md).
    AJour,
    /// [`MAX_BLOCS_PAR_INVOCATION`] atteint : relancer pour continuer.
    LimiteAtteinte,
    /// Le nœud a servi une réponse incohérente (mauvaise hauteur, morceaux hors bornes,
    /// racine en désaccord, message inattendu). Le lot n'a rien appliqué.
    Incoherent(String),
    /// L'enregistrement du wallet a échoué APRÈS un bloc rejoué. La position en mémoire
    /// a avancé mais le fichier ne l'a pas suivie : à signaler, jamais à taire.
    Persistance(String),
}

/// Résultat d'une invocation de la boucle.
pub struct ResumeSynchro {
    /// Blocs réellement rejoués (statut `Applique`).
    pub blocs_rejoues: u64,
    /// Sorties totales insérées dans l'arbre du wallet.
    pub entrees: u64,
    /// Notes reconnues comme nôtres sur l'ensemble des blocs.
    pub notes_recues: usize,
    /// Pourquoi la boucle s'est arrêtée.
    pub arret: Arret,
}

/// Rejoue l'historique tant que le nœud en sert, en enregistrant après chaque bloc.
///
/// `apres_bloc` est appelé APRÈS chaque bloc `Applique`, avec la progression et le
/// wallet à jour : le binaire y enregistre le fichier et affiche la ligne. Une erreur
/// rendue par `apres_bloc` (enregistrement impossible) arrête la boucle proprement —
/// continuer écrirait des blocs de plus sans jamais retenir la position sur disque.
///
/// La `Connexion` est générique sur `Read + Write` : la boucle est donc exerçable sur un
/// tuyau mémoire comme sur une vraie socket. C'est le stream sous-jacent qui porte
/// l'échéance de lecture définissant le SILENCE — la boucle, elle, se contente de
/// traiter une erreur de réception comme « plus rien à recevoir ».
pub fn synchroniser_par_connexion<S, P>(
    connexion: &mut Connexion<S>,
    wallet: &mut Wallet,
    cadence: Duration,
    mut apres_bloc: P,
) -> ResumeSynchro
where
    S: Read + Write,
    P: FnMut(&Progression, &Wallet) -> Result<(), String>,
{
    let mut resume = ResumeSynchro {
        blocs_rejoues: 0,
        entrees: 0,
        notes_recues: 0,
        arret: Arret::AJour,
    };

    for _ in 0..MAX_BLOCS_PAR_INVOCATION {
        let hauteur = wallet.prochaine_hauteur();

        // Un seul champ sur le fil : la position. Un envoi qui échoue = lien coupé =
        // plus rien à recevoir ; c'est terminal et borné, on s'arrête à jour.
        if connexion
            .envoyer(&Message::DemandeHistorique { hauteur }.to_bytes())
            .is_err()
        {
            resume.arret = Arret::AJour;
            return resume;
        }

        let morceaux = match collecter_bloc(connexion, hauteur) {
            Recolte::Complet(m) => m,
            Recolte::Silence => {
                resume.arret = Arret::AJour;
                return resume;
            }
            Recolte::Incoherent(raison) => {
                resume.arret = Arret::Incoherent(raison);
                return resume;
            }
        };

        // Rejeu d'UN bloc, par TOUS ses morceaux d'un coup — jamais morceau par morceau
        // (le rejeu refuserait un lot incomplet, et un tampon côté client recréerait
        // l'état partiel qu'on a justement supprimé du wallet).
        match wallet.synchroniser(&morceaux) {
            Ok(p) if p.statut == Statut::Applique => {
                resume.blocs_rejoues += 1;
                resume.entrees += p.entrees;
                resume.notes_recues += p.notes_recues;
                if let Err(e) = apres_bloc(&p, wallet) {
                    resume.arret = Arret::Persistance(e);
                    return resume;
                }
            }
            // `DejaApplique` : le nœud redélivre le passé. Ce n'est pas un pas —
            // le compter ferait tourner la boucle sur place. On s'arrête.
            Ok(_) => {
                resume.arret = Arret::AJour;
                return resume;
            }
            Err(e) => {
                resume.arret = Arret::Incoherent(format!("{e}"));
                return resume;
            }
        }

        // Le SEUL levier de débit côté client : espacer les demandes.
        if !cadence.is_zero() {
            std::thread::sleep(cadence);
        }
    }

    resume.arret = Arret::LimiteAtteinte;
    resume
}

/// Rassemble TOUS les morceaux d'un bloc, ou renonce.
enum Recolte {
    Complet(Vec<MorceauHistorique>),
    /// Silence (échéance de lecture, lien coupé) — y compris un lot resté incomplet.
    Silence,
    Incoherent(String),
}

fn collecter_bloc<S: Read + Write>(connexion: &mut Connexion<S>, hauteur: u64) -> Recolte {
    // Le premier morceau fixe le nombre attendu ; tous les autres doivent l'annoncer
    // identiquement, faute de quoi on renonce.
    let (premier, attendus) = match recevoir_historique(connexion, hauteur) {
        Recue::Ok(m, attendus) => (m, attendus),
        Recue::Silence => return Recolte::Silence,
        Recue::Incoherent(r) => return Recolte::Incoherent(r),
    };
    if attendus == 0 || attendus > MAX_MORCEAUX_PAR_BLOC {
        return Recolte::Incoherent(format!("nombre de morceaux hors bornes : {attendus}"));
    }

    let mut morceaux = Vec::with_capacity(attendus as usize);
    morceaux.push(premier);
    while (morceaux.len() as u32) < attendus {
        match recevoir_historique(connexion, hauteur) {
            Recue::Ok(m, a) => {
                if a != attendus {
                    return Recolte::Incoherent(format!(
                        "morceaux annoncés incohérents ({a} puis {attendus})"
                    ));
                }
                morceaux.push(m);
            }
            // Un lot resté incomplet est un silence : le rejeu ne s'appliquera pas, et
            // le wallet reste exactement où il était.
            Recue::Silence => return Recolte::Silence,
            Recue::Incoherent(r) => return Recolte::Incoherent(r),
        }
    }
    Recolte::Complet(morceaux)
}

/// Une réception unitaire, décodée et validée contre la hauteur demandée.
enum Recue {
    /// Un morceau, et le nombre total de morceaux qu'il annonce.
    Ok(MorceauHistorique, u32),
    Silence,
    Incoherent(String),
}

fn recevoir_historique<S: Read + Write>(connexion: &mut Connexion<S>, hauteur: u64) -> Recue {
    // Toute erreur de réception (échéance, lien coupé, cadre altéré) est traitée comme
    // un silence : borné, sûr, et le wallet n'a rien appliqué.
    let octets = match connexion.recevoir() {
        Ok(o) => o,
        Err(_) => return Recue::Silence,
    };
    match Message::from_bytes(&octets) {
        Ok(Message::Historique(r)) => {
            // On a demandé UNE hauteur ; le nœud n'a pas le droit d'en servir une autre.
            // Sans ce contrôle, `synchroniser` refuserait plus loin (hauteur ou feuille
            // hors séquence), mais nommer l'incohérence ici la rend lisible.
            if r.hauteur != hauteur {
                return Recue::Incoherent(format!(
                    "hauteur servie {} ≠ demandée {hauteur}",
                    r.hauteur
                ));
            }
            Recue::Ok(r.pour_le_wallet(), r.morceaux)
        }
        Ok(_) => {
            Recue::Incoherent("message inattendu en réponse à une demande d'historique".into())
        }
        Err(e) => Recue::Incoherent(format!("réponse indécodable : {e}")),
    }
}
