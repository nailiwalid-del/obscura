//! Protocole applicatif : ce qui circule DANS le canal chiffré (phase 5).
//!
//! Le transport (`net`) achemine des octets ; le mempool (`ledger`) attend des
//! `ProvedTx`. Ce module est le maillon manquant entre les deux.
//!
//! # Annoncer des digests, pas des transactions
//!
//! Une `ProvedTx` pèse ~105 Kio. Envoyer spontanément la transaction à chaque pair
//! serait offrir une **amplification** à l'attaquant : une transaction injectée une
//! fois se démultiplierait en autant d'envois qu'il y a de liens. Le protocole est
//! donc en trois temps :
//!
//! ```text
//!   Annonce(digests)  →   « j'ai ces transactions »        ~64 o par entrée
//!   Demande(digests)  ←   « envoie-moi celles qui manquent »
//!   Transaction(tx)   →   la transaction elle-même         ~105 Kio
//! ```
//!
//! Un pair ne télécharge ainsi que ce qu'il n'a pas, et la bande passante suit le
//! besoin réel plutôt que le nombre de liens.
//!
//! # Surface hostile
//!
//! Ces messages arrivent du réseau : décodage borné, longueurs vérifiées AVANT
//! allocation, `Result` partout, aucune panique — même discipline que
//! `circuit::ProvedTx::from_bytes` et `net::frame`.

use crate::synchro::{ReponseDecodeError, ReponseHistorique};
use circuit::ProvedTx;

/// Nombre maximal de digests par message d'annonce ou de demande.
///
/// Borne l'allocation ET le travail induit : sans elle, une annonce de 10⁶ digests
/// coûterait 64 Mo et autant de recherches dans le mempool.
pub const MAX_DIGESTS: usize = 1_000;

/// Longueur d'un digest de transaction (`tx_digest`, non tronqué).
const TAILLE_DIGEST: usize = 64;

const TAG_ANNONCE: u8 = 1;
const TAG_DEMANDE: u8 = 2;
const TAG_TRANSACTION: u8 = 3;
const TAG_BLOC: u8 = 4;
const TAG_DEMANDE_BLOC: u8 = 5;
const TAG_DEMANDE_HISTORIQUE: u8 = 6;
const TAG_HISTORIQUE: u8 = 7;
const TAG_PROPOSITION: u8 = 8;
const TAG_VOTE: u8 = 9;
const TAG_VERSION: u8 = 10;

/// Version du protocole APPLICATIF que ce nœud parle et annonce (J3).
///
/// Distincte de `VERSION_BLOC`, de `VERSION_ETAT` et de `VERSION_SYNCHRO` : celles-là
/// versionnent des ARTEFACTS (un bloc, un dump, une réponse), celle-ci versionne le
/// DIALOGUE. Les confondre reviendrait à ne pouvoir faire évoluer l'un sans l'autre.
pub const VERSION_PROTOCOLE: u16 = 1;

/// Version minimale avec laquelle nous acceptons de dialoguer.
///
/// Strictement en dessous, la connexion est fermée PROPREMENT et SANS sanction : un
/// pair en retard n'est pas hostile, c'est [`MessageError::version_inconnue`]
/// généralisé au dialogue entier. Le pénaliser bannirait, en cours de mise à jour,
/// les nœuds restés en arrière — et avec eux la diversité de groupes réseau dont
/// dépend l'anti-eclipse.
///
/// Égale à [`VERSION_PROTOCOLE`] aujourd'hui : rien d'antérieur n'a existé sur un
/// réseau public. Elle ne doit monter qu'en connaissance de cause — chaque
/// incrément EXCLUT une population de nœuds.
pub const VERSION_MIN_ACCEPTEE: u16 = 1;

/// Dernier tag attribué. **À incrémenter avec chaque nouveau message.**
///
/// Sert la frontière « connu / version future » : un tag au-delà vient d'une
/// version plus récente du protocole et ne doit PAS être sanctionné. Le test
/// `le_tag_de_demande_bloc_nest_pas_une_version_future` s'en sert — sans cette
/// constante il figeait le dernier tag en dur, et il a cassé au premier ajout.
const DERNIER_TAG: u8 = TAG_VERSION;

/// CONSIGNÉ À LA COMPILATION : `DERNIER_TAG` majore bien tous les tags attribués.
///
/// Ajouter un message sans mettre `DERNIER_TAG` à jour casse la compilation, au
/// lieu de déplacer silencieusement la frontière « connu / version future » — et
/// donc de faire sanctionner un pair à jour comme s'il parlait une version future.
const _: () = assert!(
    TAG_ANNONCE <= DERNIER_TAG
        && TAG_DEMANDE <= DERNIER_TAG
        && TAG_TRANSACTION <= DERNIER_TAG
        && TAG_BLOC <= DERNIER_TAG
        && TAG_DEMANDE_BLOC <= DERNIER_TAG
        && TAG_DEMANDE_HISTORIQUE <= DERNIER_TAG
        && TAG_HISTORIQUE <= DERNIER_TAG
        && TAG_PROPOSITION <= DERNIER_TAG
        && TAG_VOTE <= DERNIER_TAG
        && TAG_VERSION <= DERNIER_TAG
);

/// CONSIGNÉ À LA COMPILATION : la négociation de version prend un tag NEUF, au-delà
/// de la frontière connue des nœuds d'AVANT J3 (`TAG_VOTE`).
///
/// C'est ce qui rend la coexistence possible dans le sens « ancien reçoit du neuf » :
/// chez un nœud en arrière, `TAG_VERSION` tombe dans `TagInconnu`, donc dans
/// [`MessageError::version_inconnue`] — ignoré, jamais sanctionné. Réutiliser ou
/// abaisser ce tag ferait décoder notre annonce comme un AUTRE message chez lui, et
/// la malformation qui s'ensuivrait le ferait bannir un pair à jour.
const _: () = assert!(TAG_VERSION > TAG_VOTE);

/// Majorant du VOTE sur le fil : id + index + signature longueur-préfixée.
const TAILLE_VOTE_MAX: usize = 64 + 2 + 4 + ledger::bloc::TAILLE_SCELLEMENT_MAX;

/// CONSIGNÉ À LA COMPILATION : un bloc scellé au plafond, enveloppé (`TAG_BLOC`)
/// puis CHIFFRÉ (le cadre borne le chiffré, pas le clair), tient dans un cadre.
///
/// C'est ici que la relation entre les trois crates est vérifiable : `ledger` fixe
/// le plafond, `crypto` le surcoût de la cascade, `net` le cadre. Tout ajustement
/// de l'un des trois qui rendrait un bloc plein indiffusable casse la compilation
/// au lieu de produire une partition découverte sur le fil.
const _: () = assert!(ledger::bloc::MAX_OCTETS_BLOC + 1 + crypto::aead::SURCOUT <= net::MAX_CADRE);

/// Erreur de décodage d'un message applicatif.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum MessageError {
    #[error("message tronqué")]
    Tronque,
    #[error("octets résiduels après la fin du message")]
    OctetsResiduels,
    #[error("type de message inconnu")]
    TagInconnu,
    #[error("trop de digests (borne : {MAX_DIGESTS})")]
    TropDeDigests,
    #[error("transaction indécodable")]
    TransactionInvalide,
    #[error("bloc indécodable : {0}")]
    BlocInvalide(ledger::bloc::BlocDecodeError),
    #[error("réponse d'historique indécodable : {0}")]
    HistoriqueInvalide(ReponseDecodeError),
    #[error("proposition PORTANT un certificat : une proposition n'est pas certifiée")]
    PropositionCertifiee,
    #[error("vote indécodable ou hors bornes")]
    VoteInvalide,
}

impl MessageError {
    /// Ce message vient-il d'une version du protocole que nous ne connaissons pas ?
    ///
    /// # Pourquoi la distinction n'est pas cosmétique
    ///
    /// « Je ne comprends pas cette version » et « ce pair ne parle pas le protocole »
    /// méritent des réactions opposées. Confondus, une mise à jour de réseau devient
    /// une PARTITION : un nœud d'ancienne version diffuse un bloc, le nœud à jour le
    /// juge indécodable, pénalise −10, et le bannit au dixième bloc — soit 100
    /// secondes à la cadence de scellement par défaut.
    ///
    /// La conséquence dépasse la perte d'un pair : les bannis quittent la sélection
    /// sortante, la diversité de groupes réseau s'effondre, et c'est précisément la
    /// propriété anti-ECLIPSE sur laquelle repose l'anonymat de Dandelion++. Un
    /// testnet en cours de mise à jour se partitionnerait tout seul en dégradant sa
    /// propre défense — sans qu'aucun message ne désigne la version comme cause.
    ///
    /// Un tag inconnu relève du même cas : c'est un message d'une version future.
    pub fn version_inconnue(&self) -> bool {
        matches!(
            self,
            MessageError::TagInconnu
                | MessageError::BlocInvalide(ledger::bloc::BlocDecodeError::VersionInconnue(_))
                | MessageError::HistoriqueInvalide(ReponseDecodeError::VersionInconnue(_))
        )
    }
}

/// Le VOTE d'une autorité pour un bloc donné (ADR J1, jalon J1-b1).
///
/// # Ce qu'il ne porte PAS, et pourquoi
///
/// Ni hauteur, ni vue. L'identifiant du bloc les engage DÉJÀ — les deux entrent
/// dans son corps. Les répéter créerait un champ capable de MENTIR par rapport à
/// l'`id`, donc une divergence à arbitrer, pour zéro information nouvelle.
///
/// # Ce qu'il porte, et pourquoi
///
/// L'index de l'autorité. Sans lui, le collecteur devrait essayer la signature
/// contre chacune des `n` autorités — jusqu'à 64 vérifications hybrides pour
/// attribuer UN vote, offertes à quiconque envoie n'importe quoi.
pub struct Vote {
    /// Identifiant du bloc voté. C'est lui qui est signé, sous `DOMAINE_VOTE`.
    pub id: [u8; 64],
    /// Index de l'autorité dans la liste gravée en genèse.
    pub index: u16,
    pub signature: crypto::sig::HybridSignature,
}

/// Message applicatif échangé entre nœuds.
pub enum Message {
    /// « J'ai ces transactions » — inventaire, digests seulement.
    Annonce(Vec<[u8; TAILLE_DIGEST]>),
    /// « Envoie-moi celles-ci » — demande ciblée.
    Demande(Vec<[u8; TAILLE_DIGEST]>),
    /// Livraison d'une transaction complète.
    Transaction(Box<ProvedTx>),
    /// Livraison d'un BLOC — l'ordre qui rend les transactions définitives.
    ///
    /// Contrairement aux transactions, un bloc est diffusé ENTIER plutôt qu'annoncé
    /// par digest. La raison est asymétrique : une transaction annoncée peut être
    /// déjà connue de dix pairs, alors qu'un bloc neuf ne l'est de personne — un
    /// aller-retour annonce/demande ne ferait que retarder ce que tout le monde va
    /// vouloir. ⚠️ Un bloc plein (~52 Mio) dépasse largement le cadre réseau de
    /// 1 Mio : à la cadence actuelle du prototype les blocs sont petits, mais un
    /// transfert fragmenté sera nécessaire avant tout usage sérieux.
    Bloc(Box<ledger::bloc::Bloc>),
    /// PROPOSITION d'un bloc par le producteur du tour — **non certifié**.
    ///
    /// Premier temps du consensus BFT (ADR J1) : le producteur légitime de
    /// `(hauteur, vue)` diffuse le bloc qu'il propose, sans certificat puisqu'il
    /// n'a pas encore les votes. Les autorités qui l'acceptent répondent par un
    /// [`Message::Vote`] ; au quorum, le producteur rediffuse le bloc CERTIFIÉ
    /// par [`Message::Bloc`], qui s'applique alors par le chemin normal.
    ///
    /// ⚠️ Un bloc PORTANT un certificat n'est pas une proposition : le décodeur le
    /// refuse. Accepter les deux formes donnerait deux encodages du même objet, et
    /// le receveur ne saurait pas s'il doit voter ou appliquer.
    Proposition(Box<ledger::bloc::Bloc>),
    /// VOTE d'une autorité pour une proposition.
    Vote(Box<Vote>),
    /// « Envoie-moi le bloc de cette hauteur » — RATTRAPAGE.
    ///
    /// Sans ce message, un nœud qui manque UN bloc est figé pour toujours : l'état
    /// est append-only, tous les blocs suivants sont refusés pour chaînage, et rien
    /// ne permet de redemander la hauteur trouée. Pire qu'un nœud en panne, il sert
    /// un historique plus court mais parfaitement COHÉRENT — un wallet qui s'y
    /// synchronise conclut à tort qu'il est à jour.
    ///
    /// La réponse réutilise [`Message::Bloc`] : un bloc reçu par rattrapage passe
    /// exactement par le même chemin d'application, avec les mêmes contrôles, que
    /// n'importe quel bloc diffusé. Aucun raccourci — un chemin d'admission
    /// parallèle serait une seconde porte d'entrée dans l'état.
    ///
    /// Un seul champ, et c'est délibéré : aucune plage, aucun `max` d'entrées choisi
    /// par le client (contrainte de docs/THREAT_MODEL.md — un paramètre client est
    /// une empreinte qui survit à une identité de transport éphémère). Le débit se
    /// règle par la FRÉQUENCE des demandes.
    DemandeBloc { hauteur: u64 },
    /// « Envoie-moi les sorties du bloc de cette hauteur » — SYNCHRONISATION du wallet.
    ///
    /// Un seul champ, exactement comme [`Message::DemandeBloc`], et pour une raison qui
    /// pèse davantage ici : ce message est celui qu'un WALLET émet, en clair de bout en
    /// bout pour le nœud qui le sert. Tout champ supplémentaire choisi par le client —
    /// un `max` d'entrées, une plage — serait une **empreinte** qui survit à l'identité
    /// de transport éphémère : le nœud séparerait les wallets par leur `max`, puis
    /// suivrait chacun par sa position. Le débit se règle par la FRÉQUENCE des
    /// demandes ; le découpage des réponses est décidé par le SERVEUR
    /// (cf. [`crate::synchro`]).
    ///
    /// L'unité est le BLOC et non la plage de feuilles, parce que `ProvedTx::anchor`
    /// est public : des wallets s'arrêtant chacun à une feuille différente
    /// publieraient chacun une ancre quasi unique.
    DemandeHistorique { hauteur: u64 },
    /// UN MORCEAU des sorties d'un bloc — la réponse à [`Message::DemandeHistorique`].
    ///
    /// Un bloc plein produit ≈1,4 Mio de sorties, au-delà du cadre réseau de 1 Mio :
    /// une demande peut donc produire PLUSIEURS messages. Le découpage est canonique et
    /// vérifié au décodage (cf. [`crate::synchro::ReponseHistorique`]).
    Historique(Box<ReponseHistorique>),
    /// « Voici la version du protocole que je parle » — négociation EXPLICITE (J3).
    ///
    /// Émis en TÊTE de connexion, comme premier message applicatif, dans les deux
    /// sens (sortant comme entrant). Il circule sur la `Session` déjà chiffrée : le
    /// transport reste PUR (`net` n'en sait rien), et la version n'est donc jamais
    /// annoncée en clair à un observateur.
    ///
    /// # Ce qu'il change par rapport à l'existant
    ///
    /// La tolérance de version était RÉACTIVE : [`MessageError::version_inconnue`] ne
    /// sanctionne pas ce qu'elle ne comprend pas, mais aucun nœud ne SAIT ce que parle
    /// son pair — la version n'était constatée qu'a posteriori, par échec de décodage,
    /// message par message. Ici elle est dite.
    ///
    /// # ⚠️ OPTIONNEL, et ce n'est pas un détail
    ///
    /// Son ABSENCE n'est pas une faute : un nœud d'une version antérieure n'en émet
    /// aucun, et rien ne doit l'exiger — ni sanction, ni attente bloquante, ni refus
    /// de servir. Le pair est alors présumé parler la version de base. Exiger ce
    /// message forkerait le réseau au premier déploiement, exactement ce que la
    /// négociation existe pour éviter.
    Version { protocole: u16 },
}

impl Message {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        match self {
            Message::Annonce(d) => {
                b.push(TAG_ANNONCE);
                ecrire_digests(&mut b, d);
            }
            Message::Demande(d) => {
                b.push(TAG_DEMANDE);
                ecrire_digests(&mut b, d);
            }
            Message::Transaction(tx) => {
                b.push(TAG_TRANSACTION);
                b.extend_from_slice(&tx.to_bytes());
            }
            Message::Bloc(bloc) => {
                b.push(TAG_BLOC);
                b.extend_from_slice(&bloc.to_bytes());
            }
            // La proposition réutilise l'encodage du bloc : un seul format de bloc
            // sur le fil, un seul décodeur à auditer. Seul le TAG distingue « vote
            // là-dessus » de « applique ça ».
            Message::Proposition(bloc) => {
                b.push(TAG_PROPOSITION);
                b.extend_from_slice(&bloc.to_bytes());
            }
            Message::Vote(v) => {
                b.push(TAG_VOTE);
                b.extend_from_slice(&v.id);
                b.extend_from_slice(&v.index.to_le_bytes());
                let sig = v.signature.to_bytes();
                b.extend_from_slice(&(sig.len() as u32).to_le_bytes());
                b.extend_from_slice(&sig);
            }
            Message::DemandeBloc { hauteur } => {
                b.push(TAG_DEMANDE_BLOC);
                b.extend_from_slice(&hauteur.to_le_bytes());
            }
            Message::DemandeHistorique { hauteur } => {
                b.push(TAG_DEMANDE_HISTORIQUE);
                b.extend_from_slice(&hauteur.to_le_bytes());
            }
            Message::Historique(reponse) => {
                b.push(TAG_HISTORIQUE);
                b.extend_from_slice(&reponse.to_bytes());
            }
            Message::Version { protocole } => {
                b.push(TAG_VERSION);
                b.extend_from_slice(&protocole.to_le_bytes());
            }
        }
        b
    }

    /// Décode un message reçu du réseau. Borné et validant : jamais de panique.
    pub fn from_bytes(b: &[u8]) -> Result<Self, MessageError> {
        let (tag, reste) = b.split_first().ok_or(MessageError::Tronque)?;
        match *tag {
            TAG_ANNONCE => Ok(Message::Annonce(lire_digests(reste)?)),
            TAG_DEMANDE => Ok(Message::Demande(lire_digests(reste)?)),
            TAG_TRANSACTION => {
                let tx =
                    ProvedTx::from_bytes(reste).map_err(|_| MessageError::TransactionInvalide)?;
                Ok(Message::Transaction(Box::new(tx)))
            }
            TAG_BLOC => {
                let bloc =
                    ledger::bloc::Bloc::from_bytes(reste).map_err(MessageError::BlocInvalide)?;
                Ok(Message::Bloc(Box::new(bloc)))
            }
            TAG_PROPOSITION => {
                let bloc =
                    ledger::bloc::Bloc::from_bytes(reste).map_err(MessageError::BlocInvalide)?;
                // Une proposition est PAR DÉFINITION non certifiée. Accepter les
                // deux formes donnerait deux encodages du même objet, et le receveur
                // ne saurait pas s'il doit voter ou appliquer.
                if bloc.certificat.is_some() {
                    return Err(MessageError::PropositionCertifiee);
                }
                Ok(Message::Proposition(Box::new(bloc)))
            }
            TAG_VOTE => {
                // Borné AVANT toute lecture : un vote annonçant une signature
                // délirante ne doit rien coûter.
                if reste.len() > TAILLE_VOTE_MAX {
                    return Err(MessageError::VoteInvalide);
                }
                if reste.len() < 64 + 2 + 4 {
                    return Err(MessageError::Tronque);
                }
                let id: [u8; 64] = reste[..64].try_into().expect("64 octets");
                let index = u16::from_le_bytes(reste[64..66].try_into().expect("2 octets"));
                let n = u32::from_le_bytes(reste[66..70].try_into().expect("4 octets")) as usize;
                if n == 0 || n > ledger::bloc::TAILLE_SCELLEMENT_MAX {
                    return Err(MessageError::VoteInvalide);
                }
                if 70 + n != reste.len() {
                    return Err(MessageError::OctetsResiduels);
                }
                let signature = crypto::sig::HybridSignature::from_bytes(&reste[70..])
                    .map_err(|_| MessageError::VoteInvalide)?;
                Ok(Message::Vote(Box::new(Vote {
                    id,
                    index,
                    signature,
                })))
            }
            // Longueur EXACTE : 8 octets, ni moins (troncature) ni plus (octets
            // résiduels). Pas d'allocation à borner ici — la borne utile est en aval,
            // c'est l'archive qui décide ce qu'elle sait servir, et une hauteur
            // absurde n'y coûte que 64 comparaisons d'entiers.
            TAG_DEMANDE_BLOC => Ok(Message::DemandeBloc {
                hauteur: lire_hauteur_exacte(reste)?,
            }),
            // Même forme, même discipline : 9 octets, longueur EXACTE, aucun champ
            // client autre que la position. Deux wallets à la même position émettent
            // donc des octets IDENTIQUES — cf. `demandes_identiques_a_position_egale`.
            TAG_DEMANDE_HISTORIQUE => Ok(Message::DemandeHistorique {
                hauteur: lire_hauteur_exacte(reste)?,
            }),
            TAG_HISTORIQUE => {
                let r = ReponseHistorique::from_bytes(reste)
                    .map_err(MessageError::HistoriqueInvalide)?;
                Ok(Message::Historique(Box::new(r)))
            }
            // Longueur EXACTE : 2 octets, ni moins (troncature) ni plus (résiduels).
            // Aucune allocation à borner — le message est de taille fixe, et c'est
            // délibéré : un champ de longueur variable en tête de connexion serait
            // le premier octet qu'un pair non authentifié nous ferait allouer.
            //
            // ⚠️ Aucun filtrage de VALEUR ici. `0` comme `u16::MAX` se décodent :
            // constater n'est pas décider. La politique (refus sous
            // `VERSION_MIN_ACCEPTEE`) appartient à l'orchestration, sans quoi un pair
            // trop ancien serait indistinguable d'un pair MALFORMÉ — et donc
            // sanctionné, ce que toute cette mécanique existe pour empêcher.
            TAG_VERSION => {
                let brut: [u8; 2] = reste
                    .get(..2)
                    .ok_or(MessageError::Tronque)?
                    .try_into()
                    .map_err(|_| MessageError::Tronque)?;
                if reste.len() > 2 {
                    return Err(MessageError::OctetsResiduels);
                }
                Ok(Message::Version {
                    protocole: u16::from_le_bytes(brut),
                })
            }
            _ => Err(MessageError::TagInconnu),
        }
    }
}

/// Lit une hauteur de longueur EXACTE (8 octets, ni moins ni plus).
///
/// Pas d'allocation à borner ici — la borne utile est en aval, chez celui qui décide ce
/// qu'il sait servir. La canonicité reste exigée : sans le rejet des octets résiduels,
/// un même message admettrait une infinité d'encodages, de quoi glisser des octets non
/// couverts par le cadre applicatif.
fn lire_hauteur_exacte(reste: &[u8]) -> Result<u64, MessageError> {
    let brut: [u8; 8] = reste
        .get(..8)
        .ok_or(MessageError::Tronque)?
        .try_into()
        .map_err(|_| MessageError::Tronque)?;
    if reste.len() > 8 {
        return Err(MessageError::OctetsResiduels);
    }
    Ok(u64::from_le_bytes(brut))
}

fn ecrire_digests(b: &mut Vec<u8>, digests: &[[u8; TAILLE_DIGEST]]) {
    b.extend_from_slice(&(digests.len() as u32).to_le_bytes());
    for d in digests {
        b.extend_from_slice(d);
    }
}

fn lire_digests(b: &[u8]) -> Result<Vec<[u8; TAILLE_DIGEST]>, MessageError> {
    if b.len() < 4 {
        return Err(MessageError::Tronque);
    }
    let n = u32::from_le_bytes(b[..4].try_into().unwrap()) as usize;
    // Borne AVANT allocation : une annonce de 10⁶ digests ne doit pas nous coûter
    // 64 Mo ni autant de recherches.
    if n > MAX_DIGESTS {
        return Err(MessageError::TropDeDigests);
    }
    let attendu = 4 + n * TAILLE_DIGEST;
    if b.len() < attendu {
        return Err(MessageError::Tronque);
    }
    if b.len() > attendu {
        return Err(MessageError::OctetsResiduels);
    }
    let mut sortie = Vec::with_capacity(n);
    for i in 0..n {
        let debut = 4 + i * TAILLE_DIGEST;
        sortie.push(b[debut..debut + TAILLE_DIGEST].try_into().unwrap());
    }
    Ok(sortie)
}

#[cfg(test)]
mod tests {
    use super::*;

    // `matches!` plutôt que `assert_eq!` : `Message` ne peut être ni `Debug` ni
    // `PartialEq`, car il porte une `ProvedTx` (preuve STARK, signature hybride).
    fn dg(n: u8) -> [u8; TAILLE_DIGEST] {
        [n; TAILLE_DIGEST]
    }

    #[test]
    fn annonce_et_demande_roundtrip() {
        for construire in [
            Message::Annonce as fn(Vec<[u8; 64]>) -> Message,
            Message::Demande,
        ] {
            let d = vec![dg(1), dg(2), dg(3)];
            let octets = construire(d.clone()).to_bytes();
            match Message::from_bytes(&octets).unwrap() {
                Message::Annonce(r) | Message::Demande(r) => assert_eq!(r, d),
                _ => panic!("mauvais type"),
            }
        }
    }

    /// Une liste VIDE est légitime (« je n'ai rien de nouveau ») et ne doit pas être
    /// confondue avec un message malformé.
    #[test]
    fn liste_vide_legitime() {
        let octets = Message::Annonce(Vec::new()).to_bytes();
        match Message::from_bytes(&octets).unwrap() {
            Message::Annonce(r) => assert!(r.is_empty()),
            _ => panic!("mauvais type"),
        }
    }

    /// ANTI-DoS : une annonce dépassant la borne est rejetée AVANT allocation. Le
    /// test n'envoie que l'en-tête — si le code allouait d'abord, il réserverait
    /// 64 Mo pour 4 octets reçus.
    #[test]
    fn annonce_hors_borne_rejetee_sans_allouer() {
        let mut b = vec![TAG_ANNONCE];
        b.extend_from_slice(&1_000_000u32.to_le_bytes());
        assert!(matches!(
            Message::from_bytes(&b),
            Err(MessageError::TropDeDigests)
        ));

        // Juste au-dessus de la borne : rejeté aussi.
        let mut b2 = vec![TAG_ANNONCE];
        b2.extend_from_slice(&((MAX_DIGESTS + 1) as u32).to_le_bytes());
        assert!(matches!(
            Message::from_bytes(&b2),
            Err(MessageError::TropDeDigests)
        ));
    }

    /// Message vide, tag inconnu, troncature, octets résiduels : `Result`, jamais
    /// de panique.
    #[test]
    fn messages_malformes_rejetes_sans_panique() {
        assert!(matches!(
            Message::from_bytes(&[]),
            Err(MessageError::Tronque)
        ));
        assert!(matches!(
            Message::from_bytes(&[99]),
            Err(MessageError::TagInconnu)
        ));
        assert!(matches!(
            Message::from_bytes(&[TAG_ANNONCE]),
            Err(MessageError::Tronque)
        ));

        // Annonce annonçant 2 digests mais n'en fournissant qu'un.
        let mut court = vec![TAG_ANNONCE];
        court.extend_from_slice(&2u32.to_le_bytes());
        court.extend_from_slice(&dg(1));
        assert!(matches!(
            Message::from_bytes(&court),
            Err(MessageError::Tronque)
        ));

        // Octets résiduels.
        let mut trop = Message::Annonce(vec![dg(1)]).to_bytes();
        trop.push(0);
        assert!(matches!(
            Message::from_bytes(&trop),
            Err(MessageError::OctetsResiduels)
        ));
    }

    /// Aller-retour d'un bloc VIDE sur le fil — le cas courant d'une chaîne au repos.
    #[test]
    fn bloc_roundtrip() {
        let bloc = ledger::bloc::Bloc::sceller(&[5u8; 64], 3, Vec::new()).unwrap();
        let id = bloc.id();
        let octets = Message::Bloc(Box::new(bloc)).to_bytes();
        match Message::from_bytes(&octets).unwrap() {
            Message::Bloc(b) => {
                assert_eq!(b.id(), id, "l'identifiant doit survivre au fil");
                assert_eq!(b.hauteur, 3);
            }
            _ => panic!("mauvais type"),
        }
    }

    /// Aller-retour des deux messages du consensus.
    #[test]
    fn aller_retour_proposition_et_vote() {
        let genese = ledger::bloc::Bloc::genese();
        let bloc = ledger::bloc::Bloc::sceller(&genese.id(), 1, Vec::new()).unwrap();
        let id = bloc.id();
        let octets = Message::Proposition(Box::new(bloc)).to_bytes();
        match Message::from_bytes(&octets).expect("proposition décodable") {
            Message::Proposition(b) => assert_eq!(b.id(), id, "l'identifiant survit au fil"),
            _ => panic!("Proposition attendue"),
        }

        let k = crypto::sig::SigKeypair::generate();
        let v = Vote {
            id,
            index: 3,
            signature: k.sign(ledger::bloc::DOMAINE_VOTE, &id),
        };
        let octets = Message::Vote(Box::new(v)).to_bytes();
        match Message::from_bytes(&octets).expect("vote décodable") {
            Message::Vote(v) => {
                assert_eq!(v.id, id);
                assert_eq!(v.index, 3);
                assert!(
                    crypto::sig::verify(&k.public, ledger::bloc::DOMAINE_VOTE, &id, &v.signature),
                    "la signature doit survivre au fil"
                );
            }
            _ => panic!("Vote attendu"),
        }
    }

    /// Une proposition PORTANT un certificat est refusée : accepter les deux formes
    /// donnerait deux encodages du même objet, et le receveur ne saurait pas s'il
    /// doit voter ou appliquer.
    #[test]
    fn proposition_certifiee_refusee() {
        let genese = ledger::bloc::Bloc::genese();
        let mut bloc = ledger::bloc::Bloc::sceller(&genese.id(), 1, Vec::new()).unwrap();
        bloc.signer_vote(0, &crypto::sig::SigKeypair::generate());
        let octets = Message::Proposition(Box::new(bloc)).to_bytes();
        assert!(matches!(
            Message::from_bytes(&octets),
            Err(MessageError::PropositionCertifiee)
        ));
    }

    /// Votes malformés : jamais de panique, et la borne est vérifiée AVANT lecture.
    #[test]
    fn votes_malformes_sans_panique() {
        assert!(Message::from_bytes(&[TAG_VOTE]).is_err());
        assert!(Message::from_bytes(&[TAG_VOTE, 0, 1, 2]).is_err());

        // Longueur de signature délirante.
        let mut b = vec![TAG_VOTE];
        b.extend_from_slice(&[0u8; 64]);
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            Message::from_bytes(&b),
            Err(MessageError::VoteInvalide)
        ));

        // Longueur nulle.
        let mut b = vec![TAG_VOTE];
        b.extend_from_slice(&[0u8; 64]);
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            Message::from_bytes(&b),
            Err(MessageError::VoteInvalide)
        ));

        // Octets résiduels après la signature annoncée.
        let k = crypto::sig::SigKeypair::generate();
        let sig = k.sign(ledger::bloc::DOMAINE_VOTE, &[0u8; 64]).to_bytes();
        let mut b = vec![TAG_VOTE];
        b.extend_from_slice(&[0u8; 64]);
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&((sig.len() - 1) as u32).to_le_bytes());
        b.extend_from_slice(&sig);
        assert!(matches!(
            Message::from_bytes(&b),
            Err(MessageError::OctetsResiduels)
        ));
    }

    /// Un bloc indécodable est rejeté proprement, et l'erreur CONSERVE la cause :
    /// « trop de transactions » et « tronqué » n'appellent pas la même réaction (la
    /// première est une tentative d'abus, la seconde peut être un lien coupé).
    #[test]
    fn bloc_indecodable_rejete_en_conservant_la_cause() {
        // Version RÉELLE du bloc, pas un littéral : un octet recopié en dur ici a
        // déjà cassé ce test le jour où le format de bloc a changé, sans que rien
        // n'ait bougé du côté du protocole applicatif.
        //
        // ⚠️ La constante ne suffit PAS : ce test reconstruit l'EN-TÊTE à la main,
        // donc tout champ ajouté au bloc doit être ajouté ici aussi. La vue (0x04)
        // en est le second exemple — sans elle, le compteur de transactions se
        // retrouvait lu comme une vue, et le test échouait pour la mauvaise raison.
        let mut b = vec![TAG_BLOC, ledger::bloc::VERSION_BLOC];
        b.extend_from_slice(&[0u8; 64]); // parent
        b.extend_from_slice(&0u64.to_le_bytes()); // hauteur
        b.extend_from_slice(&0u32.to_le_bytes()); // vue
        b.extend_from_slice(&1_000_000u32.to_le_bytes()); // n hors borne
        assert!(matches!(
            Message::from_bytes(&b),
            Err(MessageError::BlocInvalide(
                ledger::bloc::BlocDecodeError::TropDeTransactions
            ))
        ));
    }

    /// Aller-retour d'une demande de bloc, y compris aux BORNES du domaine.
    ///
    /// La hauteur vient du réseau : 0 et `u64::MAX` doivent traverser le fil comme
    /// n'importe quelle autre valeur. Un encodage qui déborderait ou saturerait
    /// silencieusement ferait servir la MAUVAISE hauteur — le demandeur recevrait un
    /// bloc qui ne s'enchaîne pas et resterait figé en croyant avoir rattrapé.
    #[test]
    fn demande_bloc_roundtrip() {
        for h in [0u64, 1, 42, u64::MAX] {
            let octets = Message::DemandeBloc { hauteur: h }.to_bytes();
            assert_eq!(octets.len(), 9, "tag + u64, rien d'autre");
            match Message::from_bytes(&octets).unwrap() {
                Message::DemandeBloc { hauteur } => assert_eq!(hauteur, h),
                _ => panic!("mauvais type"),
            }
        }
    }

    /// Une demande de bloc TRONQUÉE ou SUIVIE d'octets parasites est rejetée.
    ///
    /// Le champ est de longueur fixe : il n'y a donc aucune longueur à lire avant
    /// d'allouer, mais la canonicité reste exigée. Sans le rejet des octets
    /// résiduels, un même message admettrait une infinité d'encodages — de quoi
    /// glisser des octets non couverts par le cadre applicatif.
    #[test]
    fn demande_bloc_malformee_rejetee() {
        for n in 0..8usize {
            let mut court = vec![TAG_DEMANDE_BLOC];
            court.extend_from_slice(&[0u8; 8][..n]);
            assert!(matches!(
                Message::from_bytes(&court),
                Err(MessageError::Tronque)
            ));
        }
        let mut trop = Message::DemandeBloc { hauteur: 3 }.to_bytes();
        trop.push(0);
        assert!(matches!(
            Message::from_bytes(&trop),
            Err(MessageError::OctetsResiduels)
        ));
    }

    /// Le nouveau tag ne doit PAS être confondu avec une version future.
    ///
    /// `version_inconnue()` gouverne la sanction : un message jugé « d'une version
    /// future » est ignoré sans pénalité. Si une demande de bloc MALFORMÉE tombait
    /// dans ce cas, un pair pourrait envoyer des demandes cassées sans jamais être
    /// pénalisé ; si le tag lui-même y tombait, le rattrapage serait ignoré en
    /// silence par tout nœud à jour.
    #[test]
    fn le_tag_de_demande_bloc_nest_pas_une_version_future() {
        let erreur = |o: &[u8]| match Message::from_bytes(o) {
            Err(e) => e,
            Ok(_) => panic!("décodage inattendu"),
        };
        assert!(
            !erreur(&[TAG_DEMANDE_BLOC]).version_inconnue(),
            "une demande tronquée est une MALFORMATION, pas une version future"
        );
        // Et le tag reste décodable : ce n'est pas un tag inconnu.
        assert!(Message::from_bytes(&Message::DemandeBloc { hauteur: 1 }.to_bytes()).is_ok());
        // Les tags au-delà de ceux que nous connaissons restent, eux, « futurs ».
        // `DERNIER_TAG` porte la frontière : ce test avait figé `TAG_HISTORIQUE + 1`
        // en dur et a cassé au premier ajout de message.
        assert!(erreur(&[DERNIER_TAG + 1]).version_inconnue());
        // Et tous les tags attribués sont, eux, décodables ou malformés — jamais
        // « version future ». C'est ce qui empêche de bannir un pair à jour.
        for tag in 1..=DERNIER_TAG {
            assert!(
                !erreur(&[tag]).version_inconnue(),
                "le tag {tag} est attribué : sa troncature est une MALFORMATION"
            );
        }
    }

    /// Une version INCONNUE se distingue d'une malformation.
    ///
    /// Sans cette distinction, une mise à jour de réseau bannit les nœuds restés en
    /// arrière et effondre la diversité de pairs dont dépend l'anti-eclipse.
    #[test]
    fn version_inconnue_distinguee_dune_malformation() {
        // Bloc d'une version future : PAS une faute.
        let mut futur = vec![TAG_BLOC, ledger::bloc::VERSION_BLOC + 1];
        futur.extend_from_slice(&[0u8; 64]);
        // `Message` n'est ni `Debug` ni `PartialEq` (il porte une `ProvedTx`) : on
        // extrait l'erreur par filtrage plutôt que par `unwrap_err`.
        let erreur = |o: &[u8]| match Message::from_bytes(o) {
            Err(e) => e,
            Ok(_) => panic!("décodage inattendu"),
        };
        assert!(
            erreur(&futur).version_inconnue(),
            "un bloc d'une version supérieure est un message du FUTUR"
        );

        // Tag applicatif inconnu : idem, message d'une version future.
        assert!(erreur(&[99]).version_inconnue());

        // Malformations DANS une version connue : ce sont bien des fautes.
        for octets in [
            vec![TAG_ANNONCE],
            Message::Annonce(vec![dg(1)]).to_bytes()[..3].to_vec(),
        ] {
            assert!(
                !erreur(&octets).version_inconnue(),
                "une troncature n'est pas une question de version"
            );
        }
    }

    /// Une transaction indécodable est rejetée proprement (le message porte des
    /// octets arbitraires venant du réseau).
    #[test]
    fn transaction_indecodable_rejetee() {
        let mut b = vec![TAG_TRANSACTION];
        b.extend_from_slice(&[0xAB; 200]);
        assert!(matches!(
            Message::from_bytes(&b),
            Err(MessageError::TransactionInvalide)
        ));
    }

    /// DEUX WALLETS À LA MÊME POSITION ÉMETTENT DES OCTETS IDENTIQUES.
    ///
    /// C'est la propriété qui justifie l'absence de tout champ client hormis la
    /// position. Un `max` d'entrées, une plage, un identifiant de morceau : chacun
    /// serait une **empreinte** stable qui survit à l'identité de transport éphémère.
    /// Le nœud servirait alors à séparer les wallets par leur paramètre, puis à suivre
    /// chacun par sa position — un pseudonyme reconstruit exactement là où le projet
    /// s'échine à n'en laisser aucun (clé d'intention neuve, ancre sur frontière de
    /// bloc, Dandelion++).
    ///
    /// Le test compare les OCTETS, pas la structure : c'est le fil qui fuit, pas le
    /// type Rust.
    #[test]
    fn demandes_identiques_a_position_egale() {
        for h in [0u64, 1, 4_242, u64::MAX] {
            let alice = Message::DemandeHistorique { hauteur: h }.to_bytes();
            let bob = Message::DemandeHistorique { hauteur: h }.to_bytes();
            assert_eq!(alice, bob, "hauteur {h} : deux wallets, un seul encodage");
            assert_eq!(alice.len(), 9, "tag + hauteur, rien d'autre");
        }
        // Et deux positions DIFFÉRENTES doivent bien se distinguer : sans quoi le
        // wallet ne pourrait pas demander ce qu'il lui manque.
        assert_ne!(
            Message::DemandeHistorique { hauteur: 1 }.to_bytes(),
            Message::DemandeHistorique { hauteur: 2 }.to_bytes()
        );
    }

    /// Aller-retour d'une demande d'historique, aux bornes du domaine.
    #[test]
    fn demande_historique_roundtrip() {
        for h in [0u64, 7, u64::MAX] {
            let octets = Message::DemandeHistorique { hauteur: h }.to_bytes();
            match Message::from_bytes(&octets).unwrap() {
                Message::DemandeHistorique { hauteur } => assert_eq!(hauteur, h),
                _ => panic!("mauvais type"),
            }
        }
    }

    /// Une demande d'historique tronquée ou suivie d'octets parasites est refusée, et
    /// ce n'est PAS un message « d'une version future » : la distinction gouverne la
    /// sanction, et un pair pourrait sinon envoyer des demandes cassées gratuitement.
    #[test]
    fn demande_historique_malformee_rejetee() {
        for n in 0..8usize {
            let mut court = vec![TAG_DEMANDE_HISTORIQUE];
            court.extend_from_slice(&[0u8; 8][..n]);
            let e = match Message::from_bytes(&court) {
                Err(e) => e,
                Ok(_) => panic!("décodage inattendu"),
            };
            assert!(matches!(e, MessageError::Tronque));
            assert!(!e.version_inconnue());
        }
        let mut trop = Message::DemandeHistorique { hauteur: 3 }.to_bytes();
        trop.push(0);
        assert!(matches!(
            Message::from_bytes(&trop),
            Err(MessageError::OctetsResiduels)
        ));
    }

    /// Aller-retour d'une réponse d'historique sur le fil, tag applicatif compris.
    #[test]
    fn historique_roundtrip() {
        use ledger::historique::TrancheBloc;
        let tranche = TrancheBloc {
            hauteur: 3,
            debut: 4,
            fin: 4,
            racine_apres: proved_hash::digest::Digest(core::array::from_fn(|i| {
                proved_hash::felt::Felt::from_canonical_u64(500 + i as u64).unwrap()
            })),
        };
        let morceaux =
            crate::synchro::ReponseHistorique::decouper(&tranche, &[], 9).expect("découpage");
        let octets = Message::Historique(Box::new(morceaux.into_iter().next().unwrap())).to_bytes();
        match Message::from_bytes(&octets).unwrap() {
            Message::Historique(r) => {
                assert_eq!(r.hauteur, 3);
                assert_eq!(r.hauteur_tete, 9);
                assert_eq!((r.debut, r.fin), (4, 4));
                assert!(r.sorties.is_empty());
            }
            _ => panic!("mauvais type"),
        }
    }

    /// Une réponse d'historique indécodable est rejetée en CONSERVANT la cause, et une
    /// version de synchronisation inconnue reste un message « du futur ».
    ///
    /// Confondre les deux ferait bannir, lors d'une évolution du format de
    /// synchronisation, les nœuds restés en arrière — et avec eux la diversité de
    /// groupes réseau dont dépend l'anti-eclipse.
    #[test]
    fn historique_indecodable_conserve_la_cause() {
        let erreur = |o: &[u8]| match Message::from_bytes(o) {
            Err(e) => e,
            Ok(_) => panic!("décodage inattendu"),
        };
        assert!(matches!(
            erreur(&[TAG_HISTORIQUE]),
            MessageError::HistoriqueInvalide(crate::synchro::ReponseDecodeError::Tronque)
        ));
        let futur = vec![TAG_HISTORIQUE, crate::synchro::VERSION_SYNCHRO + 1];
        assert!(
            erreur(&futur).version_inconnue(),
            "une version de synchronisation supérieure est un message du FUTUR"
        );
    }

    /// Petit utilitaire partagé par les tests de version : extrait l'erreur par
    /// filtrage (`Message` n'est ni `Debug` ni `PartialEq`).
    fn erreur(o: &[u8]) -> MessageError {
        match Message::from_bytes(o) {
            Err(e) => e,
            Ok(_) => panic!("décodage inattendu"),
        }
    }

    /// `Message::Version` fait l'aller-retour sur le fil (TAG_VERSION ‖ u16 LE).
    #[test]
    fn version_aller_retour() {
        let m = Message::Version {
            protocole: VERSION_PROTOCOLE,
        };
        let octets = m.to_bytes();
        assert_eq!(octets.len(), 3, "tag + u16, rien d'autre");
        let relu = Message::from_bytes(&octets).expect("décodable");
        assert!(matches!(relu, Message::Version { protocole } if protocole == VERSION_PROTOCOLE));
    }

    /// Aux BORNES du domaine : la version vient du réseau, `0` et `u16::MAX` doivent
    /// traverser comme n'importe quelle autre valeur. Les REFUSER ici serait une
    /// erreur de couche — le décodeur constate, la politique décide.
    #[test]
    fn version_roundtrip_aux_bornes() {
        for v in [0u16, 1, 42, u16::MAX] {
            let octets = Message::Version { protocole: v }.to_bytes();
            match Message::from_bytes(&octets).expect("décodable") {
                Message::Version { protocole } => assert_eq!(protocole, v),
                _ => panic!("mauvais type"),
            }
        }
    }

    /// `TAG_VERSION` est le dernier tag connu ; un tag au-delà reste « version future ».
    #[test]
    fn version_est_le_dernier_tag_connu() {
        assert_eq!(DERNIER_TAG, TAG_VERSION);
        assert!(erreur(&[TAG_VERSION + 1]).version_inconnue());
    }

    /// Un `Message::Version` TRONQUÉ ou suivi d'octets parasites est une
    /// MALFORMATION, pas une version future : sinon un pair pourrait envoyer des
    /// messages cassés sans jamais être pénalisé.
    #[test]
    fn version_tronquee_est_malformation() {
        assert!(matches!(erreur(&[TAG_VERSION]), MessageError::Tronque));
        assert!(!erreur(&[TAG_VERSION]).version_inconnue());
        assert!(matches!(erreur(&[TAG_VERSION, 1]), MessageError::Tronque));
        assert!(matches!(
            erreur(&[TAG_VERSION, 1, 0, 0]),
            MessageError::OctetsResiduels
        ));
    }

    /// COEXISTENCE, sens « ancien nœud reçoit du neuf » : un nœud d'AVANT J3 ne
    /// connaît que les tags jusqu'à `TAG_VOTE`. `TAG_VERSION` tombe donc chez lui dans
    /// `TagInconnu`, c'est-à-dire « version future » — ignoré, JAMAIS sanctionné.
    ///
    /// Le tag lui-même est tenu par l'assertion de COMPILATION `TAG_VERSION >
    /// TAG_VOTE` ci-dessus (un tag repris serait mal décodé par un nœud en arrière) ;
    /// ici on vérifie la POLITIQUE qui en découle : un tag hors frontière est classé
    /// « version future », donc jamais sanctionné.
    #[test]
    fn tag_version_est_une_version_future_pour_un_noeud_davant_j3() {
        // La frontière d'un nœud d'avant J3 était `TAG_VOTE` ; pour lui, notre tag
        // est « au-delà », exactement comme `DERNIER_TAG + 1` l'est pour nous.
        assert!(erreur(&[DERNIER_TAG + 1]).version_inconnue());
        assert!(MessageError::TagInconnu.version_inconnue());
    }

    /// La borne d'annonce tient compte du cadrage : `MAX_DIGESTS` digests doivent
    /// tenir dans un cadre `net::frame` (1 Mio), sinon le message serait
    /// systématiquement rejeté par la couche inférieure.
    #[test]
    fn borne_annonce_compatible_avec_le_cadrage() {
        let taille_max = 1 + 4 + MAX_DIGESTS * TAILLE_DIGEST;
        assert!(
            taille_max < net::MAX_CADRE,
            "une annonce pleine ({taille_max} o) doit tenir dans un cadre ({} o)",
            net::MAX_CADRE
        );
    }
}
