//! Protocole applicatif : ce qui circule DANS le canal chiffré (phase 5).
//!
//! Le transport (`net`) achemine des octets ; le mempool (`ledger`) attend des
//! `ProvedTx`. Ce module est le maillon manquant entre les deux.
//!
//! # Annoncer des digests, pas des transactions
//!
//! Une `ProvedTx` pèse ~68 Kio. Envoyer spontanément la transaction à chaque pair
//! serait offrir une **amplification** à l'attaquant : une transaction injectée une
//! fois se démultiplierait en autant d'envois qu'il y a de liens. Le protocole est
//! donc en trois temps :
//!
//! ```text
//!   Annonce(digests)  →   « j'ai ces transactions »        ~64 o par entrée
//!   Demande(digests)  ←   « envoie-moi celles qui manquent »
//!   Transaction(tx)   →   la transaction elle-même         ~68 Kio
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
        )
    }
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
    /// vouloir. ⚠️ Un bloc plein (~34 Mio) dépasse largement le cadre réseau de
    /// 1 Mio : à la cadence actuelle du prototype les blocs sont petits, mais un
    /// transfert fragmenté sera nécessaire avant tout usage sérieux.
    Bloc(Box<ledger::bloc::Bloc>),
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
                let tx = ProvedTx::from_bytes(reste).map_err(|_| MessageError::TransactionInvalide)?;
                Ok(Message::Transaction(Box::new(tx)))
            }
            TAG_BLOC => {
                let bloc =
                    ledger::bloc::Bloc::from_bytes(reste).map_err(MessageError::BlocInvalide)?;
                Ok(Message::Bloc(Box::new(bloc)))
            }
            _ => Err(MessageError::TagInconnu),
        }
    }
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
        assert!(matches!(Message::from_bytes(&b), Err(MessageError::TropDeDigests)));

        // Juste au-dessus de la borne : rejeté aussi.
        let mut b2 = vec![TAG_ANNONCE];
        b2.extend_from_slice(&((MAX_DIGESTS + 1) as u32).to_le_bytes());
        assert!(matches!(Message::from_bytes(&b2), Err(MessageError::TropDeDigests)));
    }

    /// Message vide, tag inconnu, troncature, octets résiduels : `Result`, jamais
    /// de panique.
    #[test]
    fn messages_malformes_rejetes_sans_panique() {
        assert!(matches!(Message::from_bytes(&[]), Err(MessageError::Tronque)));
        assert!(matches!(Message::from_bytes(&[99]), Err(MessageError::TagInconnu)));
        assert!(matches!(Message::from_bytes(&[TAG_ANNONCE]), Err(MessageError::Tronque)));

        // Annonce annonçant 2 digests mais n'en fournissant qu'un.
        let mut court = vec![TAG_ANNONCE];
        court.extend_from_slice(&2u32.to_le_bytes());
        court.extend_from_slice(&dg(1));
        assert!(matches!(Message::from_bytes(&court), Err(MessageError::Tronque)));

        // Octets résiduels.
        let mut trop = Message::Annonce(vec![dg(1)]).to_bytes();
        trop.push(0);
        assert!(matches!(Message::from_bytes(&trop), Err(MessageError::OctetsResiduels)));
    }

    /// Aller-retour d'un bloc VIDE sur le fil — le cas courant d'une chaîne au repos.
    #[test]
    fn bloc_roundtrip() {
        let bloc = ledger::bloc::Bloc::sceller(&[5u8; 64], 3, Vec::new());
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

    /// Un bloc indécodable est rejeté proprement, et l'erreur CONSERVE la cause :
    /// « trop de transactions » et « tronqué » n'appellent pas la même réaction (la
    /// première est une tentative d'abus, la seconde peut être un lien coupé).
    #[test]
    fn bloc_indecodable_rejete_en_conservant_la_cause() {
        let mut b = vec![TAG_BLOC, 0x01];
        b.extend_from_slice(&[0u8; 64]); // parent
        b.extend_from_slice(&0u64.to_le_bytes()); // hauteur
        b.extend_from_slice(&1_000_000u32.to_le_bytes()); // n hors borne
        assert!(matches!(
            Message::from_bytes(&b),
            Err(MessageError::BlocInvalide(
                ledger::bloc::BlocDecodeError::TropDeTransactions
            ))
        ));
    }

    /// Une version INCONNUE se distingue d'une malformation.
    ///
    /// Sans cette distinction, une mise à jour de réseau bannit les nœuds restés en
    /// arrière et effondre la diversité de pairs dont dépend l'anti-eclipse.
    #[test]
    fn version_inconnue_distinguee_dune_malformation() {
        // Bloc d'une version future : PAS une faute.
        let mut futur = vec![TAG_BLOC, 0x02];
        futur.extend_from_slice(&[0u8; 64]);
        // `Message` n'est ni `Debug` ni `PartialEq` (il porte une `ProvedTx`) : on
        // extrait l'erreur par filtrage plutôt que par `unwrap_err`.
        let erreur = |o: &[u8]| match Message::from_bytes(o) {
            Err(e) => e,
            Ok(_) => panic!("décodage inattendu"),
        };
        assert!(
            erreur(&futur).version_inconnue(),
            "un bloc 0x02 est un message du FUTUR"
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
        assert!(matches!(Message::from_bytes(&b), Err(MessageError::TransactionInvalide)));
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
