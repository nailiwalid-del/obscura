//! Bloc : le lot ORDONNÉ qui donne sa finalité à une transaction.
//!
//! # Pourquoi une transaction ne pouvait pas être appliquée jusqu'ici
//!
//! `ProvedLedgerState::apply_proved_tx` implémente la règle de consensus depuis
//! longtemps, et n'était appelée par aucun chemin du nœud. Ce n'était pas un
//! câblage oublié : appliquer chacun dans son coin, dès réception, ferait
//! **diverger les arbres**. Deux nœuds recevant les mêmes transactions dans un
//! ordre différent insèrent les mêmes commitments à des index différents, donc
//! obtiennent des racines différentes — et se rejettent mutuellement toutes les
//! transactions suivantes pour « ancre inconnue ».
//!
//! Un mempool n'a pas d'ordre : c'est un ensemble. Il manquait l'artefact qui en
//! FIXE un. C'est le bloc : une suite de transactions, dans un ordre écrit, chaînée
//! à son parent. Deux nœuds qui acceptent la même chaîne de blocs obtiennent le même
//! arbre, feuille par feuille.
//!
//! # Ce que ce module ne décide PAS : qui produit les blocs
//!
//! L'élection du producteur (preuve de travail, preuve d'enjeu, autorité) est une
//! question d'ÉCONOMIE et de gouvernance, explicitement hors périmètre du prototype
//! (docs/THREAT_MODEL.md). Elle est orthogonale : quel que soit le mécanisme retenu,
//! il produira des blocs de cette forme et l'application restera celle-ci.
//!
//! Tant qu'aucun mécanisme n'est choisi, **n'importe qui peut sceller un bloc**. Une
//! chaîne Obscura n'a donc aujourd'hui aucune résistance à la réécriture par un
//! adversaire : c'est un ordre CONVENU, pas un ordre DÉFENDU.
//!
//! # ⚠️ Aucune réorganisation n'est possible, par construction
//!
//! L'état du nœud repose sur une `MerkleFrontier` **append-only** : elle ne conserve
//! que le bord droit de l'arbre et ne sait pas revenir en arrière. Les nullifiers
//! dépensés sont un ensemble sans historique. Rien, dans le modèle d'état actuel, ne
//! peut être défait.
//!
//! Ce n'est donc pas un choix d'implémentation qu'on lèverait plus tard sans y
//! toucher : **supporter les réorganisations exigerait de redessiner l'état du
//! ledger** (arbre versionné, nullifiers datés par hauteur, journal de défaisage).
//! La chaîne est linéaire, un bloc accepté est définitif, et un bloc concurrent à la
//! même hauteur est simplement refusé. C'est écrit ici parce que la conséquence est
//! structurelle et facile à ne pas voir.
//!
//! # L'ÉMISSION n'existe que dans la GENÈSE
//!
//! Un bloc porte un champ `emissions`, et la règle de consensus est brutale :
//! **`hauteur > 0 ⇒ emissions.is_empty()`**. Créer de la monnaie n'est possible qu'au
//! moment où la chaîne est paramétrée, avant que quiconque ait quoi que ce soit.
//!
//! Ce n'est pas une timidité de prototype, c'est la seule conception qui ne DÉTRUIT
//! pas la protection existante. Jusqu'ici la protection contre l'inflation n'était pas
//! une règle : c'était la DIVERGENCE. `ProvedLedgerState::mint` n'était appelée par
//! aucun chemin de consensus ni de réseau ; un nœud qui s'en servait obtenait une
//! racine que personne d'autre n'avait, et sa monnaie était inutilisable parce
//! qu'invisible. Rendre les émissions applicables à TOUTE hauteur aurait supprimé cet
//! effet et rendu l'inflation **diffusée et acceptée par tous** — une régression du
//! modèle de menace, pas une fonctionnalité.
//!
//! Le jour où une coinbase shielded aura un sens (récompense de producteur), elle
//! devra s'accompagner d'une règle qui BORNE le montant émis — et ce montant est
//! précisément ce que le chiffrement cache. C'est une brique de conception, pas un
//! champ à débloquer.
//!
//! # Pourquoi `Emission` ne porte JAMAIS un `Option<EncNote>`
//!
//! Une émission sans bénéficiaire (amorçage d'un testnet, allocation réservée) porte
//! une enveloppe **factice** chiffrée vers une clé KEM jetable, indistinguable d'une
//! vraie. Un drapeau de présence — `Option` — partitionnerait publiquement les
//! feuilles de l'arbre en « émises » et « transférées », et ce gabarit serait recopié
//! le jour d'une coinbase shielded : le witness-hiding du circuit serait vidé de son
//! sens par un octet de sérialisation. La propriété d'indistinguabilité est celle que
//! les tests IK-CCA de `crate::proved_wallet` vérifient déjà.

use circuit::tx::{KEM_CT_LEN, MAX_ENC_NOTE_LEN};
use circuit::{EncNote, ProvedTx};
use proved_hash::digest::{Digest, DIGEST_BYTES};

/// Nombre maximal de transactions par bloc.
///
/// Borne l'allocation ET le travail induit : chaque transaction coûte ~4 ms de
/// vérification STARK, donc un bloc de 10⁶ transactions occuperait un nœud plus d'une
/// heure. La borne est vérifiée AVANT toute allocation — même discipline que
/// `node::message` et `net::frame`.
pub const MAX_TX_PAR_BLOC: usize = 512;

/// Longueur d'un identifiant de bloc : `dual_hash` complet (BLAKE3‖SHA3-256), **non
/// tronqué**. Un identifiant tronqué offrirait des collisions à qui veut faire passer
/// un bloc pour un autre.
pub const TAILLE_ID: usize = crypto::hash::DUAL_DIGEST_LEN;

/// Identifiant du parent du bloc de genèse : il n'en a pas.
pub const PAS_DE_PARENT: [u8; TAILLE_ID] = [0u8; TAILLE_ID];

/// Nombre maximal d'émissions dans un bloc de genèse.
///
/// Borne l'allocation au décodage ET la taille d'une genèse échangée entre opérateurs.
/// Vérifiée AVANT allocation dans `from_bytes` **et** dans le constructeur
/// `Bloc::genese_avec` : une borne qui n'existe qu'au décodage ne protège que
/// l'entrant, jamais celui qui fabrique l'artefact (règle tirée de la revue
/// adversariale, cf. docs/THREAT_MODEL.md).
pub const MAX_EMISSIONS_PAR_BLOC: usize = 512;

/// Version du format de bloc.
///
/// Passée à `0x02` par l'ajout des émissions. Ce n'est pas cosmétique : l'encodage
/// entrant dans `Bloc::id`, l'identifiant de la genèse VIDE change lui aussi. Un état
/// dumpé par une version antérieure porte donc une tête périmée — d'où le passage
/// simultané de `proved_state::VERSION_ETAT` à `0x02`, qui le refuse au lieu de le
/// lire de travers.
pub const VERSION_BLOC: u8 = 0x02;
const DOMAINE_ID: &str = "obscura/bloc/id/v1";

/// Taille indicative d'une `ProvedTx` (≈68 Kio) et cadre maximal de `net::frame`
/// (1 Mio ; `ledger` ne dépend pas de `net`, d'où la constante répétée).
const TAILLE_TX_INDICATIVE: usize = 68 * 1024;
const CADRE_NET: usize = 1024 * 1024;

/// CONSIGNÉ À LA COMPILATION : un bloc plein ne tient PAS dans un cadre réseau.
///
/// 512 × ~68 Kio ≈ 34 Mio, trente fois le cadre de 1 Mio. Acheminer un bloc plein
/// exigera donc un transfert FRAGMENTÉ — par transaction, comme le gossip le fait
/// déjà — et non un seul cadre. L'assertion est ici plutôt que dans un test pour que
/// tout futur ajustement de `MAX_TX_PAR_BLOC` qui rendrait la remarque caduque casse
/// la compilation au lieu de laisser une note périmée.
const _: () = assert!(MAX_TX_PAR_BLOC * TAILLE_TX_INDICATIVE > CADRE_NET);

/// Surcoût d'encodage d'un bloc VIDE : `version ‖ parent ‖ hauteur ‖ n ‖ m`.
pub const SURCOUT_BLOC_VIDE: usize = 1 + TAILLE_ID + 8 + 4 + 4;

/// Marge réservée à l'enveloppe applicative (`Message::Bloc` = 1 octet de tag) et à
/// tout en-tête futur. Généreuse à dessein : la dépasser coûterait un bloc indiffusable.
const MARGE_MESSAGE: usize = 64;

/// PLAFOND DE SCELLEMENT EN OCTETS — la borne qui rend un bloc DIFFUSABLE.
///
/// `MAX_TX_PAR_BLOC` borne le NOMBRE de transactions, pas leur POIDS : à ≈68 Kio
/// pièce, une quinzaine suffit à dépasser le cadre réseau. Un bloc scellé au-delà
/// serait localement valide, applicable par son producteur… et refusé par tous les
/// autres faute de pouvoir seulement le recevoir — partition définitive, l'état étant
/// append-only. C'est le défaut n°1 de la revue adversariale dans sa variante OCTETS.
///
/// Ce que le cadre borne est la quantité CHIFFRÉE (cf. `crypto::aead::SURCOUT`, dont
/// la doc décrit exactement ce piège) : le budget du bloc soustrait donc le surcoût
/// de la cascade EN PLUS de la marge applicative. Sans cette soustraction, un bloc
/// scellé à la borne passait le constructeur puis était refusé par `ecrire_cadre`
/// une fois chiffré — 5 octets au-dessus du cadre, indiffusable.
pub const MAX_OCTETS_BLOC: usize = CADRE_NET - crypto::aead::SURCOUT - MARGE_MESSAGE;

const _: () = assert!(MAX_OCTETS_BLOC < CADRE_NET);
const _: () = assert!(SURCOUT_BLOC_VIDE < MAX_OCTETS_BLOC);

/// Coût sérialisé d'une transaction DANS un bloc : sa longueur + son préfixe de 4 o.
pub fn cout_transaction(octets_tx: usize) -> usize {
    4 + octets_tx
}

/// Taille maximale d'une émission sérialisée : commitment + les deux champs de
/// l'`EncNote`, chacun préfixé de sa longueur.
const TAILLE_EMISSION_MAX: usize = DIGEST_BYTES + 4 + KEM_CT_LEN + 4 + MAX_ENC_NOTE_LEN;

/// CONSIGNÉ À LA COMPILATION : une genèse PLEINE tient dans un cadre réseau.
///
/// Contrairement à un bloc plein de transactions, une genèse doit pouvoir être
/// échangée d'un bloc (fichier, message) : c'est l'artefact que deux opérateurs
/// comparent. Si `MAX_EMISSIONS_PAR_BLOC` grossissait au point de la rendre
/// inacheminable, la compilation casse plutôt qu'une note devienne fausse.
const _: () = assert!(MAX_EMISSIONS_PAR_BLOC * TAILLE_EMISSION_MAX < CADRE_NET);

/// Erreur de décodage d'un bloc. Comme `ProvedTx::from_bytes`, c'est un point
/// d'entrée RÉSEAU : il ne fait jamais confiance à ses octets et ne panique jamais.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum BlocDecodeError {
    #[error("bloc tronqué")]
    Tronque,
    #[error("octets résiduels après la fin du bloc")]
    OctetsResiduels,
    #[error("version de bloc inconnue : {0:#04x}")]
    VersionInconnue(u8),
    #[error("trop de transactions (borne : {MAX_TX_PAR_BLOC})")]
    TropDeTransactions,
    #[error("transaction indécodable en position {0}")]
    TransactionInvalide(usize),
    #[error("trop d'émissions (borne : {MAX_EMISSIONS_PAR_BLOC})")]
    TropDEmissions,
    #[error("émission indécodable ou hors bornes en position {0}")]
    EmissionInvalide(usize),
}

/// Erreur de CONSTRUCTION d'un bloc de genèse. Distincte du décodage : elle protège
/// celui qui fabrique l'artefact, là où `BlocDecodeError` protège celui qui le reçoit.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum BlocConstructionError {
    #[error("{recues} émissions (borne : {MAX_EMISSIONS_PAR_BLOC})")]
    TropDEmissions { recues: usize },
    #[error("émission {0} hors bornes (kem_ct ou enc_note de taille invalide)")]
    EmissionHorsBornes(usize),
    #[error("{recues} transactions (borne : {MAX_TX_PAR_BLOC})")]
    TropDeTransactions { recues: usize },
    #[error("bloc de {octets} o : indiffusable (borne : {MAX_OCTETS_BLOC} o)")]
    TropDOctets { octets: usize },
}

/// Une émission : un commitment de note créé EX NIHILO, avec son enveloppe chiffrée.
///
/// N'existe légitimement que dans la genèse (cf. tête de module). `enc_note` n'est
/// **jamais** optionnel : une émission sans bénéficiaire porte une enveloppe factice,
/// indistinguable d'une vraie — voir `crate::proved_wallet::emission_factice`.
#[derive(Clone)]
pub struct Emission {
    /// Commitment de la note émise, inséré dans l'arbre au moment de l'amorçage.
    pub commitment: Digest,
    /// Enveloppe chiffrée de la note, réelle ou factice — indistinguables.
    pub enc_note: EncNote,
}

/// Un bloc : des transactions dans un ORDRE écrit, chaînées à un parent.
pub struct Bloc {
    /// Identifiant du bloc parent, ou `PAS_DE_PARENT` pour la genèse.
    pub parent: [u8; TAILLE_ID],
    /// Hauteur dans la chaîne (genèse = 0). Redondante avec le chaînage, et gardée
    /// exprès : elle rend un refus de bloc EXPLICABLE (« hauteur 7 attendue, 12
    /// reçue ») là où un simple parent inconnu ne dirait pas si le nœud est en
    /// retard ou face à une autre chaîne.
    pub hauteur: u64,
    /// Les transactions, dans l'ordre d'application. **C'est tout l'objet du bloc.**
    pub transactions: Vec<ProvedTx>,
    /// Les émissions. **Doit être vide dès que `hauteur > 0`** — règle de consensus
    /// appliquée par `ProvedLedgerState::appliquer_bloc`, contrôle O(1) placé avant
    /// toute vérification coûteuse.
    pub emissions: Vec<Emission>,
}

impl Bloc {
    /// Bloc de genèse VIDE : sans parent, sans transaction, sans émission.
    ///
    /// Utilisable pour un testnet local où la monnaie est amorcée autrement (aucune
    /// note n'existe : la chaîne démarre sur un arbre vide). Une chaîne réelle part
    /// d'une genèse construite par `genese_avec`.
    pub fn genese() -> Self {
        Bloc {
            parent: PAS_DE_PARENT,
            hauteur: 0,
            transactions: Vec::new(),
            emissions: Vec::new(),
        }
    }

    /// Bloc de genèse PARAMÉTRÉ : la seule façon de faire exister de la monnaie.
    ///
    /// La borne `MAX_EMISSIONS_PAR_BLOC` et les bornes d'`EncNote` sont vérifiées ICI,
    /// pas seulement au décodage : sinon on pourrait fabriquer une genèse localement
    /// valide qu'aucun pair ne saurait décoder — exactement le défaut corrigé pour
    /// `Noeud::sceller` (une borne de `from_bytes` doit exister aussi dans le
    /// constructeur).
    pub fn genese_avec(emissions: Vec<Emission>) -> Result<Self, BlocConstructionError> {
        if emissions.len() > MAX_EMISSIONS_PAR_BLOC {
            return Err(BlocConstructionError::TropDEmissions {
                recues: emissions.len(),
            });
        }
        if let Some(i) = emissions.iter().position(|e| !e.enc_note.within_bounds()) {
            return Err(BlocConstructionError::EmissionHorsBornes(i));
        }
        Ok(Bloc {
            parent: PAS_DE_PARENT,
            hauteur: 0,
            transactions: Vec::new(),
            emissions,
        })
    }

    /// Scelle un bloc à la suite de `parent`.
    ///
    /// « Sceller » et non « miner » : aucun travail n'est fourni, aucune autorité
    /// n'est prouvée. Voir l'avertissement en tête de module.
    ///
    /// Aucune émission n'est acceptée ici, et il n'existe aucun paramètre pour en
    /// ajouter : à hauteur non nulle elles seraient refusées par le consensus, et
    /// offrir le champ inviterait à croire le contraire.
    /// Scelle un bloc, en refusant ce qui serait INDIFFUSABLE.
    ///
    /// Deux bornes, toutes deux vérifiées ICI et pas seulement au décodage (même
    /// discipline que `genese_avec`) : le NOMBRE de transactions, et surtout leur
    /// POIDS — un bloc plus lourd qu'un cadre réseau ne peut atteindre personne.
    pub fn sceller(
        parent: &[u8; TAILLE_ID],
        hauteur: u64,
        transactions: Vec<ProvedTx>,
    ) -> Result<Self, BlocConstructionError> {
        if transactions.len() > MAX_TX_PAR_BLOC {
            return Err(BlocConstructionError::TropDeTransactions {
                recues: transactions.len(),
            });
        }
        let bloc = Bloc {
            parent: *parent,
            hauteur,
            transactions,
            emissions: Vec::new(),
        };
        let octets = bloc.to_bytes().len();
        if octets > MAX_OCTETS_BLOC {
            return Err(BlocConstructionError::TropDOctets { octets });
        }
        Ok(bloc)
    }

    /// Identifiant du bloc = `dual_hash` de son encodage canonique.
    ///
    /// L'encodage étant canonique et injectif, deux blocs de même identifiant ont le
    /// même parent, la même hauteur et les mêmes transactions dans le même ordre.
    /// Réordonner les transactions change l'identifiant — ce qui est le but : c'est
    /// l'ORDRE qu'on veut rendre infalsifiable.
    pub fn id(&self) -> [u8; TAILLE_ID] {
        crypto::hash::dual_hash(DOMAINE_ID, &self.to_bytes())
    }

    /// Encodage canonique : `version ‖ parent ‖ hauteur LE ‖ n LE ‖ [len(txᵢ) LE ‖ txᵢ]
    /// ‖ m LE ‖ [cmⱼ ‖ len(kem_ctⱼ) LE ‖ kem_ctⱼ ‖ len(enc_noteⱼ) LE ‖ enc_noteⱼ]`.
    ///
    /// Les émissions sont encodées SANS drapeau de présence : une émission factice a
    /// exactement la même forme et la même longueur qu'une émission destinée à
    /// quelqu'un (cf. tête de module).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = vec![VERSION_BLOC];
        b.extend_from_slice(&self.parent);
        b.extend_from_slice(&self.hauteur.to_le_bytes());
        b.extend_from_slice(&(self.transactions.len() as u32).to_le_bytes());
        for tx in &self.transactions {
            let o = tx.to_bytes();
            b.extend_from_slice(&(o.len() as u32).to_le_bytes());
            b.extend_from_slice(&o);
        }
        b.extend_from_slice(&(self.emissions.len() as u32).to_le_bytes());
        for em in &self.emissions {
            b.extend_from_slice(&em.commitment.to_bytes());
            b.extend_from_slice(&(em.enc_note.kem_ct.len() as u32).to_le_bytes());
            b.extend_from_slice(&em.enc_note.kem_ct);
            b.extend_from_slice(&(em.enc_note.enc_note.len() as u32).to_le_bytes());
            b.extend_from_slice(&em.enc_note.enc_note);
        }
        b
    }

    /// Décode un bloc reçu du réseau. Borné et validant : jamais de panique.
    pub fn from_bytes(b: &[u8]) -> Result<Self, BlocDecodeError> {
        let mut pos = 0usize;
        fn prendre<'a>(
            b: &'a [u8],
            pos: &mut usize,
            n: usize,
        ) -> Result<&'a [u8], BlocDecodeError> {
            let fin = pos.checked_add(n).ok_or(BlocDecodeError::Tronque)?;
            if fin > b.len() {
                return Err(BlocDecodeError::Tronque);
            }
            let s = &b[*pos..fin];
            *pos = fin;
            Ok(s)
        }

        let version = prendre(b, &mut pos, 1)?[0];
        if version != VERSION_BLOC {
            return Err(BlocDecodeError::VersionInconnue(version));
        }
        let parent: [u8; TAILLE_ID] = prendre(b, &mut pos, TAILLE_ID)?
            .try_into()
            .map_err(|_| BlocDecodeError::Tronque)?;
        let hauteur = u64::from_le_bytes(prendre(b, &mut pos, 8)?.try_into().unwrap());

        let n = u32::from_le_bytes(prendre(b, &mut pos, 4)?.try_into().unwrap()) as usize;
        // Borne AVANT allocation : un en-tête annonçant 10⁶ transactions ne doit rien
        // coûter à qui le reçoit.
        if n > MAX_TX_PAR_BLOC {
            return Err(BlocDecodeError::TropDeTransactions);
        }
        let mut transactions = Vec::with_capacity(n);
        for i in 0..n {
            let taille = u32::from_le_bytes(prendre(b, &mut pos, 4)?.try_into().unwrap()) as usize;
            let octets = prendre(b, &mut pos, taille)?;
            transactions.push(
                ProvedTx::from_bytes(octets).map_err(|_| BlocDecodeError::TransactionInvalide(i))?,
            );
        }
        let m = u32::from_le_bytes(prendre(b, &mut pos, 4)?.try_into().unwrap()) as usize;
        // Borne AVANT allocation, comme pour les transactions.
        if m > MAX_EMISSIONS_PAR_BLOC {
            return Err(BlocDecodeError::TropDEmissions);
        }
        let mut emissions = Vec::with_capacity(m);
        for j in 0..m {
            let cm: [u8; DIGEST_BYTES] = prendre(b, &mut pos, DIGEST_BYTES)?
                .try_into()
                .map_err(|_| BlocDecodeError::Tronque)?;
            // Digest CANONIQUE : des felts hors du corps seraient acceptés puis
            // feraient diverger le hachage prouvé, ou paniqueraient plus loin.
            let commitment =
                Digest::from_bytes(&cm).map_err(|_| BlocDecodeError::EmissionInvalide(j))?;

            let lk = u32::from_le_bytes(prendre(b, &mut pos, 4)?.try_into().unwrap()) as usize;
            // Bornes AVANT allocation : `prendre` refuserait déjà une longueur
            // délirante, mais on veut le refus AVANT toute réservation et avec une
            // erreur qui désigne l'émission fautive.
            if lk != KEM_CT_LEN {
                return Err(BlocDecodeError::EmissionInvalide(j));
            }
            let kem_ct = prendre(b, &mut pos, lk)?.to_vec();

            let le = u32::from_le_bytes(prendre(b, &mut pos, 4)?.try_into().unwrap()) as usize;
            if le > MAX_ENC_NOTE_LEN {
                return Err(BlocDecodeError::EmissionInvalide(j));
            }
            let enc_note = prendre(b, &mut pos, le)?.to_vec();

            emissions.push(Emission {
                commitment,
                enc_note: EncNote { kem_ct, enc_note },
            });
        }

        if pos != b.len() {
            return Err(BlocDecodeError::OctetsResiduels);
        }
        Ok(Bloc {
            parent,
            hauteur,
            transactions,
            emissions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un bloc de genèse a un identifiant STABLE : c'est le point de départ commun
    /// que deux nœuds doivent partager sans se parler.
    #[test]
    fn genese_deterministe() {
        assert_eq!(Bloc::genese().id(), Bloc::genese().id());
        assert_eq!(Bloc::genese().parent, PAS_DE_PARENT);
        assert_eq!(Bloc::genese().hauteur, 0);
    }

    /// L'identifiant dépend de la HAUTEUR et du PARENT, pas seulement du contenu :
    /// sans cela, deux blocs vides à des hauteurs différentes seraient confondus et
    /// la chaîne pourrait être repliée sur elle-même.
    #[test]
    fn id_lie_le_chainage() {
        let g = Bloc::genese().id();
        let a = Bloc::sceller(&g, 1, Vec::new()).unwrap();
        let b = Bloc::sceller(&g, 2, Vec::new()).unwrap();
        let c = Bloc::sceller(&[9u8; TAILLE_ID], 1, Vec::new()).unwrap();
        assert_ne!(a.id(), b.id(), "la hauteur doit entrer dans l'identifiant");
        assert_ne!(a.id(), c.id(), "le parent doit entrer dans l'identifiant");
    }

    /// Aller-retour d'un bloc VIDE (le cas le plus courant d'une chaîne au repos).
    #[test]
    fn aller_retour_bloc_vide() {
        let bloc = Bloc::sceller(&[3u8; TAILLE_ID], 7, Vec::new()).unwrap();
        let r = Bloc::from_bytes(&bloc.to_bytes()).expect("aller-retour");
        assert_eq!(r.parent, bloc.parent);
        assert_eq!(r.hauteur, 7);
        assert!(r.transactions.is_empty());
        assert_eq!(r.id(), bloc.id());
        assert_eq!(r.to_bytes(), bloc.to_bytes(), "canonique");
    }

    /// ANTI-DoS : un en-tête annonçant plus de transactions que la borne est rejeté
    /// AVANT allocation. Le test n'envoie QUE l'en-tête — si le code allouait
    /// d'abord, il réserverait de la mémoire pour des octets jamais reçus.
    #[test]
    fn nombre_hors_borne_rejete_sans_allouer() {
        let mut b = vec![VERSION_BLOC];
        b.extend_from_slice(&PAS_DE_PARENT);
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&1_000_000u32.to_le_bytes());
        assert!(matches!(Bloc::from_bytes(&b), Err(BlocDecodeError::TropDeTransactions)));

        let mut juste_au_dessus = b[..b.len() - 4].to_vec();
        juste_au_dessus.extend_from_slice(&((MAX_TX_PAR_BLOC + 1) as u32).to_le_bytes());
        assert!(matches!(Bloc::from_bytes(&juste_au_dessus), Err(BlocDecodeError::TropDeTransactions)));
    }

    /// Bloc vide, version inconnue, troncature, octets résiduels : `Result`, jamais
    /// de panique. C'est un point d'entrée réseau.
    #[test]
    fn blocs_malformes_rejetes_sans_panique() {
        assert!(matches!(Bloc::from_bytes(&[]), Err(BlocDecodeError::Tronque)));
        assert!(matches!(Bloc::from_bytes(&[0x03]), Err(BlocDecodeError::VersionInconnue(0x03))));
        // La version PRÉCÉDENTE est refusée, pas réinterprétée : son encodage n'a pas
        // de compteur d'émissions, le lire comme la version courante ferait dériver
        // toutes les longueurs suivantes.
        assert!(matches!(Bloc::from_bytes(&[0x01]), Err(BlocDecodeError::VersionInconnue(0x01))));
        assert!(matches!(Bloc::from_bytes(&[VERSION_BLOC]), Err(BlocDecodeError::Tronque)));

        let bon = Bloc::sceller(&[1u8; TAILLE_ID], 3, Vec::new()).unwrap().to_bytes();
        assert!(matches!(Bloc::from_bytes(&bon[..bon.len() - 1]), Err(BlocDecodeError::Tronque)));
        let mut trop = bon.clone();
        trop.push(0);
        assert!(matches!(Bloc::from_bytes(&trop), Err(BlocDecodeError::OctetsResiduels)));

        // Une transaction annoncée à une taille délirante : refusée sans allouer.
        let mut menteur = vec![VERSION_BLOC];
        menteur.extend_from_slice(&PAS_DE_PARENT);
        menteur.extend_from_slice(&1u64.to_le_bytes());
        menteur.extend_from_slice(&1u32.to_le_bytes()); // n_tx = 1
        menteur.extend_from_slice(&u32::MAX.to_le_bytes()); // taille annoncée délirante
        assert!(matches!(Bloc::from_bytes(&menteur), Err(BlocDecodeError::Tronque)));
    }

    // ================================================================================
    // ÉMISSIONS
    // ================================================================================

    fn cm(seed: u64) -> Digest {
        Digest(core::array::from_fn(|i| {
            proved_hash::felt::Felt::from_canonical_u64(seed + i as u64).unwrap()
        }))
    }

    /// Aller-retour d'une genèse PORTEUSE d'émissions : l'encodage est canonique et
    /// l'identifiant est stable. Sans cela, deux opérateurs partageant le même fichier
    /// de genèse liraient deux chaînes différentes.
    #[test]
    fn aller_retour_genese_avec_emissions() {
        let emissions: Vec<Emission> = (0..3)
            .map(|i| crate::proved_wallet::emission_factice(&cm(i * 100 + 1)))
            .collect();
        let genese = Bloc::genese_avec(emissions).expect("genèse bornée");
        let octets = genese.to_bytes();

        let relu = Bloc::from_bytes(&octets).expect("aller-retour");
        assert_eq!(relu.emissions.len(), 3);
        assert_eq!(relu.to_bytes(), octets, "canonique");
        assert_eq!(relu.id(), genese.id());
        for (a, b) in relu.emissions.iter().zip(genese.emissions.iter()) {
            assert_eq!(a.commitment.to_bytes(), b.commitment.to_bytes());
            assert_eq!(a.enc_note.kem_ct, b.enc_note.kem_ct);
            assert_eq!(a.enc_note.enc_note, b.enc_note.enc_note);
        }
    }

    /// LES ÉMISSIONS ENTRENT DANS L'IDENTIFIANT DE LA GENÈSE.
    ///
    /// C'est ce qui rend une erreur d'amorçage détectable : deux nœuds paramétrés
    /// différemment n'ont pas la même tête, donc leurs blocs ne s'enchaînent pas. Si
    /// les émissions étaient hors identifiant, deux chaînes aux monnaies initiales
    /// DIFFÉRENTES se croiraient la même et divergeraient silencieusement sur les
    /// racines.
    #[test]
    fn les_emissions_entrent_dans_lidentifiant() {
        let vide = Bloc::genese();
        let une = Bloc::genese_avec(vec![crate::proved_wallet::emission_factice(&cm(1))]).unwrap();
        assert_ne!(vide.id(), une.id());

        // Même commitment, enveloppe factice fraîche ⇒ identifiant différent.
        let autre = Bloc::genese_avec(vec![crate::proved_wallet::emission_factice(&cm(1))]).unwrap();
        assert_ne!(une.id(), autre.id());
    }

    /// UNE ÉMISSION FACTICE EST INDISTINGUABLE D'UNE VRAIE SUR LE FIL.
    ///
    /// Aucun drapeau de présence, aucune longueur qui varie : la seule chose que
    /// l'encodage révèle est « il y a une émission ici ». Un `Option<EncNote>` aurait
    /// partitionné publiquement les feuilles en émises-sans-bénéficiaire et
    /// attribuées, et ce gabarit aurait été recopié le jour d'une coinbase shielded.
    /// Le plafond d'octets EST la capacité réelle d'un bloc, et elle est bien plus
    /// basse que `MAX_TX_PAR_BLOC` : une quinzaine de transactions, pas 512. Ce test
    /// fige le chiffre — s'il bouge, c'est que le format de transaction a changé.
    #[test]
    fn le_plafond_doctets_borne_a_une_quinzaine_de_transactions() {
        // `MAX_OCTETS_BLOC < CADRE_NET` est garanti par l'assertion de COMPILATION
        // en tête de module — pas besoin de le re-tester ici.
        let pour = |n: usize| SURCOUT_BLOC_VIDE + n * cout_transaction(TAILLE_TX_INDICATIVE);
        assert!(pour(15) <= MAX_OCTETS_BLOC, "15 transactions doivent tenir");
        assert!(
            pour(16) > MAX_OCTETS_BLOC,
            "16 doivent déborder : c'est précisément pourquoi le plafond existe,              MAX_TX_PAR_BLOC = {MAX_TX_PAR_BLOC} ne bornant que le NOMBRE"
        );
    }

    #[test]
    fn emission_factice_indistinguable_dune_reelle() {
        use circuit::SpendNote;
        let beneficiaire = crypto::kem::KemKeypair::generate();
        let note = SpendNote { value: 1_000, owner: cm(7), rho: cm(20), r: cm(30) };
        let vrai_cm =
            proved_hash::rescue::note_commitment(note.value, &note.owner, &note.rho, &note.r);

        let reelle =
            crate::proved_wallet::emission_vers(&beneficiaire.public, &vrai_cm, &note).unwrap();
        let factice = crate::proved_wallet::emission_factice(&cm(999));

        assert_eq!(
            reelle.enc_note.kem_ct.len(),
            factice.enc_note.kem_ct.len(),
            "une longueur de kem_ct qui varierait trahirait le type d'émission"
        );
        assert_eq!(
            reelle.enc_note.enc_note.len(),
            factice.enc_note.enc_note.len(),
            "une longueur d'enc_note qui varierait trahirait le type d'émission"
        );
        // Et sur le fil, dans un bloc : même taille d'entrée sérialisée.
        let taille = |e: Emission| Bloc::genese_avec(vec![e]).unwrap().to_bytes().len();
        assert_eq!(taille(reelle), taille(factice));
    }

    /// PERSONNE ne peut déchiffrer une émission factice — pas même celui qui l'a
    /// fabriquée : la moitié secrète de la clé KEM jetable meurt avec l'appel. Une
    /// « émission sans bénéficiaire » chiffrée vers un secret conservé quelque part
    /// serait une réserve cachée, pas un remplissage.
    #[test]
    fn emission_factice_nest_dechiffrable_par_personne() {
        let factice = crate::proved_wallet::emission_factice(&cm(4));
        for _ in 0..4 {
            let curieux = crypto::kem::KemKeypair::generate();
            assert!(
                crate::proved_wallet::scan_proved_output(
                    &curieux,
                    &cm(4),
                    &factice.commitment,
                    &factice.enc_note,
                )
                .is_none(),
                "une émission factice ne doit s'ouvrir pour personne"
            );
        }
    }

    /// ANTI-DoS : le compteur d'émissions est borné AVANT allocation. Le test n'envoie
    /// QUE l'en-tête — si le code allouait d'abord, il réserverait ≈700 Mio pour des
    /// octets jamais reçus.
    #[test]
    fn emissions_hors_borne_rejetees_sans_allouer() {
        let mut b = vec![VERSION_BLOC];
        b.extend_from_slice(&PAS_DE_PARENT);
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // aucune transaction
        b.extend_from_slice(&500_000u32.to_le_bytes()); // émissions annoncées
        assert!(matches!(Bloc::from_bytes(&b), Err(BlocDecodeError::TropDEmissions)));

        let mut juste_au_dessus = b[..b.len() - 4].to_vec();
        juste_au_dessus.extend_from_slice(&((MAX_EMISSIONS_PAR_BLOC + 1) as u32).to_le_bytes());
        assert!(matches!(
            Bloc::from_bytes(&juste_au_dessus),
            Err(BlocDecodeError::TropDEmissions)
        ));
    }

    /// LA MÊME BORNE EXISTE DANS LE CONSTRUCTEUR.
    ///
    /// Une borne qui n'est vérifiée qu'au décodage ne protège que celui qui REÇOIT :
    /// on pourrait fabriquer localement une genèse qu'aucun pair ne saurait relire.
    /// C'est exactement le défaut corrigé pour `Noeud::sceller`.
    #[test]
    fn borne_demissions_aussi_dans_le_constructeur() {
        // Une seule enveloppe fabriquée, recopiée : générer 513 paires KEM serait lent
        // sans rien ajouter à la propriété testée.
        let modele = crate::proved_wallet::emission_factice(&cm(1));
        let trop: Vec<Emission> = (0..=MAX_EMISSIONS_PAR_BLOC).map(|_| modele.clone()).collect();
        assert!(matches!(
            Bloc::genese_avec(trop),
            Err(BlocConstructionError::TropDEmissions { .. })
        ));

        // Et une enveloppe hors bornes est refusée à la construction comme au décodage.
        let mut gonflee = modele.clone();
        gonflee.enc_note.enc_note = vec![0u8; circuit::tx::MAX_ENC_NOTE_LEN + 1];
        assert!(matches!(
            Bloc::genese_avec(vec![gonflee]),
            Err(BlocConstructionError::EmissionHorsBornes(0))
        ));
    }

    /// Une émission malformée sur le fil (kem_ct de mauvaise taille, enc_note gonflée,
    /// commitment non canonique) est refusée avec une erreur qui DÉSIGNE la position —
    /// jamais une panique.
    #[test]
    fn emissions_malformees_rejetees_sans_panique() {
        let entete = |n_em: u32| {
            let mut b = vec![VERSION_BLOC];
            b.extend_from_slice(&PAS_DE_PARENT);
            b.extend_from_slice(&0u64.to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes());
            b.extend_from_slice(&n_em.to_le_bytes());
            b
        };

        // kem_ct de taille non conforme.
        let mut b = entete(1);
        b.extend_from_slice(&cm(1).to_bytes());
        b.extend_from_slice(&(KEM_CT_LEN as u32 - 1).to_le_bytes());
        assert!(matches!(
            Bloc::from_bytes(&b),
            Err(BlocDecodeError::EmissionInvalide(0))
        ));

        // enc_note annoncée au-delà de la borne : refus AVANT de lire les octets.
        let mut b = entete(1);
        b.extend_from_slice(&cm(1).to_bytes());
        b.extend_from_slice(&(KEM_CT_LEN as u32).to_le_bytes());
        b.extend_from_slice(&vec![0u8; KEM_CT_LEN]);
        b.extend_from_slice(&((MAX_ENC_NOTE_LEN + 1) as u32).to_le_bytes());
        assert!(matches!(
            Bloc::from_bytes(&b),
            Err(BlocDecodeError::EmissionInvalide(0))
        ));

        // Commitment NON CANONIQUE (felts ≥ p) : accepté, il ferait diverger le
        // hachage prouvé ou paniquerait plus loin.
        let mut b = entete(1);
        b.extend_from_slice(&[0xFFu8; DIGEST_BYTES]);
        assert!(matches!(
            Bloc::from_bytes(&b),
            Err(BlocDecodeError::EmissionInvalide(0))
        ));

        // Émission tronquée : `Tronque`, pas de panique.
        let mut b = entete(1);
        b.extend_from_slice(&cm(1).to_bytes()[..10]);
        assert!(matches!(Bloc::from_bytes(&b), Err(BlocDecodeError::Tronque)));
    }

    /// `sceller` n'offre AUCUN moyen de glisser une émission : le champ existe mais le
    /// constructeur des blocs ordinaires le laisse vide. Un bloc scellé ne peut donc
    /// pas être refusé pour inflation par accident.
    #[test]
    fn un_bloc_scelle_na_jamais_demission() {
        let b = Bloc::sceller(&[1u8; TAILLE_ID], 9, Vec::new()).unwrap();
        assert!(b.emissions.is_empty());
    }
}
