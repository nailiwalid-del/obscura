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
//! # Qui produit les blocs : l'ÉLECTION DE PRODUCTEUR (v0x03)
//!
//! La genèse peut graver une liste d'AUTORITÉS de scellement (champ `autorites`,
//! dans son identifiant). La règle, appliquée par `ProvedLedgerState::appliquer_bloc` :
//! le producteur légitime de la hauteur h est `autorites[(h−1) mod n]` (tour de
//! rôle), et le bloc porte sa signature de scellement sur l'IDENTIFIANT (champ
//! `scellement` — hors de l'id, sinon circulaire, mais sur le fil). L'unicité du
//! bloc par hauteur est ainsi garantie PAR CONSTRUCTION — indispensable, l'état
//! étant append-only sans réorganisation : il n'existe aucun fork choice pour
//! rattraper une divergence. Liveness = option A, assumée : une autorité absente
//! FIGE la chaîne à son tour (spec « élection de producteur »).
//!
//! Une genèse SANS autorités (le défaut) reste une chaîne OUVERTE : **n'importe qui
//! peut sceller**, ordre CONVENU et non DÉFENDU — mode testnet local.
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
use crypto::sig::{HybridSignature, SigKeypair, SigPublicKey};
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

/// Nombre maximal d'AUTORITÉS de scellement dans une genèse.
///
/// Une clé hybride pèse ~2 Kio : 64 autorités ≈ 128 Kio, loin sous le cadre réseau.
/// Vérifiée AVANT allocation dans `from_bytes` **et** dans le constructeur
/// `Bloc::genese_avec_autorites` (même règle que `MAX_EMISSIONS_PAR_BLOC`).
pub const MAX_AUTORITES: usize = 64;

/// Domaine de la signature de SCELLEMENT d'un bloc par son producteur.
///
/// Signée sur `dual_hash(DOMAINE_SCELLEMENT, id_du_bloc)` : l'identifiant engage
/// déjà parent, hauteur, transactions, émissions et autorités — signer l'id suffit,
/// et rien de nouveau n'entre dans l'id lui-même (sinon la signature serait
/// circulaire).
pub const DOMAINE_SCELLEMENT: &str = "obscura/bloc/scellement/v1";

/// Domaine de signature d'un VOTE de quorum (ADR J1).
///
/// ⚠️ DISTINCT de [`DOMAINE_SCELLEMENT`], et ce n'est pas cosmétique : les deux
/// portent sur le MÊME identifiant de bloc. Sans domaines séparés, le scellement
/// du producteur pourrait être compté comme l'un des votes du quorum, et `2f`
/// votes réels suffiraient à en afficher `2f+1`.
pub const DOMAINE_VOTE: &str = "obscura/bloc/vote/v1";

/// Majorant du coût WIRE du champ scellement : 4 o de longueur + signature hybride
/// (1 + 64 + 3293 = 3358 o en ed25519+dilithium3 round-3). Majoré à 4 Kio pour
/// survivre à une migration FIPS sans recalibrer ; un test épingle la taille réelle.
pub const TAILLE_SCELLEMENT_MAX: usize = 4 + 4096;

/// Majorant d'une clé publique d'autorité sérialisée (1 + 32 + 1952 = 1985 o en
/// round-3) — borne d'allocation au décodage, même marge FIPS que ci-dessus.
pub const TAILLE_AUTORITE_MAX: usize = 4096;

/// Version du format de bloc.
///
/// `0x02` : ajout des émissions. `0x03` : ajout des AUTORITÉS de scellement (genèse),
/// du champ `scellement` (élection de producteur) et de l'EN-TÊTE EXTENSIBLE réservé
/// (vide, verrouillé — la place de la future coinbase). Ce n'est pas cosmétique :
/// l'encodage entrant dans `Bloc::id`, l'identifiant de la genèse VIDE change à
/// chaque passage. Un état dumpé par une version antérieure porte donc une tête
/// périmée — d'où le bump simultané de `proved_state::VERSION_ETAT`, qui le refuse
/// au lieu de le lire de travers.
pub const VERSION_BLOC: u8 = 0x04;
/// Version PÉRIMÉE, refusée par son nom (ADR J1). Aucune chaîne publique n'a
/// existé en `0x03` : il n'y a rien à migrer, et supporter deux versions
/// n'achèterait qu'une surface de confusion.
const VERSION_BLOC_PERIMEE: u8 = 0x03;
const DOMAINE_ID: &str = "obscura/bloc/id/v1";

/// Taille indicative d'une `ProvedTx` **sur le fil** et cadre maximal de
/// `net::frame` (1 Mio ; `ledger` ne dépend pas de `net`, d'où la constante
/// répétée).
///
/// 105 Kio : mesuré (`cargo run --release --example tx_bench -p circuit`), pas
/// estimé. Était 68 Kio avant le durcissement de soundness — passer les requêtes
/// FRI de 32 à 48 a fait grossir la preuve, donc DIMINUÉ le nombre de
/// transactions qu'un bloc diffusable peut porter (~15 → ~9). C'est la
/// conséquence directe et assumée du choix de sécurité.
const TAILLE_TX_INDICATIVE: usize = 105 * 1024;
const CADRE_NET: usize = 1024 * 1024;

/// CONSIGNÉ À LA COMPILATION : un bloc plein ne tient PAS dans un cadre réseau.
///
/// 512 × ~105 Kio ≈ 52 Mio, cinquante fois le cadre de 1 Mio. Acheminer un bloc plein
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
/// `MAX_TX_PAR_BLOC` borne le NOMBRE de transactions, pas leur POIDS : à ≈105 Kio
/// pièce, une dizaine suffit à dépasser le cadre réseau. Un bloc scellé au-delà
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
    #[error("trop d'autorités (borne : {MAX_AUTORITES})")]
    TropDAutorites,
    #[error("autorité indécodable ou hors bornes en position {0}")]
    AutoriteInvalide(usize),
    #[error("certificat de quorum indécodable ou hors bornes")]
    CertificatInvalide,
    #[error("scellement indécodable ou hors bornes")]
    ScellementInvalide,
    #[error(
        "bloc de version {version:#04x} : format PÉRIMÉ, refusé (courant : {VERSION_BLOC:#04x})"
    )]
    VersionPerimee { version: u8 },
    #[error("extension non vide : aucun contenu n'est défini en version {VERSION_BLOC:#04x}")]
    ExtensionInconnue,
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
    #[error("{recues} autorités (borne : {MAX_AUTORITES})")]
    TropDAutorites { recues: usize },
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
/// Certificat de quorum : la preuve que `2f+1` autorités ont vu ce bloc à cette
/// `(hauteur, vue)` (ADR J1).
///
/// # Le masque, et pourquoi il n'y a pas de liste d'index
///
/// Un bit mis = l'autorité de cet index a voté. Huit octets couvrent les 64
/// autorités possibles, mais surtout : **les doublons deviennent structurellement
/// impossibles**. Un bit est mis ou ne l'est pas. Avec une liste d'index, il
/// faudrait dédupliquer — donc pouvoir se tromper, et compter deux fois le même
/// votant pour atteindre le quorum.
///
/// # Pas d'agrégation
///
/// Aucune signature post-quantique n'offre l'agrégation : l'astuce des BFT
/// modernes (BLS) repose sur des couplages, cassés par Shor. Le certificat pèse
/// donc `popcount(masque) × 3374` octets, linéairement. C'est ce qui BORNE la
/// taille du comité — cf. `examples/dimensionner-quorum.rs`.
///
/// Ni `Debug` ni `PartialEq` : `HybridSignature` ne les offre pas, et un
/// certificat se compare par son masque et la validité de ses signatures, jamais
/// par égalité structurelle.
#[derive(Clone)]
pub struct Certificat {
    /// Bit `i` mis = l'autorité d'index `i` a voté.
    pub masque: u64,
    /// Une signature par bit mis, dans l'ORDRE CROISSANT des index.
    pub signatures: Vec<HybridSignature>,
}

impl Certificat {
    /// Index des votants, croissants et sans doublon par construction.
    pub fn votants(&self) -> impl Iterator<Item = usize> + '_ {
        let masque = self.masque;
        (0..64).filter(move |i| masque & (1u64 << i) != 0)
    }

    /// Nombre de votants annoncés par le masque.
    pub fn nombre_de_votants(&self) -> usize {
        self.masque.count_ones() as usize
    }

    /// Encodage : `masque LE (8) ‖ [len(sigᵢ) LE ‖ sigᵢ]`.
    ///
    /// Le NOMBRE de signatures n'est pas encodé : il est DÉRIVÉ du masque. Un
    /// décodeur qui accepterait les deux se ferait servir deux encodages du même
    /// certificat, et la canonicité tomberait.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = self.masque.to_le_bytes().to_vec();
        for sig in &self.signatures {
            let o = sig.to_bytes();
            b.extend_from_slice(&(o.len() as u32).to_le_bytes());
            b.extend_from_slice(&o);
        }
        b
    }

    /// Décode, borné AVANT allocation : le nombre de signatures vient du masque,
    /// lui-même borné par [`MAX_AUTORITES`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, BlocDecodeError> {
        if b.len() < 8 {
            return Err(BlocDecodeError::Tronque);
        }
        let masque = u64::from_le_bytes(b[..8].try_into().expect("8 octets"));
        let attendu = masque.count_ones() as usize;
        if attendu > MAX_AUTORITES {
            return Err(BlocDecodeError::CertificatInvalide);
        }
        let mut signatures = Vec::with_capacity(attendu);
        let mut pos = 8usize;
        for _ in 0..attendu {
            if pos + 4 > b.len() {
                return Err(BlocDecodeError::Tronque);
            }
            let n = u32::from_le_bytes(b[pos..pos + 4].try_into().expect("4 octets")) as usize;
            pos += 4;
            if n == 0 || n > TAILLE_SCELLEMENT_MAX {
                return Err(BlocDecodeError::CertificatInvalide);
            }
            let fin = pos.checked_add(n).ok_or(BlocDecodeError::Tronque)?;
            if fin > b.len() {
                return Err(BlocDecodeError::Tronque);
            }
            signatures.push(
                HybridSignature::from_bytes(&b[pos..fin])
                    .map_err(|_| BlocDecodeError::CertificatInvalide)?,
            );
            pos = fin;
        }
        if pos != b.len() {
            return Err(BlocDecodeError::OctetsResiduels);
        }
        Ok(Certificat { masque, signatures })
    }
}

pub struct Bloc {
    /// Identifiant du bloc parent, ou `PAS_DE_PARENT` pour la genèse.
    pub parent: [u8; TAILLE_ID],
    /// Hauteur dans la chaîne (genèse = 0). Redondante avec le chaînage, et gardée
    /// exprès : elle rend un refus de bloc EXPLICABLE (« hauteur 7 attendue, 12
    /// reçue ») là où un simple parent inconnu ne dirait pas si le nœud est en
    /// retard ou face à une autre chaîne.
    pub hauteur: u64,
    /// VUE du consensus : numéro de tentative à cette hauteur (ADR J1, point 3).
    ///
    /// **Entre dans l'identifiant.** Deux vues produisent deux blocs DIFFÉRENTS,
    /// jamais deux encodages du même — c'est la canonicité, et c'est ce qui permet
    /// au certificat de quorum de porter sur `(hauteur, vue)` sans ambiguïté.
    ///
    /// `0` en fonctionnement nominal, donc sur tout l'existant. Elle n'augmente que
    /// lorsque l'autorité du tour ne répond pas — mécanisme livré par J1-b.
    pub vue: u32,
    /// Les transactions, dans l'ordre d'application. **C'est tout l'objet du bloc.**
    pub transactions: Vec<ProvedTx>,
    /// Les émissions. **Doit être vide dès que `hauteur > 0`** — règle de consensus
    /// appliquée par `ProvedLedgerState::appliquer_bloc`, contrôle O(1) placé avant
    /// toute vérification coûteuse.
    pub emissions: Vec<Emission>,
    /// Les AUTORITÉS de scellement de la chaîne — **genèse seulement**, même règle
    /// que `emissions` (`hauteur > 0 ⇒ autorites.is_empty()`). Liste VIDE = chaîne
    /// OUVERTE (tout nœud peut sceller — mode testnet local, l'état actuel du
    /// prototype) ; liste non vide = tour de rôle par hauteur, bloc signé exigé.
    /// La liste entre dans l'IDENTIFIANT de la genèse : deux réseaux aux autorités
    /// différentes sont deux chaînes distinctes dès l'octet zéro.
    pub autorites: Vec<SigPublicKey>,
    /// EN-TÊTE EXTENSIBLE — la place RÉSERVÉE d'une future coinbase prouvée et d'un
    /// collecteur de frais (plan Testnet 0, T2). **Obligatoirement VIDE en 0x03** :
    /// son contenu n'est défini par aucune règle, donc `from_bytes` refuse le
    /// moindre octet (fail-closed). Le champ entre dans l'IDENTIFIANT : le jour où
    /// une version le remplit, son contenu est engagé sans déplacer un seul champ
    /// existant — ajouter la coinbase ne refondra pas le format.
    pub extension: Vec<u8>,
    /// Signature de SCELLEMENT du producteur, sur l'identifiant du bloc.
    ///
    /// HORS de l'identifiant (sinon circulaire) mais SUR le fil. `None` pour la
    /// genèse (elle amorce, personne ne la produit) et sur une chaîne ouverte ;
    /// exigée par `appliquer_bloc` dès que la chaîne a des autorités.
    pub scellement: Option<HybridSignature>,
    /// CERTIFICAT DE QUORUM (ADR J1). **Hors de l'identifiant**, comme le
    /// scellement : une signature portant SUR l'identifiant ne peut pas y entrer.
    ///
    /// `None` sur une chaîne ouverte et sur la genèse — qui n'a pas de quorum,
    /// elle amorce. Exigé par `appliquer_bloc` dès que la chaîne a des autorités.
    pub certificat: Option<Certificat>,
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
            vue: 0,
            transactions: Vec::new(),
            emissions: Vec::new(),
            autorites: Vec::new(),
            extension: Vec::new(),
            scellement: None,
            certificat: None,
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
        Self::genese_avec_autorites(emissions, Vec::new())
    }

    /// Genèse paramétrée AVEC autorités de scellement : la seule façon de fermer le
    /// droit de sceller. Liste vide = chaîne OUVERTE (comportement historique).
    ///
    /// La borne `MAX_AUTORITES` est vérifiée ICI et pas seulement au décodage — même
    /// règle que pour les émissions (une borne de `from_bytes` doit exister aussi
    /// dans le constructeur).
    pub fn genese_avec_autorites(
        emissions: Vec<Emission>,
        autorites: Vec<SigPublicKey>,
    ) -> Result<Self, BlocConstructionError> {
        if emissions.len() > MAX_EMISSIONS_PAR_BLOC {
            return Err(BlocConstructionError::TropDEmissions {
                recues: emissions.len(),
            });
        }
        if let Some(i) = emissions.iter().position(|e| !e.enc_note.within_bounds()) {
            return Err(BlocConstructionError::EmissionHorsBornes(i));
        }
        if autorites.len() > MAX_AUTORITES {
            return Err(BlocConstructionError::TropDAutorites {
                recues: autorites.len(),
            });
        }
        Ok(Bloc {
            parent: PAS_DE_PARENT,
            hauteur: 0,
            vue: 0,
            transactions: Vec::new(),
            emissions,
            autorites,
            extension: Vec::new(),
            scellement: None,
            certificat: None,
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
            autorites: Vec::new(),
            vue: 0,
            extension: Vec::new(),
            scellement: None,
            certificat: None,
        };
        // Budget vérifié SCELLEMENT COMPRIS : le champ pèse ~4,7 Kio une fois signé,
        // et la borne doit couvrir le bloc tel qu'il partira sur le fil.
        let octets = bloc.to_bytes().len() + TAILLE_SCELLEMENT_MAX;
        if octets > MAX_OCTETS_BLOC {
            return Err(BlocConstructionError::TropDOctets { octets });
        }
        Ok(bloc)
    }

    /// Signe le scellement du bloc avec l'identité du producteur.
    ///
    /// À appeler APRÈS `sceller` (l'identifiant est celui du corps, la signature
    /// n'y entre pas — la re-signer ne change pas l'id, cf. test dédié).
    pub fn signer_scellement(&mut self, identite: &SigKeypair) {
        let id = self.id();
        self.scellement = Some(identite.sign(DOMAINE_SCELLEMENT, &id));
    }

    /// Ajoute le VOTE de l'autorité d'index `index` au certificat du bloc.
    ///
    /// Les votes sont rangés dans l'ordre croissant des index, et le masque garantit
    /// qu'un même index ne peut pas voter deux fois — un second appel avec le même
    /// index remplace le vote plutôt que de le dupliquer.
    ///
    /// ⚠️ À appeler APRÈS `sceller` : le vote porte sur l'identifiant, qui n'inclut
    /// ni le scellement ni le certificat. Ajouter un vote ne change donc pas l'`id`,
    /// et les votes des autres restent valides.
    pub fn signer_vote(&mut self, index: usize, identite: &SigKeypair) {
        debug_assert!(index < MAX_AUTORITES, "index de votant hors borne");
        let id = self.id();
        let sig = identite.sign(DOMAINE_VOTE, &id);
        let mut c = self.certificat.take().unwrap_or(Certificat {
            masque: 0,
            signatures: Vec::new(),
        });
        // Rang d'insertion = nombre de bits déjà mis SOUS `index`.
        let rang = (c.masque & ((1u64 << index) - 1)).count_ones() as usize;
        if c.masque & (1u64 << index) != 0 {
            c.signatures[rang] = sig;
        } else {
            c.masque |= 1u64 << index;
            c.signatures.insert(rang, sig);
        }
        self.certificat = Some(c);
    }

    /// Vérifie le scellement contre la clé d'UN producteur attendu.
    pub fn verifier_scellement(&self, attendu: &SigPublicKey) -> bool {
        match &self.scellement {
            Some(sig) => crypto::sig::verify(attendu, DOMAINE_SCELLEMENT, &self.id(), sig),
            None => false,
        }
    }

    /// Identifiant du bloc = `dual_hash` de son CORPS canonique (tout SAUF le
    /// scellement — signer l'id serait sinon circulaire).
    ///
    /// L'encodage étant canonique et injectif, deux blocs de même identifiant ont le
    /// même parent, la même hauteur, les mêmes transactions dans le même ordre — et
    /// les mêmes autorités pour une genèse. Réordonner les transactions change
    /// l'identifiant — ce qui est le but : c'est l'ORDRE qu'on veut rendre
    /// infalsifiable.
    pub fn id(&self) -> [u8; TAILLE_ID] {
        crypto::hash::dual_hash(DOMAINE_ID, &self.corps_bytes())
    }

    /// CORPS canonique (ce que l'identifiant engage) : `version ‖ parent ‖ hauteur LE
    /// ‖ n LE ‖ [len(txᵢ) LE ‖ txᵢ] ‖ m LE ‖ [cmⱼ ‖ len(kem_ctⱼ) LE ‖ kem_ctⱼ ‖
    /// len(enc_noteⱼ) LE ‖ enc_noteⱼ] ‖ a LE ‖ [len(pkₖ) LE ‖ pkₖ]`.
    ///
    /// Les émissions sont encodées SANS drapeau de présence : une émission factice a
    /// exactement la même forme et la même longueur qu'une émission destinée à
    /// quelqu'un (cf. tête de module).
    fn corps_bytes(&self) -> Vec<u8> {
        let mut b = vec![VERSION_BLOC];
        b.extend_from_slice(&self.parent);
        b.extend_from_slice(&self.hauteur.to_le_bytes());
        b.extend_from_slice(&self.vue.to_le_bytes());
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
        b.extend_from_slice(&(self.autorites.len() as u32).to_le_bytes());
        for pk in &self.autorites {
            let o = pk.to_bytes();
            b.extend_from_slice(&(o.len() as u32).to_le_bytes());
            b.extend_from_slice(&o);
        }
        // En-tête extensible (réservé, vide en 0x03) — DANS le corps, donc engagé
        // par l'identifiant.
        b.extend_from_slice(&(self.extension.len() as u32).to_le_bytes());
        b.extend_from_slice(&self.extension);
        b
    }

    /// Encodage WIRE : le corps, suivi du scellement (longueur-préfixé, `0` =
    /// absent). Le scellement est HORS du corps — donc hors de l'identifiant.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = self.corps_bytes();
        match &self.scellement {
            Some(sig) => {
                let o = sig.to_bytes();
                b.extend_from_slice(&(o.len() as u32).to_le_bytes());
                b.extend_from_slice(&o);
            }
            None => b.extend_from_slice(&0u32.to_le_bytes()),
        }
        // Certificat de quorum, même style que le scellement : longueur préfixée,
        // `0` = absent. HORS du corps, donc hors de l'identifiant.
        match &self.certificat {
            Some(c) => {
                let o = c.to_bytes();
                b.extend_from_slice(&(o.len() as u32).to_le_bytes());
                b.extend_from_slice(&o);
            }
            None => b.extend_from_slice(&0u32.to_le_bytes()),
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
        if version == VERSION_BLOC_PERIMEE {
            return Err(BlocDecodeError::VersionPerimee { version });
        }
        if version != VERSION_BLOC {
            return Err(BlocDecodeError::VersionInconnue(version));
        }
        let parent: [u8; TAILLE_ID] = prendre(b, &mut pos, TAILLE_ID)?
            .try_into()
            .map_err(|_| BlocDecodeError::Tronque)?;
        let hauteur = u64::from_le_bytes(prendre(b, &mut pos, 8)?.try_into().unwrap());
        let vue = u32::from_le_bytes(prendre(b, &mut pos, 4)?.try_into().unwrap());

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
                ProvedTx::from_bytes(octets)
                    .map_err(|_| BlocDecodeError::TransactionInvalide(i))?,
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

        let a = u32::from_le_bytes(prendre(b, &mut pos, 4)?.try_into().unwrap()) as usize;
        // Borne AVANT allocation, comme partout ailleurs dans ce décodeur.
        if a > MAX_AUTORITES {
            return Err(BlocDecodeError::TropDAutorites);
        }
        let mut autorites = Vec::with_capacity(a);
        for k in 0..a {
            let lp = u32::from_le_bytes(prendre(b, &mut pos, 4)?.try_into().unwrap()) as usize;
            if lp > TAILLE_AUTORITE_MAX {
                return Err(BlocDecodeError::AutoriteInvalide(k));
            }
            let pk = SigPublicKey::from_bytes(prendre(b, &mut pos, lp)?)
                .map_err(|_| BlocDecodeError::AutoriteInvalide(k))?;
            autorites.push(pk);
        }

        // En-tête extensible : RÉSERVÉ, donc verrouillé VIDE — aucun contenu n'est
        // défini en 0x03, le moindre octet est refusé (fail-closed, avant allocation).
        let lx = u32::from_le_bytes(prendre(b, &mut pos, 4)?.try_into().unwrap()) as usize;
        if lx != 0 {
            return Err(BlocDecodeError::ExtensionInconnue);
        }

        let ls = u32::from_le_bytes(prendre(b, &mut pos, 4)?.try_into().unwrap()) as usize;
        let scellement = if ls == 0 {
            None
        } else {
            if ls > TAILLE_SCELLEMENT_MAX {
                return Err(BlocDecodeError::ScellementInvalide);
            }
            Some(
                HybridSignature::from_bytes(prendre(b, &mut pos, ls)?)
                    .map_err(|_| BlocDecodeError::ScellementInvalide)?,
            )
        };

        let lc = u32::from_le_bytes(prendre(b, &mut pos, 4)?.try_into().unwrap()) as usize;
        let certificat = if lc == 0 {
            None
        } else {
            // Majorant : masque + MAX_AUTORITES signatures longueur-préfixées.
            if lc > 8 + MAX_AUTORITES * (4 + TAILLE_SCELLEMENT_MAX) {
                return Err(BlocDecodeError::CertificatInvalide);
            }
            Some(Certificat::from_bytes(prendre(b, &mut pos, lc)?)?)
        };

        if pos != b.len() {
            return Err(BlocDecodeError::OctetsResiduels);
        }
        Ok(Bloc {
            parent,
            hauteur,
            vue,
            transactions,
            emissions,
            autorites,
            extension: Vec::new(),
            scellement,
            certificat,
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

    /// Les AUTORITÉS entrent dans l'identifiant de la genèse (deux réseaux aux
    /// autorités différentes = deux chaînes dès l'octet zéro) et survivent au fil.
    #[test]
    fn autorites_dans_lidentifiant_et_sur_le_fil() {
        let a = SigKeypair::generate();
        let b = SigKeypair::generate();
        let g0 = Bloc::genese();
        let g2 = Bloc::genese_avec_autorites(Vec::new(), vec![a.public.clone(), b.public.clone()])
            .unwrap();
        assert_ne!(
            g0.id(),
            g2.id(),
            "les autorités doivent entrer dans l'identifiant"
        );

        let relu = Bloc::from_bytes(&g2.to_bytes()).expect("genèse à autorités décodable");
        assert_eq!(relu.id(), g2.id(), "aller-retour à identifiant stable");
        assert_eq!(
            relu.autorites.len(),
            2,
            "les autorités doivent survivre au fil"
        );
        assert_eq!(relu.autorites[0].to_bytes(), a.public.to_bytes());
        assert_eq!(relu.autorites[1].to_bytes(), b.public.to_bytes());
    }

    /// Le SCELLEMENT circule sur le fil mais n'entre PAS dans l'identifiant
    /// (signer l'id serait sinon circulaire).
    #[test]
    fn scellement_sur_le_fil_mais_hors_de_lidentifiant() {
        let identite = SigKeypair::generate();
        let parent = Bloc::genese().id();
        let mut bloc = Bloc::sceller(&parent, 1, Vec::new()).unwrap();
        let id_avant = bloc.id();

        bloc.signer_scellement(&identite);
        assert_eq!(
            bloc.id(),
            id_avant,
            "la signature ne doit pas entrer dans l'id"
        );
        assert!(bloc.verifier_scellement(&identite.public));
        assert!(
            !bloc.verifier_scellement(&SigKeypair::generate().public),
            "une autre clé ne doit pas vérifier"
        );

        let relu = Bloc::from_bytes(&bloc.to_bytes()).expect("bloc scellé décodable");
        assert_eq!(relu.id(), id_avant);
        assert!(
            relu.verifier_scellement(&identite.public),
            "le scellement doit survivre au fil"
        );

        // Et un bloc NON scellé ne vérifie jamais.
        let nu = Bloc::sceller(&parent, 1, Vec::new()).unwrap();
        assert!(!nu.verifier_scellement(&identite.public));
    }

    /// La borne d'autorités vit dans le CONSTRUCTEUR et au DÉCODAGE — même règle
    /// que les émissions (une borne de `from_bytes` doit exister aussi côté
    /// fabricant).
    #[test]
    fn trop_dautorites_refusees_des_deux_cotes() {
        let pk = SigKeypair::generate().public;
        let trop: Vec<SigPublicKey> = (0..MAX_AUTORITES + 1).map(|_| pk.clone()).collect();
        assert!(matches!(
            Bloc::genese_avec_autorites(Vec::new(), trop.clone()),
            Err(BlocConstructionError::TropDAutorites { .. })
        ));

        // Bloc HOSTILE par littéral (le constructeur refuserait) : le décodeur doit
        // refuser AVANT allocation.
        let hostile = Bloc {
            parent: PAS_DE_PARENT,
            hauteur: 0,
            vue: 0,
            transactions: Vec::new(),
            emissions: Vec::new(),
            autorites: trop,
            extension: Vec::new(),
            scellement: None,
            certificat: None,
        };
        assert!(matches!(
            Bloc::from_bytes(&hostile.to_bytes()),
            Err(BlocDecodeError::TropDAutorites)
        ));
    }

    /// L'EN-TÊTE EXTENSIBLE est réservé (dans l'identifiant) et VERROUILLÉ VIDE :
    /// aucun contenu n'est défini en 0x03, donc le moindre octet est refusé au
    /// décodage — fail-closed. Le jour où une version le remplit (coinbase,
    /// collecteur de frais), son contenu sera engagé sans déplacer un champ.
    /// Certificat SYNTHÉTIQUE : signatures valides EN FORME, sans rapport avec un
    /// bloc réel. Suffit à éprouver l'ENCODAGE ; la vérification est ailleurs.
    fn certificat_de_test(masque: u64, combien: usize) -> Certificat {
        let k = SigKeypair::generate();
        Certificat {
            masque,
            signatures: (0..combien)
                .map(|i| k.sign(DOMAINE_VOTE, &[i as u8]))
                .collect(),
        }
    }

    /// L'encodage est CANONIQUE : le nombre de signatures est DÉRIVÉ du masque,
    /// jamais annoncé. Un décodeur qui accepterait les deux se ferait servir deux
    /// encodages du même certificat.
    #[test]
    fn certificat_nombre_de_signatures_derive_du_masque() {
        let c = certificat_de_test(0b1011, 3);
        let relu = Certificat::from_bytes(&c.to_bytes()).expect("décodable");
        assert_eq!(relu.masque, 0b1011);
        assert_eq!(relu.signatures.len(), 3);
        assert_eq!(relu.votants().collect::<Vec<_>>(), vec![0, 1, 3]);
        assert_eq!(relu.nombre_de_votants(), 3);
    }

    /// Masque et nombre de signatures INCOHÉRENTS : le décodage échoue. Ici le
    /// masque annonce deux votants alors que trois signatures suivent — les octets
    /// résiduels trahissent le mensonge.
    #[test]
    fn certificat_incoherent_refuse() {
        let c = certificat_de_test(0b1011, 3);
        let mut o = c.to_bytes();
        o[0] = 0b0011;
        assert!(matches!(
            Certificat::from_bytes(&o),
            Err(BlocDecodeError::OctetsResiduels)
        ));
    }

    /// Un masque désignant plus d'autorités que la borne : refusé AVANT allocation.
    #[test]
    fn certificat_masque_hors_borne_refuse() {
        let mut o = u64::MAX.to_le_bytes().to_vec(); // 64 bits mis
        o.extend_from_slice(&[0u8; 4]);
        // 64 == MAX_AUTORITES, donc accepté au comptage puis tronqué faute de
        // signatures. Le point du test est l'ABSENCE DE PANIQUE et l'absence
        // d'allocation démesurée.
        assert!(Certificat::from_bytes(&o).is_err());
    }

    /// Certificat vide, tronqué, ou à signature de longueur nulle : jamais de panique.
    #[test]
    fn certificats_malformes_sans_panique() {
        assert!(matches!(
            Certificat::from_bytes(&[]),
            Err(BlocDecodeError::Tronque)
        ));
        assert!(matches!(
            Certificat::from_bytes(&[0u8; 7]),
            Err(BlocDecodeError::Tronque)
        ));
        // Masque à un votant, longueur de signature nulle.
        let mut o = 1u64.to_le_bytes().to_vec();
        o.extend_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            Certificat::from_bytes(&o),
            Err(BlocDecodeError::CertificatInvalide)
        ));
    }

    /// Un bloc PORTE son certificat sur le fil, et l'identifiant n'en dépend PAS —
    /// une signature sur l'identifiant ne peut pas y entrer.
    #[test]
    fn certificat_sur_le_fil_hors_de_lidentifiant() {
        let genese = Bloc::genese();
        let mut b = Bloc::sceller(&genese.id(), 1, Vec::new()).unwrap();
        let sans = b.id();
        b.certificat = Some(certificat_de_test(0b111, 3));
        assert_eq!(b.id(), sans, "le certificat n'entre pas dans l'identifiant");
        let relu = Bloc::from_bytes(&b.to_bytes()).expect("décodable");
        assert_eq!(relu.certificat.as_ref().map(|c| c.masque), Some(0b111));
        assert_eq!(relu.id(), sans);
    }

    /// Un bloc SANS certificat reste décodable (genèse, chaîne ouverte).
    #[test]
    fn bloc_sans_certificat_decodable() {
        let b = Bloc::genese();
        assert!(b.certificat.is_none());
        assert!(Bloc::from_bytes(&b.to_bytes())
            .unwrap()
            .certificat
            .is_none());
    }

    /// La VUE entre dans l'IDENTIFIANT : deux vues donnent deux blocs, jamais deux
    /// encodages du même. Sans cela, un producteur présenterait le même bloc sous
    /// deux vues et la canonicité — que tout le projet défend — tomberait.
    #[test]
    fn la_vue_entre_dans_l_identifiant() {
        let genese = Bloc::genese();
        let a = Bloc::sceller(&genese.id(), 1, Vec::new()).unwrap();
        let mut b = Bloc::sceller(&genese.id(), 1, Vec::new()).unwrap();
        b.vue = 1;
        assert_ne!(a.id(), b.id(), "la vue doit changer l'identifiant");
    }

    /// Un bloc de l'ANCIENNE version est refusé par une variante QUI LE NOMME,
    /// jamais réinterprété comme un 0x04 mal formé.
    #[test]
    fn version_0x03_refusee_par_son_nom() {
        let mut octets = Bloc::genese().to_bytes();
        octets[0] = 0x03;
        assert!(matches!(
            Bloc::from_bytes(&octets),
            Err(BlocDecodeError::VersionPerimee { version: 0x03 })
        ));
    }

    /// Aller-retour wire avec une vue non nulle : la vue survit, l'identifiant aussi.
    #[test]
    fn aller_retour_avec_vue() {
        let genese = Bloc::genese();
        let mut b = Bloc::sceller(&genese.id(), 1, Vec::new()).unwrap();
        b.vue = 7;
        let relu = Bloc::from_bytes(&b.to_bytes()).expect("décodable");
        assert_eq!(relu.vue, 7);
        assert_eq!(relu.id(), b.id());
    }

    #[test]
    fn extension_reservee_et_verrouillee_vide() {
        let bloc = Bloc::sceller(&PAS_DE_PARENT, 1, Vec::new()).unwrap();
        assert!(bloc.extension.is_empty());
        let relu = Bloc::from_bytes(&bloc.to_bytes()).expect("bloc décodable");
        assert!(relu.extension.is_empty());
        assert_eq!(relu.id(), bloc.id());

        // Bloc HOSTILE à extension non vide : refusé au décodage.
        let mut hostile = Bloc::sceller(&PAS_DE_PARENT, 1, Vec::new()).unwrap();
        hostile.extension = vec![1, 2, 3];
        assert!(matches!(
            Bloc::from_bytes(&hostile.to_bytes()),
            Err(BlocDecodeError::ExtensionInconnue)
        ));

        // Et le champ est ENGAGÉ par l'identifiant.
        let mut autre = Bloc::sceller(&PAS_DE_PARENT, 1, Vec::new()).unwrap();
        autre.extension = vec![9];
        assert_ne!(
            autre.id(),
            bloc.id(),
            "l'extension entre dans l'identifiant"
        );
    }

    /// Les majorants wire (`TAILLE_SCELLEMENT_MAX`, `TAILLE_AUTORITE_MAX`) couvrent
    /// les tailles RÉELLES des primitives round-3 — épinglées ici pour qu'une
    /// migration FIPS qui les ferait déborder casse un test au lieu du décodage.
    #[test]
    fn majorants_wire_couvrent_les_tailles_reelles() {
        let kp = SigKeypair::generate();
        let sig = kp.sign(DOMAINE_SCELLEMENT, b"mesure");
        assert!(4 + sig.to_bytes().len() <= TAILLE_SCELLEMENT_MAX);
        assert!(kp.public.to_bytes().len() <= TAILLE_AUTORITE_MAX);
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
        // VUE (0x04) : l'en-tête fabriqué à la main doit la porter, sinon le
        // décodeur lit la vue là où ce test croyait écrire un compteur.
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&1_000_000u32.to_le_bytes());
        assert!(matches!(
            Bloc::from_bytes(&b),
            Err(BlocDecodeError::TropDeTransactions)
        ));

        let mut juste_au_dessus = b[..b.len() - 4].to_vec();
        juste_au_dessus.extend_from_slice(&((MAX_TX_PAR_BLOC + 1) as u32).to_le_bytes());
        assert!(matches!(
            Bloc::from_bytes(&juste_au_dessus),
            Err(BlocDecodeError::TropDeTransactions)
        ));
    }

    /// Bloc vide, version inconnue, troncature, octets résiduels : `Result`, jamais
    /// de panique. C'est un point d'entrée réseau.
    #[test]
    fn blocs_malformes_rejetes_sans_panique() {
        assert!(matches!(
            Bloc::from_bytes(&[]),
            Err(BlocDecodeError::Tronque)
        ));
        // Une version FUTURE est inconnue, pas périmée.
        assert!(matches!(
            Bloc::from_bytes(&[0x05]),
            Err(BlocDecodeError::VersionInconnue(0x05))
        ));
        // Les versions PRÉCÉDENTES sont refusées, pas réinterprétées : le 0x01 n'a
        // pas de compteur d'émissions, le 0x02 ni autorités ni scellement, le 0x03
        // pas de vue — les lire comme la version courante ferait dériver toutes les
        // longueurs suivantes.
        assert!(matches!(
            Bloc::from_bytes(&[0x01]),
            Err(BlocDecodeError::VersionInconnue(0x01))
        ));
        assert!(matches!(
            Bloc::from_bytes(&[0x02]),
            Err(BlocDecodeError::VersionInconnue(0x02))
        ));
        // Le 0x03 est la version IMMÉDIATEMENT précédente : refusée par une variante
        // qui la NOMME, pour qu'un opérateur sache qu'il a un artefact périmé et non
        // un fichier corrompu.
        assert!(matches!(
            Bloc::from_bytes(&[0x03]),
            Err(BlocDecodeError::VersionPerimee { version: 0x03 })
        ));
        assert!(matches!(
            Bloc::from_bytes(&[VERSION_BLOC]),
            Err(BlocDecodeError::Tronque)
        ));

        let bon = Bloc::sceller(&[1u8; TAILLE_ID], 3, Vec::new())
            .unwrap()
            .to_bytes();
        assert!(matches!(
            Bloc::from_bytes(&bon[..bon.len() - 1]),
            Err(BlocDecodeError::Tronque)
        ));
        let mut trop = bon.clone();
        trop.push(0);
        assert!(matches!(
            Bloc::from_bytes(&trop),
            Err(BlocDecodeError::OctetsResiduels)
        ));

        // Une transaction annoncée à une taille délirante : refusée sans allouer.
        let mut menteur = vec![VERSION_BLOC];
        menteur.extend_from_slice(&PAS_DE_PARENT);
        menteur.extend_from_slice(&1u64.to_le_bytes());
        menteur.extend_from_slice(&0u32.to_le_bytes()); // vue
        menteur.extend_from_slice(&1u32.to_le_bytes()); // n_tx = 1
        menteur.extend_from_slice(&u32::MAX.to_le_bytes()); // taille annoncée délirante
        assert!(matches!(
            Bloc::from_bytes(&menteur),
            Err(BlocDecodeError::Tronque)
        ));
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
        let autre =
            Bloc::genese_avec(vec![crate::proved_wallet::emission_factice(&cm(1))]).unwrap();
        assert_ne!(une.id(), autre.id());
    }

    /// UNE ÉMISSION FACTICE EST INDISTINGUABLE D'UNE VRAIE SUR LE FIL.
    ///
    /// Aucun drapeau de présence, aucune longueur qui varie : la seule chose que
    /// l'encodage révèle est « il y a une émission ici ». Un `Option<EncNote>` aurait
    /// partitionné publiquement les feuilles en émises-sans-bénéficiaire et
    /// attribuées, et ce gabarit aurait été recopié le jour d'une coinbase shielded.
    /// Le plafond d'octets EST la capacité réelle d'un bloc, et elle est bien plus
    /// basse que `MAX_TX_PAR_BLOC` : une dizaine de transactions, pas 512. Ce test
    /// fige le chiffre — s'il bouge, c'est que le format de transaction a changé.
    #[test]
    fn le_plafond_doctets_borne_a_une_dizaine_de_transactions() {
        // `MAX_OCTETS_BLOC < CADRE_NET` est garanti par l'assertion de COMPILATION
        // en tête de module — pas besoin de le re-tester ici.
        let pour = |n: usize| SURCOUT_BLOC_VIDE + n * cout_transaction(TAILLE_TX_INDICATIVE);
        assert!(pour(9) <= MAX_OCTETS_BLOC, "9 transactions doivent tenir");
        assert!(
            pour(10) > MAX_OCTETS_BLOC,
            "10 doivent déborder : c'est précisément pourquoi le plafond existe,              MAX_TX_PAR_BLOC = {MAX_TX_PAR_BLOC} ne bornant que le NOMBRE"
        );
    }

    #[test]
    fn emission_factice_indistinguable_dune_reelle() {
        use circuit::SpendNote;
        let beneficiaire = crypto::kem::KemKeypair::generate();
        let note = SpendNote {
            value: 1_000,
            owner: cm(7),
            rho: cm(20),
            r: cm(30),
        };
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
        // VUE (0x04) : l'en-tête fabriqué à la main doit la porter, sinon le
        // décodeur lit la vue là où ce test croyait écrire un compteur.
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // aucune transaction
        b.extend_from_slice(&500_000u32.to_le_bytes()); // émissions annoncées
        assert!(matches!(
            Bloc::from_bytes(&b),
            Err(BlocDecodeError::TropDEmissions)
        ));

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
        let trop: Vec<Emission> = (0..=MAX_EMISSIONS_PAR_BLOC)
            .map(|_| modele.clone())
            .collect();
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
            b.extend_from_slice(&0u32.to_le_bytes()); // vue
            b.extend_from_slice(&0u32.to_le_bytes()); // n_tx
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
        assert!(matches!(
            Bloc::from_bytes(&b),
            Err(BlocDecodeError::Tronque)
        ));
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
