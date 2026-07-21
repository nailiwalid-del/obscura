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

use circuit::ProvedTx;

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

const VERSION_BLOC: u8 = 0x01;
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
}

impl Bloc {
    /// Bloc de genèse : vide, sans parent. Toutes les chaînes en partent.
    pub fn genese() -> Self {
        Bloc {
            parent: PAS_DE_PARENT,
            hauteur: 0,
            transactions: Vec::new(),
        }
    }

    /// Scelle un bloc à la suite de `parent`.
    ///
    /// « Sceller » et non « miner » : aucun travail n'est fourni, aucune autorité
    /// n'est prouvée. Voir l'avertissement en tête de module.
    pub fn sceller(parent: &[u8; TAILLE_ID], hauteur: u64, transactions: Vec<ProvedTx>) -> Self {
        Bloc {
            parent: *parent,
            hauteur,
            transactions,
        }
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

    /// Encodage canonique : `version ‖ parent ‖ hauteur LE ‖ n LE ‖ [len(txᵢ) LE ‖ txᵢ]`.
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
        if pos != b.len() {
            return Err(BlocDecodeError::OctetsResiduels);
        }
        Ok(Bloc {
            parent,
            hauteur,
            transactions,
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
        let a = Bloc::sceller(&g, 1, Vec::new());
        let b = Bloc::sceller(&g, 2, Vec::new());
        let c = Bloc::sceller(&[9u8; TAILLE_ID], 1, Vec::new());
        assert_ne!(a.id(), b.id(), "la hauteur doit entrer dans l'identifiant");
        assert_ne!(a.id(), c.id(), "le parent doit entrer dans l'identifiant");
    }

    /// Aller-retour d'un bloc VIDE (le cas le plus courant d'une chaîne au repos).
    #[test]
    fn aller_retour_bloc_vide() {
        let bloc = Bloc::sceller(&[3u8; TAILLE_ID], 7, Vec::new());
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
        assert!(matches!(Bloc::from_bytes(&[0x02]), Err(BlocDecodeError::VersionInconnue(0x02))));
        assert!(matches!(Bloc::from_bytes(&[VERSION_BLOC]), Err(BlocDecodeError::Tronque)));

        let bon = Bloc::sceller(&[1u8; TAILLE_ID], 3, Vec::new()).to_bytes();
        assert!(matches!(Bloc::from_bytes(&bon[..bon.len() - 1]), Err(BlocDecodeError::Tronque)));
        let mut trop = bon.clone();
        trop.push(0);
        assert!(matches!(Bloc::from_bytes(&trop), Err(BlocDecodeError::OctetsResiduels)));

        // Une transaction annoncée à une taille délirante : refusée sans allouer.
        let mut menteur = bon[..bon.len() - 4].to_vec();
        menteur.extend_from_slice(&1u32.to_le_bytes());
        menteur.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(Bloc::from_bytes(&menteur), Err(BlocDecodeError::Tronque)));
    }
}
