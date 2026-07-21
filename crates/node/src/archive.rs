//! Archive des blocs récents : de quoi RÉPONDRE à un pair qui a manqué une hauteur.
//!
//! # Pourquoi ce module existe
//!
//! `ProvedLedgerState` est append-only et ne garde que le bord droit de l'arbre : une
//! fois un bloc appliqué, plus rien dans l'état ne permet de le reproduire. Un nœud
//! qui manquait UN bloc restait donc figé pour toujours — et, pire, il servait un
//! historique plus court mais parfaitement COHÉRENT : tout wallet qui s'y
//! synchronisait concluait à tort qu'il était à jour. Le compteur `blocs_desaccordes`
//! rendait l'état visible ; il ne le réparait pas.
//!
//! Rattraper suppose que QUELQU'UN puisse re-servir la hauteur manquante. C'est le
//! seul rôle de ce module.
//!
//! # Ce stockage est BORNÉ, et distinct de l'état de consensus
//!
//! Contrainte de `docs/THREAT_MODEL.md` : l'état de consensus reste borné (frontier).
//! L'archive ne l'élargit pas — elle vit à côté, elle n'entre dans aucune règle de
//! validation, et un nœud qui la vide reste parfaitement valide (il ne peut
//! simplement plus aider personne à rattraper).
//!
//! Elle est bornée **deux fois**, et les deux bornes comptent :
//!
//! - [`BLOCS_CONSERVES`] (64) plafonne le NOMBRE de blocs ;
//! - [`OCTETS_CONSERVES`] (64 Mio) plafonne la TAILLE totale.
//!
//! Une seule borne ne suffirait pas. Un bloc plein pèse ≈ 34 Mio (512 × ~68 Kio) :
//! plafonner à 64 blocs sans plafonner les octets autoriserait ≈ 2,1 Gio de mémoire
//! résidente, décidés par les producteurs de blocs et pas par nous. À l'inverse,
//! plafonner uniquement les octets laisserait une chaîne de blocs vides remplir
//! l'archive d'entrées sans intérêt. On garde donc le plus contraignant des deux :
//! aux tailles de blocs du prototype (quelques transactions) c'est le nombre qui
//! mord ; sous des blocs pleins, ce sont les octets, et l'archive ne tient plus
//! qu'un ou deux blocs.
//!
//! Conséquence assumée : **une demande pour une hauteur trop ancienne reçoit le
//! silence**. Le rattrapage est un service de proximité, pas un archivage. Un nœud
//! très en retard ne rattrape pas ; il faudra le resynchroniser autrement (le rôle
//! d'archiviste complet est une brique séparée, cf. THREAT_MODEL.md).
//!
//! # L'archive n'est pas persistée
//!
//! Elle repart vide à chaque lancement. Un nœud fraîchement redémarré ne peut donc
//! pas servir les blocs qu'il avait appliqués avant : il aide de nouveau dès qu'il
//! en applique. C'est une limite ÉCRITE, pas un oubli — persister l'archive
//! reviendrait à persister jusqu'à 64 Mio à chaque sauvegarde d'état, pour un
//! service que n'importe quel autre pair rend aussi bien.

use ledger::bloc::Bloc;
use std::collections::VecDeque;

/// Nombre maximal de blocs conservés pour le rattrapage.
///
/// Petit à dessein : le rattrapage vise le nœud qui a manqué un bloc ou deux, pas
/// celui qui doit reconstruire une chaîne. Voir l'en-tête du module pour le coût.
pub const BLOCS_CONSERVES: usize = 64;

/// Budget mémoire total de l'archive, en octets sérialisés.
///
/// C'est la borne qui mord réellement dès que les blocs se remplissent : sans elle,
/// 64 blocs pleins vaudraient ≈ 2,1 Gio.
pub const OCTETS_CONSERVES: usize = 64 * 1024 * 1024;

/// CONSIGNÉ À LA COMPILATION : le budget d'octets doit laisser passer au moins UN
/// bloc plein, sinon l'archive serait vidée par le premier bloc conséquent et le
/// rattrapage ne servirait jamais à rien sous charge.
const TAILLE_BLOC_PLEIN_INDICATIVE: usize = ledger::bloc::MAX_TX_PAR_BLOC * 68 * 1024;
const _: () = assert!(OCTETS_CONSERVES > TAILLE_BLOC_PLEIN_INDICATIVE);

/// Les N derniers blocs appliqués, sous leur forme sérialisée.
///
/// On stocke les OCTETS et non des `Bloc` : c'est exactement ce qu'il faudra
/// réémettre, cela rend la comptabilité mémoire exacte plutôt qu'estimée, et cela
/// évite de dupliquer en mémoire des preuves STARK déjà décodées une fois.
pub struct ArchiveBlocs {
    /// (hauteur, octets) du plus ancien au plus récent.
    blocs: VecDeque<(u64, Vec<u8>)>,
    octets: usize,
}

impl Default for ArchiveBlocs {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchiveBlocs {
    pub fn new() -> Self {
        ArchiveBlocs {
            blocs: VecDeque::new(),
            octets: 0,
        }
    }

    /// Conserve un bloc qui vient d'être APPLIQUÉ à notre chaîne.
    ///
    /// N'est appelée que sur le chemin d'application (scellement local ou bloc reçu
    /// qui s'enchaîne) : l'archive ne contient donc que des blocs de NOTRE chaîne, et
    /// jamais un bloc arbitraire reçu du réseau. Servir un bloc qu'on n'a pas
    /// soi-même appliqué reviendrait à relayer une chaîne qu'on ne suit pas.
    pub fn conserver(&mut self, bloc: &Bloc) {
        let octets = bloc.to_bytes();
        self.octets = self.octets.saturating_add(octets.len());
        self.blocs.push_back((bloc.hauteur, octets));
        // Éviction du plus ancien tant qu'UNE des deux bornes est dépassée. La
        // dernière entrée n'est jamais évincée : un bloc plus gros que le budget
        // laisserait sinon l'archive vide en permanence, sans qu'aucune erreur ne le
        // dise.
        while self.blocs.len() > 1
            && (self.blocs.len() > BLOCS_CONSERVES || self.octets > OCTETS_CONSERVES)
        {
            if let Some((_, vieux)) = self.blocs.pop_front() {
                self.octets = self.octets.saturating_sub(vieux.len());
            }
        }
    }

    /// Octets sérialisés du bloc à cette hauteur, s'il est encore conservé.
    ///
    /// `hauteur` vient du RÉSEAU : elle n'est jamais utilisée comme indice. La
    /// recherche est linéaire sur au plus [`BLOCS_CONSERVES`] entrées — 64
    /// comparaisons d'entiers, sans allocation, donc sans asymétrie de coût
    /// exploitable.
    pub fn octets_a(&self, hauteur: u64) -> Option<&[u8]> {
        self.blocs
            .iter()
            .find(|(h, _)| *h == hauteur)
            .map(|(_, o)| o.as_slice())
    }

    /// Nombre de blocs conservés.
    pub fn len(&self) -> usize {
        self.blocs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocs.is_empty()
    }

    /// Octets actuellement occupés par l'archive.
    pub fn octets(&self) -> usize {
        self.octets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bloc(hauteur: u64) -> Bloc {
        Bloc::sceller(&[hauteur as u8; ledger::bloc::TAILLE_ID], hauteur, Vec::new()).unwrap()
    }

    /// Un bloc conservé est resservi À L'IDENTIQUE, octet pour octet.
    ///
    /// C'est la propriété dont dépend tout le rattrapage : un bloc resservi altéré ne
    /// s'enchaînerait pas chez le demandeur (son identifiant changerait), et celui-ci
    /// resterait figé exactement comme s'il n'avait rien reçu — en croyant avoir
    /// demandé.
    #[test]
    fn un_bloc_conserve_est_resservi_a_lidentique() {
        let mut a = ArchiveBlocs::new();
        let b = bloc(7);
        let attendu = b.to_bytes();
        a.conserver(&b);
        assert_eq!(a.octets_a(7), Some(attendu.as_slice()));
        let relu = Bloc::from_bytes(a.octets_a(7).unwrap()).expect("décodage");
        assert_eq!(relu.id(), b.id(), "l'identifiant survit à l'aller-retour");
    }

    /// Une hauteur jamais archivée rend `None` — jamais une panique, jamais un
    /// voisin. `octets_a` reçoit un `u64` venu du réseau : `u64::MAX` et 0 doivent
    /// se traiter comme n'importe quelle autre valeur.
    #[test]
    fn hauteur_inconnue_rend_none_sans_paniquer() {
        let mut a = ArchiveBlocs::new();
        a.conserver(&bloc(3));
        for h in [0, 2, 4, u64::MAX] {
            assert!(a.octets_a(h).is_none(), "hauteur {h} n'est pas archivée");
        }
    }

    /// LA BORNE EN NOMBRE : au-delà de `BLOCS_CONSERVES`, le plus ANCIEN part.
    ///
    /// Sans éviction, l'archive croîtrait avec la chaîne : la mémoire d'un nœud
    /// deviendrait une fonction de son temps de fonctionnement, ce qu'aucune borne du
    /// projet n'autorise. Le sens de l'éviction compte aussi — évincer le plus récent
    /// garderait précisément les blocs que personne ne demande.
    #[test]
    fn au_dela_de_la_borne_le_plus_ancien_est_evince() {
        let mut a = ArchiveBlocs::new();
        let derniere = BLOCS_CONSERVES as u64 + 10;
        for h in 1..=derniere {
            a.conserver(&bloc(h));
        }
        assert_eq!(a.len(), BLOCS_CONSERVES);
        // Hauteurs 1 à 10 évincées, 11 à `derniere` conservées.
        assert!(a.octets_a(10).is_none(), "les anciennes hauteurs sont parties");
        assert!(a.octets_a(11).is_some(), "la plus ancienne encore conservée");
        assert!(a.octets_a(derniere).is_some(), "la tête est là");
    }

    /// LA BORNE EN OCTETS existe indépendamment de la borne en nombre.
    ///
    /// Elle est ce qui empêche un producteur de blocs de décider notre empreinte
    /// mémoire : 64 blocs pleins vaudraient ≈ 2,1 Gio. Le test ne fabrique pas des
    /// blocs de 34 Mio (il faudrait 512 preuves STARK) ; il vérifie l'INVARIANT
    /// permanent, qui est ce que la borne garantit réellement.
    #[test]
    fn le_budget_doctets_est_un_invariant_permanent() {
        let mut a = ArchiveBlocs::new();
        for h in 1..=200u64 {
            a.conserver(&bloc(h));
            assert!(a.len() <= BLOCS_CONSERVES);
            assert!(
                a.octets() <= OCTETS_CONSERVES || a.len() == 1,
                "seule une entrée unique plus grosse que le budget peut le dépasser"
            );
        }
        // La comptabilité d'octets suit vraiment le contenu, elle ne dérive pas.
        let somme: usize = (0..)
            .map_while(|i| a.octets_a(200 - i))
            .map(|o| o.len())
            .sum();
        assert_eq!(a.octets(), somme, "le compteur d'octets reflète le contenu");
    }
}
