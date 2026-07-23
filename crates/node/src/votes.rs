//! Registre des votes ÉMIS — la règle de sûreté du consensus (ADR J1).
//!
//! # La règle (modèle A, J1-b2)
//!
//! Un nœud ne vote **qu'une fois par HAUTEUR**, toutes vues confondues. Sans elle,
//! deux blocs différents peuvent réunir le quorum à la même hauteur, et deux nœuds
//! honnêtes appliquent des blocs différents. Sur un ledger **append-only**, cette
//! divergence est **définitive** : aucune réorganisation ne la résorbe, et les
//! deux moitiés du réseau se rejettent ensuite tout.
//!
//! C'est la propriété qui rend l'absence de réorganisation TENABLE, et — sous le
//! modèle A — elle rend la preuve de sûreté triviale : deux quorums à la même
//! hauteur ont un votant honnête commun, qui n'a voté qu'un id. **La vue n'entre
//! jamais dans la décision** (contrairement à J1-b1, où la clé était
//! `(hauteur, vue)` — voir le format `0x02`).
//!
//! # Pourquoi c'est PERSISTÉ
//!
//! Un registre en mémoire seule ne protège que le processus en cours. Un nœud qui
//! redémarre — panne, mise à jour, simple `systemctl restart` — aurait tout oublié
//! et pourrait voter une seconde fois, pour un AUTRE bloc, à la même hauteur. La
//! panne la plus banale produirait la faute la plus grave.
//!
//! ⚠️ **L'ordre d'écriture est la garantie, et il n'est pas symétrique.** Le vote
//! est persisté AVANT d'être émis. Si la machine tombe entre les deux, on a promis
//! sans le dire : inoffensif, le vote sera simplement redemandé. Dans l'autre
//! ordre, on aurait dit sans avoir promis — et au redémarrage on pourrait promettre
//! autre chose. C'est la même discipline que « l'historique avant l'état » dans
//! [`crate::persistance`].
//!
//! # Pourquoi DEUX champs suffisent
//!
//! Le registre est **monotone** en hauteur : on ne vote que pour une hauteur
//! strictement supérieure à la dernière, ou pour exactement le même id à la même
//! hauteur. Rien à conserver d'autre que le dernier vote — pas d'historique, pas
//! d'élagage, pas de fichier qui croît. Même forme qu'une frontier de Merkle : on
//! ne garde que ce qui interdit de revenir en arrière.

/// Version du format du registre. `0x02` (J1-b2) : clé HAUTEUR seule, la `vue` a
/// disparu (modèle A). Un `0x01` (J1-b1) est refusé par son nom, jamais
/// réinterprété — même discipline que partout ailleurs.
const VERSION_VOTES: u8 = 0x02;

/// Taille du fichier : version + hauteur + identifiant. La `vue` de `0x01` est
/// retirée (le modèle A ne vote qu'un id par hauteur, toutes vues confondues).
const TAILLE: usize = 1 + 8 + 64;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum VoteDecodeError {
    #[error("registre de votes tronqué ou surdimensionné ({recus} o, attendu {TAILLE})")]
    Taille { recus: usize },
    #[error("registre de votes de version {0:#04x} : inconnue")]
    VersionInconnue(u8),
}

/// Dernier vote émis. Voir la tête de module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistreVotes {
    hauteur: u64,
    id: [u8; 64],
}

impl RegistreVotes {
    /// Registre VIERGE : aucun vote émis.
    ///
    /// `hauteur = 0` est sûr comme valeur initiale parce qu'aucun vote n'a jamais
    /// lieu à la hauteur 0 — la genèse amorce, personne ne la propose.
    pub fn neuf() -> Self {
        RegistreVotes {
            hauteur: 0,
            id: [0u8; 64],
        }
    }

    /// Avons-nous le droit de voter pour ce bloc à cette hauteur ?
    ///
    /// # Modèle A : la clé est la HAUTEUR seule, la vue n'entre pas
    ///
    /// - hauteur **strictement après** le dernier vote → oui ;
    /// - **même hauteur et MÊME id** → oui. Re-voter est idempotent, donc sans
    ///   danger, et **nécessaire** : un vote peut se perdre, le refuser figerait la
    ///   hauteur ;
    /// - **même hauteur, autre id** → NON, **même à une vue supérieure**. C'est le
    ///   cœur du modèle A : un nœud ne vote qu'un id par hauteur, ce qui rend la
    ///   sûreté triviale à prouver sans que la vue n'intervienne jamais.
    ///
    /// Un retour en arrière est refusé aussi : rien de légitime ne le demande.
    pub fn peut_voter(&self, hauteur: u64, id: &[u8; 64]) -> bool {
        match hauteur.cmp(&self.hauteur) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Equal => &self.id == id,
            std::cmp::Ordering::Less => false,
        }
    }

    /// Mémorise le vote. À appeler AVANT de l'émettre, et à persister dans la
    /// foulée (cf. [`crate::persistance::Donnees::enregistrer_votes`]).
    ///
    /// Ne recule jamais : un appel pour une hauteur antérieure est ignoré.
    pub fn enregistrer(&mut self, hauteur: u64, id: [u8; 64]) {
        if hauteur >= self.hauteur {
            self.hauteur = hauteur;
            self.id = id;
        }
    }

    /// Dernière hauteur votée — pour le journal d'exploitation.
    pub fn hauteur(&self) -> u64 {
        self.hauteur
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(TAILLE);
        b.push(VERSION_VOTES);
        b.extend_from_slice(&self.hauteur.to_le_bytes());
        b.extend_from_slice(&self.id);
        b
    }

    /// Décode. Taille EXACTE exigée : ni troncature, ni octets résiduels.
    pub fn from_bytes(b: &[u8]) -> Result<Self, VoteDecodeError> {
        if b.len() != TAILLE {
            return Err(VoteDecodeError::Taille { recus: b.len() });
        }
        if b[0] != VERSION_VOTES {
            return Err(VoteDecodeError::VersionInconnue(b[0]));
        }
        let hauteur = u64::from_le_bytes(b[1..9].try_into().expect("8 octets"));
        let id: [u8; 64] = b[9..73].try_into().expect("64 octets");
        Ok(RegistreVotes { hauteur, id })
    }
}

impl Default for RegistreVotes {
    fn default() -> Self {
        Self::neuf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// LA règle de sûreté, clé HAUTEUR seule : un id par hauteur, toutes vues
    /// confondues.
    #[test]
    fn un_seul_id_par_hauteur() {
        let mut r = RegistreVotes::neuf();
        assert!(r.peut_voter(1, &[1u8; 64]));
        r.enregistrer(1, [1u8; 64]);

        // Même hauteur, MÊME id : idempotent (un vote peut se perdre).
        assert!(r.peut_voter(1, &[1u8; 64]));
        // Même hauteur, AUTRE id : refusé — c'est tout le point du modèle A, la
        // vue n'entre pas dans la décision. Un id à la hauteur 1 en verrouille un
        // seul, définitivement, quelle que soit la vue.
        assert!(!r.peut_voter(1, &[2u8; 64]));
        // Hauteur suivante : autorisée.
        assert!(r.peut_voter(2, &[3u8; 64]));

        r.enregistrer(2, [3u8; 64]);
        // Retour en arrière : refusé.
        assert!(!r.peut_voter(1, &[9u8; 64]));
    }

    /// `enregistrer` ne recule jamais : sûr même appelé dans le désordre.
    #[test]
    fn enregistrer_ne_recule_pas() {
        let mut r = RegistreVotes::neuf();
        r.enregistrer(5, [1u8; 64]);
        r.enregistrer(3, [2u8; 64]); // en arrière : ignoré
        assert_eq!(r.hauteur(), 5);
        assert!(!r.peut_voter(5, &[2u8; 64]), "l'ancien vote tient toujours");
    }

    /// L'interdit doit SURVIVRE au redémarrage — c'est toute la raison d'être de
    /// la persistance.
    #[test]
    fn le_registre_survit_a_laller_retour() {
        let mut r = RegistreVotes::neuf();
        r.enregistrer(7, [4u8; 64]);
        let relu = RegistreVotes::from_bytes(&r.to_bytes()).expect("relisible");
        assert_eq!(relu, r);
        assert!(
            !relu.peut_voter(7, &[5u8; 64]),
            "après redémarrage, l'équivocation reste interdite — toutes vues"
        );
        assert!(
            relu.peut_voter(8, &[5u8; 64]),
            "la hauteur suivante reste ouverte"
        );
    }

    /// Registre vierge : tout premier vote autorisé, et il se relit.
    #[test]
    fn registre_vierge_autorise_le_premier_vote() {
        let r = RegistreVotes::neuf();
        assert!(r.peut_voter(1, &[1u8; 64]));
        assert_eq!(
            RegistreVotes::from_bytes(&r.to_bytes()).expect("relisible"),
            r
        );
    }

    /// Un ancien registre J1-b1 (0x01) est refusé, jamais réinterprété : sa vue
    /// décalerait tous les octets et l'id serait lu de travers.
    #[test]
    fn registre_0x01_refuse_par_son_nom() {
        // Format 0x01 : version + hauteur(8) + vue(4) + id(64) = 77 octets.
        let mut ancien = vec![0x01u8];
        ancien.extend_from_slice(&7u64.to_le_bytes());
        ancien.extend_from_slice(&0u32.to_le_bytes());
        ancien.extend_from_slice(&[4u8; 64]);
        // Refusé sur la taille (77 ≠ 73) — un 0x01 ne peut pas se faire passer
        // pour un 0x02, les longueurs diffèrent.
        assert!(matches!(
            RegistreVotes::from_bytes(&ancien),
            Err(VoteDecodeError::Taille { .. })
        ));
    }

    #[test]
    fn registre_malforme_refuse_sans_panique() {
        assert!(matches!(
            RegistreVotes::from_bytes(&[]),
            Err(VoteDecodeError::Taille { recus: 0 })
        ));
        assert!(matches!(
            RegistreVotes::from_bytes(&[0u8; 10]),
            Err(VoteDecodeError::Taille { .. })
        ));
        // Bonne taille, version inconnue : refusée PAR SON NOM.
        let mut o = RegistreVotes::neuf().to_bytes();
        o[0] = 0x03;
        assert!(matches!(
            RegistreVotes::from_bytes(&o),
            Err(VoteDecodeError::VersionInconnue(0x03))
        ));
        // Un octet de trop : refusé aussi (pas d'octets résiduels tolérés).
        let mut trop = RegistreVotes::neuf().to_bytes();
        trop.push(0);
        assert!(matches!(
            RegistreVotes::from_bytes(&trop),
            Err(VoteDecodeError::Taille { .. })
        ));
    }
}
