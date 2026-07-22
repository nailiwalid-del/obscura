//! Registre des votes ÉMIS — la règle de sûreté du consensus (ADR J1, J1-b1).
//!
//! # La règle
//!
//! Un nœud ne vote **qu'une fois par `(hauteur, vue)`**. Sans elle, deux blocs
//! différents peuvent réunir `2f+1` votes à la même hauteur, et deux nœuds
//! honnêtes appliquent des blocs différents. Sur un ledger **append-only**, cette
//! divergence est **définitive** : il n'existe aucune réorganisation pour la
//! résorber, et les deux moitiés du réseau se rejettent ensuite tout.
//!
//! C'est donc la propriété qui rend l'absence de réorganisation TENABLE. Le reste
//! du consensus peut échouer bruyamment ; celle-ci échoue en silence.
//!
//! # Pourquoi c'est PERSISTÉ
//!
//! Un registre en mémoire seule ne protège que le processus en cours. Un nœud qui
//! redémarre — panne, mise à jour, simple `systemctl restart` — aurait tout oublié
//! et pourrait voter une seconde fois, pour un AUTRE bloc, à la même
//! `(hauteur, vue)`. La panne la plus banale produirait la faute la plus grave.
//!
//! ⚠️ **L'ordre d'écriture est la garantie, et il n'est pas symétrique.** Le vote
//! est persisté AVANT d'être émis. Si la machine tombe entre les deux, on a promis
//! sans le dire : inoffensif, le vote sera simplement redemandé. Dans l'autre
//! ordre, on aurait dit sans avoir promis — et au redémarrage on pourrait promettre
//! autre chose. C'est la même discipline que « l'historique avant l'état » dans
//! [`crate::persistance`].
//!
//! # Pourquoi trois champs suffisent
//!
//! Le registre est **monotone** : on ne vote que pour une `(hauteur, vue)`
//! strictement supérieure à la dernière, ou pour exactement le même bloc à la même
//! position. Il n'y a donc rien à conserver d'autre que le dernier vote — pas
//! d'historique, pas d'élagage, pas de fichier qui croît. Même forme qu'une
//! frontier de Merkle : on ne garde que ce qui interdit de revenir en arrière.

/// Version du format du registre. Un `0x00` ou un `0x02` est refusé, jamais
/// réinterprété — même discipline que partout ailleurs dans le dépôt.
const VERSION_VOTES: u8 = 0x01;

/// Taille du fichier : version + hauteur + vue + identifiant.
const TAILLE: usize = 1 + 8 + 4 + 64;

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
    vue: u32,
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
            vue: 0,
            id: [0u8; 64],
        }
    }

    /// Avons-nous le droit de voter pour ce bloc à cette position ?
    ///
    /// Trois cas, et un seul autorise :
    ///
    /// - `(hauteur, vue)` **strictement après** le dernier vote → oui ;
    /// - **exactement la même position et le MÊME bloc** → oui. Re-voter est
    ///   idempotent, donc sans danger, et c'est **nécessaire** : un vote peut se
    ///   perdre sur le réseau, et le refuser figerait la hauteur ;
    /// - même position, **autre bloc** → NON. C'est l'équivocation.
    ///
    /// Un retour en arrière (`hauteur` ou `vue` inférieure) est refusé aussi : rien
    /// de légitime ne le demande, et l'autoriser rouvrirait la fenêtre qu'on ferme.
    pub fn peut_voter(&self, hauteur: u64, vue: u32, id: &[u8; 64]) -> bool {
        match (hauteur, vue).cmp(&(self.hauteur, self.vue)) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Equal => &self.id == id,
            std::cmp::Ordering::Less => false,
        }
    }

    /// Mémorise le vote. À appeler AVANT de l'émettre, et à persister dans la
    /// foulée (cf. [`crate::persistance::Donnees::enregistrer_votes`]).
    ///
    /// Ne recule jamais : un appel pour une position antérieure est ignoré, ce qui
    /// rend la fonction sûre même appelée dans le désordre.
    pub fn enregistrer(&mut self, hauteur: u64, vue: u32, id: [u8; 64]) {
        if (hauteur, vue) >= (self.hauteur, self.vue) {
            self.hauteur = hauteur;
            self.vue = vue;
            self.id = id;
        }
    }

    /// Position du dernier vote — pour le journal d'exploitation.
    pub fn position(&self) -> (u64, u32) {
        (self.hauteur, self.vue)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(TAILLE);
        b.push(VERSION_VOTES);
        b.extend_from_slice(&self.hauteur.to_le_bytes());
        b.extend_from_slice(&self.vue.to_le_bytes());
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
        let vue = u32::from_le_bytes(b[9..13].try_into().expect("4 octets"));
        let id: [u8; 64] = b[13..77].try_into().expect("64 octets");
        Ok(RegistreVotes { hauteur, vue, id })
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

    /// LA règle de sûreté, vue depuis le registre.
    #[test]
    fn un_seul_vote_par_hauteur_et_vue() {
        let mut r = RegistreVotes::neuf();
        assert!(r.peut_voter(1, 0, &[1u8; 64]));
        r.enregistrer(1, 0, [1u8; 64]);

        // Même position, MÊME bloc : idempotent, donc autorisé — et nécessaire,
        // puisqu'un vote peut se perdre.
        assert!(r.peut_voter(1, 0, &[1u8; 64]));
        // Même position, AUTRE bloc : c'est l'équivocation. Refusée.
        assert!(!r.peut_voter(1, 0, &[2u8; 64]));
        // Vue suivante : autorisée.
        assert!(r.peut_voter(1, 1, &[2u8; 64]));
        // Hauteur suivante : autorisée.
        assert!(r.peut_voter(2, 0, &[3u8; 64]));

        r.enregistrer(2, 0, [3u8; 64]);
        // RETOUR EN ARRIÈRE : refusé, même à une vue élevée d'une hauteur passée.
        assert!(!r.peut_voter(1, 5, &[9u8; 64]));
    }

    /// `enregistrer` ne recule jamais : sûr même appelé dans le désordre.
    #[test]
    fn enregistrer_ne_recule_pas() {
        let mut r = RegistreVotes::neuf();
        r.enregistrer(5, 2, [1u8; 64]);
        r.enregistrer(3, 0, [2u8; 64]); // en arrière : ignoré
        assert_eq!(r.position(), (5, 2));
        assert!(
            !r.peut_voter(5, 2, &[2u8; 64]),
            "l'ancien vote tient toujours"
        );
    }

    /// L'interdit doit SURVIVRE au redémarrage — c'est toute la raison d'être de
    /// la persistance.
    #[test]
    fn le_registre_survit_a_laller_retour() {
        let mut r = RegistreVotes::neuf();
        r.enregistrer(7, 2, [4u8; 64]);
        let relu = RegistreVotes::from_bytes(&r.to_bytes()).expect("relisible");
        assert_eq!(relu, r);
        assert!(
            !relu.peut_voter(7, 2, &[5u8; 64]),
            "après redémarrage, l'équivocation reste interdite"
        );
        assert!(
            relu.peut_voter(7, 3, &[5u8; 64]),
            "la vue suivante reste ouverte"
        );
    }

    /// Registre vierge : tout premier vote autorisé, et il se relit.
    #[test]
    fn registre_vierge_autorise_le_premier_vote() {
        let r = RegistreVotes::neuf();
        assert!(r.peut_voter(1, 0, &[1u8; 64]));
        assert_eq!(
            RegistreVotes::from_bytes(&r.to_bytes()).expect("relisible"),
            r
        );
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
        o[0] = 0x02;
        assert!(matches!(
            RegistreVotes::from_bytes(&o),
            Err(VoteDecodeError::VersionInconnue(0x02))
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
