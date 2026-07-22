//! Journalisation d'exploitation : ce qu'un opérateur lit quand le nœud tourne.
//!
//! # Pourquoi pas `tracing` / `log`
//!
//! Le dépôt tient une discipline de dépendances minimales sur le chemin du
//! consensus, et ce module fait moins de cent lignes. Une façade de journalisation
//! complète (souscripteurs, champs structurés, filtres par module) apporterait des
//! dépendances transitives pour un besoin qui tient en quatre niveaux et un filtre.
//! Le jour où le besoin dépasse ça, la bascule est locale à ce fichier.
//!
//! # Pourquoi PAS d'horodatage absolu
//!
//! On affiche l'UPTIME (`[ 12.345s]`), pas la date. Un nœud tourne sous systemd,
//! sous Docker ou dans un terminal — et **les trois horodatent déjà**, à la
//! milliseconde et dans le fuseau du serveur (`journalctl`, `docker logs -t`).
//! Refaire un calendrier UTC sans dépendance coûterait une trentaine de lignes de
//! code de date à maintenir, pour dupliquer ce que l'hôte fait mieux. L'uptime, lui,
//! n'est PAS dérivable des logs de l'hôte et répond à la question qu'on se pose
//! vraiment : « depuis combien de temps ce nœud tourne-t-il sans redémarrer ? »
//!
//! # Tout part sur STDERR
//!
//! Y compris `INFO`. Convention Unix : la sortie standard porte des *données*, la
//! sortie d'erreur porte le *déroulement*. Un opérateur peut ainsi rediriger l'un
//! sans perdre l'autre, et `journald` capte les deux de toute façon.

use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Instant;

/// Niveau de journalisation, du plus grave au plus bavard.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Niveau {
    /// Le nœud ne peut pas faire ce qu'on lui demande.
    Erreur = 0,
    /// Anormal mais surmontable — ce qu'un opérateur doit voir passer.
    Avert = 1,
    /// Le déroulement normal : blocs, connexions, statut.
    Info = 2,
    /// Détail de diagnostic, volumineux.
    Debug = 3,
}

impl Niveau {
    fn etiquette(self) -> &'static str {
        match self {
            Niveau::Erreur => "ERREUR",
            Niveau::Avert => "AVERT ",
            Niveau::Info => "INFO  ",
            Niveau::Debug => "DEBUG ",
        }
    }

    /// Analyse une valeur de `OBSCURA_LOG`. Insensible à la casse, tolère les
    /// abréviations usuelles. Une valeur INCONNUE ne fait pas taire le nœud :
    /// elle retombe sur `Info` — se taire sur une faute de frappe serait le pire
    /// comportement possible pour un journal.
    pub fn depuis_texte(t: &str) -> Option<Self> {
        match t.trim().to_ascii_lowercase().as_str() {
            "erreur" | "error" | "err" => Some(Niveau::Erreur),
            "avert" | "warn" | "warning" => Some(Niveau::Avert),
            "info" => Some(Niveau::Info),
            "debug" | "dbg" => Some(Niveau::Debug),
            _ => None,
        }
    }
}

/// Niveau actif, partagé sans verrou (lu à chaque ligne journalisée).
static NIVEAU: AtomicU8 = AtomicU8::new(Niveau::Info as u8);

/// Fixe le niveau actif.
pub fn definir_niveau(n: Niveau) {
    NIVEAU.store(n as u8, Ordering::Relaxed);
}

/// Niveau actif.
pub fn niveau() -> Niveau {
    match NIVEAU.load(Ordering::Relaxed) {
        0 => Niveau::Erreur,
        1 => Niveau::Avert,
        3 => Niveau::Debug,
        _ => Niveau::Info,
    }
}

/// Lit `OBSCURA_LOG` et applique le niveau. Retourne ce qui a été appliqué, et
/// si la valeur lue était invalide — l'appelant peut alors le SIGNALER plutôt que
/// de laisser l'opérateur croire à un filtre qui ne s'applique pas.
pub fn depuis_environnement() -> (Niveau, Option<String>) {
    match std::env::var("OBSCURA_LOG") {
        Ok(v) => match Niveau::depuis_texte(&v) {
            Some(n) => {
                definir_niveau(n);
                (n, None)
            }
            None => {
                definir_niveau(Niveau::Info);
                (Niveau::Info, Some(v))
            }
        },
        Err(_) => (niveau(), None),
    }
}

/// Horloge de référence du processus, pour l'uptime affiché.
pub struct Journal {
    depart: Instant,
}

impl Journal {
    pub fn demarrer() -> Self {
        Journal {
            depart: Instant::now(),
        }
    }

    /// Écrit une ligne si le niveau le permet.
    pub fn ligne(&self, n: Niveau, message: &str) {
        if n > niveau() {
            return;
        }
        eprintln!(
            "[{:9.3}s] {} {}",
            self.depart.elapsed().as_secs_f64(),
            n.etiquette(),
            message
        );
    }

    pub fn erreur(&self, m: &str) {
        self.ligne(Niveau::Erreur, m)
    }
    pub fn avert(&self, m: &str) {
        self.ligne(Niveau::Avert, m)
    }
    pub fn info(&self, m: &str) {
        self.ligne(Niveau::Info, m)
    }
    pub fn debug(&self, m: &str) {
        self.ligne(Niveau::Debug, m)
    }

    /// Uptime du processus, en secondes.
    pub fn uptime_s(&self) -> f64 {
        self.depart.elapsed().as_secs_f64()
    }
}

/// Instantané d'exploitation — LA ligne qu'un opérateur surveille.
///
/// Elle réunit les cinq chiffres qui disent si un nœud va bien, et surtout
/// `desaccords` : un nœud FIGÉ (qui refuse tous les blocs parce qu'il a manqué une
/// hauteur) reste sinon indiscernable d'un nœud au repos — il sert un historique
/// plus court mais parfaitement cohérent. C'est le mode de panne le plus coûteux du
/// protocole, et le seul que ces chiffres rendent visible.
pub struct Statut {
    pub hauteur: u64,
    pub pairs: usize,
    pub liens: usize,
    pub mempool: usize,
    pub desaccords: u64,
}

impl Statut {
    /// Rend la ligne de statut. Séparée de l'écriture pour être TESTABLE sans
    /// capturer la sortie d'erreur.
    pub fn ligne(&self) -> String {
        format!(
            "statut — hauteur {} | pairs {} | liens {} | mempool {} | désaccords {}",
            self.hauteur, self.pairs, self.liens, self.mempool, self.desaccords
        )
    }

    /// `true` si ce statut mérite l'attention de l'opérateur (et non un simple
    /// `INFO` de routine) : aucun lien ouvert, ou des blocs refusés pour chaînage.
    ///
    /// Zéro lien n'est pas anodin — un nœud sans pair ne reçoit rien, ne diffuse
    /// rien, et continue pourtant de répondre normalement à qui l'interroge.
    pub fn preoccupant(&self) -> bool {
        self.liens == 0 || self.desaccords > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Une valeur inconnue de `OBSCURA_LOG` ne doit PAS faire taire le nœud.
    #[test]
    fn niveau_inconnu_retombe_sur_info() {
        assert_eq!(Niveau::depuis_texte("bavard"), None);
        assert_eq!(Niveau::depuis_texte("DEBUG"), Some(Niveau::Debug));
        assert_eq!(Niveau::depuis_texte(" warn "), Some(Niveau::Avert));
        assert_eq!(Niveau::depuis_texte("err"), Some(Niveau::Erreur));
    }

    /// L'ordre des niveaux commande le filtrage : `Erreur` passe toujours,
    /// `Debug` seulement au niveau le plus bavard.
    #[test]
    fn ordre_des_niveaux() {
        assert!(Niveau::Erreur < Niveau::Avert);
        assert!(Niveau::Avert < Niveau::Info);
        assert!(Niveau::Info < Niveau::Debug);
    }

    /// Le filtrage laisse passer ce qui est au moins aussi grave que le seuil.
    #[test]
    fn filtrage_par_niveau() {
        definir_niveau(Niveau::Avert);
        assert_eq!(niveau(), Niveau::Avert);
        assert!(Niveau::Erreur <= niveau(), "une erreur passe toujours");
        assert!(Niveau::Info > niveau(), "info est filtré à ce seuil");
        definir_niveau(Niveau::Info); // remise à l'état par défaut
    }

    /// La ligne de statut porte les cinq chiffres, et rien d'autre à retenir.
    #[test]
    fn ligne_de_statut_complete() {
        let s = Statut {
            hauteur: 12,
            pairs: 3,
            liens: 2,
            mempool: 7,
            desaccords: 0,
        };
        let l = s.ligne();
        for attendu in [
            "hauteur 12",
            "pairs 3",
            "liens 2",
            "mempool 7",
            "désaccords 0",
        ] {
            assert!(l.contains(attendu), "« {attendu} » manque dans : {l}");
        }
        assert!(
            !s.preoccupant(),
            "des liens et aucun désaccord : rien à signaler"
        );
    }

    /// UN NŒUD SANS LIEN OU EN DÉSACCORD DOIT SE VOIR.
    ///
    /// C'est tout l'objet du statut : un nœud figé sert un historique cohérent mais
    /// tronqué, et reste sinon indiscernable d'un nœud au repos.
    #[test]
    fn statut_preoccupant_detecte_les_deux_pannes_silencieuses() {
        let sans_lien = Statut {
            hauteur: 5,
            pairs: 4,
            liens: 0,
            mempool: 0,
            desaccords: 0,
        };
        assert!(sans_lien.preoccupant(), "aucun lien : le nœud est isolé");

        let fige = Statut {
            hauteur: 5,
            pairs: 4,
            liens: 3,
            mempool: 0,
            desaccords: 9,
        };
        assert!(fige.preoccupant(), "des blocs refusés : le nœud décroche");
    }
}
