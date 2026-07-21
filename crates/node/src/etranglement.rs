//! Étranglement du service d'historique, indexé sur le GROUPE RÉSEAU.
//!
//! # Pourquoi jamais sur `PeerId`
//!
//! Une identité de pair est **gratuite** : c'est un hachage de clé publique, et le
//! wallet en tire délibérément une neuve à chaque commande (cf. « identité de
//! transport éphémère », `crates/wallet`). Un seau par `PeerId` ne défendrait donc
//! rien — l'attaquant tourne les identités et repart avec un crédit plein — et il
//! grossirait sans fin, chaque rotation créant une entrée de plus.
//!
//! [`GroupeReseau`] (IPv4 `/16`, IPv6 `/32`) est **déjà l'unité de coût Sybil du
//! projet** : c'est elle que la sélection anti-eclipse compte, et occuper N groupes
//! distincts exige de l'adressage réparti, coûteux et traçable. Le service
//! d'historique se règle sur la même unité, sans en inventer une seconde.
//!
//! # On étrangle le NOMBRE de requêtes, pas seulement les entrées servies
//!
//! Une réponse « courte » n'est pas gratuite : allocation, cascade AEAD (deux
//! chiffrements sur le message entier), écriture, flush. Un attaquant qui demanderait
//! en boucle une hauteur inexistante paierait 9 octets pour nous coûter un aller-retour
//! complet. Chaque requête débite donc [`COUT_REQUETE`] **avant** qu'on sache s'il y a
//! quelque chose à servir, et les entrées effectivement servies se débitent en plus.
//!
//! # À crédit épuisé : le SILENCE
//!
//! Pas de réponse courte, pas d'erreur, pas de sanction. Trois raisons, et il faut les
//! trois :
//!
//! - demander son historique est un comportement **normal** — sanctionner rendrait la
//!   synchronisation plus risquée que l'immobilité ;
//! - une réponse « je n'ai plus de crédit » coûterait exactement ce qu'on cherche à
//!   éviter (allocation + AEAD + écriture) ;
//! - le silence est déjà la réponse du protocole à une hauteur inconnue
//!   (`sur_demande_bloc`) : un refus distinct ferait du crédit une information
//!   observable, donc un moyen de sonder le nœud.
//!
//! # ⚠️ Ce que cela ne protège pas
//!
//! - Un adversaire disposant réellement de nombreux préfixes (opérateur, cloud
//!   multi-régions) obtient autant de seaux pleins que de groupes. C'est la limite
//!   assumée de tout le projet : rendre l'attaque chère et visible, pas impossible.
//! - La table de seaux est BORNÉE ([`MAX_GROUPES_SUIVIS`]). À saturation, un groupe
//!   inconnu n'est pas servi (fail-closed) tant qu'aucun seau n'est revenu à plein.
//!   Occuper toutes les places exige `MAX_GROUPES_SUIVIS` groupes réseau distincts, et
//!   le déni obtenu ne porte que sur le service d'historique : le consensus, la
//!   propagation et le rattrapage de blocs sont intacts. Écrit plutôt que supposé.

use net::pairs::GroupeReseau;
use std::collections::HashMap;

/// Crédit maximal d'un groupe, en « entrées-équivalent ».
///
/// Dimensionné pour laisser passer une rafale de plusieurs blocs pleins
/// (`MAX_SORTIES_PAR_REPONSE` ≈ 739 entrées par cadre) : un wallet qui démarre doit
/// pouvoir avancer vite, c'est le régime honnête le plus gourmand.
pub const CAPACITE_SEAU: u64 = 4_096;

/// Recharge, en entrées-équivalent par seconde.
///
/// Régime permanent : ≈256 entrées/s, soit ≈360 Kio/s par groupe réseau. Un wallet en
/// retard de 1 000 blocs à 2 sorties se resynchronise en ≈8 s ; un adversaire qui
/// voudrait saturer notre lien devrait aligner autant de groupes réseau distincts que
/// de multiples de ce débit.
pub const RECHARGE_PAR_SECONDE: u64 = 256;

/// Coût FIXE d'une requête, en entrées-équivalent, débité même quand on ne sert rien.
///
/// Sans lui, sonder des hauteurs inexistantes serait gratuit pour l'attaquant et
/// coûteux pour nous.
pub const COUT_REQUETE: u64 = 8;

/// Nombre maximal de groupes suivis simultanément.
///
/// Le seul état qui grossit ici. Sans borne, la mémoire du nœud deviendrait une
/// fonction du nombre de préfixes qui l'ont contacté — c'est-à-dire du temps.
pub const MAX_GROUPES_SUIVIS: usize = 1_024;

/// CONSIGNÉ À LA COMPILATION : le crédit plein doit permettre de servir au moins un
/// bloc plein d'un coup, sinon aucun wallet ne pourrait franchir un tel bloc et le
/// service serait inutilisable exactement quand il sert.
const _: () = assert!(CAPACITE_SEAU >= (ledger::bloc::MAX_TX_PAR_BLOC as u64) * 2 + COUT_REQUETE);

/// Le crédit est compté en MILLIÈMES d'entrée.
///
/// # Pourquoi, et ce que cela ferme
///
/// Recharger en unités entières perdrait la fraction gagnée entre deux requêtes
/// rapprochées : à une requête toutes les 3 ms, `3 × 256 / 1000 = 0` jeton gagné, et si
/// l'on avançait quand même l'horodatage du seau, le crédit ne remonterait **jamais**.
/// Un pair bavard s'auto-bannirait du service à vie sans qu'aucune ligne ne le décide.
const MILLI: u64 = 1_000;

struct Seau {
    /// Crédit courant, en millièmes d'entrée.
    milli: u64,
    /// Horodatage de la dernière recharge appliquée.
    dernier_ms: u64,
}

impl Seau {
    fn plein(maintenant_ms: u64) -> Self {
        Seau {
            milli: CAPACITE_SEAU * MILLI,
            dernier_ms: maintenant_ms,
        }
    }

    /// Recharge à l'instant donné. Un horodatage qui recule (horloge non monotone,
    /// test) ne crédite rien plutôt que de déborder.
    fn recharger(&mut self, maintenant_ms: u64) {
        let ecoule = maintenant_ms.saturating_sub(self.dernier_ms);
        let gain = ecoule.saturating_mul(RECHARGE_PAR_SECONDE);
        self.milli = self.milli.saturating_add(gain).min(CAPACITE_SEAU * MILLI);
        self.dernier_ms = maintenant_ms;
    }

    fn est_plein(&self) -> bool {
        self.milli >= CAPACITE_SEAU * MILLI
    }

    fn debiter(&mut self, entrees: u64) {
        let cout = entrees.saturating_mul(MILLI);
        self.milli = self.milli.saturating_sub(cout);
    }
}

/// Seaux à jetons, un par groupe réseau.
#[derive(Default)]
pub struct Etrangleur {
    seaux: HashMap<GroupeReseau, Seau>,
}

impl Etrangleur {
    pub fn new() -> Self {
        Etrangleur {
            seaux: HashMap::new(),
        }
    }

    /// Autorise (et facture) UNE requête du groupe donné.
    ///
    /// `false` = crédit épuisé, ou table saturée : l'appelant doit se taire. Il ne doit
    /// **pas** répondre plus court — cf. tête de module.
    ///
    /// Le coût fixe est débité ici, avant même de savoir si la hauteur demandée existe :
    /// c'est ce qui rend le sondage payant.
    pub fn autoriser(&mut self, groupe: GroupeReseau, maintenant_ms: u64) -> bool {
        if !self.seaux.contains_key(&groupe) && !self.faire_place(maintenant_ms) {
            // Table saturée et aucun seau à plein crédit : on ne peut pas suivre ce
            // groupe, donc on ne peut pas l'étrangler, donc on ne le sert pas.
            return false;
        }
        let seau = self
            .seaux
            .entry(groupe)
            .or_insert_with(|| Seau::plein(maintenant_ms));
        seau.recharger(maintenant_ms);
        if seau.milli < COUT_REQUETE * MILLI {
            return false;
        }
        seau.debiter(COUT_REQUETE);
        true
    }

    /// Débite le coût VARIABLE : les entrées effectivement servies.
    ///
    /// Séparé d'[`Etrangleur::autoriser`] parce qu'on ne sait ce qu'on sert qu'après
    /// avoir consulté l'historique — et qu'on veut faire payer la requête même quand la
    /// réponse est vide.
    pub fn debiter(&mut self, groupe: GroupeReseau, entrees: u64) {
        if let Some(seau) = self.seaux.get_mut(&groupe) {
            seau.debiter(entrees);
        }
    }

    /// Fait de la place si la table est pleine, en évinçant un seau à PLEIN crédit.
    ///
    /// Le choix de la victime est load-bearing : évincer un seau ÉPUISÉ rendrait son
    /// crédit à celui qui vient de le vider (il suffirait de saturer la table pour se
    /// blanchir). Un seau plein est en revanche indiscernable d'un groupe jamais vu —
    /// l'évincer n'accorde rien à personne. Si aucun n'est plein, on n'évince rien.
    fn faire_place(&mut self, maintenant_ms: u64) -> bool {
        if self.seaux.len() < MAX_GROUPES_SUIVIS {
            return true;
        }
        let victime = self.seaux.iter_mut().find_map(|(g, s)| {
            s.recharger(maintenant_ms);
            if s.est_plein() {
                Some(*g)
            } else {
                None
            }
        });
        match victime {
            Some(g) => {
                self.seaux.remove(&g);
                true
            }
            None => false,
        }
    }

    /// Crédit courant d'un groupe, en entrées-équivalent (diagnostic et tests).
    /// Un groupe jamais vu vaut la capacité pleine.
    pub fn credit(&self, groupe: &GroupeReseau) -> u64 {
        match self.seaux.get(groupe) {
            Some(s) => s.milli / MILLI,
            None => CAPACITE_SEAU,
        }
    }

    /// Nombre de groupes suivis.
    pub fn len(&self) -> usize {
        self.seaux.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seaux.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    fn groupe_v4(a: u8, b: u8, c: u8, d: u8) -> GroupeReseau {
        GroupeReseau::de(&SocketAddr::from((Ipv4Addr::new(a, b, c, d), 8333)))
    }

    /// LA ROTATION D'IDENTITÉ NE REND PAS DE CRÉDIT.
    ///
    /// C'est LA propriété de cette brique. Un `PeerId` est un hachage de clé publique :
    /// gratuit, et le wallet en tire un neuf à chaque commande. Si le seau était indexé
    /// dessus, il suffirait de régénérer une clé pour repartir à crédit plein — le
    /// service serait étranglé sur le papier et illimité en pratique. Ici, 256 adresses
    /// du même `/16` partagent UN seau : le crédit total reste celui d'un groupe.
    #[test]
    fn le_credit_est_partage_par_tout_le_groupe_reseau() {
        let mut e = Etrangleur::new();
        // 256 « pairs » différents, tous dans 203.0.0.0/16.
        let mut servies = 0u64;
        for n in 0..256u16 {
            let g = groupe_v4(203, 0, (n % 256) as u8, (n / 256) as u8);
            if e.autoriser(g, 0) {
                e.debiter(g, 64);
                servies += 1;
            }
        }
        // Coût par requête : COUT_REQUETE + 64 entrées (la dernière peut passer avec
        // un crédit partiel, d'où la tolérance d'une unité).
        let attendu = CAPACITE_SEAU / (COUT_REQUETE + 64);
        assert!(
            (attendu..=attendu + 1).contains(&servies),
            "le crédit d'un /16 ne se multiplie pas par le nombre d'adresses \
             (servies = {servies}, attendu ≈ {attendu})"
        );
        assert_eq!(e.len(), 1, "un seul seau pour tout le groupe");
    }

    /// Des groupes DISTINCTS ont des crédits distincts : étrangler un attaquant ne doit
    /// pas étrangler les autres. Sans cela, saturer son propre seau suffirait à couper
    /// le service d'historique pour tout le réseau — un déni de service à prix d'une
    /// seule machine.
    #[test]
    fn deux_groupes_distincts_ne_se_penalisent_pas() {
        let mut e = Etrangleur::new();
        let a = groupe_v4(203, 0, 113, 1);
        let b = groupe_v4(198, 51, 100, 1);
        while e.autoriser(a, 0) {
            e.debiter(a, 512);
        }
        assert!(e.credit(&a) < COUT_REQUETE, "a est à sec");
        assert!(e.autoriser(b, 0), "b n'a rien fait et doit être servi");
    }

    /// LE NOMBRE DE REQUÊTES EST ÉTRANGLÉ, PAS SEULEMENT LES ENTRÉES SERVIES.
    ///
    /// Une réponse vide n'est pas gratuite : allocation, double chiffrement, écriture,
    /// flush. Si seules les entrées servies étaient facturées, demander en boucle une
    /// hauteur inexistante coûterait 9 octets à l'attaquant et un aller-retour complet
    /// au nœud — l'asymétrie exacte que tout le projet cherche à éviter.
    #[test]
    fn les_requetes_sans_reponse_consomment_du_credit() {
        let mut e = Etrangleur::new();
        let g = groupe_v4(203, 0, 113, 1);
        let mut n = 0u64;
        while e.autoriser(g, 0) {
            n += 1; // on ne sert RIEN : aucun `debiter`
            assert!(
                n <= CAPACITE_SEAU,
                "boucle infinie : le sondage serait gratuit"
            );
        }
        assert_eq!(n, CAPACITE_SEAU / COUT_REQUETE);
    }

    /// LA RECHARGE NE PERD PAS LES FRACTIONS.
    ///
    /// Un pair qui interroge toutes les 3 ms gagnerait `3 × 256 / 1000 = 0` jeton entier.
    /// Si l'horodatage avançait quand même, son crédit ne remonterait jamais : il
    /// s'auto-bannirait du service à vie sans qu'aucune ligne ne l'ait décidé. Le
    /// comptage en millièmes ferme ce cas.
    #[test]
    fn la_recharge_ne_perd_pas_les_fractions() {
        let mut e = Etrangleur::new();
        let g = groupe_v4(203, 0, 113, 1);
        // Vider le seau.
        while e.autoriser(g, 0) {
            e.debiter(g, 1_024);
        }
        assert!(e.credit(&g) < COUT_REQUETE);

        // 1 000 pas de 3 ms = 3 s de recharge, soit 3 × 256 = 768 entrées-équivalent,
        // donc ≈96 requêtes à COUT_REQUETE. Avec une recharge tronquée à l'entier, le
        // gain par pas vaudrait 0 et le compte serait ZÉRO.
        let mut passees = 0u64;
        for i in 1..=1_000u64 {
            if e.autoriser(g, i * 3) {
                passees += 1;
            }
        }
        assert!(
            passees > 50,
            "le crédit doit remonter malgré des pas plus courts qu'un jeton \
             (seulement {passees} requêtes passées en 3 s)"
        );
    }

    /// Le crédit PLAFONNE : un groupe silencieux depuis un an ne doit pas accumuler un
    /// droit de rafale illimité, sinon la borne ne borne plus rien.
    #[test]
    fn le_credit_plafonne_a_la_capacite() {
        let mut e = Etrangleur::new();
        let g = groupe_v4(203, 0, 113, 1);
        assert!(e.autoriser(g, 0));
        assert!(e.autoriser(g, u64::MAX / 2));
        assert!(
            e.credit(&g) <= CAPACITE_SEAU,
            "le crédit ne dépasse jamais la capacité"
        );
    }

    /// La table de seaux est BORNÉE, et l'éviction n'accorde rien.
    ///
    /// Sans borne, la mémoire du nœud croîtrait avec le nombre de préfixes rencontrés.
    /// L'éviction ne choisit que des seaux à PLEIN crédit : évincer un seau épuisé
    /// reviendrait à rendre son crédit à celui qui vient de le vider — il suffirait de
    /// saturer la table pour se blanchir.
    #[test]
    fn la_table_est_bornee_et_leviction_naccorde_rien() {
        let mut e = Etrangleur::new();
        // Un groupe qu'on vide entièrement.
        let vide = groupe_v4(10, 0, 0, 1);
        while e.autoriser(vide, 0) {
            e.debiter(vide, 1_024);
        }
        let credit_apres_vidage = e.credit(&vide);

        // Puis on inonde la table avec des groupes distincts (IPv6 /32 : l'espace est
        // vaste, c'est le cas le plus favorable à l'attaquant).
        for n in 0..(MAX_GROUPES_SUIVIS as u32 * 2) {
            let adr = SocketAddr::from((
                Ipv6Addr::new(
                    (n >> 16) as u16 | 0x2000,
                    (n & 0xffff) as u16,
                    0,
                    0,
                    0,
                    0,
                    0,
                    1,
                ),
                8333,
            ));
            let _ = e.autoriser(GroupeReseau::de(&adr), 0);
        }
        assert!(
            e.len() <= MAX_GROUPES_SUIVIS,
            "la table doit rester bornée ({} entrées)",
            e.len()
        );
        assert!(
            e.credit(&vide) <= credit_apres_vidage,
            "saturer la table ne doit pas blanchir un groupe épuisé"
        );
    }
}
