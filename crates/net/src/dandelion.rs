//! Dandelion++ : anonymisation de l'ORIGINE des transactions (phase 4, brique 4).
//!
//! Une transaction se propage en deux temps :
//!
//! - **stem** (tige) : elle est relayée à UN SEUL pair, formant une ligne dans le
//!   réseau. Un observateur qui la voit passer ne peut pas distinguer l'émetteur
//!   d'un simple relais.
//! - **fluff** (floraison) : à chaque saut, avec une probabilité `q`, le nœud bascule
//!   en diffusion classique vers tous ses pairs.
//!
//! # Pourquoi le successeur est stable par ÉPOQUE
//!
//! Dandelion **v1** tirait un successeur au hasard POUR CHAQUE TRANSACTION. Un
//! adversaire recevant plusieurs transactions d'un même nœud apprenait ainsi son
//! voisinage et pouvait corréler — l'attaque de *graph learning*.
//!
//! Dandelion**++** fixe **un seul successeur par époque** : sur toute une époque,
//! l'adversaire voit soit TOUTES nos transactions stemmées, soit AUCUNE. Il
//! n'apprend rien de la topologie. C'est LA correction qui distingue les deux
//! versions, et elle est structurelle — pas un réglage.
//!
//! # Pourquoi la décision stem/fluff est un HACHAGE, pas un tirage
//!
//! Un tirage aléatoire pur laisserait un adversaire SONDER : réémettre la même
//! transaction jusqu'à obtenir un fluff, et observer. La décision est donc un
//! hachage déterministe de `(époque, transaction, secret du nœud)` : reproductible
//! pour le nœud (donc testable et stable face au sondage), imprévisible pour qui
//! ignore le secret.
//!
//! # Pourquoi l'embargo
//!
//! Un successeur malveillant peut simplement AVALER la transaction (*black-holing*) :
//! elle n'est jamais diffusée et l'émetteur l'ignore. L'embargo impose donc une
//! échéance : passé ce délai sans avoir vu la transaction revenir, le nœud la
//! diffuse lui-même.
//!
//! # Dépendance à la brique 2
//!
//! Le successeur est tiré de la sélection SORTANTE (`pairs::TablePairs`), donc de
//! pairs à groupes réseau distincts. Si un adversaire éclipsait le nœud, il serait
//! successeur à coup sûr et Dandelion++ ne protégerait plus rien : **l'anonymat
//! repose sur la diversité des pairs**, pas seulement sur ce module.

use crate::pairs::{PeerId, TablePairs};
use crypto::hash::dual_hash;

const D_SUCCESSEUR: &str = "obscura/net/dandelion/successeur/v1";
const D_FLUFF: &str = "obscura/net/dandelion/fluff/v1";

/// Probabilité de basculer en fluff à chaque saut, en millièmes (`100` = 10 %).
/// Valeur usuelle de la littérature Dandelion++.
pub const PROBABILITE_FLUFF_MILLIEMES: u32 = 100;

/// Délai d'embargo (millisecondes) : passé ce temps sans avoir revu la transaction,
/// le nœud la diffuse lui-même pour contrer le *black-holing*.
pub const EMBARGO_MS: u64 = 30_000;

/// Décision de routage pour une transaction.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Routage {
    /// Relayer à ce seul pair (phase tige).
    Stem(PeerId),
    /// Diffuser à tous les pairs (phase floraison).
    Fluff,
}

/// État Dandelion++ d'un nœud.
///
/// Le `secret` rend la décision stem/fluff imprévisible pour un adversaire tout en
/// la gardant déterministe pour le nœud : c'est ce qui ferme le sondage.
pub struct Dandelion {
    secret: [u8; 32],
    epoque: u64,
    successeur: Option<PeerId>,
    /// Transactions stemmées en attente : digest → échéance d'embargo (ms).
    embargos: Vec<([u8; 64], u64)>,
}

impl Dandelion {
    pub fn new(secret: [u8; 32]) -> Self {
        Dandelion {
            secret,
            epoque: 0,
            successeur: None,
            embargos: Vec::new(),
        }
    }

    pub fn epoque(&self) -> u64 {
        self.epoque
    }

    /// Successeur courant, s'il a été choisi pour cette époque.
    pub fn successeur(&self) -> Option<PeerId> {
        self.successeur
    }

    /// Ouvre une nouvelle époque et re-choisit le successeur.
    ///
    /// Le choix est déterministe en `(époque, secret)` : deux nœuds distincts
    /// choisissent différemment, et le même nœud rechoisit de façon reproductible —
    /// ce qui rend la propriété testable sans introduire d'aléa non maîtrisé.
    pub fn nouvelle_epoque(&mut self, epoque: u64, table: &TablePairs) {
        self.epoque = epoque;
        let candidats = table.selection_sortante();
        if candidats.is_empty() {
            self.successeur = None;
            return;
        }
        // Sélection par hachage : (secret, époque) → index.
        let mut graine = Vec::with_capacity(40);
        graine.extend_from_slice(&self.secret);
        graine.extend_from_slice(&epoque.to_le_bytes());
        let h = dual_hash(D_SUCCESSEUR, &graine);
        let idx = u64::from_le_bytes(h[..8].try_into().unwrap()) as usize % candidats.len();
        self.successeur = Some(candidats[idx].id);
    }

    /// Décide du routage d'une transaction, et arme l'embargo si elle est stemmée.
    ///
    /// `maintenant_ms` est injecté plutôt que lu d'une horloge : le comportement
    /// temporel est ainsi testable de façon déterministe.
    pub fn router(&mut self, digest: &[u8; 64], maintenant_ms: u64) -> Routage {
        match self.successeur {
            // Sans successeur (aucun pair diversifié), stemmer serait un trou noir :
            // on diffuse plutôt que de perdre la transaction.
            None => Routage::Fluff,
            Some(s) => {
                if self.doit_fleurir(digest) {
                    Routage::Fluff
                } else {
                    self.armer_embargo(digest, maintenant_ms);
                    Routage::Stem(s)
                }
            }
        }
    }

    /// Décision stem/fluff : hachage de `(secret, époque, digest)` comparé au seuil.
    /// Déterministe pour le nœud, imprévisible pour un adversaire — donc insensible
    /// au sondage par réémission.
    fn doit_fleurir(&self, digest: &[u8; 64]) -> bool {
        let mut graine = Vec::with_capacity(104);
        graine.extend_from_slice(&self.secret);
        graine.extend_from_slice(&self.epoque.to_le_bytes());
        graine.extend_from_slice(digest);
        let h = dual_hash(D_FLUFF, &graine);
        let tirage = u32::from_le_bytes(h[..4].try_into().unwrap()) % 1000;
        tirage < PROBABILITE_FLUFF_MILLIEMES
    }

    fn armer_embargo(&mut self, digest: &[u8; 64], maintenant_ms: u64) {
        if self.embargos.iter().any(|(d, _)| d == digest) {
            return;
        }
        self.embargos
            .push((*digest, maintenant_ms.saturating_add(EMBARGO_MS)));
    }

    /// La transaction a été revue sur le réseau (quelqu'un l'a diffusée) : l'embargo
    /// est levé.
    pub fn transaction_revue(&mut self, digest: &[u8; 64]) {
        self.embargos.retain(|(d, _)| d != digest);
    }

    /// Transactions dont l'embargo a EXPIRÉ : le successeur ne les a pas diffusées,
    /// on les diffuse soi-même. Les retire de la liste d'attente.
    ///
    /// C'est la parade au *black-holing* : sans elle, un successeur malveillant fait
    /// disparaître silencieusement les transactions qu'on lui confie.
    pub fn embargos_expires(&mut self, maintenant_ms: u64) -> Vec<[u8; 64]> {
        let (expires, restants): (Vec<_>, Vec<_>) = self
            .embargos
            .iter()
            .partition(|(_, echeance)| *echeance <= maintenant_ms);
        self.embargos = restants;
        expires.into_iter().map(|(d, _)| d).collect()
    }

    /// Nombre de transactions sous embargo.
    pub fn en_attente(&self) -> usize {
        self.embargos.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    fn table_diversifiee(n: u8) -> TablePairs {
        let mut t = TablePairs::new();
        for i in 0..n {
            let id = PeerId::depuis_octets_de_test(i as u64);
            t.ajouter(id, SocketAddr::from((Ipv4Addr::new(203, i, 113, 1), 8333)));
        }
        t
    }

    fn digest_de(n: u64) -> [u8; 64] {
        dual_hash("test", &n.to_le_bytes())
    }

    /// LA propriété qui distingue Dandelion++ de v1 : sur une époque donnée, TOUTES
    /// les transactions stemmées partent vers le MÊME successeur.
    ///
    /// Avec un successeur tiré par transaction (v1), un adversaire recevant
    /// plusieurs de nos transactions apprendrait notre voisinage — c'est l'attaque
    /// de graph learning.
    #[test]
    fn successeur_stable_sur_toute_l_epoque() {
        let table = table_diversifiee(8);
        let mut d = Dandelion::new([7u8; 32]);
        d.nouvelle_epoque(1, &table);
        let s = d.successeur().expect("un successeur");

        let mut stemmees = 0;
        for n in 0..200u64 {
            if let Routage::Stem(vers) = d.router(&digest_de(n), 0) {
                assert_eq!(vers, s, "toutes les tiges d'une époque vont au MÊME pair");
                stemmees += 1;
            }
        }
        assert!(
            stemmees > 100,
            "la majorité doit être stemmée (fluff ~10 %)"
        );
    }

    /// Changer d'époque re-tire le successeur (sinon la route serait figée à vie et
    /// un adversaire finirait par l'identifier).
    #[test]
    fn le_successeur_change_avec_l_epoque() {
        let table = table_diversifiee(8);
        let mut d = Dandelion::new([7u8; 32]);
        let mut vus = Vec::new();
        for e in 0..20u64 {
            d.nouvelle_epoque(e, &table);
            vus.push(d.successeur().unwrap());
        }
        vus.dedup();
        assert!(
            vus.len() > 1,
            "le successeur doit varier d'une époque à l'autre"
        );
    }

    /// Deux nœuds différents (secrets différents) ne choisissent pas le même
    /// successeur au même moment — sinon la topologie de tige serait globale et
    /// prévisible.
    #[test]
    fn deux_noeuds_choisissent_differemment() {
        let table = table_diversifiee(8);
        let (mut a, mut b) = (Dandelion::new([1u8; 32]), Dandelion::new([2u8; 32]));
        let mut differences = 0;
        for e in 0..20u64 {
            a.nouvelle_epoque(e, &table);
            b.nouvelle_epoque(e, &table);
            if a.successeur() != b.successeur() {
                differences += 1;
            }
        }
        assert!(differences > 10, "deux nœuds doivent router différemment");
    }

    /// La décision stem/fluff est DÉTERMINISTE pour une même transaction : réémettre
    /// ne permet pas de « retirer » jusqu'à obtenir un fluff (sondage).
    #[test]
    fn decision_insensible_au_sondage() {
        let table = table_diversifiee(8);
        let mut d = Dandelion::new([7u8; 32]);
        d.nouvelle_epoque(1, &table);
        let dg = digest_de(42);
        let premiere = d.router(&dg, 0);
        for _ in 0..50 {
            assert_eq!(
                d.router(&dg, 0),
                premiere,
                "réémettre ne doit pas changer la décision (anti-sondage)"
            );
        }
    }

    /// La proportion de fluff est proche du réglage (≈ 10 %) — ni toujours stem
    /// (la transaction ne se diffuserait jamais), ni toujours fluff (aucun anonymat).
    #[test]
    fn proportion_de_fluff_conforme_au_reglage() {
        let table = table_diversifiee(8);
        let mut d = Dandelion::new([7u8; 32]);
        d.nouvelle_epoque(1, &table);
        let n = 2000u64;
        let fluffs = (0..n)
            .filter(|i| d.router(&digest_de(*i), 0) == Routage::Fluff)
            .count();
        let pour_mille = (fluffs * 1000) / n as usize;
        assert!(
            (50..=180).contains(&pour_mille),
            "proportion de fluff hors plage : {pour_mille}‰ (réglage {PROBABILITE_FLUFF_MILLIEMES}‰)"
        );
    }

    /// EMBARGO : une transaction stemmée dont on n'entend plus parler est diffusée
    /// par nous-mêmes. Sans cela, un successeur malveillant l'avale silencieusement.
    #[test]
    fn embargo_expire_contre_le_black_holing() {
        let table = table_diversifiee(8);
        let mut d = Dandelion::new([7u8; 32]);
        d.nouvelle_epoque(1, &table);

        // Trouver une transaction effectivement stemmée.
        let dg = (0..100u64)
            .map(digest_de)
            .find(|dg| matches!(d.router(dg, 1_000), Routage::Stem(_)))
            .expect("au moins une tige");
        assert_eq!(d.en_attente(), 1);

        // Avant l'échéance : rien.
        assert!(d.embargos_expires(1_000 + EMBARGO_MS - 1).is_empty());
        // À l'échéance : on la diffuse nous-mêmes.
        let expires = d.embargos_expires(1_000 + EMBARGO_MS);
        assert_eq!(
            expires,
            vec![dg],
            "l'embargo expiré doit forcer la diffusion"
        );
        assert_eq!(d.en_attente(), 0, "et être retiré de l'attente");
    }

    /// Si la transaction est revue sur le réseau, l'embargo est levé : pas de
    /// double diffusion.
    #[test]
    fn transaction_revue_leve_l_embargo() {
        let table = table_diversifiee(8);
        let mut d = Dandelion::new([7u8; 32]);
        d.nouvelle_epoque(1, &table);
        let dg = (0..100u64)
            .map(digest_de)
            .find(|dg| matches!(d.router(dg, 0), Routage::Stem(_)))
            .expect("au moins une tige");

        d.transaction_revue(&dg);
        assert_eq!(d.en_attente(), 0);
        assert!(
            d.embargos_expires(EMBARGO_MS * 10).is_empty(),
            "une transaction revue ne doit pas être re-diffusée"
        );
    }

    /// SANS PAIR DIVERSIFIÉ, on diffuse plutôt que de stemmer : stemmer vers
    /// personne équivaudrait à un trou noir auto-infligé.
    #[test]
    fn sans_successeur_on_diffuse() {
        let vide = TablePairs::new();
        let mut d = Dandelion::new([7u8; 32]);
        d.nouvelle_epoque(1, &vide);
        assert_eq!(d.successeur(), None);
        assert_eq!(d.router(&digest_de(1), 0), Routage::Fluff);
        assert_eq!(d.en_attente(), 0, "rien sous embargo si rien n'est stemmé");
    }

    /// Le successeur provient de la sélection SORTANTE, donc de groupes réseau
    /// distincts. Une table inondée depuis un seul /16 n'offre qu'un candidat —
    /// l'anonymat de Dandelion++ dépend de la brique 2.
    #[test]
    fn successeur_issu_de_la_selection_diversifiee() {
        let mut inondee = TablePairs::new();
        for i in 0..200u64 {
            inondee.ajouter(
                PeerId::depuis_octets_de_test(i),
                SocketAddr::from((Ipv4Addr::new(203, 0, (i % 256) as u8, 1), 8333)),
            );
        }
        let mut d = Dandelion::new([7u8; 32]);
        d.nouvelle_epoque(1, &inondee);
        // Un seul groupe → un seul candidat : l'adversaire est successeur à coup sûr.
        // Le test FIGE cette dépendance plutôt que de la laisser implicite.
        let s = d.successeur().expect("un candidat");
        let sel = inondee.selection_sortante();
        assert_eq!(sel.len(), 1);
        assert_eq!(
            s, sel[0].id,
            "le successeur sort de la sélection diversifiée"
        );
    }
}
