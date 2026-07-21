//! Table de pairs et sélection résistante à l'ECLIPSE (phase 4, brique 2).
//!
//! # Pourquoi cette brique est de la sécurité, pas de la comptabilité
//!
//! Si un adversaire contrôle TOUS nos pairs (attaque *eclipse*), Dandelion++
//! (brique 4) devient **inutile** : la phase *stem* ne route plus qu'à travers lui,
//! qui apprend donc l'origine de chaque transaction. La confidentialité réseau que
//! vise toute la phase 4 s'effondre ICI, avant même le protocole d'anonymisation.
//!
//! Conséquence de conception : **on ne choisit jamais ses pairs sortants au hasard
//! dans une liste plate**. Une liste plate se laisse inonder — créer 10 000 entrées
//! depuis une seule machine ne coûte rien.
//!
//! # Le coût imposé à l'attaquant
//!
//! Les pairs sont regroupés par **groupe réseau** (IPv4 `/16`, IPv6 `/32`), et la
//! sélection sortante impose des groupes DISTINCTS. Occuper N emplacements sortants
//! exige donc N groupes réseau distincts — c'est-à-dire de l'adressage réparti,
//! coûteux et traçable, au lieu d'un simple script sur une machine.
//!
//! ⚠️ Cela ne rend pas l'eclipse impossible : un adversaire disposant réellement de
//! nombreux préfixes (opérateur, cloud multi-régions, BGP) reste capable. Le but est
//! de **rendre l'attaque chère et visible**, pas de la nier.

use crypto::hash::dual_hash;
use crypto::sig::SigPublicKey;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

const D_PEER_ID: &str = "obscura/net/peer-id/v1";

/// Identifiant stable d'un pair : hachage de sa clé publique d'identité.
///
/// **Jamais tronqué** (principe du projet) : les 64 octets de `dual_hash`
/// (BLAKE3‖SHA3-256) sont conservés. Un identifiant tronqué inviterait des
/// collisions choisies — un adversaire fabriquerait une identité au même préfixe
/// pour usurper une place dans la table.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PeerId([u8; 64]);

impl PeerId {
    pub fn depuis_identite(pk: &SigPublicKey) -> Self {
        PeerId(dual_hash(D_PEER_ID, &pk.to_bytes()))
    }

    pub fn octets(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Groupe réseau d'une adresse : l'unité de coût pour un attaquant Sybil.
///
/// IPv4 → `/16`, IPv6 → `/32`. Deux adresses du même groupe sont considérées comme
/// relevant du même « propriétaire réseau » : elles ne peuvent pas occuper deux
/// emplacements sortants.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct GroupeReseau([u8; 4]);

impl GroupeReseau {
    pub fn de(adresse: &SocketAddr) -> Self {
        match adresse.ip() {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                GroupeReseau([0, 0, o[0], o[1]]) // /16
            }
            IpAddr::V6(v6) => {
                let o = v6.octets();
                GroupeReseau([o[0], o[1], o[2], o[3]]) // /32
            }
        }
    }
}

/// État d'un pair connu.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pair {
    pub id: PeerId,
    pub adresse: SocketAddr,
    /// Score de comportement. Négatif = suspect ; sous `SEUIL_BANNISSEMENT`, exclu
    /// de toute sélection.
    pub score: i32,
}

impl Pair {
    pub fn groupe(&self) -> GroupeReseau {
        GroupeReseau::de(&self.adresse)
    }

    pub fn banni(&self) -> bool {
        self.score <= SEUIL_BANNISSEMENT
    }
}

/// Sous ce score, un pair n'est plus jamais sélectionné.
pub const SEUIL_BANNISSEMENT: i32 = -100;

/// Nombre d'emplacements sortants. Chacun doit venir d'un groupe réseau DISTINCT.
pub const EMPLACEMENTS_SORTANTS: usize = 8;

/// Table des pairs connus.
#[derive(Default)]
pub struct TablePairs {
    pairs: HashMap<PeerId, Pair>,
}

impl TablePairs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ajoute ou met à jour un pair. Retourne `true` si c'était un nouveau.
    pub fn ajouter(&mut self, id: PeerId, adresse: SocketAddr) -> bool {
        match self.pairs.get_mut(&id) {
            Some(p) => {
                p.adresse = adresse;
                false
            }
            None => {
                self.pairs.insert(id, Pair { id, adresse, score: 0 });
                true
            }
        }
    }

    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    pub fn get(&self, id: &PeerId) -> Option<&Pair> {
        self.pairs.get(id)
    }

    /// Ajuste le score d'un pair (positif = bon comportement, négatif = mauvais).
    pub fn ajuster_score(&mut self, id: &PeerId, delta: i32) {
        if let Some(p) = self.pairs.get_mut(id) {
            p.score = p.score.saturating_add(delta);
        }
    }

    /// Nombre de groupes réseau distincts représentés parmi les pairs non bannis.
    ///
    /// C'est la mesure de la DIVERSITÉ réellement disponible : elle plafonne le
    /// nombre d'emplacements sortants qu'on peut remplir sans se contredire.
    pub fn groupes_disponibles(&self) -> usize {
        let mut vus: Vec<GroupeReseau> = self
            .pairs
            .values()
            .filter(|p| !p.banni())
            .map(|p| p.groupe())
            .collect();
        vus.sort_by_key(|g| g.0);
        vus.dedup();
        vus.len()
    }

    /// Sélectionne les pairs sortants : **au plus un par groupe réseau**, jamais de
    /// pair banni, au plus `EMPLACEMENTS_SORTANTS`.
    ///
    /// C'est LA propriété anti-eclipse. Inonder la table depuis un seul groupe
    /// n'augmente PAS le nombre d'emplacements occupés : le résultat reste borné par
    /// le nombre de groupes distincts.
    ///
    /// Déterministe (tri par identifiant) pour que les tests soient reproductibles ;
    /// une version de production y ajouterait un aléa par nœud afin qu'un adversaire
    /// ne puisse pas prédire quel pair d'un groupe sera retenu.
    pub fn selection_sortante(&self) -> Vec<&Pair> {
        let mut candidats: Vec<&Pair> = self.pairs.values().filter(|p| !p.banni()).collect();
        // Meilleur score d'abord, puis identifiant pour départager de façon stable.
        candidats.sort_by(|a, b| b.score.cmp(&a.score).then(a.id.0.cmp(&b.id.0)));

        let mut groupes_pris: Vec<GroupeReseau> = Vec::new();
        let mut retenus = Vec::new();
        for p in candidats {
            if retenus.len() >= EMPLACEMENTS_SORTANTS {
                break;
            }
            let g = p.groupe();
            if groupes_pris.contains(&g) {
                continue; // un seul par groupe réseau
            }
            groupes_pris.push(g);
            retenus.push(p);
        }
        retenus
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::sig::SigKeypair;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn id_quelconque(n: u64) -> PeerId {
        // Identifiant synthétique déterministe (évite de générer une paire de clés
        // hybride — coûteuse — pour chaque pair de test).
        PeerId(dual_hash(D_PEER_ID, &n.to_le_bytes()))
    }

    fn adresse_v4(a: u8, b: u8, c: u8, d: u8) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(a, b, c, d), 8333))
    }

    /// L'identifiant dérive de l'identité, est déterministe, et distingue deux
    /// identités.
    #[test]
    fn peer_id_derive_de_l_identite() {
        let a = SigKeypair::generate();
        let b = SigKeypair::generate();
        assert_eq!(
            PeerId::depuis_identite(&a.public),
            PeerId::depuis_identite(&a.public),
            "déterministe"
        );
        assert_ne!(
            PeerId::depuis_identite(&a.public),
            PeerId::depuis_identite(&b.public)
        );
        // Non tronqué : 64 octets de dual_hash.
        assert_eq!(PeerId::depuis_identite(&a.public).octets().len(), 64);
    }

    /// Le groupe réseau agrège bien par /16 (IPv4) et /32 (IPv6).
    #[test]
    fn groupe_reseau_agrege_par_prefixe() {
        // Même /16 → même groupe, même si les deux derniers octets diffèrent.
        assert_eq!(
            GroupeReseau::de(&adresse_v4(203, 0, 113, 1)),
            GroupeReseau::de(&adresse_v4(203, 0, 200, 99))
        );
        // /16 différent → groupe différent.
        assert_ne!(
            GroupeReseau::de(&adresse_v4(203, 0, 113, 1)),
            GroupeReseau::de(&adresse_v4(203, 1, 113, 1))
        );
        // IPv6 : /32.
        let v6a = SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1), 8333));
        let v6b = SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 9, 9, 9, 9, 9, 9), 8333));
        let v6c = SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb9, 1, 0, 0, 0, 0, 1), 8333));
        assert_eq!(GroupeReseau::de(&v6a), GroupeReseau::de(&v6b));
        assert_ne!(GroupeReseau::de(&v6a), GroupeReseau::de(&v6c));
    }

    /// ANTI-ECLIPSE — la propriété centrale de cette brique.
    ///
    /// Un attaquant inonde la table avec 500 pairs depuis UN SEUL groupe réseau
    /// (trivial : une machine, un /16). Il ne doit obtenir qu'UN emplacement
    /// sortant, pas 8 — sinon il éclipse le nœud et Dandelion++ ne protège plus rien.
    #[test]
    fn inondation_depuis_un_seul_groupe_n_obtient_qu_un_emplacement() {
        let mut t = TablePairs::new();
        for n in 0..500u64 {
            // Tous dans 203.0.x.y → même /16.
            t.ajouter(id_quelconque(n), adresse_v4(203, 0, (n % 256) as u8, 7));
        }
        assert_eq!(t.len(), 500, "la table accepte les entrées…");
        let sel = t.selection_sortante();
        assert_eq!(
            sel.len(),
            1,
            "…mais un seul groupe réseau ne donne qu'UN emplacement sortant"
        );
    }

    /// À l'inverse, une vraie diversité remplit les emplacements.
    #[test]
    fn diversite_reelle_remplit_les_emplacements() {
        let mut t = TablePairs::new();
        for n in 0..EMPLACEMENTS_SORTANTS as u64 {
            t.ajouter(id_quelconque(n), adresse_v4(203, n as u8, 113, 1));
        }
        assert_eq!(t.groupes_disponibles(), EMPLACEMENTS_SORTANTS);
        assert_eq!(t.selection_sortante().len(), EMPLACEMENTS_SORTANTS);
    }

    /// La sélection est BORNÉE : au-delà des emplacements, on ne prend pas plus.
    #[test]
    fn selection_bornee_par_les_emplacements() {
        let mut t = TablePairs::new();
        for n in 0..(EMPLACEMENTS_SORTANTS as u64 * 4) {
            t.ajouter(id_quelconque(n), adresse_v4(10, n as u8, 0, 1));
        }
        assert_eq!(t.selection_sortante().len(), EMPLACEMENTS_SORTANTS);
    }

    /// Un pair banni est exclu de la sélection ET du décompte de diversité — sinon
    /// un attaquant « réserverait » un groupe avec un pair banni pour empêcher un
    /// pair honnête du même groupe d'être choisi.
    #[test]
    fn pair_banni_exclu_de_la_selection_et_de_la_diversite() {
        let mut t = TablePairs::new();
        let mechant = id_quelconque(1);
        t.ajouter(mechant, adresse_v4(198, 51, 100, 1));
        assert_eq!(t.groupes_disponibles(), 1);

        t.ajuster_score(&mechant, SEUIL_BANNISSEMENT);
        assert!(t.get(&mechant).unwrap().banni());
        assert!(t.selection_sortante().is_empty(), "banni jamais sélectionné");
        assert_eq!(t.groupes_disponibles(), 0, "un banni ne réserve pas son groupe");
    }

    /// Le score départage à l'intérieur d'un groupe : le mieux noté l'emporte.
    #[test]
    fn meilleur_score_prefere_dans_un_groupe() {
        let mut t = TablePairs::new();
        let faible = id_quelconque(1);
        let fort = id_quelconque(2);
        t.ajouter(faible, adresse_v4(192, 0, 2, 1));
        t.ajouter(fort, adresse_v4(192, 0, 2, 2)); // même /16
        t.ajuster_score(&fort, 50);

        let sel = t.selection_sortante();
        assert_eq!(sel.len(), 1, "même groupe → un seul retenu");
        assert_eq!(sel[0].id, fort, "le mieux noté doit l'emporter");
    }

    /// Le score sature au lieu de déborder (un pair très longtemps pénalisé ne doit
    /// pas repasser positif par wrap-around).
    #[test]
    fn score_sature_sans_deborder() {
        let mut t = TablePairs::new();
        let p = id_quelconque(1);
        t.ajouter(p, adresse_v4(192, 0, 2, 1));
        t.ajuster_score(&p, i32::MIN);
        t.ajuster_score(&p, i32::MIN);
        assert!(t.get(&p).unwrap().banni(), "doit rester banni, pas wrapper");
    }

    /// Ré-ajouter un pair connu met à jour son adresse sans le dupliquer ni remettre
    /// son score à zéro (sinon un banni se blanchirait en se réannonçant).
    #[test]
    fn reajout_ne_blanchit_pas_un_banni() {
        let mut t = TablePairs::new();
        let p = id_quelconque(1);
        t.ajouter(p, adresse_v4(192, 0, 2, 1));
        t.ajuster_score(&p, SEUIL_BANNISSEMENT);

        assert!(!t.ajouter(p, adresse_v4(198, 51, 100, 9)), "pas un nouveau");
        assert_eq!(t.len(), 1, "pas de doublon");
        assert!(
            t.get(&p).unwrap().banni(),
            "se réannoncer ne doit PAS effacer un bannissement"
        );
    }
}
