//! Mempool : transactions prouvées reçues, validées, en attente d'inclusion
//! (phase 4, brique 3).
//!
//! # L'asymétrie de coût est LE vecteur de DoS de ce projet
//!
//! Vérifier une `ProvedTx` coûte ~4 ms (vérification STARK) pour ~68 Kio envoyés.
//! Le rapport est écrasant en faveur de l'attaquant : avec une bande passante
//! modeste il sature le CPU de tout le réseau, bien plus efficacement qu'avec une
//! attaque volumétrique.
//!
//! La parade n'est pas un filtre de plus, c'est un **ORDRE** : tous les contrôles
//! O(1) passent AVANT la vérification coûteuse. Une transaction rejetée par un
//! contrôle bon marché coûte des microsecondes ; seule une transaction qui les
//! franchit tous mérite qu'on dépense 4 ms.
//!
//! ```text
//!  1. mempool plein ?              O(1)
//!  2. déjà connue (tx_digest) ?    O(1)
//!  3. conflit de nullifier ?       O(1)
//!  4. déjà dépensée on-chain ?     O(1)
//!  5. ancre récente connue ?       O(1)
//!  ────────────────────────────────────  frontière du coût
//!  6. vérification STARK + signature   ~4 ms
//! ```
//!
//! Cet ordre est TESTÉ, pas seulement documenté : voir
//! `doublon_court_circuite_avant_la_verification`.
//!
//! # Mémoire bornée
//!
//! Un mempool non borné est un DoS trivial. La capacité est fixe et l'admission
//! échoue quand elle est atteinte — plutôt qu'une éviction, qui offrirait à un
//! attaquant un moyen de chasser les transactions honnêtes.

use crate::proved_state::ProvedLedgerState;
use circuit::{verify_proved_tx_full, ProvedTx};
use std::collections::{HashMap, HashSet};

/// Capacité par défaut, en nombre de transactions. Bornée : c'est elle qui
/// transforme « mémoire dictée par l'attaquant » en « refus ».
pub const CAPACITE_DEFAUT: usize = 5_000;

/// Raison d'un refus d'admission. Chaque variante indique aussi À QUEL COÛT le refus
/// a été prononcé — ce qui permet à l'appelant de pénaliser un pair différemment
/// selon qu'il envoie du bruit bon marché ou une preuve invalide (coûteuse).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Refus {
    /// Capacité atteinte. Contrôle O(1).
    Plein,
    /// Transaction déjà présente. O(1) — cas le plus fréquent en propagation
    /// normale, donc placé tôt.
    DejaConnue,
    /// Un nullifier entre en conflit avec une transaction DÉJÀ dans le mempool
    /// (double-dépense entre transactions en attente). O(1).
    ConflitMempool,
    /// Un nullifier est déjà dépensé sur la chaîne. O(1).
    DejaDepense,
    /// L'ancre n'est pas une racine récente connue. O(1).
    AncreInconnue,
    /// La preuve STARK ou la signature d'intention est invalide. **Coûteux** :
    /// seul refus ayant consommé ~4 ms — c'est celui qui doit pénaliser lourdement
    /// le pair émetteur.
    PreuveInvalide,
}

impl Refus {
    /// `true` si le refus a été prononcé APRÈS la vérification coûteuse. Un pair qui
    /// en provoque doit être pénalisé bien plus lourdement qu'un pair qui envoie des
    /// doublons : il nous a fait dépenser du CPU.
    pub fn couteux(self) -> bool {
        matches!(self, Refus::PreuveInvalide)
    }
}

/// Réserve de transactions en attente.
pub struct Mempool {
    capacite: usize,
    /// Indexé par `tx_digest` : identifiant naturel et déjà lié à tous les champs.
    par_digest: HashMap<[u8; 64], ProvedTx>,
    /// Nullifiers engagés par les transactions présentes — détecte les
    /// double-dépenses ENTRE transactions en attente, invisibles à l'état on-chain.
    nullifiers: HashSet<[u8; 32]>,
}

impl Mempool {
    pub fn new() -> Self {
        Self::avec_capacite(CAPACITE_DEFAUT)
    }

    pub fn avec_capacite(capacite: usize) -> Self {
        Mempool {
            capacite,
            par_digest: HashMap::new(),
            nullifiers: HashSet::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.par_digest.len()
    }

    pub fn is_empty(&self) -> bool {
        self.par_digest.is_empty()
    }

    pub fn contient(&self, digest: &[u8; 64]) -> bool {
        self.par_digest.contains_key(digest)
    }

    pub fn get(&self, digest: &[u8; 64]) -> Option<&ProvedTx> {
        self.par_digest.get(digest)
    }

    /// Les digests présents — c'est ce qu'on ANNONCE aux pairs (et non les
    /// transactions elles-mêmes : annoncer 68 Kio à chaque pair serait une
    /// amplification offerte à l'attaquant).
    pub fn digests(&self) -> Vec<[u8; 64]> {
        self.par_digest.keys().copied().collect()
    }

    /// Tente d'admettre `tx`. Applique les contrôles du MOINS au PLUS coûteux ;
    /// la vérification STARK n'est atteinte que si tout le reste passe.
    pub fn admettre(&mut self, etat: &ProvedLedgerState, tx: ProvedTx) -> Result<(), Refus> {
        // 1. Capacité — O(1).
        if self.par_digest.len() >= self.capacite {
            return Err(Refus::Plein);
        }
        // 2. Doublon — O(1). Cas le PLUS fréquent en propagation normale (plusieurs
        //    pairs annoncent la même transaction), donc placé au plus tôt.
        if self.par_digest.contains_key(&tx.tx_digest) {
            return Err(Refus::DejaConnue);
        }
        // 3. Conflit avec une transaction déjà en attente — O(1).
        for nf in &tx.nullifiers {
            if self.nullifiers.contains(&nf.to_bytes()) {
                return Err(Refus::ConflitMempool);
            }
        }
        // 4. Déjà dépensé sur la chaîne — O(1).
        for nf in &tx.nullifiers {
            if etat.is_spent(nf) {
                return Err(Refus::DejaDepense);
            }
        }
        // 5. Ancre récente — O(1).
        if !etat.anchor_connu(&tx.anchor) {
            return Err(Refus::AncreInconnue);
        }

        // ---- frontière du coût : tout ce qui suit est cher ----

        // 6. Preuve STARK + signature d'intention (~4 ms).
        if !verify_proved_tx_full(&tx.anchor, etat.tree.depth(), &tx) {
            return Err(Refus::PreuveInvalide);
        }

        for nf in &tx.nullifiers {
            self.nullifiers.insert(nf.to_bytes());
        }
        self.par_digest.insert(tx.tx_digest, tx);
        Ok(())
    }

    /// Retire une transaction (typiquement parce qu'elle vient d'être incluse dans
    /// un bloc) et libère ses nullifiers.
    pub fn retirer(&mut self, digest: &[u8; 64]) -> Option<ProvedTx> {
        let tx = self.par_digest.remove(digest)?;
        for nf in &tx.nullifiers {
            self.nullifiers.remove(&nf.to_bytes());
        }
        Some(tx)
    }

    /// Purge les transactions devenues invalides après une avancée de l'état
    /// (nullifiers désormais dépensés, ancre sortie de la fenêtre). Retourne le
    /// nombre de transactions retirées.
    ///
    /// Sans cette purge, une transaction incluse dans un bloc resterait
    /// indéfiniment en mémoire et continuerait d'être annoncée aux pairs.
    pub fn purger(&mut self, etat: &ProvedLedgerState) -> usize {
        let obsoletes: Vec<[u8; 64]> = self
            .par_digest
            .iter()
            .filter(|(_, tx)| {
                tx.nullifiers.iter().any(|nf| etat.is_spent(nf)) || !etat.anchor_connu(&tx.anchor)
            })
            .map(|(d, _)| *d)
            .collect();
        for d in &obsoletes {
            self.retirer(d);
        }
        obsoletes.len()
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proved_wallet::encrypt_note;
    use circuit::{prove_tx, ProvedInput, SpendNote};
    use proved_hash::digest::{Digest, ShieldedSecret};
    use proved_hash::domain::Domain;
    use proved_hash::felt::Felt;
    use proved_hash::{merkle, rescue};

    const DEPTH: usize = 4;

    fn digest(seed: u64) -> Digest {
        Digest(core::array::from_fn(|i| {
            Felt::from_canonical_u64(seed + i as u64).unwrap()
        }))
    }

    /// État avec deux notes émises + une transaction valide contre cet état.
    fn etat_et_tx(graine: u64) -> (ProvedLedgerState, ProvedTx) {
        let secret = ShieldedSecret::from_felts(core::array::from_fn(|i| {
            Felt::from_canonical_u64(graine + i as u64).unwrap()
        }));
        let owner = rescue::hash(Domain::Owner, secret.as_felts());
        let n0 = SpendNote { value: 1_000, owner, rho: digest(graine + 20), r: digest(30) };
        let n1 = SpendNote { value: 500, owner, rho: digest(graine + 40), r: digest(50) };
        let cm0 = rescue::note_commitment(n0.value, &n0.owner, &n0.rho, &n0.r);
        let cm1 = rescue::note_commitment(n1.value, &n1.owner, &n1.rho, &n1.r);

        let mut etat = ProvedLedgerState::with_depth(DEPTH);
        let mut arbre = merkle::ProvedMerkleTree::new(DEPTH);
        let i0 = etat.mint(&cm0).unwrap();
        let i1 = etat.mint(&cm1).unwrap();
        arbre.append(&cm0);
        arbre.append(&cm1);

        let o0 = SpendNote { value: 900, owner: digest(60), rho: digest(61), r: digest(62) };
        let o1 = SpendNote { value: 580, owner: digest(70), rho: digest(71), r: digest(72) };
        let oc0 = rescue::note_commitment(o0.value, &o0.owner, &o0.rho, &o0.r);
        let oc1 = rescue::note_commitment(o1.value, &o1.owner, &o1.rho, &o1.r);
        let (r0, r1) = (crypto::kem::KemKeypair::generate(), crypto::kem::KemKeypair::generate());
        let enc = [encrypt_note(&r0.public, &oc0, &o0), encrypt_note(&r1.public, &oc1, &o1)];

        let inputs = [
            ProvedInput { note: n0, path: arbre.path(i0).unwrap(), index: i0 },
            ProvedInput { note: n1, path: arbre.path(i1).unwrap(), index: i1 },
        ];
        let intent = crypto::sig::SigKeypair::generate();
        let (_root, tx) = prove_tx(&secret, inputs, [o0, o1], 20, &intent, enc);
        (etat, tx)
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
    fn admet_une_transaction_valide() {
        let (etat, tx) = etat_et_tx(700);
        let mut m = Mempool::new();
        assert_eq!(m.admettre(&etat, tx), Ok(()));
        assert_eq!(m.len(), 1);
    }

    /// L'ORDRE des contrôles, pas seulement leur présence.
    ///
    /// On insère une transaction VALIDE, puis on resoumet la MÊME (même tx_digest)
    /// mais avec une preuve CORROMPUE. Si le doublon est bien testé AVANT la
    /// vérification STARK, le refus est `DejaConnue` — donc gratuit. S'il venait
    /// après, on obtiendrait `PreuveInvalide`, c'est-à-dire 4 ms brûlées sur une
    /// transaction qu'on avait déjà.
    ///
    /// C'est exactement le levier d'un attaquant : réémettre en boucle des doublons
    /// coûteux à écarter.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
    fn doublon_court_circuite_avant_la_verification() {
        let (etat, tx) = etat_et_tx(700);
        let digest_tx = tx.tx_digest;
        let mut m = Mempool::new();
        assert_eq!(m.admettre(&etat, tx), Ok(()));

        // Même digest, preuve inutilisable : seule une vérification STARK pourrait
        // s'en apercevoir.
        let (_e2, mut corrompue) = etat_et_tx(700);
        corrompue.tx_digest = digest_tx;
        assert_eq!(
            m.admettre(&etat, corrompue),
            Err(Refus::DejaConnue),
            "le doublon doit court-circuiter AVANT la vérification coûteuse"
        );
    }

    /// Double-dépense ENTRE deux transactions en attente : invisible à l'état
    /// on-chain (rien n'est encore dépensé), donc c'est au mempool de la voir.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
    fn conflit_de_nullifier_dans_le_mempool_rejete() {
        let (etat, tx) = etat_et_tx(700);
        let mut m = Mempool::new();
        assert_eq!(m.admettre(&etat, tx), Ok(()));

        // Une autre transaction dépensant les MÊMES notes — donc les MÊMES
        // nullifiers, qui sont déterministes — mais avec un digest différent (clé
        // d'intention fraîche) : le filtre de doublon ne l'attrape donc PAS.
        let (_e, autre) = etat_et_tx(700);
        assert_eq!(m.admettre(&etat, autre), Err(Refus::ConflitMempool));
    }

    /// Ancre inconnue : refus BON MARCHÉ, avant toute vérification.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
    fn ancre_inconnue_rejetee() {
        let (etat, mut tx) = etat_et_tx(700);
        tx.anchor = digest(999_999);
        let mut m = Mempool::new();
        let r = m.admettre(&etat, tx).unwrap_err();
        assert_eq!(r, Refus::AncreInconnue);
        assert!(!r.couteux(), "ce refus doit être gratuit");
    }

    /// Capacité bornée : au-delà, on refuse plutôt que d'évincer — une éviction
    /// offrirait à un attaquant un moyen de chasser les transactions honnêtes.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
    fn capacite_bornee_refuse_au_lieu_d_evincer() {
        let (etat, tx) = etat_et_tx(700);
        let mut m = Mempool::avec_capacite(1);
        assert_eq!(m.admettre(&etat, tx), Ok(()));

        let (_e, autre) = etat_et_tx(800);
        assert_eq!(m.admettre(&etat, autre), Err(Refus::Plein));
        assert_eq!(m.len(), 1, "la transaction déjà présente n'est PAS évincée");
    }

    /// Une preuve invalide est le seul refus COÛTEUX — l'appelant doit pouvoir le
    /// distinguer pour pénaliser lourdement le pair.
    #[test]
    fn seul_le_refus_de_preuve_est_couteux() {
        assert!(Refus::PreuveInvalide.couteux());
        for r in [Refus::Plein, Refus::DejaConnue, Refus::ConflitMempool, Refus::DejaDepense, Refus::AncreInconnue] {
            assert!(!r.couteux(), "{r:?} doit être un refus bon marché");
        }
    }

    /// Purge : une transaction dont les nullifiers sont désormais dépensés
    /// on-chain quitte le mempool — sinon elle serait annoncée indéfiniment.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
    fn purge_les_transactions_devenues_obsoletes() {
        let (mut etat, tx) = etat_et_tx(700);
        let d = tx.tx_digest;
        let mut m = Mempool::new();
        assert_eq!(m.admettre(&etat, tx), Ok(()));

        // Une transaction équivalente (mêmes notes → MÊMES nullifiers) est appliquée
        // à la chaîne : celle du mempool devient donc obsolète.
        let (_e, jumelle) = etat_et_tx(700);
        etat.apply_proved_tx(&jumelle).expect("tx valide");
        assert_eq!(m.purger(&etat), 1, "doit purger la transaction incluse");
        assert!(!m.contient(&d));
        assert!(m.is_empty());
    }
}
