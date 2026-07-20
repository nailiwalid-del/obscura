//! État du ledger PROUVÉ (3c) : arbre Rescue + nullifiers, piloté par la preuve STARK.
//!
//! Contrairement à `state::apply_transparent` (mode de dev non-sound), `apply_proved_tx`
//! applique la RÈGLE DE CONSENSUS CIBLE : il vérifie la preuve `ProvedTx`
//! (`circuit::verify_tx`, qui établit P1–P7 + non-rejeu) contre une racine récente,
//! puis dépense les nullifiers et insère les commitments de sortie dans l'arbre Rescue.
//!
//! L'arbre du nœud est une `proved_hash::merkle::MerkleFrontier` (durcissement #7) :
//! append-only, ne conserve que le bord droit (O(depth), mémoire bornée), et rend
//! `TreeFull` plutôt que paniquer sur un arbre plein. Il produit les MÊMES racines
//! que la `ProvedMerkleTree` de référence (test différentiel), donc les preuves
//! d'appartenance `circuit::membership` restent valides. Le nœud n'a pas besoin des
//! CHEMINS (produits côté wallet par `ProvedMerkleTree`) : il n'appelle qu'`append` +
//! `root`.
//!
//! Depuis 3z-a6, `ProvedTx` est monolithique (v3 depuis enc-notes) : `proof` est LA
//! preuve unique (P1–P7 pour toute la tx, une seule trace) et les nullifiers/commitments
//! de sortie sont des champs publics top-level (`tx.nullifiers`, plus de
//! `tx.spends[i].nullifier`) — la provenance change, la logique de consensus
//! ci-dessous (anchor → preuve → signature d'intention → nullifiers → application
//! atomique) est inchangée.
//!
//! Depuis 3z-b1, la preuve monolithique vérifiée ici est witness-hiding (HVZK en
//! ROM — voir docs/STARK_STATEMENT.md, « Argument HVZK ») ; rien ne change côté
//! ledger (blinding transparent au vérifieur).
//!
//! Hors périmètre (→ ledger/Phase 3z-c) : généralisation M-in/N-out.

use crate::LedgerError;
use circuit::{verify_tx, ProvedTx, INTENT_DOMAIN};
use crypto::sig;
use proved_hash::digest::Digest;
use proved_hash::merkle::{FrontierDecodeError, MerkleFrontier};
use std::collections::{HashSet, VecDeque};

/// Erreur de désérialisation de l'état (`ProvedLedgerState::from_bytes`). Le
/// fichier d'état est local et trusté : la validation détecte la corruption sans
/// jamais paniquer.
#[derive(Debug, PartialEq, Eq)]
pub enum StateDecodeError {
    /// Champ tronqué (moins d'octets que nécessaire).
    TooShort,
    /// Octets résiduels après la fin — encodage non canonique.
    TrailingBytes,
    /// La `MerkleFrontier` embarquée est corrompue.
    BadFrontier(FrontierDecodeError),
}

/// Erreur de chargement d'un état depuis un fichier (`load`).
#[derive(Debug)]
pub enum StateLoadError {
    Io(std::io::Error),
    Decode(StateDecodeError),
}

impl std::fmt::Display for StateLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateLoadError::Io(e) => write!(f, "E/S : {e}"),
            StateLoadError::Decode(e) => write!(f, "décodage d'état : {e:?}"),
        }
    }
}
impl std::error::Error for StateLoadError {}

/// Fenêtre glissante de racines récentes acceptées (cf. `state::RECENT_ROOTS_WINDOW`).
pub const RECENT_ROOTS_WINDOW: usize = 100;

pub struct ProvedLedgerState {
    pub tree: MerkleFrontier,
    nullifiers: HashSet<[u8; 32]>,
    recent_roots: HashSet<[u8; 32]>,
    roots_order: VecDeque<[u8; 32]>,
}

impl ProvedLedgerState {
    /// État aux paramètres consensus (profondeur 32).
    pub fn new() -> Self {
        Self::with_tree(MerkleFrontier::consensus())
    }

    /// État en profondeur `depth` — tests/dev uniquement.
    pub fn with_depth(depth: usize) -> Self {
        Self::with_tree(MerkleFrontier::new(depth))
    }

    fn with_tree(tree: MerkleFrontier) -> Self {
        let mut s = ProvedLedgerState {
            tree,
            nullifiers: HashSet::new(),
            recent_roots: HashSet::new(),
            roots_order: VecDeque::new(),
        };
        let root = s.tree.root();
        s.remember_root(root);
        s
    }

    fn remember_root(&mut self, root: Digest) {
        let key = root.to_bytes();
        if self.recent_roots.insert(key) {
            self.roots_order.push_back(key);
            if self.roots_order.len() > RECENT_ROOTS_WINDOW {
                if let Some(old) = self.roots_order.pop_front() {
                    self.recent_roots.remove(&old);
                }
            }
        }
    }

    /// Émission (faucet du prototype) : insère un commitment prouvé, retourne son
    /// index. `TreeFull` si l'arbre est saturé (2^profondeur feuilles).
    pub fn mint(&mut self, cm: &Digest) -> Result<u64, LedgerError> {
        let idx = self.tree.append(cm).map_err(|_| LedgerError::TreeFull)?;
        let root = self.tree.root();
        self.remember_root(root);
        Ok(idx)
    }

    pub fn is_spent(&self, nullifier: &Digest) -> bool {
        self.nullifiers.contains(&nullifier.to_bytes())
    }

    /// Valide et applique une transaction PROUVÉE (règle de consensus cible).
    ///
    /// Étapes : (1) l'anchor est une racine récente ; (2) la preuve établit P1–P7 +
    /// non-rejeu (`verify_tx`) ; (3) aucun nullifier déjà dépensé, ni doublon interne ;
    /// puis application atomique (dépense des nullifiers, insertion des sorties).
    /// Retourne les index d'insertion des commitments de sortie.
    pub fn apply_proved_tx(&mut self, tx: &ProvedTx) -> Result<Vec<u64>, LedgerError> {
        // 1. Anchor connu et récent.
        if !self.recent_roots.contains(&tx.anchor.to_bytes()) {
            return Err(LedgerError::UnknownRoot);
        }
        // 2. La preuve établit P1–P7 + liaison tx_digest contre CET anchor.
        if !verify_tx(&tx.anchor, self.tree.depth(), tx) {
            return Err(LedgerError::InvalidProof);
        }
        // 2 bis. Enveloppe d'intention : signature hybride valide sur tx_digest
        // (anti-malléabilité ; le signataire est lié dans tx_digest).
        if !sig::verify(&tx.signer, INTENT_DOMAIN, &tx.tx_digest, &tx.intent_sig) {
            return Err(LedgerError::InvalidSignature);
        }
        // 3. Nullifiers non dépensés + pas de doublon dans la tx.
        let mut seen = HashSet::new();
        for nf in &tx.nullifiers {
            let nf = nf.to_bytes();
            if self.nullifiers.contains(&nf) || !seen.insert(nf) {
                return Err(LedgerError::DoubleSpend);
            }
        }
        // 3 bis. Capacité : refuser AVANT toute mutation si les sorties ne tiennent
        // pas dans l'arbre (atomicité — les nullifiers ne sont pas encore dépensés
        // ici). À 2^32 feuilles c'est hors de portée pratique, mais on garantit qu'un
        // arbre saturé rejette proprement (`TreeFull`) au lieu de paniquer.
        let n_out = tx.output_commitments.len() as u128;
        if (self.tree.len() as u128) + n_out > (1u128 << self.tree.depth()) {
            return Err(LedgerError::TreeFull);
        }
        // Application atomique.
        for nf in &tx.nullifiers {
            self.nullifiers.insert(nf.to_bytes());
        }
        let mut indices = Vec::with_capacity(tx.output_commitments.len());
        for oc in &tx.output_commitments {
            indices.push(self.tree.append(oc).map_err(|_| LedgerError::TreeFull)?);
        }
        let root = self.tree.root();
        self.remember_root(root);
        Ok(indices)
    }

    /// Encodage canonique de l'état consensus (durcissement #7) : `len(tree) u32 LE
    /// ‖ tree ‖ N u64 LE ‖ nullifiers TRIÉS (32 o) ‖ M u64 LE ‖ roots_order FIFO
    /// (32 o)`. Les nullifiers sont triés (le `HashSet` n'a pas d'ordre stable) →
    /// même état ⇒ mêmes octets. `roots_order` garde son ordre FIFO (la fenêtre
    /// glissante en dépend) ; `recent_roots` est reconstruit au chargement.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        let tree = self.tree.to_bytes();
        b.extend_from_slice(&(tree.len() as u32).to_le_bytes());
        b.extend_from_slice(&tree);

        let mut nfs: Vec<[u8; 32]> = self.nullifiers.iter().copied().collect();
        nfs.sort_unstable();
        b.extend_from_slice(&(nfs.len() as u64).to_le_bytes());
        for nf in &nfs {
            b.extend_from_slice(nf);
        }

        b.extend_from_slice(&(self.roots_order.len() as u64).to_le_bytes());
        for r in &self.roots_order {
            b.extend_from_slice(r);
        }
        b
    }

    /// Décode l'état depuis `to_bytes`. Curseur BORNÉ (chaque prise vérifie les
    /// octets restants) et validant — aucune panique sur fichier corrompu.
    pub fn from_bytes(b: &[u8]) -> Result<Self, StateDecodeError> {
        let mut pos = 0usize;
        fn take<'a>(b: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], StateDecodeError> {
            let end = pos.checked_add(n).ok_or(StateDecodeError::TooShort)?;
            if end > b.len() {
                return Err(StateDecodeError::TooShort);
            }
            let s = &b[*pos..end];
            *pos = end;
            Ok(s)
        }

        let tree_len = u32::from_le_bytes(take(b, &mut pos, 4)?.try_into().unwrap()) as usize;
        let tree_bytes = take(b, &mut pos, tree_len)?;
        let tree = MerkleFrontier::from_bytes(tree_bytes).map_err(StateDecodeError::BadFrontier)?;

        let n = u64::from_le_bytes(take(b, &mut pos, 8)?.try_into().unwrap());
        let n = usize::try_from(n).map_err(|_| StateDecodeError::TooShort)?;
        let mut nullifiers = HashSet::with_capacity(n);
        for _ in 0..n {
            let d: [u8; 32] = take(b, &mut pos, 32)?.try_into().unwrap();
            nullifiers.insert(d);
        }

        let m = u64::from_le_bytes(take(b, &mut pos, 8)?.try_into().unwrap());
        let m = usize::try_from(m).map_err(|_| StateDecodeError::TooShort)?;
        let mut roots_order = VecDeque::with_capacity(m);
        let mut recent_roots = HashSet::with_capacity(m);
        for _ in 0..m {
            let d: [u8; 32] = take(b, &mut pos, 32)?.try_into().unwrap();
            roots_order.push_back(d);
            recent_roots.insert(d);
        }

        if pos != b.len() {
            return Err(StateDecodeError::TrailingBytes);
        }
        Ok(ProvedLedgerState {
            tree,
            nullifiers,
            recent_roots,
            roots_order,
        })
    }

    /// Sauvegarde ATOMIQUE : écrit dans `<path>.tmp` puis `rename` (aucun état à
    /// moitié écrit après un crash — `rename` est atomique sur un même système de
    /// fichiers).
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, self.to_bytes())?;
        std::fs::rename(&tmp, path)
    }

    /// Recharge un état depuis un fichier écrit par `save`.
    pub fn load(path: &std::path::Path) -> Result<Self, StateLoadError> {
        let bytes = std::fs::read(path).map_err(StateLoadError::Io)?;
        Self::from_bytes(&bytes).map_err(StateLoadError::Decode)
    }
}

impl Default for ProvedLedgerState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit::{prove_tx, ProvedInput, SpendNote};
    use proved_hash::domain::Domain;
    use proved_hash::felt::Felt;
    use proved_hash::rescue;

    fn digest(seed: u64) -> Digest {
        Digest(core::array::from_fn(|i| {
            Felt::from_canonical_u64(seed + i as u64).unwrap()
        }))
    }

    const DEPTH: usize = 4; // petit pour la vitesse (membership@32 validé ailleurs)

    /// Prépare un état avec 2 notes d'entrée émises et construit une tx équilibrée.
    /// Retourne (état, tx, indices d'entrée).
    fn setup() -> (ProvedLedgerState, circuit::ProvedTx) {
        let secret = proved_hash::digest::ShieldedSecret::from_felts(core::array::from_fn(|i| {
            Felt::from_canonical_u64(700 + i as u64).unwrap()
        }));
        let owner = rescue::hash(Domain::Owner, secret.as_felts());

        let n0 = SpendNote { value: 1_000, owner, rho: digest(20), r: digest(30) };
        let n1 = SpendNote { value: 500, owner, rho: digest(40), r: digest(50) };
        let cm0 = rescue::note_commitment(n0.value, &n0.owner, &n0.rho, &n0.r);
        let cm1 = rescue::note_commitment(n1.value, &n1.owner, &n1.rho, &n1.r);

        let mut state = ProvedLedgerState::with_depth(DEPTH);
        // Arbre wallet parallèle : produit les chemins (le nœud n'a que la frontier,
        // qui n'expose pas `path`). Mêmes commitments, même ordre → même racine
        // (garanti par `merkle::frontier_differentiel_full_tree`), donc témoin valide.
        let mut wallet_tree = proved_hash::merkle::ProvedMerkleTree::new(DEPTH);
        let i0 = state.mint(&cm0).unwrap();
        let i1 = state.mint(&cm1).unwrap();
        wallet_tree.append(&cm0);
        wallet_tree.append(&cm1);
        debug_assert_eq!(state.tree.root(), wallet_tree.root());
        let path0 = wallet_tree.path(i0).unwrap();
        let path1 = wallet_tree.path(i1).unwrap();

        let o0 = SpendNote { value: 900, owner: digest(60), rho: digest(61), r: digest(62) };
        let o1 = SpendNote { value: 580, owner: digest(70), rho: digest(71), r: digest(72) };
        let oc0 = rescue::note_commitment(o0.value, &o0.owner, &o0.rho, &o0.r);
        let oc1 = rescue::note_commitment(o1.value, &o1.owner, &o1.rho, &o1.r);

        let inputs = [
            ProvedInput { note: n0, path: path0, index: i0 },
            ProvedInput { note: n1, path: path1, index: i1 },
        ];
        let intent = crypto::sig::SigKeypair::generate();
        // enc_notes RÉELS chiffrés vers deux destinataires (keypairs éphémères ici — le
        // scan de bout en bout est testé par `applique_puis_scanne`). Leur binding dans
        // tx_digest v3 est ainsi exercé sur de vrais ciphertexts.
        let (r0, r1) = (crypto::kem::KemKeypair::generate(), crypto::kem::KemKeypair::generate());
        let enc_notes = [
            crate::proved_wallet::encrypt_note(&r0.public, &oc0, &o0),
            crate::proved_wallet::encrypt_note(&r1.public, &oc1, &o1),
        ];
        let (_root, tx) = prove_tx(&secret, inputs, [o0, o1], 20, &intent, enc_notes);
        (state, tx)
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn applique_une_tx_prouvee() {
        let (mut state, tx) = setup();
        // Les nullifiers ne sont pas encore dépensés.
        assert!(!state.is_spent(&tx.nullifiers[0]));
        let indices = state.apply_proved_tx(&tx).expect("tx valide");
        assert_eq!(indices.len(), 2); // 2 sorties insérées
        // Nullifiers désormais dépensés.
        assert!(state.is_spent(&tx.nullifiers[0]));
        assert!(state.is_spent(&tx.nullifiers[1]));
    }

    /// e2e chemin prouvé : construire → appliquer → SCANNER. Les deux destinataires
    /// retrouvent LEUR note de sortie via `scan_proved_output` sur
    /// `(output_commitments[j], enc_notes[j])` ; un non-destinataire échoue.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn applique_puis_scanne() {
        let secret = proved_hash::digest::ShieldedSecret::from_felts(core::array::from_fn(|i| {
            Felt::from_canonical_u64(700 + i as u64).unwrap()
        }));
        let owner = rescue::hash(Domain::Owner, secret.as_felts());
        let n0 = SpendNote { value: 1_000, owner, rho: digest(20), r: digest(30) };
        let n1 = SpendNote { value: 500, owner, rho: digest(40), r: digest(50) };
        let cm0 = rescue::note_commitment(n0.value, &n0.owner, &n0.rho, &n0.r);
        let cm1 = rescue::note_commitment(n1.value, &n1.owner, &n1.rho, &n1.r);

        let mut state = ProvedLedgerState::with_depth(DEPTH);
        // Arbre wallet parallèle pour les chemins (cf. `setup`).
        let mut wallet_tree = proved_hash::merkle::ProvedMerkleTree::new(DEPTH);
        let (i0, i1) = (state.mint(&cm0).unwrap(), state.mint(&cm1).unwrap());
        wallet_tree.append(&cm0);
        wallet_tree.append(&cm1);
        let (path0, path1) = (wallet_tree.path(i0).unwrap(), wallet_tree.path(i1).unwrap());

        // Deux destinataires avec leurs clés KEM et owners prouvés.
        let alice = crypto::kem::KemKeypair::generate();
        let bob = crypto::kem::KemKeypair::generate();
        let (owner_a, owner_b) = (digest(60), digest(70));
        let o0 = SpendNote { value: 900, owner: owner_a, rho: digest(61), r: digest(62) };
        let o1 = SpendNote { value: 580, owner: owner_b, rho: digest(71), r: digest(72) };
        let oc0 = rescue::note_commitment(o0.value, &o0.owner, &o0.rho, &o0.r);
        let oc1 = rescue::note_commitment(o1.value, &o1.owner, &o1.rho, &o1.r);

        let inputs = [
            ProvedInput { note: n0, path: path0, index: i0 },
            ProvedInput { note: n1, path: path1, index: i1 },
        ];
        let enc_notes = [
            crate::proved_wallet::encrypt_note(&alice.public, &oc0, &o0),
            crate::proved_wallet::encrypt_note(&bob.public, &oc1, &o1),
        ];
        let intent = crypto::sig::SigKeypair::generate();
        let (_root, tx) = prove_tx(&secret, inputs, [o0.clone(), o1.clone()], 20, &intent, enc_notes);

        state.apply_proved_tx(&tx).expect("tx valide");

        // Alice retrouve o0, Bob retrouve o1 — sur les PUBLICS de la tx (oc + enc_note).
        assert_eq!(
            crate::proved_wallet::scan_proved_output(&alice, &owner_a, &tx.output_commitments[0], &tx.enc_notes[0]),
            Some(o0)
        );
        assert_eq!(
            crate::proved_wallet::scan_proved_output(&bob, &owner_b, &tx.output_commitments[1], &tx.enc_notes[1]),
            Some(o1)
        );
        // Alice n'est pas destinataire de la sortie 1.
        assert_eq!(
            crate::proved_wallet::scan_proved_output(&alice, &owner_a, &tx.output_commitments[1], &tx.enc_notes[1]),
            None
        );
    }

    /// Anti-substitution au NIVEAU LEDGER (relais passif) : substituer un enc_note sans
    /// re-signer casse le digest → `verify_tx` échoue → `apply_proved_tx` rejette
    /// (`InvalidProof`, avant même la vérification de signature). NB : un relais ACTIF
    /// qui re-signe avec sa propre clé produirait un substitut accepté (déni de scan) —
    /// limitation documentée (le signataire d'intention n'est pas lié au secret).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn enc_note_substitue_rejete_au_ledger() {
        let (mut state, mut tx) = setup();
        tx.enc_notes[0].enc_note = vec![0xBA, 0xD0];
        assert!(matches!(
            state.apply_proved_tx(&tx),
            Err(LedgerError::InvalidProof)
        ));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn double_depense_rejetee() {
        let (mut state, tx) = setup();
        assert!(state.apply_proved_tx(&tx).is_ok());
        // Rejouer la même tx : nullifiers déjà dépensés.
        assert!(matches!(
            state.apply_proved_tx(&tx),
            Err(LedgerError::DoubleSpend)
        ));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn anchor_inconnu_rejete() {
        let (mut state, mut tx) = setup();
        tx.anchor = digest(123456); // racine jamais vue
        assert!(matches!(
            state.apply_proved_tx(&tx),
            Err(LedgerError::UnknownRoot)
        ));
    }

    // En v2, les montants ne sont plus des champs publics visibles (`tx.outputs` a
    // disparu) : on ne peut plus saboter l'équilibre en mutant une valeur en clair
    // après-coup. On falsifie donc un autre public — le commitment de sortie. Cela
    // casserait AUSSI `tx_digest`, mais `verify_tx` court-circuite sur `verify_monolith`
    // AVANT la comparaison du digest : c'est donc l'assertion du monolithe (cellule
    // liée) qui rejette ici — la défense `tx_digest` n'est pas exercée par ce test.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn preuve_falsifiee_rejetee() {
        let (mut state, mut tx) = setup();
        // Sabotage d'un public de la preuve : anchor reste récent mais verify_tx échoue.
        tx.output_commitments[0] = digest(321);
        assert!(matches!(
            state.apply_proved_tx(&tx),
            Err(LedgerError::InvalidProof)
        ));
    }

    /// Un nullifier ne peut pas être substitué après coup : il est asserté DANS la
    /// preuve du monolithe (cellule liée au commitment consommé) ET lié dans
    /// `tx_digest`. Le remplacer par un digest arbitraire violerait les deux, mais
    /// `verify_tx` court-circuite sur `verify_monolith` AVANT de comparer `tx_digest` :
    /// c'est donc l'assertion du monolithe qui rejette (`InvalidProof`), la défense
    /// `tx_digest` restant non exercée. Distinct de `preuve_falsifiee_rejetee` qui
    /// falsifie le commitment de sortie plutôt que le nullifier.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn nullifier_ne_peut_etre_substitue() {
        let (mut state, mut tx) = setup();
        tx.nullifiers[0] = digest(999_999);
        assert!(matches!(
            state.apply_proved_tx(&tx),
            Err(LedgerError::InvalidProof)
        ));
    }

    /// Signature d'intention falsifiée (signée par une autre clé) → rejet.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn signature_intention_falsifiee_rejetee() {
        let (mut state, mut tx) = setup();
        // Signature valide MAIS d'une autre clé que `tx.signer` → verify échoue.
        let autre = crypto::sig::SigKeypair::generate();
        tx.intent_sig = autre.sign(INTENT_DOMAIN, &tx.tx_digest);
        assert!(matches!(
            state.apply_proved_tx(&tx),
            Err(LedgerError::InvalidSignature)
        ));
    }

    /// Saturation via `mint` : un arbre de faible profondeur refuse le mint qui
    /// dépasse `2^profondeur` — `Result` (`TreeFull`), jamais de panique. Aucune
    /// preuve STARK ⇒ tourne en build nu (pas de `--release`).
    #[test]
    fn mint_sur_arbre_plein_rend_treefull() {
        let mut state = ProvedLedgerState::with_depth(1); // 2^1 = 2 feuilles
        assert!(state.mint(&digest(1)).is_ok());
        assert!(state.mint(&digest(2)).is_ok());
        assert!(matches!(state.mint(&digest(3)), Err(LedgerError::TreeFull)));
    }

    /// Persistance (#7) : `from_bytes(to_bytes)` restaure un état au COMPORTEMENT
    /// fidèle — nullifiers dépensés, fenêtre de racines, arbre. Aucune preuve STARK
    /// ⇒ build nu.
    #[test]
    fn etat_serialisation_roundtrip_comportement() {
        let mut state = ProvedLedgerState::with_depth(8);
        state.mint(&digest(1)).unwrap();
        state.mint(&digest(2)).unwrap();
        // Simuler une dépense : marquer un nullifier (champ privé, accès module).
        state.nullifiers.insert(digest(4242).to_bytes());
        let root_courant = state.tree.root();

        let bytes = state.to_bytes();
        let reloaded = ProvedLedgerState::from_bytes(&bytes).expect("roundtrip");

        assert_eq!(reloaded.to_bytes(), bytes, "canonique (même octets)");
        assert_eq!(reloaded.tree.root(), root_courant);
        assert_eq!(reloaded.tree.len(), state.tree.len());
        assert!(reloaded.is_spent(&digest(4242)));
        // La racine courante reste dans la fenêtre (anchor accepté après rechargement).
        assert!(reloaded.recent_roots.contains(&root_courant.to_bytes()));
    }

    /// Matrice de rejet de `from_bytes` — jamais de panique.
    #[test]
    fn etat_serialisation_rejette_les_malformes() {
        let state = ProvedLedgerState::with_depth(4);
        let bytes = state.to_bytes();
        assert!(matches!(
            ProvedLedgerState::from_bytes(&bytes[..bytes.len() - 1]),
            Err(StateDecodeError::TooShort)
        ));
        let mut trailing = bytes.clone();
        trailing.push(7);
        assert!(matches!(
            ProvedLedgerState::from_bytes(&trailing),
            Err(StateDecodeError::TrailingBytes)
        ));
        assert!(matches!(
            ProvedLedgerState::from_bytes(&[]),
            Err(StateDecodeError::TooShort)
        ));
    }

    /// `save`/`load` à travers un vrai fichier temporaire : l'état rechargé égale
    /// l'original (mêmes octets). Écriture atomique (tmp + rename).
    #[test]
    fn save_load_fichier_roundtrip() {
        let mut state = ProvedLedgerState::with_depth(6);
        state.mint(&digest(11)).unwrap();
        state.mint(&digest(22)).unwrap();
        state.nullifiers.insert(digest(7).to_bytes());

        let path = std::env::temp_dir().join(format!(
            "obscura_state_test_{}.bin",
            std::process::id()
        ));
        state.save(&path).expect("save");
        let reloaded = ProvedLedgerState::load(&path).expect("load");
        assert_eq!(reloaded.to_bytes(), state.to_bytes());
        assert!(reloaded.is_spent(&digest(7)));
        std::fs::remove_file(&path).ok();
    }

    /// Charger un fichier absent = erreur d'E/S (pas de panique).
    #[test]
    fn load_fichier_absent_est_erreur_io() {
        let path = std::env::temp_dir().join("obscura_absent_zzz_introuvable.bin");
        std::fs::remove_file(&path).ok();
        assert!(matches!(
            ProvedLedgerState::load(&path),
            Err(StateLoadError::Io(_))
        ));
    }

    /// Échanger le signataire casse `tx_digest` (il y est lié) → la preuve est rejetée
    /// AVANT même la signature — le signataire n'est pas échangeable.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn signataire_non_echangeable() {
        let (mut state, mut tx) = setup();
        tx.signer = crypto::sig::SigKeypair::generate().public;
        assert!(matches!(
            state.apply_proved_tx(&tx),
            Err(LedgerError::InvalidProof)
        ));
    }
}
