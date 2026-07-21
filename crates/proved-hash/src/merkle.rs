//! Arbre de Merkle « hash prouvé » (Rescue-Prime) — référence HORS-CIRCUIT.
//!
//! C'est le pendant Rescue du `ledger::merkle` (BLAKE3) : il définit la feuille, le
//! nœud et la racine tels que le CIRCUIT (3b2b) devra les reproduire. Le différentiel
//! natif ⟷ circuit se fera contre `root` ci-dessous.
//!
//! Convention de bit alignée sur `ledger::merkle::verify_path` :
//! `bit 0 → (courant, frère)`, `bit 1 → (frère, courant)`, du bas vers le haut.

use crate::digest::Digest;
use crate::domain::Domain;
use crate::rescue;

/// Profondeur consensus (2^32 feuilles), cf. `ledger::merkle::CONSENSUS_DEPTH`.
pub const CONSENSUS_DEPTH: usize = 32;

/// Feuille : hash prouvé du commitment.
pub fn leaf(cm: &Digest) -> Digest {
    rescue::hash(Domain::MerkleLeaf, &cm.0)
}

/// Nœud interne : compression 2→1 domaine-séparée de (gauche, droite).
pub fn node(left: &Digest, right: &Digest) -> Digest {
    rescue::merge(Domain::MerkleNode, left, right)
}

/// Repli d'un chemin depuis une feuille DÉJÀ hachée `leaf`, en remontant `path`
/// selon les bits de `index`. C'est le cœur du calcul de racine (sans le hash de
/// feuille) — la référence du différentiel du chaînage en circuit (3b2b).
pub fn fold(leaf: &Digest, path: &[Digest], index: u64) -> Digest {
    let mut cur = *leaf;
    for (level, sib) in path.iter().enumerate() {
        let bit = (index >> level) & 1;
        cur = if bit == 0 {
            node(&cur, sib)
        } else {
            node(sib, &cur)
        };
    }
    cur
}

/// Racine obtenue en remontant `path` (frères, du bas vers le haut) depuis la
/// feuille `cm`, l'ordre à chaque niveau étant dicté par le bit de `index`.
pub fn root(cm: &Digest, path: &[Digest], index: u64) -> Digest {
    fold(&leaf(cm), path, index)
}

/// Profondeur réduite pour tests/dev, cf. `ledger::merkle::DEV_DEPTH`.
pub const DEV_DEPTH: usize = 16;

/// Feuille des sous-arbres vides (payload de longueur 0 → distinct de tout `leaf(cm)`
/// dont le payload fait 4 Felts : les `LEN` du préambule diffèrent).
fn empty_leaf() -> Digest {
    rescue::hash(Domain::MerkleLeaf, &[])
}

/// Hashs des sous-arbres vides pour chaque profondeur `0..=depth`.
fn empties(depth: usize) -> Vec<Digest> {
    let mut e = Vec::with_capacity(depth + 1);
    e.push(empty_leaf());
    for d in 0..depth {
        e.push(node(&e[d], &e[d]));
    }
    e
}

/// Arbre de Merkle « hash prouvé » incrémental — le pendant Rescue de
/// `ledger::merkle::MerkleTree`. Les chemins qu'il produit sont **compatibles
/// circuit** : `root(cm, tree.path(i), i) == tree.root()` (relation prouvée par
/// `circuit::membership`). Convention de bit identique (`bit 0 → (courant, frère)`).
pub struct ProvedMerkleTree {
    leaves: Vec<Digest>,
    depth: usize,
}

impl ProvedMerkleTree {
    pub fn new(depth: usize) -> Self {
        assert!(depth > 0 && depth <= 48, "profondeur invalide");
        ProvedMerkleTree {
            leaves: Vec::new(),
            depth,
        }
    }

    /// Arbre aux paramètres consensus (profondeur 32).
    pub fn consensus() -> Self {
        Self::new(CONSENSUS_DEPTH)
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Ajoute un commitment, retourne son index.
    pub fn append(&mut self, cm: &Digest) -> u64 {
        assert!(
            (self.leaves.len() as u128) < (1u128 << self.depth),
            "arbre plein"
        );
        self.leaves.push(leaf(cm));
        (self.leaves.len() - 1) as u64
    }

    /// Racine courante (feuilles réelles + sous-arbres vides).
    pub fn root(&self) -> Digest {
        let e = empties(self.depth);
        let mut level = self.leaves.clone();
        for ed in e.iter().take(self.depth) {
            if level.is_empty() {
                return e[self.depth];
            }
            if level.len() % 2 == 1 {
                level.push(*ed);
            }
            level = level.chunks(2).map(|p| node(&p[0], &p[1])).collect();
        }
        level[0]
    }

    /// Chemin d'appartenance (frères, du bas vers le haut) pour la feuille `index`.
    /// `None` si l'index dépasse le nombre de feuilles.
    pub fn path(&self, index: u64) -> Option<Vec<Digest>> {
        if index as usize >= self.leaves.len() {
            return None;
        }
        let e = empties(self.depth);
        let mut level = self.leaves.clone();
        let mut idx = index as usize;
        let mut siblings = Vec::with_capacity(self.depth);
        for ed in e.iter().take(self.depth) {
            if level.len() % 2 == 1 {
                level.push(*ed);
            }
            let sib = idx ^ 1;
            siblings.push(if sib < level.len() { level[sib] } else { *ed });
            level = level.chunks(2).map(|p| node(&p[0], &p[1])).collect();
            idx >>= 1;
        }
        Some(siblings)
    }

    /// Encodage canonique : `depth (u8) ‖ n (u64 LE) ‖ feuilles (n × 32 o)`.
    ///
    /// Les octets sont les feuilles DÉJÀ HACHÉES (`leaf(cm)`), pas les commitments —
    /// c'est ce que l'arbre conserve. Sérialiser cette représentation plutôt que les
    /// commitments d'origine évite d'exposer un accesseur qu'un appelant pourrait
    /// réalimenter par `append`, ce qui hacherait deux fois et produirait un arbre
    /// silencieusement faux.
    ///
    /// ⚠️ Coût inhérent au rôle wallet : contrairement à la `MerkleFrontier` du nœud
    /// (O(depth)), le dump est en O(n). Garder les feuilles est précisément ce qui
    /// permet de produire les chemins.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(1 + 8 + self.leaves.len() * 32);
        b.push(self.depth as u8);
        b.extend_from_slice(&(self.leaves.len() as u64).to_le_bytes());
        for l in &self.leaves {
            b.extend_from_slice(&l.to_bytes());
        }
        b
    }

    /// Décode un arbre depuis `to_bytes`. Borné et validant — aucune panique sur
    /// octets corrompus, et le compte de feuilles est vérifié AVANT allocation.
    pub fn from_bytes(b: &[u8]) -> Result<Self, TreeDecodeError> {
        if b.len() < 9 {
            return Err(TreeDecodeError::TooShort);
        }
        let depth = b[0] as usize;
        if depth == 0 || depth > 48 {
            return Err(TreeDecodeError::BadDepth);
        }
        let n = u64::from_le_bytes(b[1..9].try_into().unwrap());
        // Borne AVANT allocation : un en-tête annonçant 2^48 feuilles ne doit pas
        // nous faire réserver 9 Pio pour 9 octets lus.
        if (n as u128) > (1u128 << depth) {
            return Err(TreeDecodeError::BadCount);
        }
        let n = usize::try_from(n).map_err(|_| TreeDecodeError::BadCount)?;
        let attendu = 9usize
            .checked_add(n.checked_mul(32).ok_or(TreeDecodeError::BadCount)?)
            .ok_or(TreeDecodeError::BadCount)?;
        if b.len() < attendu {
            return Err(TreeDecodeError::TooShort);
        }
        if b.len() > attendu {
            return Err(TreeDecodeError::TrailingBytes);
        }
        let mut leaves = Vec::with_capacity(n);
        for i in 0..n {
            let arr: [u8; 32] = b[9 + i * 32..9 + (i + 1) * 32].try_into().unwrap();
            leaves.push(Digest::from_bytes(&arr).map_err(|_| TreeDecodeError::BadDigest)?);
        }
        Ok(ProvedMerkleTree { leaves, depth })
    }
}

/// Erreur de désérialisation d'un `ProvedMerkleTree` (`from_bytes`).
#[derive(Debug, PartialEq, Eq)]
pub enum TreeDecodeError {
    /// Moins d'octets qu'annoncé.
    TooShort,
    /// Octets résiduels après la fin — encodage non canonique.
    TrailingBytes,
    /// `depth` nul ou > 48.
    BadDepth,
    /// Plus de feuilles que `2^depth` n'en peut contenir.
    BadCount,
    /// Feuille non canonique (`Digest::from_bytes` échoue).
    BadDigest,
}

/// L'arbre a atteint `2^depth` feuilles : plus aucune insertion possible.
#[derive(Debug, PartialEq, Eq)]
pub struct TreeFull;

/// Erreur de désérialisation d'une `MerkleFrontier` (`from_bytes`). Le fichier
/// d'état est local et trusté : la validation détecte la CORRUPTION (troncature,
/// tailles/index incohérents) sans jamais paniquer.
#[derive(Debug, PartialEq, Eq)]
pub enum FrontierDecodeError {
    /// Moins d'octets que la taille attendue pour cette profondeur.
    TooShort,
    /// Octets résiduels après la fin — encodage non canonique.
    TrailingBytes,
    /// `depth` nul ou > 48.
    BadDepth,
    /// `next_index` > 2^depth (arbre impossible).
    BadIndex,
    /// Digest non canonique (`Digest::from_bytes` échoue).
    BadDigest,
    /// Arbre déclaré vide mais racine ≠ racine tout-vide.
    InconsistentRoot,
}

/// Arbre de Merkle append-only qui ne conserve QUE le bord droit (frontier) :
/// mémoire et coût par opération en O(depth), pas O(n). C'est l'état d'arbre du
/// NŒUD consensus (`ledger::ProvedLedgerState`), qui n'a besoin que d'`append` +
/// `root`. Les CHEMINS d'appartenance restent produits par `ProvedMerkleTree`
/// (rôle wallet : lui garde les feuilles). Racine identique à `ProvedMerkleTree`
/// (mêmes `node`/`leaf`/`empties`) → les preuves `circuit::membership` sont
/// inchangées (test différentiel `frontier_differentiel_full_tree`).
///
/// `Clone` est bon marché (O(depth), pas O(n)) — c'est ce qui permet d'appliquer un
/// bloc de façon ATOMIQUE en gardant une copie de l'arbre avant mutation.
#[derive(Clone)]
pub struct MerkleFrontier {
    depth: usize,
    /// Bord droit : à chaque niveau `i`, le dernier nœud gauche en attente de frère.
    filled_subtrees: Vec<Digest>,
    /// Sous-arbres vides `empties()[0..=depth]` (frère droit par défaut).
    zeros: Vec<Digest>,
    current_root: Digest,
    next_index: u64,
}

impl MerkleFrontier {
    pub fn new(depth: usize) -> Self {
        assert!(depth > 0 && depth <= 48, "profondeur invalide");
        let zeros = empties(depth); // longueur depth+1
        MerkleFrontier {
            depth,
            filled_subtrees: vec![zeros[0]; depth],
            current_root: zeros[depth],
            zeros,
            next_index: 0,
        }
    }

    /// Frontier aux paramètres consensus (profondeur 32).
    pub fn consensus() -> Self {
        Self::new(CONSENSUS_DEPTH)
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn len(&self) -> u64 {
        self.next_index
    }

    pub fn is_empty(&self) -> bool {
        self.next_index == 0
    }

    /// Racine courante — mémoïsée, O(1).
    pub fn root(&self) -> Digest {
        self.current_root
    }

    /// Ajoute un commitment (la feuille `leaf(cm)` est calculée en interne, comme
    /// `ProvedMerkleTree::append`). Retourne l'index d'insertion, ou `TreeFull` si
    /// l'arbre a atteint `2^depth` feuilles (aucune panique — durcissement #7).
    pub fn append(&mut self, cm: &Digest) -> Result<u64, TreeFull> {
        if (self.next_index as u128) >= (1u128 << self.depth) {
            return Err(TreeFull);
        }
        let index = self.next_index;
        let mut idx = self.next_index;
        let mut cur = leaf(cm);
        for i in 0..self.depth {
            let (left, right) = if idx.is_multiple_of(2) {
                // Nœud gauche : mémorise-le, frère droit encore vide.
                self.filled_subtrees[i] = cur;
                (cur, self.zeros[i])
            } else {
                // Nœud droit : combine avec le gauche mémorisé.
                (self.filled_subtrees[i], cur)
            };
            cur = node(&left, &right);
            idx /= 2;
        }
        self.current_root = cur;
        self.next_index += 1;
        Ok(index)
    }

    /// Encodage canonique : `depth (u8) ‖ next_index (u64 LE) ‖ filled_subtrees
    /// (depth × 32 o) ‖ current_root (32 o)`. `zeros` est dérivable de `depth`,
    /// donc non sérialisé.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(1 + 8 + self.depth * 32 + 32);
        b.push(self.depth as u8);
        b.extend_from_slice(&self.next_index.to_le_bytes());
        for d in &self.filled_subtrees {
            b.extend_from_slice(&d.to_bytes());
        }
        b.extend_from_slice(&self.current_root.to_bytes());
        b
    }

    /// Décode une frontier depuis `to_bytes`. Borné et validant (voir
    /// `FrontierDecodeError`) — aucune panique sur octets corrompus.
    pub fn from_bytes(b: &[u8]) -> Result<Self, FrontierDecodeError> {
        if b.is_empty() {
            return Err(FrontierDecodeError::TooShort);
        }
        let depth = b[0] as usize;
        if depth == 0 || depth > 48 {
            return Err(FrontierDecodeError::BadDepth);
        }
        let expected = 1 + 8 + depth * 32 + 32;
        if b.len() < expected {
            return Err(FrontierDecodeError::TooShort);
        }
        if b.len() > expected {
            return Err(FrontierDecodeError::TrailingBytes);
        }
        let next_index = u64::from_le_bytes(b[1..9].try_into().unwrap());
        if (next_index as u128) > (1u128 << depth) {
            return Err(FrontierDecodeError::BadIndex);
        }
        let mut pos = 9;
        let read_digest = |b: &[u8], pos: &mut usize| -> Result<Digest, FrontierDecodeError> {
            let arr: [u8; 32] = b[*pos..*pos + 32].try_into().unwrap();
            *pos += 32;
            Digest::from_bytes(&arr).map_err(|_| FrontierDecodeError::BadDigest)
        };
        let mut filled_subtrees = Vec::with_capacity(depth);
        for _ in 0..depth {
            filled_subtrees.push(read_digest(b, &mut pos)?);
        }
        let current_root = read_digest(b, &mut pos)?;
        let zeros = empties(depth);
        // Cohérence bon marché : un arbre déclaré vide DOIT avoir la racine tout-vide.
        if next_index == 0 && current_root != zeros[depth] {
            return Err(FrontierDecodeError::InconsistentRoot);
        }
        Ok(MerkleFrontier {
            depth,
            filled_subtrees,
            zeros,
            current_root,
            next_index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::felt::Felt;

    fn digest(seed: u64) -> Digest {
        Digest(core::array::from_fn(|i| {
            Felt::from_canonical_u64(seed + i as u64).unwrap()
        }))
    }

    /// Un arbre wallet RECHARGÉ doit produire les mêmes CHEMINS, pas seulement la
    /// même racine.
    ///
    /// La racine seule ne suffirait pas à conclure : c'est le chemin qui entre dans
    /// la preuve STARK. Un arbre rechargé à la racine correcte mais aux chemins faux
    /// laisserait le wallet construire des preuves systématiquement rejetées, sans
    /// aucun message expliquant pourquoi.
    #[test]
    fn arbre_recharge_produit_les_memes_chemins() {
        let mut t = ProvedMerkleTree::new(6);
        for i in 0..11u64 {
            t.append(&digest(i * 10 + 1));
        }
        let octets = t.to_bytes();
        let r = ProvedMerkleTree::from_bytes(&octets).expect("aller-retour");

        assert_eq!(r.depth(), t.depth());
        assert_eq!(r.len(), t.len());
        assert_eq!(r.root(), t.root());
        for i in 0..t.len() as u64 {
            assert_eq!(r.path(i), t.path(i), "chemin divergent en {i}");
        }
        assert_eq!(r.to_bytes(), octets, "canonique : même arbre ⇒ mêmes octets");
    }

    /// Un arbre VIDE se recharge en arbre vide (cas limite d'un wallet neuf).
    #[test]
    fn arbre_vide_aller_retour() {
        let t = ProvedMerkleTree::new(4);
        let r = ProvedMerkleTree::from_bytes(&t.to_bytes()).unwrap();
        assert!(r.is_empty());
        assert_eq!(r.root(), t.root());
    }

    /// Octets corrompus : `Result`, jamais de panique — et le compte de feuilles est
    /// rejeté AVANT allocation (un en-tête annonçant 2^48 feuilles ne doit rien
    /// coûter).
    #[test]
    fn arbre_malforme_rejete_sans_paniquer() {
        let mut t = ProvedMerkleTree::new(5);
        t.append(&digest(1));
        let bon = t.to_bytes();

        // `matches!` : `ProvedMerkleTree` n'est pas `PartialEq` (comparer deux
        // arbres feuille à feuille n'a pas de sens comme opération publique).
        assert!(matches!(
            ProvedMerkleTree::from_bytes(&[]),
            Err(TreeDecodeError::TooShort)
        ));
        assert!(matches!(
            ProvedMerkleTree::from_bytes(&bon[..bon.len() - 1]),
            Err(TreeDecodeError::TooShort)
        ));
        let mut trop = bon.clone();
        trop.push(0);
        assert!(matches!(
            ProvedMerkleTree::from_bytes(&trop),
            Err(TreeDecodeError::TrailingBytes)
        ));

        let mut mauvaise_profondeur = bon.clone();
        mauvaise_profondeur[0] = 0;
        assert!(matches!(
            ProvedMerkleTree::from_bytes(&mauvaise_profondeur),
            Err(TreeDecodeError::BadDepth)
        ));

        // En-tête seul annonçant plus de feuilles que l'arbre n'en peut contenir :
        // refusé sans allouer (2^5 = 32 max ici).
        let mut enorme = vec![5u8];
        enorme.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            ProvedMerkleTree::from_bytes(&enorme),
            Err(TreeDecodeError::BadCount)
        ));
    }

    #[test]
    fn racine_deterministe() {
        let cm = digest(1);
        let path = [digest(10), digest(20), digest(30)];
        assert_eq!(root(&cm, &path, 0b101), root(&cm, &path, 0b101));
    }

    #[test]
    fn le_bit_change_l_ordre() {
        // Un seul niveau : bit 0 = node(feuille, frère), bit 1 = node(frère, feuille).
        let cm = digest(1);
        let sib = digest(10);
        let leaf = leaf(&cm);
        assert_eq!(root(&cm, &[sib], 0), node(&leaf, &sib));
        assert_eq!(root(&cm, &[sib], 1), node(&sib, &leaf));
        assert_ne!(root(&cm, &[sib], 0), root(&cm, &[sib], 1));
    }

    #[test]
    fn un_frere_different_change_la_racine() {
        let cm = digest(1);
        let path_a = [digest(10), digest(20)];
        let path_b = [digest(10), digest(21)];
        assert_ne!(root(&cm, &path_a, 0), root(&cm, &path_b, 0));
    }

    #[test]
    fn profondeur_consensus() {
        // Une racine de profondeur 32 se calcule sans panique et est déterministe.
        let cm = digest(7);
        let path: Vec<Digest> = (0..CONSENSUS_DEPTH as u64).map(|i| digest(100 + i)).collect();
        let r = root(&cm, &path, 0xDEAD_BEEF);
        assert_eq!(r, root(&cm, &path, 0xDEAD_BEEF));
    }

    /// L'arbre incrémental produit des chemins COMPATIBLES CIRCUIT : pour chaque
    /// feuille, `root(cm, tree.path(i), i) == tree.root()` — exactement la relation
    /// que `circuit::membership` prouve.
    #[test]
    fn arbre_incremental_chemins_compatibles_circuit() {
        for depth in [DEV_DEPTH, CONSENSUS_DEPTH] {
            let mut tree = ProvedMerkleTree::new(depth);
            let cms: Vec<Digest> = (0..5u64).map(|i| digest(1 + i * 10)).collect();
            for cm in &cms {
                tree.append(cm);
            }
            let r = tree.root();
            for (i, cm) in cms.iter().enumerate() {
                let path = tree.path(i as u64).unwrap();
                assert_eq!(path.len(), depth);
                assert_eq!(root(cm, &path, i as u64), r, "feuille {i} @ depth {depth}");
            }
        }
    }

    #[test]
    fn arbre_racine_change_avec_les_ajouts_et_index_hors_borne() {
        let mut tree = ProvedMerkleTree::consensus();
        let r0 = tree.root();
        tree.append(&digest(42));
        assert_ne!(r0, tree.root());
        assert!(tree.path(0).is_some());
        assert!(tree.path(1).is_none()); // une seule feuille
    }

    // --- MerkleFrontier (durcissement #7) ---

    /// Un frontier vide a la MÊME racine (tout-vide) que `ProvedMerkleTree` vide,
    /// à profondeur dev et consensus.
    #[test]
    fn frontier_vide_meme_racine_que_full() {
        for depth in [DEV_DEPTH, CONSENSUS_DEPTH] {
            let f = MerkleFrontier::new(depth);
            assert_eq!(f.len(), 0);
            assert!(f.is_empty());
            assert_eq!(f.depth(), depth);
            assert_eq!(f.root(), ProvedMerkleTree::new(depth).root());
        }
    }

    /// Ancre de correction : la frontier incrémentale et le recalcul complet
    /// produisent la MÊME racine à CHAQUE étape (tailles paires ET impaires), à
    /// profondeur dev ET consensus. Deux implémentations indépendantes qui doivent
    /// s'accorder → cross-check du hash consensus-critique.
    #[test]
    fn frontier_differentiel_full_tree() {
        for depth in [DEV_DEPTH, CONSENSUS_DEPTH] {
            let mut frontier = MerkleFrontier::new(depth);
            let mut full = ProvedMerkleTree::new(depth);
            for n in 0..9u64 {
                let cm = digest(1 + n * 7);
                let i_f = frontier.append(&cm).expect("pas plein");
                let i_t = full.append(&cm);
                assert_eq!(i_f, i_t, "index d'insertion identique @ depth {depth}");
                assert_eq!(
                    frontier.root(),
                    full.root(),
                    "racines identiques après {} feuilles @ depth {depth}",
                    n + 1
                );
            }
            assert_eq!(frontier.len(), 9);
        }
    }

    /// Saturation : un arbre de profondeur 2 (4 feuilles) accepte 4 append puis
    /// refuse le 5ᵉ avec `TreeFull`, sans panique ni mutation d'état.
    #[test]
    fn frontier_pleine_rend_treefull() {
        let mut f = MerkleFrontier::new(2); // 2^2 = 4 feuilles max
        for n in 0..4u64 {
            assert_eq!(f.append(&digest(n)), Ok(n));
        }
        assert_eq!(f.len(), 4);
        let root_avant = f.root();
        assert_eq!(f.append(&digest(99)), Err(TreeFull));
        assert_eq!(f.len(), 4, "len inchangée après refus");
        assert_eq!(f.root(), root_avant, "racine inchangée après refus");
    }

    /// Sérialisation canonique : `from_bytes(to_bytes)` restaure un état FIDÈLE
    /// (même racine, même `len`), et un append ultérieur donne la même racine des
    /// deux côtés (état interne identique, pas seulement la racine mémoïsée).
    #[test]
    fn frontier_serialisation_roundtrip() {
        for depth in [DEV_DEPTH, CONSENSUS_DEPTH] {
            let mut f = MerkleFrontier::new(depth);
            for n in 0..5u64 {
                f.append(&digest(1 + n * 3)).unwrap();
            }
            let bytes = f.to_bytes();
            let f2 = MerkleFrontier::from_bytes(&bytes).expect("roundtrip");
            assert_eq!(f2.to_bytes(), bytes, "ré-encodage identique (canonique)");
            assert_eq!(f2.len(), f.len());
            assert_eq!(f2.root(), f.root());
            // État interne fidèle : un append supplémentaire donne la même racine.
            let mut g = MerkleFrontier::from_bytes(&bytes).unwrap();
            f.append(&digest(999)).unwrap();
            g.append(&digest(999)).unwrap();
            assert_eq!(f.root(), g.root(), "état interne restauré à l'identique");
        }
    }

    /// Le roundtrip d'un arbre VIDE passe et reste vide (racine tout-vide).
    #[test]
    fn frontier_serialisation_arbre_vide() {
        let f = MerkleFrontier::new(DEV_DEPTH);
        let f2 = MerkleFrontier::from_bytes(&f.to_bytes()).expect("roundtrip vide");
        assert!(f2.is_empty());
        assert_eq!(f2.root(), f.root());
    }

    /// Matrice de rejet : chaque corruption rend l'erreur attendue, jamais de panique.
    #[test]
    fn frontier_serialisation_rejette_les_malformes() {
        let mut f = MerkleFrontier::new(4);
        f.append(&digest(1)).unwrap();
        let bytes = f.to_bytes();
        // `matches!` plutôt que `assert_eq!` : `MerkleFrontier` n'est pas `PartialEq`.
        assert!(matches!(
            MerkleFrontier::from_bytes(&bytes[..bytes.len() - 1]),
            Err(FrontierDecodeError::TooShort)
        ));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            MerkleFrontier::from_bytes(&trailing),
            Err(FrontierDecodeError::TrailingBytes)
        ));
        // depth = 0.
        let mut bad_depth = bytes.clone();
        bad_depth[0] = 0;
        assert!(matches!(
            MerkleFrontier::from_bytes(&bad_depth),
            Err(FrontierDecodeError::BadDepth)
        ));
        // next_index énorme (octets 1..9 à 0xFF).
        let mut bad_idx = bytes.clone();
        for byte in bad_idx[1..9].iter_mut() {
            *byte = 0xFF;
        }
        assert!(matches!(
            MerkleFrontier::from_bytes(&bad_idx),
            Err(FrontierDecodeError::BadIndex)
        ));
        // Vide.
        assert!(matches!(
            MerkleFrontier::from_bytes(&[]),
            Err(FrontierDecodeError::TooShort)
        ));
        // Racine incohérente : on reprend `bytes` (1 feuille, current_root réelle et
        // canonique ≠ racine tout-vide) mais on force next_index = 0 → l'arbre est
        // déclaré vide alors que sa racine ne l'est pas.
        let mut inconsistent = bytes.clone();
        for byte in inconsistent[1..9].iter_mut() {
            *byte = 0;
        }
        assert!(matches!(
            MerkleFrontier::from_bytes(&inconsistent),
            Err(FrontierDecodeError::InconsistentRoot)
        ));
    }
}
