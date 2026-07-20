# Merkle frontier — plan d'implémentation

> **Pour worker agentique :** SOUS-SKILL REQUIS : superpowers:subagent-driven-development
> ou executing-plans. Étapes en cases à cocher (`- [ ]`).

**Goal :** remplacer le stub `ProvedMerkleTree` (O(n), mémoire non bornée, panique
« arbre plein ») par une `MerkleFrontier` append-only O(depth) côté nœud, sans
paniquer et en préservant les racines.

**Architecture :** nouvelle struct `MerkleFrontier` dans `proved_hash::merkle`
(bord droit seul) ; `ProvedMerkleTree` inchangé (rôle wallet/test avec `path()`) ;
`ProvedLedgerState` bascule sur `MerkleFrontier` et propage `LedgerError::TreeFull`.

**Tech Stack :** Rust, `proved_hash` (Rescue-Prime), `thiserror`.

## Global Constraints

- Défaut = consensus seul : `MerkleFrontier`/`ProvedLedgerState` non-gatés, aucune
  dépendance nouvelle vers du code de dev.
- Racines identiques à `ProvedMerkleTree` (mêmes `node`/`leaf`/`empties`/`Domain`) —
  les preuves `circuit::membership` existantes restent valides.
- Profondeur consensus 32 ; dev 16. `depth` valide ∈ `1..=48`.
- Commentaires/docs en français.

---

### Task 1 : `MerkleFrontier` — structure, `new`, `root` vide, `TreeFull`

**Files :**
- Modify : `crates/proved-hash/src/merkle.rs`
- Test : même fichier, `mod tests`

**Interfaces :**
- Consumes : `leaf`, `node`, `empties` (déjà dans le module), `Digest`.
- Produces : `struct MerkleFrontier { depth, filled_subtrees, zeros, current_root, next_index }` ;
  `MerkleFrontier::new(usize) -> Self` ; `consensus() -> Self` ; `depth()->usize` ;
  `len()->u64` ; `is_empty()->bool` ; `root()->Digest` ; `struct TreeFull` (PartialEq/Eq/Debug).

- [ ] **Step 1 : test — racine d'un arbre vide == `ProvedMerkleTree` vide**

```rust
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
```

- [ ] **Step 2 : run — échoue (type inexistant)**

Run : `cargo test -p proved-hash frontier_vide -q`
Expected : erreur de compilation `cannot find type MerkleFrontier`.

- [ ] **Step 3 : implémenter la struct + `new`/`consensus`/`depth`/`len`/`is_empty`/`root`/`TreeFull`**

```rust
/// L'arbre a atteint `2^depth` feuilles : plus aucune insertion possible.
#[derive(Debug, PartialEq, Eq)]
pub struct TreeFull;

/// Arbre de Merkle append-only qui ne conserve QUE le bord droit (frontier) :
/// mémoire et coût par opération en O(depth), pas O(n). C'est l'état d'arbre du
/// NŒUD consensus (`ProvedLedgerState`), qui n'a besoin que d'`append` + `root`.
/// Les CHEMINS d'appartenance restent produits par `ProvedMerkleTree` (wallet).
/// Racine identique à `ProvedMerkleTree` (mêmes `node`/`empties`) → preuves
/// `circuit::membership` inchangées.
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
}
```

Rendre `empties` accessible : elle est déjà `fn empties(depth) -> Vec<Digest>`
dans le module (privée) — `MerkleFrontier` est dans le même module, OK.

- [ ] **Step 4 : run — passe**

Run : `cargo test -p proved-hash frontier_vide -q`
Expected : PASS.

- [ ] **Step 5 : commit**

```bash
git add crates/proved-hash/src/merkle.rs
git commit -m "proved-hash(frontier): MerkleFrontier — struct + racine vide + TreeFull"
```

---

### Task 2 : `append` incrémental + test différentiel

**Files :**
- Modify : `crates/proved-hash/src/merkle.rs`
- Test : même fichier

**Interfaces :**
- Consumes : `MerkleFrontier` (Task 1), `leaf`, `node`.
- Produces : `MerkleFrontier::append(&mut self, cm: &Digest) -> Result<u64, TreeFull>`.

- [ ] **Step 1 : test différentiel — frontier.root() == full.root() à chaque étape**

```rust
#[test]
fn frontier_differentiel_full_tree() {
    for depth in [DEV_DEPTH, CONSENSUS_DEPTH] {
        let mut frontier = MerkleFrontier::new(depth);
        let mut full = ProvedMerkleTree::new(depth);
        // Tailles paires ET impaires, plusieurs paliers.
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
```

- [ ] **Step 2 : run — échoue (méthode inexistante)**

Run : `cargo test -p proved-hash frontier_differentiel -q`
Expected : erreur de compilation `no method named append`.

- [ ] **Step 3 : implémenter `append`**

```rust
impl MerkleFrontier {
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
            let (left, right) = if idx % 2 == 0 {
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
}
```

- [ ] **Step 4 : run — passe (différentiel à depth 16 ET 32)**

Run : `cargo test -p proved-hash frontier_differentiel -q`
Expected : PASS.

- [ ] **Step 5 : commit**

```bash
git add crates/proved-hash/src/merkle.rs
git commit -m "proved-hash(frontier): append incrémental O(depth) + test différentiel vs full tree"
```

---

### Task 3 : `TreeFull` observable — arbre profondeur 2 saturé

**Files :**
- Modify : `crates/proved-hash/src/merkle.rs`
- Test : même fichier

**Interfaces :**
- Consumes : `MerkleFrontier::append` (Task 2).
- Produces : (aucune API nouvelle — test de comportement).

- [ ] **Step 1 : test — 4 append OK puis TreeFull**

```rust
#[test]
fn frontier_pleine_rend_treefull() {
    let mut f = MerkleFrontier::new(2); // 2^2 = 4 feuilles max
    for n in 0..4u64 {
        assert_eq!(f.append(&digest(n)), Ok(n));
    }
    assert_eq!(f.len(), 4);
    let root_avant = f.root();
    // 5ᵉ insertion refusée, sans panique ni mutation d'état.
    assert_eq!(f.append(&digest(99)), Err(TreeFull));
    assert_eq!(f.len(), 4, "len inchangée après refus");
    assert_eq!(f.root(), root_avant, "racine inchangée après refus");
}
```

- [ ] **Step 2 : run — passe directement (append gère déjà TreeFull)**

Run : `cargo test -p proved-hash frontier_pleine -q`
Expected : PASS (le garde `TreeFull` est déjà dans `append`).

- [ ] **Step 3 : commit**

```bash
git add crates/proved-hash/src/merkle.rs
git commit -m "proved-hash(frontier): test saturation — TreeFull sans panique ni mutation"
```

---

### Task 4 : `ProvedLedgerState` bascule sur `MerkleFrontier` + `LedgerError::TreeFull`

**Files :**
- Modify : `crates/ledger/src/lib.rs` (énum `LedgerError`)
- Modify : `crates/ledger/src/proved_state.rs`
- Test : `crates/ledger/src/proved_state.rs` (`mod tests`)

**Interfaces :**
- Consumes : `MerkleFrontier` (Tasks 1-2), `ProvedMerkleTree` (pour les chemins de test).
- Produces : `ProvedLedgerState.tree: MerkleFrontier` ; `mint(&mut self, &Digest) -> Result<u64, LedgerError>` ;
  `apply_proved_tx` propage `TreeFull` ; `LedgerError::TreeFull`.

- [ ] **Step 1 : ajouter la variante d'erreur**

Dans `crates/ledger/src/lib.rs`, ajouter à l'énum `LedgerError` (vérifier le style
`thiserror` existant et coller au format des variantes voisines) :

```rust
    #[error("arbre plein : capacité 2^profondeur atteinte")]
    TreeFull,
```

- [ ] **Step 2 : basculer le champ et les usages dans `proved_state.rs`**

Remplacer l'import et le champ :

```rust
use proved_hash::merkle::MerkleFrontier; // au lieu de ProvedMerkleTree
```

```rust
pub struct ProvedLedgerState {
    pub tree: MerkleFrontier,
    nullifiers: HashSet<[u8; 32]>,
    recent_roots: HashSet<[u8; 32]>,
    roots_order: VecDeque<[u8; 32]>,
}
```

`new`/`with_depth`/`with_tree` : `ProvedMerkleTree::consensus()` →
`MerkleFrontier::consensus()`, `ProvedMerkleTree::new(depth)` →
`MerkleFrontier::new(depth)`.

`mint` devient faillible :

```rust
    /// Émission (faucet du prototype) : insère un commitment prouvé, retourne son
    /// index. `TreeFull` si l'arbre est saturé (2^profondeur feuilles).
    pub fn mint(&mut self, cm: &Digest) -> Result<u64, LedgerError> {
        let idx = self.tree.append(cm).map_err(|_| LedgerError::TreeFull)?;
        let root = self.tree.root();
        self.remember_root(root);
        Ok(idx)
    }
```

`apply_proved_tx` : ajouter un contrôle de capacité atomique AVANT de dépenser les
nullifiers, puis insérer les sorties (l'insertion elle-même ne peut alors plus
échouer, mais on propage par prudence) :

```rust
        // 3 bis. Capacité : refuser AVANT toute mutation si les sorties ne tiennent
        // pas (atomicité — les nullifiers ne sont pas encore dépensés ici).
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
```

- [ ] **Step 3 : réparer les tests qui utilisaient `state.tree.path()`**

`MerkleFrontier` n'expose plus `path`. Dans `setup()` et `applique_puis_scanne()`,
construire une `ProvedMerkleTree` locale (rôle wallet) minée en parallèle avec les
MÊMES commitments dans le MÊME ordre, et en tirer les chemins. Adapter les appels
`state.mint(...)` en `state.mint(...).unwrap()` (ou `.expect("arbre non plein")`).

Patron pour `setup()` (idem `applique_puis_scanne`) :

```rust
        let mut state = ProvedLedgerState::with_depth(DEPTH);
        // Arbre wallet parallèle : produit les chemins (le nœud n'a que la frontier).
        let mut wallet_tree = proved_hash::merkle::ProvedMerkleTree::new(DEPTH);
        let i0 = state.mint(&cm0).unwrap();
        let i1 = state.mint(&cm1).unwrap();
        wallet_tree.append(&cm0);
        wallet_tree.append(&cm1);
        // Racines cohérentes (test différentiel le garantit) → témoin valide.
        debug_assert_eq!(state.tree.root(), wallet_tree.root());
        let path0 = wallet_tree.path(i0).unwrap();
        let path1 = wallet_tree.path(i1).unwrap();
```

- [ ] **Step 4 : run — suite ledger release (e2e prouvés)**

Run : `cargo test -p ledger --release -q`
Expected : PASS — `applique_une_tx_prouvee`, `applique_puis_scanne`,
`double_depense_rejetee`, `anchor_inconnu_rejete`, `preuve_falsifiee_rejetee`,
`enc_note_substitue_rejete_au_ledger`, `signature_intention_falsifiee_rejetee`,
`signataire_non_echangeable`, `nullifier_ne_peut_etre_substitue`.

- [ ] **Step 5 : commit**

```bash
git add crates/ledger/src/lib.rs crates/ledger/src/proved_state.rs
git commit -m "ledger(frontier): ProvedLedgerState sur MerkleFrontier + LedgerError::TreeFull"
```

---

### Task 5 : test ledger — `TreeFull` via `apply_proved_tx` + docs

**Files :**
- Modify : `crates/ledger/src/proved_state.rs` (test)
- Modify : `crates/proved-hash/src/merkle.rs` (doc de tête si nécessaire)
- Modify : `CLAUDE.md`, `docs/STARK_STATEMENT.md` (journal #7)

**Interfaces :**
- Consumes : tout ce qui précède.

- [ ] **Step 1 : test — `mint` renvoie `TreeFull` sur un petit arbre saturé**

```rust
/// Un arbre de faible profondeur saturé refuse le mint suivant (Result, pas panique).
#[test]
fn mint_sur_arbre_plein_rend_treefull() {
    let mut state = ProvedLedgerState::with_depth(1); // 2^1 = 2 feuilles
    assert!(state.mint(&digest(1)).is_ok());
    assert!(state.mint(&digest(2)).is_ok());
    assert!(matches!(state.mint(&digest(3)), Err(LedgerError::TreeFull)));
}
```

Note : ce test ne nécessite PAS `--release` (aucune preuve STARK) — il tourne en
build nu.

- [ ] **Step 2 : run — passe**

Run : `cargo test -p ledger mint_sur_arbre_plein -q`
Expected : PASS.

- [ ] **Step 3 : docs**

- `crates/proved-hash/src/merkle.rs` : la doc de tête mentionne les deux rôles
  (frontier = nœud ; `ProvedMerkleTree` = wallet/chemins).
- `CLAUDE.md` : section « Prochaine étape », point #7 — cocher « Merkle frontier »
  (fait) ; ne restent que key-privacy IK-CCA (phase 4).
- `docs/STARK_STATEMENT.md` : journal de tête — ajouter « Merkle frontier
  (O(depth), TreeFull en Result) fait ».

- [ ] **Step 4 : run — suite complète verte**

Run : `cargo test --all-features --release -q` puis
`cargo clippy --all-features --all-targets -q`
Expected : 0 échec, 0 warning.

- [ ] **Step 5 : commit**

```bash
git add -A
git commit -m "ledger(frontier): test TreeFull via mint + docs #7 (frontier fait)"
```

---

## Self-Review

- **Couverture spec** : `MerkleFrontier` (T1-2), `TreeFull`/Result (T2-3),
  bascule `ProvedLedgerState` + `LedgerError::TreeFull` (T4), atomicité full
  (T4 step 2), tests différentiel/vide/saturation/e2e (T2,T1,T3,T4-5), docs (T5).
- **Placeholders** : aucun — chaque step porte son code.
- **Cohérence de types** : `append(&Digest)->Result<u64,TreeFull>`,
  `mint(&Digest)->Result<u64,LedgerError>`, `root()->Digest`, `len()->u64`
  cohérents entre tasks. `wallet_tree.append` (ProvedMerkleTree) renvoie `u64`
  (inchangé) — pas de `?`, ok.
