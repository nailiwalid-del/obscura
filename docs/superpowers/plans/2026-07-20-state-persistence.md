# Persistance de l'état consensus — plan d'implémentation

> **Pour worker agentique :** SOUS-SKILL REQUIS : subagent-driven-development ou
> executing-plans. Étapes en cases à cocher.

**Goal :** sauvegarder/recharger `ProvedLedgerState` sur disque (arbre frontier +
nullifiers + fenêtre de racines), en octets canoniques validés, écriture atomique.

**Architecture :** `MerkleFrontier::{to_bytes, from_bytes}` (proved-hash) ;
`ProvedLedgerState::{to_bytes, from_bytes, save, load}` (ledger).

**Tech Stack :** Rust, `std::fs`/`std::path`, `Digest::{to_bytes, from_bytes}`.

## Global Constraints

- Défaut = consensus seul : code non-gaté, aucune dépendance nouvelle.
- Octets canoniques (pas de serde) ; décodage borné, aucune panique.
- Périmètre trusté (fichier local) : validation = anti-corruption.
- Commentaires en français.

---

### Task 1 : `MerkleFrontier::{to_bytes, from_bytes}` + `FrontierDecodeError`

**Files :** Modify `crates/proved-hash/src/merkle.rs` (+ tests).

**Interfaces :**
- Produces : `MerkleFrontier::to_bytes(&self) -> Vec<u8>` ;
  `MerkleFrontier::from_bytes(&[u8]) -> Result<Self, FrontierDecodeError>` ;
  `enum FrontierDecodeError { TooShort, TrailingBytes, BadDepth, BadIndex, BadDigest, InconsistentRoot }`.

- [ ] **Step 1 : test roundtrip + rejets**

```rust
#[test]
fn frontier_serialisation_roundtrip() {
    for depth in [DEV_DEPTH, CONSENSUS_DEPTH] {
        let mut f = MerkleFrontier::new(depth);
        for n in 0..5u64 { f.append(&digest(1 + n * 3)).unwrap(); }
        let bytes = f.to_bytes();
        let f2 = MerkleFrontier::from_bytes(&bytes).expect("roundtrip");
        assert_eq!(f2.to_bytes(), bytes, "ré-encodage identique (canonique)");
        assert_eq!(f2.len(), f.len());
        assert_eq!(f2.root(), f.root());
        // Un append supplémentaire donne la MÊME racine des deux côtés → état fidèle.
        let mut g = MerkleFrontier::from_bytes(&bytes).unwrap();
        f.append(&digest(999)).unwrap();
        g.append(&digest(999)).unwrap();
        assert_eq!(f.root(), g.root());
    }
}

#[test]
fn frontier_serialisation_rejette_les_malformes() {
    let mut f = MerkleFrontier::new(4);
    f.append(&digest(1)).unwrap();
    let bytes = f.to_bytes();
    assert_eq!(MerkleFrontier::from_bytes(&bytes[..bytes.len()-1]), Err(FrontierDecodeError::TooShort));
    let mut trailing = bytes.clone(); trailing.push(0);
    assert_eq!(MerkleFrontier::from_bytes(&trailing), Err(FrontierDecodeError::TrailingBytes));
    // depth = 0.
    let mut bad_depth = bytes.clone(); bad_depth[0] = 0;
    assert_eq!(MerkleFrontier::from_bytes(&bad_depth), Err(FrontierDecodeError::BadDepth));
    // next_index énorme (octets 1..9).
    let mut bad_idx = bytes.clone();
    for b in bad_idx[1..9].iter_mut() { *b = 0xFF; }
    assert_eq!(MerkleFrontier::from_bytes(&bad_idx), Err(FrontierDecodeError::BadIndex));
    // Vide.
    assert_eq!(MerkleFrontier::from_bytes(&[]), Err(FrontierDecodeError::TooShort));
}
```

- [ ] **Step 2 : run — échoue (méthode/type inexistants)**

Run : `cargo test -p proved-hash --lib frontier_serialisation -q`
Expected : erreur de compilation.

- [ ] **Step 3 : implémenter**

```rust
/// Erreur de désérialisation d'une `MerkleFrontier` (`from_bytes`). Fichier local
/// trusté : la validation détecte la corruption, sans jamais paniquer.
#[derive(Debug, PartialEq, Eq)]
pub enum FrontierDecodeError {
    TooShort,
    TrailingBytes,
    BadDepth,
    BadIndex,
    BadDigest,
    InconsistentRoot,
}

impl MerkleFrontier {
    /// Encodage canonique : `depth (u8) ‖ next_index (u64 LE) ‖ filled_subtrees
    /// (depth × 32 o) ‖ current_root (32 o)`. `zeros` est dérivable de `depth`.
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
    /// `FrontierDecodeError`).
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
        let mut read_digest = |b: &[u8], pos: &mut usize| -> Result<Digest, FrontierDecodeError> {
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
        // Cohérence bon marché : un arbre vide DOIT avoir la racine tout-vide.
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
```

- [ ] **Step 4 : run — passe**

Run : `cargo test -p proved-hash --lib frontier_serialisation -q`
Expected : PASS.

- [ ] **Step 5 : commit**

```bash
git add crates/proved-hash/src/merkle.rs
git commit -m "proved-hash(frontier): to_bytes/from_bytes canoniques + FrontierDecodeError"
```

---

### Task 2 : `ProvedLedgerState::{to_bytes, from_bytes}` + `StateDecodeError`

**Files :** Modify `crates/ledger/src/proved_state.rs` (+ tests).

**Interfaces :**
- Consumes : `MerkleFrontier::{to_bytes, from_bytes}` (Task 1).
- Produces : `ProvedLedgerState::to_bytes(&self) -> Vec<u8>` ;
  `ProvedLedgerState::from_bytes(&[u8]) -> Result<Self, StateDecodeError>` ;
  `enum StateDecodeError { TooShort, TrailingBytes, BadFrontier(FrontierDecodeError), BadDigest }`.

- [ ] **Step 1 : test roundtrip comportemental (non-release : pas de preuve)**

```rust
#[test]
fn etat_serialisation_roundtrip_comportement() {
    let mut state = ProvedLedgerState::with_depth(8);
    let a = state.mint(&digest(1)).unwrap();
    let _ = state.mint(&digest(2)).unwrap();
    // Simuler une dépense : marquer un nullifier via l'API interne de test.
    state.nullifiers.insert(digest(4242).to_bytes());
    let root_courant = state.tree.root();

    let bytes = state.to_bytes();
    let reloaded = ProvedLedgerState::from_bytes(&bytes).expect("roundtrip");

    // Canonicité + fidélité.
    assert_eq!(reloaded.to_bytes(), bytes);
    assert_eq!(reloaded.tree.root(), root_courant);
    assert_eq!(reloaded.tree.len(), state.tree.len());
    assert!(reloaded.is_spent(&digest(4242)));
    // La racine courante reste dans la fenêtre (anchor accepté).
    assert!(reloaded.recent_roots.contains(&root_courant.to_bytes()));
    let _ = a;
}

#[test]
fn etat_serialisation_rejette_les_malformes() {
    let state = ProvedLedgerState::with_depth(4);
    let bytes = state.to_bytes();
    assert!(matches!(ProvedLedgerState::from_bytes(&bytes[..bytes.len()-1]), Err(StateDecodeError::TooShort)));
    let mut trailing = bytes.clone(); trailing.push(7);
    assert!(matches!(ProvedLedgerState::from_bytes(&trailing), Err(StateDecodeError::TrailingBytes)));
    assert!(matches!(ProvedLedgerState::from_bytes(&[]), Err(StateDecodeError::TooShort)));
}
```

Note : `nullifiers` et `recent_roots` sont des champs privés — les tests sont dans
le module, accès direct OK.

- [ ] **Step 2 : run — échoue**

Run : `cargo test -p ledger --lib etat_serialisation -q`
Expected : erreur de compilation.

- [ ] **Step 3 : implémenter** (dans `impl ProvedLedgerState`, avec un curseur borné local)

```rust
/// Erreur de désérialisation de l'état (`from_bytes`). Fichier local trusté :
/// détection de corruption, jamais de panique.
#[derive(Debug, PartialEq, Eq)]
pub enum StateDecodeError {
    TooShort,
    TrailingBytes,
    BadFrontier(proved_hash::merkle::FrontierDecodeError),
    BadDigest,
}
```

```rust
    /// Encodage canonique de l'état : `len(tree) u32 ‖ tree ‖ N u64 ‖ nullifiers
    /// triés (32 o) ‖ M u64 ‖ roots_order FIFO (32 o)`. Nullifiers triés → mêmes
    /// octets pour un même état.
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

    /// Décode l'état depuis `to_bytes`. Borné (chaque prise vérifie les octets
    /// restants) et validant.
    pub fn from_bytes(b: &[u8]) -> Result<Self, StateDecodeError> {
        let mut pos = 0usize;
        let take = |b: &[u8], pos: &mut usize, n: usize| -> Result<&[u8], StateDecodeError> {
            let end = pos.checked_add(n).ok_or(StateDecodeError::TooShort)?;
            if end > b.len() {
                return Err(StateDecodeError::TooShort);
            }
            let s = &b[*pos..end];
            *pos = end;
            Ok(s)
        };

        let tree_len = u32::from_le_bytes(take(b, &mut pos, 4)?.try_into().unwrap()) as usize;
        let tree_bytes = take(b, &mut pos, tree_len)?;
        let tree = MerkleFrontier::from_bytes(tree_bytes).map_err(StateDecodeError::BadFrontier)?;

        let n = u64::from_le_bytes(take(b, &mut pos, 8)?.try_into().unwrap());
        // Borne anti-troncature AVANT allocation : n*32 doit tenir dans le reste.
        let n = usize::try_from(n).map_err(|_| StateDecodeError::TooShort)?;
        let mut nullifiers = std::collections::HashSet::with_capacity(n);
        for _ in 0..n {
            let d: [u8; 32] = take(b, &mut pos, 32)?.try_into().unwrap();
            nullifiers.insert(d);
        }

        let m = u64::from_le_bytes(take(b, &mut pos, 8)?.try_into().unwrap());
        let m = usize::try_from(m).map_err(|_| StateDecodeError::TooShort)?;
        let mut roots_order = std::collections::VecDeque::with_capacity(m);
        let mut recent_roots = std::collections::HashSet::with_capacity(m);
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
```

Ajouter l'import `use proved_hash::merkle::{MerkleFrontier, FrontierDecodeError};`
(ou chemin complet dans l'enum). Retirer l'`use` inutile si doublon.

- [ ] **Step 4 : run — passe**

Run : `cargo test -p ledger --lib etat_serialisation -q`
Expected : PASS.

- [ ] **Step 5 : commit**

```bash
git add crates/ledger/src/proved_state.rs
git commit -m "ledger(persistence): ProvedLedgerState to_bytes/from_bytes + StateDecodeError"
```

---

### Task 3 : `save`/`load` fichier atomiques + `StateLoadError`

**Files :** Modify `crates/ledger/src/proved_state.rs` (+ tests).

**Interfaces :**
- Consumes : `to_bytes`/`from_bytes` (Task 2).
- Produces : `ProvedLedgerState::save(&self, &Path) -> Result<(), std::io::Error>` ;
  `ProvedLedgerState::load(&Path) -> Result<Self, StateLoadError>` ;
  `enum StateLoadError { Io(std::io::Error), Decode(StateDecodeError) }`.

- [ ] **Step 1 : test round-trip fichier (scratchpad)**

```rust
#[test]
fn save_load_fichier_roundtrip() {
    let mut state = ProvedLedgerState::with_depth(6);
    state.mint(&digest(11)).unwrap();
    state.mint(&digest(22)).unwrap();
    state.nullifiers.insert(digest(7).to_bytes());

    let dir = std::env::temp_dir();
    let path = dir.join(format!("obscura_state_test_{}.bin", std::process::id()));
    state.save(&path).expect("save");
    let reloaded = ProvedLedgerState::load(&path).expect("load");
    assert_eq!(reloaded.to_bytes(), state.to_bytes());
    assert!(reloaded.is_spent(&digest(7)));
    std::fs::remove_file(&path).ok();
}

#[test]
fn load_fichier_absent_est_erreur_io() {
    let path = std::path::Path::new("/chemin/inexistant/obscura_absent.bin");
    assert!(matches!(ProvedLedgerState::load(path), Err(StateLoadError::Io(_))));
}
```

- [ ] **Step 2 : run — échoue**

Run : `cargo test -p ledger --lib save_load -q`
Expected : erreur de compilation.

- [ ] **Step 3 : implémenter**

```rust
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
```

```rust
    /// Sauvegarde atomique : écrit dans `<path>.tmp` puis `rename` (aucun état à
    /// moitié écrit après un crash — `rename` est atomique sur un même FS).
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
```

- [ ] **Step 4 : run — passe**

Run : `cargo test -p ledger --lib save_load load_fichier -q`
Expected : PASS.

- [ ] **Step 5 : commit**

```bash
git add crates/ledger/src/proved_state.rs
git commit -m "ledger(persistence): save/load fichier atomiques (tmp+rename) + StateLoadError"
```

---

### Task 4 : validation globale + docs

**Files :** Modify `crates/proved-hash/src/merkle.rs` (doc), `crates/ledger/src/proved_state.rs` (doc), `CLAUDE.md`, `docs/STARK_STATEMENT.md`.

- [ ] **Step 1 : docs**

- Doc de tête `proved_state.rs` : mentionner `save`/`load` (dump complet,
  écriture atomique).
- `CLAUDE.md` #7 : cocher persistance disque (fait) ; ne reste que IK-CCA (phase 4).
- `STARK_STATEMENT.md` journal : ajouter « persistance état (dump canonique,
  save/load atomiques) fait ».

- [ ] **Step 2 : suite complète + clippy**

Run : `cargo test --all-features --release -q` puis
`cargo clippy --all-features --all-targets -q`
Expected : 0 échec, 0 warning.

- [ ] **Step 3 : commit + push**

```bash
git add -A
git commit -m "docs(persistence): #7 persistance disque faite (dump canonique atomique)"
git push origin master
```

---

## Self-Review

- **Couverture spec** : frontier ser (T1), état ser (T2), save/load atomique (T3),
  docs (T4). Tous les tests de la spec (roundtrip, rejets, comportement, fichier)
  couverts.
- **Placeholders** : aucun.
- **Cohérence de types** : `to_bytes()->Vec<u8>`, `from_bytes(&[u8])->Result<_,E>`
  homogènes ; `FrontierDecodeError` réutilisé dans `StateDecodeError::BadFrontier` ;
  nullifiers/roots en `[u8;32]` (via `Digest::to_bytes`). `save->io::Result`,
  `load->Result<_,StateLoadError>`.
