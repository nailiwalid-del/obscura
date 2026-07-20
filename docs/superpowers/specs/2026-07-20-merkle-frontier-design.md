# Arbre Merkle frontier (append-only, O(depth)) — design

**Date :** 2026-07-20
**Contexte :** durcissement pré-testnet #7, item « Merkle frontier/persistant ».
**Statut :** design approuvé (utilisateur, 2026-07-20).

## Problème

`proved_hash::merkle::ProvedMerkleTree` est un stub de prototype :

- il stocke **toutes** les feuilles (`leaves: Vec<Digest>`) — mémoire **non bornée** ;
- `root()` et `path()` **recalculent tout l'arbre en O(n)** à chaque appel —
  `apply_proved_tx` refait donc l'intégralité de l'arbre à chaque transaction ;
- `append` fait `assert!(len < 2^depth, "arbre plein")` : un arbre plein **fait
  paniquer le nœud** (via `apply_proved_tx`) au lieu de retourner une erreur.

Ces trois défauts sont le même stub. L'audit `panic`/`Result` (#7) a confirmé que
tout le reste de la surface réseau (`from_bytes`, `verify_tx`, `scan_proved_output`,
`apply_proved_tx`) est déjà sans panique ; `append` est la seule panique résiduelle
à une frontière d'API.

## Observation clé (ce qui rend le fix contenu)

Côté **consensus**, `ProvedLedgerState` n'appelle QUE `tree.append()` et
`tree.root()` (dans `mint` et `apply_proved_tx`). Il n'appelle **jamais `path()`** :
ce sont les **wallets** qui produisent les chemins d'appartenance (leur propre
donnée). Un nœud n'a donc pas besoin de stocker les feuilles ni de servir des
chemins historiques — comme un vrai nœud de chaîne.

## Solution — deux structures, deux rôles

### `MerkleFrontier` (nouveau) — l'état d'arbre du nœud

Arbre de Merkle **append-only incrémental** qui ne conserve QUE le bord droit :

```rust
pub struct MerkleFrontier {
    depth: usize,
    filled_subtrees: Vec<Digest>, // longueur = depth ; le bord droit courant
    zeros: Vec<Digest>,           // empties()[0..=depth] : sous-arbres vides par niveau
    current_root: Digest,
    next_index: u64,
}
```

- **mémoire O(depth)** (pas O(n)) ;
- `append` et `root` en **O(depth)** ;
- `append` retourne `Result<u64, TreeFull>` (plus de panique).

Algorithme d'insertion (canonique, type IMT Tornado/Semaphore) :

```
append(leaf) -> Result<u64, TreeFull>:
  if next_index >= 2^depth { return Err(TreeFull) }
  let index = next_index;
  let mut idx = next_index;
  let mut cur = leaf;
  for i in 0..depth {
    let (left, right) = if idx % 2 == 0 {
      filled_subtrees[i] = cur;   // ce nœud gauche attend son frère droit
      (cur, zeros[i])
    } else {
      (filled_subtrees[i], cur)
    };
    cur = node(&left, &right);
    idx /= 2;
  }
  current_root = cur;
  next_index += 1;
  Ok(index)
```

`node` et `zeros` sont EXACTEMENT ceux de `ProvedMerkleTree` (mêmes `Domain`,
même `empties()`), garantissant un arbre identique.

API publique :

```rust
impl MerkleFrontier {
    pub fn new(depth: usize) -> Self;   // depth in 1..=48, sinon panic (erreur de programmation, comme ProvedMerkleTree::new)
    pub fn consensus() -> Self;         // depth = CONSENSUS_DEPTH (32)
    pub fn depth(&self) -> usize;
    pub fn len(&self) -> u64;           // = next_index
    pub fn is_empty(&self) -> bool;
    pub fn root(&self) -> Digest;       // O(1) : renvoie current_root mémoïsé
    pub fn append(&mut self, cm: &Digest) -> Result<u64, TreeFull>;
}

#[derive(Debug, PartialEq, Eq)]
pub struct TreeFull; // l'arbre a atteint 2^depth feuilles
```

Note : `append` prend un `cm: &Digest` (commitment brut) et applique `leaf(cm)`
en interne, comme `ProvedMerkleTree::append` — l'appelant passe un commitment,
pas une feuille déjà hachée.

`root()` d'un arbre vide (`next_index == 0`) renvoie `zeros[depth]` (racine
tout-vide), identique à `ProvedMerkleTree::root()` sur zéro feuille. On initialise
donc `current_root = zeros[depth]` à la construction.

### `ProvedMerkleTree` (inchangé) — l'outil wallet/test

Garde `leaves: Vec` et `path()`. C'est ce que wallets et tests utilisent pour
construire un témoin (chemin d'appartenance). Aucune modification.

## Répercussions

### `ProvedLedgerState`

- champ `tree: ProvedMerkleTree` → `tree: MerkleFrontier` ;
- `mint` et `apply_proved_tx` : `self.tree.append(cm)` renvoie désormais un
  `Result` → propager en `LedgerError::TreeFull` (nouvelle variante) au lieu de
  paniquer. `mint` change de signature : `-> u64` devient `-> Result<u64, LedgerError>`.
- `apply_proved_tx` : la boucle d'insertion des sorties propage `TreeFull` via `?`.
  ⚠️ Application atomique : l'arbre passant de plein à plein pendant l'insertion des
  2 sorties est le seul point délicat. À 2^32 feuilles c'est hors de portée pratique,
  mais on vérifie AVANT d'appliquer quoi que ce soit : `if next_index + 2 > 2^depth`
  → rejet en amont (les nullifiers ne sont pas encore dépensés à ce stade). Simple
  et atomique.

### Tests de `proved_state`

Les tests appelaient `state.tree.path(i)` pour bâtir le témoin. `MerkleFrontier`
n'expose plus `path`. Correction : monter en parallèle une `ProvedMerkleTree`
locale (rôle wallet) avec les MÊMES commitments dans le MÊME ordre, et en tirer
les chemins. La racine des deux coïncide (test différentiel ci-dessous), donc le
témoin reste cohérent avec `state.tree.root()`.

### `LedgerError`

Ajouter `TreeFull` à l'énum (avec message `thiserror`).

## Ancre de correction — test différentiel

C'est le cœur de la sûreté (hash consensus-critique). Deux implémentations
INDÉPENDANTES (frontier incrémentale vs. recalcul complet) doivent produire la
MÊME racine :

- pour des séquences d'append de tailles variées **paires et impaires**
  (0, 1, 2, 3, 5, 8, … feuilles) ;
- à profondeur `DEV_DEPTH` (16) **et** `CONSENSUS_DEPTH` (32) ;
- assertion : `frontier.root() == ProvedMerkleTree.root()` après les mêmes
  insertions, à CHAQUE étape (pas seulement à la fin).

Autres tests :

- **arbre vide** : `MerkleFrontier::new(d).root() == ProvedMerkleTree::new(d).root()`
  (racine tout-vide) ;
- **`TreeFull`** : un arbre de profondeur 2 (4 feuilles) accepte 4 append puis le
  5ᵉ renvoie `Err(TreeFull)` ; `len`/`root` restent cohérents après le refus ;
- **e2e ledger non-régressé** : `applique_une_tx_prouvee`, `applique_puis_scanne`,
  double-dépense, etc. passent avec la frontier (via la `ProvedMerkleTree` locale
  pour les chemins).

## Hors périmètre (YAGNI)

- **Persistance disque** (sérialisation frontier + nullifiers + fenêtre de
  racines) : reportée. La frontier rend la persistance TRIVIALE plus tard
  (O(depth) octets), mais le format de stockage est un autre item.
- **`path()` sur la frontier** : un nœud ne sert pas de chemins ; les wallets
  gardent leur propre arbre. Non nécessaire.
- Migration `ledger::merkle` (BLAKE3, dev-transparent) : inchangée — c'est le
  pendant dev, hors consensus.

## Invariants préservés

- Même `node`/`leaf`/`empties`/`Domain` → même arbre, mêmes racines → les preuves
  d'appartenance `circuit::membership` existantes restent valides.
- Défaut = consensus seul : `MerkleFrontier` et `ProvedLedgerState` restent
  non-gatés ; aucune dépendance nouvelle vers du code de dev.
