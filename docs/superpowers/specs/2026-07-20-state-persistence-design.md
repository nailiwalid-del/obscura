# Persistance disque de l'état consensus — design

**Date :** 2026-07-20
**Contexte :** durcissement pré-testnet #7, dernier item (« Merkle
frontier/**persistante** »). Rendue triviale par la `MerkleFrontier` (bord droit
O(depth) au lieu de toutes les feuilles).
**Statut :** design approuvé (utilisateur, 2026-07-20, « go enchaine »).

## Problème

`ProvedLedgerState` (l'état consensus du nœud) vit uniquement en mémoire : un
redémarrage perd l'arbre, l'ensemble des nullifiers et la fenêtre de racines
récentes — donc tout l'historique de dépenses. Un nœud de testnet doit pouvoir
sauvegarder et recharger son état.

## Ce qui compose l'état

`ProvedLedgerState` :
- `tree: MerkleFrontier` — `depth`, `filled_subtrees[depth]` (bord droit),
  `current_root`, `next_index`. (`zeros` est dérivable de `depth`.)
- `nullifiers: HashSet<[u8; 32]>` — croît sans borne (inhérent), à persister
  intégralement.
- `recent_roots: HashSet<[u8; 32]>` + `roots_order: VecDeque<[u8; 32]>` — la
  fenêtre glissante (≤ `RECENT_ROOTS_WINDOW` = 100). `recent_roots` est dérivable
  de `roots_order` → ne persister que `roots_order`.

## Format — octets canoniques validés (pas de serde)

Cohérent avec `ProvedTx::{to_bytes, from_bytes}` : encodage explicite, décodage
BORNÉ et validant. `serde` n'est utilisé que dans les modules dev-transparent ; le
chemin consensus prouvé n'en dépend pas, on garde cette séparation.

⚠️ Périmètre **trusté** : le fichier d'état est local (écrit par le nœud
lui-même), PAS une entrée réseau adverse. La validation au chargement vise la
détection de **corruption** (troncature, incohérence de tailles), pas le
durcissement anti-adversaire. On reste néanmoins borné (aucune panique).

### `MerkleFrontier` (dans `proved_hash::merkle`)

```
to_bytes: depth (u8) ‖ next_index (u64 LE) ‖ filled_subtrees[i].to_bytes() (depth × 32 o)
          ‖ current_root.to_bytes() (32 o)
```

`from_bytes(&[u8]) -> Result<MerkleFrontier, FrontierDecodeError>` :
- lit `depth` ; rejette si `depth == 0 || depth > 48` ;
- longueur totale attendue = `1 + 8 + depth*32 + 32` ; rejette sinon
  (`TooShort`/`TrailingBytes`) ;
- lit `next_index` ; rejette si `next_index > 2^depth` (`BadIndex`) ;
- lit les `depth` digests + `current_root` via `Digest::from_bytes`
  (rejette non-canonique → `BadDigest`) ;
- recalcule `zeros = empties(depth)` ;
- **contrôle de cohérence** : si `next_index == 0`, exiger
  `current_root == zeros[depth]` (racine tout-vide) — détecte une corruption
  grossière à coût nul. (Recomputation complète de la racine non faite : la
  frontier ne rejoue pas les feuilles ; le fichier est trusté.)

```rust
#[derive(Debug, PartialEq, Eq)]
pub enum FrontierDecodeError { TooShort, TrailingBytes, BadDepth, BadIndex, BadDigest, InconsistentRoot }
```

### `ProvedLedgerState` (dans `ledger::proved_state`)

```
to_bytes: tree.to_bytes() préfixé par sa longueur (u32 LE)
          ‖ nullifiers.len() (u64 LE) ‖ [nf (32 o)]×N   (ordre trié → canonique)
          ‖ roots_order.len() (u64 LE) ‖ [root (32 o)]×M (ordre FIFO préservé)
```

Les nullifiers sont sérialisés en **ordre trié** (le `HashSet` n'a pas d'ordre
stable) → sérialisation **canonique** (même état ⇒ mêmes octets). `roots_order`
garde son ordre FIFO (la fenêtre glissante en dépend).

`from_bytes(&[u8]) -> Result<ProvedLedgerState, StateDecodeError>` :
- décode `tree` (longueur préfixée → `MerkleFrontier::from_bytes`) ;
- lit `N`, borne `N` par les octets restants (anti-troncature : `N*32` doit tenir)
  avant d'allouer, puis lit `N` nullifiers ;
- idem pour `roots_order` ;
- reconstruit `recent_roots` depuis `roots_order` ;
- rejette les octets résiduels (`TrailingBytes`).

```rust
#[derive(Debug, PartialEq, Eq)]
pub enum StateDecodeError { TooShort, TrailingBytes, BadFrontier(FrontierDecodeError), BadDigest }
```

### Wrappers fichier (dans `ledger::proved_state`)

```rust
pub fn save(&self, path: &Path) -> std::io::Result<()>;   // écriture atomique
pub fn load(path: &Path) -> Result<Self, StateLoadError>; // IO + decode
```

- `save` : écrit `to_bytes()` dans `path.with_extension("tmp")` puis
  `std::fs::rename(tmp, path)` — **atomique** sur un même système de fichiers
  (pas d'état à moitié écrit après un crash).
- `load` : lit le fichier puis `from_bytes`. `StateLoadError` enveloppe
  `std::io::Error` et `StateDecodeError`.

## Tests

- **`MerkleFrontier`** : roundtrip `from_bytes(to_bytes) == self` (même racine,
  même `len`, même `filled_subtrees`) après N append variés ; matrice de rejet
  (tronqué, résiduel, `depth` invalide, `next_index` hors borne, digest non
  canonique, racine incohérente pour arbre vide falsifié).
- **`ProvedLedgerState`** : roundtrip pur `from_bytes(to_bytes)` préservant le
  COMPORTEMENT — après rechargement : `is_spent` rend vrai pour les nullifiers
  dépensés, un `anchor` de la fenêtre est toujours accepté, un `apply_proved_tx`
  ultérieur (release) fonctionne sur l'état rechargé ; canonicité (deux
  `to_bytes` du même état identiques). Rejet des malformés.
- **`save`/`load`** : round-trip à travers un fichier temporaire (scratch) ;
  l'état rechargé égale l'original (mêmes octets `to_bytes`). Écriture atomique
  vérifiée indirectement (le fichier final existe et décode).

## Hors périmètre (YAGNI)

- **Écriture incrémentale / journal** (append-only log des deltas) : non — un
  dump complet suffit à l'échelle prototype/testnet. La frontier rend le dump
  bon marché côté arbre (O(depth)) ; seul l'ensemble des nullifiers est gros, et
  il faut de toute façon le persister entièrement.
- **Compression / format versionné multi-algo** : non pour l'instant (un byte de
  version pourra préfixer plus tard si besoin, comme KEM/sig).
- **Persistance du mode transparent** (`LedgerState`, dev) : hors sujet
  (non-consensus).

## Invariants préservés

- Défaut = consensus seul : tout ce code est non-gaté, aucune dépendance nouvelle
  vers du code de dev. `std::fs`/`std::path` uniquement (déjà dans `std`).
- La sérialisation ne change ni les racines ni la logique de consensus : c'est un
  miroir fidèle de l'état en mémoire.
