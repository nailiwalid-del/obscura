# 3b1 — AIR sponge multi-bloc (généralisation)

- Date : 2026-07-15
- Statut : design acté (Option A — sponge général), implémentation à lancer
- Portée : généraliser l'AIR de 3a2b à un payload de longueur arbitraire, pour que `owner`, `nk`, `merge` (Merkle), nullifier et commitment deviennent de simples **instances** du même circuit. Unifie 3b1–3b4.

## 1. Pourquoi généraliser maintenant

`nk = H_nk(secret)` est trivial (même préambule 8 éléments que `owner`, seul le tag change). Mais **le multi-bloc est requis presque partout** :

| Objet | payload (Felts) | préambule = 3 + payload + 1 | blocs `B = ceil(N/8)` |
|---|---|---|---|
| `owner`, `nk` | 4 | 8 | **1** |
| Merkle node (`merge`) | 8 | 12 | **2** |
| nullifier `PRF_nf(nk, rho‖cm)` | 12 | 16 | **2** |
| commitment de note | ~16 | ~20 | **3** |

Écrire un AIR ad hoc par objet = quatre fois le même travail. On écrit le sponge **une fois**.

## 2. Rappel du sponge à répliquer (winter, pinné en 3a2b)

```
state = [0; 12] ; state[CAPACITY.start] = len(elements)   // pas de padding
i = 0
for element in elements:
    state[RATE.start + i] += element ; i += 1
    if i % 8 == 0 { permutation ; i = 0 }
if i > 0 { permutation }
digest = state[4..8]
```

Nombre de permutations = `B = ceil(N/8)`. Absorption **additive**. Dernier bloc partiel : absorbé puis permuté (pas de padding — la longueur en capacité joue ce rôle).

## 3. Structure de trace

- **Cycle de 8 transitions par bloc** : positions 0..6 = **rondes** ; position 7 = **absorption** du bloc suivant (`next[RATE+j] = current[RATE+j] + payload_j`), ou **copie** (`next = current`) si le bloc n'existe pas (padding).
- **Longueur de trace** = `next_power_of_two(B * 8)`. `B=1 → 8`, `B=2 → 16`, **`B=3 → 32`** (padding par blocs « copie »).
- **Largeur de trace** = `12` (état) `+ 8` (colonnes de payload du bloc à absorber) = **20**.
- Le digest final se lit sur `état[4..8]` à la **dernière ligne du dernier bloc RÉEL** (attention au padding : ne pas lire après des blocs copie — les copies préservent l'état, donc lire la dernière ligne reste correct **si et seulement si** les blocs de padding sont bien des copies).

## 4. Masques périodiques

- `round_flag` : cycle 8 = `[1,1,1,1,1,1,1,0]` → contrainte de ronde active sur 0..6.
- `absorb_flag` : cycle 8 = `[0,0,0,0,0,0,0,1]` → contrainte d'absorption sur la position 7.
- `block_active` : un masque de cycle = longueur de trace, valant 1 sur les blocs réels et 0 sur les blocs de padding (→ transforme l'absorption en copie).

**Degrés** : ici les masques **multiplient** les contraintes → `TransitionConstraintDegree::with_cycles(...)` est **CORRECT** (à l'inverse de 3a2/3a2b où l'utiliser était précisément le bug, les ARK étant additionnées *dans* la S-box). C'est le piège n°1 de cette tranche.

## 5. Public vs témoin (exigence de sécurité)

En 3a2b tout tenait sur la ligne 0 : on assertait les constantes publiques et **jamais** le secret. En multi-bloc, les blocs suivants s'injectent via les **colonnes de payload** :

- éléments **publics** (VERSION, tag, LEN, PAD_ONE, et tout payload public comme les nœuds Merkle) → **assertés** ;
- éléments **témoins** (shielded_secret, `nk`, valeurs de note) → **jamais assertés**.

Règle : `get_assertions` ne doit référencer que des constantes publiques et le digest. Toute nouvelle instance doit être relue sur ce point.

## 6. API cible

```
// primitive générale
fn prove_sponge(domain: Domain, payload: &[Felt], public_mask: &[bool]) -> (Digest, ValidityProof)
fn verify_sponge(domain: Domain, digest: &Digest, public_payload: &[(usize, Felt)], proof: &ValidityProof) -> bool

// instances (sucre)
fn prove_owner(secret) / prove_nk(secret) / prove_merge(a, b) / prove_nullifier(nk, rho, cm)
```

`owner`/`nk` doivent rester **strictement équivalents** à 3a2b (mêmes digests) après refonte.

## 7. Validation

- **Différentiel par instance** : pour chaque objet (`owner`, `nk`, `merge`, nullifier), le digest en circuit == `proved_hash::rescue::hash(domain, payload)`. C'est le juge.
- **Non-régression 3a2b** : `prove_owner` produit le même `owner` qu'avant la généralisation.
- **Multi-bloc explicite** : au moins un cas `B=2` (nullifier ou merge) ET un cas `B=3` (padding) verts.
- **Négatif** : digest altéré → `verify` échoue, avec roundtrip vert dans la même suite (écarte le faux positif — leçon de 3a2).
- **Secret hors assertions** : revue de `get_assertions`.

## 8. Périmètre

- 3b1 livre le sponge général + `nk` + nullifier. Merkle (3b2), balance/range (3b3), commitment (3b4) réutiliseront la primitive.
- Pas de câblage ledger (3b final). **Pas de zero-knowledge** (validity-only, gate Phase 3z).

## 9. Risques

| Risque | Mitigation |
|---|---|
| `with_cycles` : correct ici, faux en 3a2 | Test de degré (winterfell panique en debug) + différentiel |
| Padding B=3 : lecture du digest après blocs copie | Contrainte de copie stricte + différentiel sur un cas B=3 |
| Fuite du témoin via une assertion de payload | Revue explicite ; seules les positions publiques sont assertées |
| Régression owner/nk | Test de non-régression vs digests 3a2b |
| Complexité (masques + 20 colonnes) | Le différentiel par instance attrape toute divergence |

## 10. Références

- `crates/circuit/src/{rescue_round.rs, owner_hash.rs}` (3a2/3a2b) ; `crates/proved-hash/src/rescue.rs` (3a1).
- Exemple `rescue` de winterfell (mécanisme de masque/flag).
