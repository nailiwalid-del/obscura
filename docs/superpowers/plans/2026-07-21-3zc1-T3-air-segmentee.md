# 3z-c1 T3 — AIR segmentée : plan détaillé

> Plan de la tâche T3 du plan `2026-07-20-3zc1-monolithe-empile.md`, dont la
> version d'origine était haut niveau (8 étapes sans code) — trop mince pour de la
> soundness. Écrit après cartographie de `monolith/air.rs` (1452 l.) et livraison
> de T1/T2.

**Goal :** `monolith/seg_air.rs` — l'AIR du monolithe SEGMENTÉ, produisant les
mêmes publics que le côte-à-côte pour le même témoin.

**Prérequis livrés :** `seg_layout` (T1, aligné 16), `seg_trace` (T2, différentiel
vert).

## Le renversement à comprendre AVANT de coder

C'est LE point qui change tout le reste :

| | côte-à-côte | segmenté |
|---|---|---|
| 4 éponges distinguées par | **colonne** (`U0/U1/O0/O1_OFF`) | **ligne** (segment) |
| sélecteur de ligne | partagé (`sel_u`, `sel_o`) | un par type de segment |
| slots de contraintes d'éponge | 4 × 12 = **48** | 1 × 12 = **12** |
| chemins de Merkle | 2 × 30 = **60** | 1 × 30 = **30** |
| liaison ancrée ligne `r` | 1 sélecteur `at(r)`, colonnes différentes | **1 sélecteur par (segment, ancre)** |

**Conséquence double :** les slots de contraintes **s'effondrent** (les familles
sont mutualisées), mais le nombre de **colonnes périodiques augmente** (chaque
liaison par entrée/sortie a besoin de son propre sélecteur mono-ligne, ancré à
`seg_start(i) + ancre_locale`). Ne pas se tromper de sens : on n'économise PAS des
colonnes périodiques, on économise des colonnes de TRACE (92 vs 201) et des slots.

## Inventaire des sélecteurs (colonnes périodiques)

Deux familles, à ne pas confondre :

**(a) Cycliques** — inchangées, elles s'alignent sur `row % cycle` et l'alignement
16 des `seg_start` (garanti compile-time depuis c5bdda7) les rend valides dans
CHAQUE segment :
- `round_flag_s` (cycle 8), `ark1`/`ark2` (cycle 8) — éponges et rondes ;
- `round_flag_m`, `init0`, `init7`, `chain` (cycle 16) — chemin de Merkle.

**(b) Pleine longueur** — à RECONSTRUIRE depuis le schedule. Toutes se bâtissent
avec un helper unique :

```rust
/// Colonne pleine longueur valant `v(local)` sur les lignes du segment `i`
/// (`local` = ligne relative au début du segment), 0 partout ailleurs.
fn par_segment(&self, garde: impl Fn(SegKind) -> bool, v: impl Fn(usize, usize) -> BaseElement) -> Vec<BaseElement>
```

- `sel_key` : 1 sur les transitions `local < KEY_USED_ROWS − 1` des segments `Key`
  (⚠️ `KEY_USED_ROWS`=8, PAS `KEY_LEN`=16 : les 8 dernières lignes sont inactives) ;
- `sel_sponge` : 1 sur les segments `Input` (`local < NF_ROWS_END`, hors frontières
  locales 31/39/55) **ET** `Output` (`local < CM_ROWS_END − 1`) — famille mutualisée ;
- `sel_m` : 1 sur les segments `Input`, `local < MERKLE_LEVEL_ROWS·depth − 1` ;
- `sel_bal` : 1 sur les segments `Input` et `Output` (`local < seg_len`) ;
- `signe` : **+1** sur `Input`, **−1** sur `Output`, **0** sur `Key` et hors segments ;
- `pow` : `2^local` si `local < RANGE_BITS`, 0 sinon, sur `Input`/`Output` ;
- `endblk` : 1 sur la DERNIÈRE ligne de chaque segment `Input`/`Output` (reset `VACC`) ;
- `blind_off` : inchangé — 1 ssi `r + 1 < used_rows(depth)`.

**Sélecteurs mono-ligne de liaison** — un par (segment, ancre). Helper :
`at_abs(seg_start(i) + ancre)`. Ancres locales identiques au côte-à-côte
(0, 7, 31, 32, 39, 40, 47) plus l'ancre `VACC` à `local = RANGE_BITS` (=60).
Pour les 2 IN et les 2 OUT, cela fait ~4 ancres × 2 IN + 2 ancres × 2 OUT.

⚠️ **Interdiction d'ancrer en `l − 1`** (la transition de la dernière ligne est
exclue du domaine d'enforcement winterfell) : contrainte déjà respectée dans le
côte-à-côte (montants ancrés à `64i+60`, pas `64i+63`) — la préserver.

## Familles de contraintes (nouveau décompte)

```
N_KEY     = 24   (2 blocs de rondes, gaté sel_key)          — inchangé
N_SPONGE  = 12   (UNE famille mutualisée, gatée sel_sponge) — était 4×12
N_MERKLE  = 30   (UNE famille, gatée sel_m)                 — était 2×30
N_BAL     = 3    (bit booléen, S chaîné, VACC)              — inchangé
N_CARRIER = ?    (porteuses constantes : owner, nk, root, rho×2, cm×2, leaf×2, vin×2, vout×2)
N_LIAISON = ?    (mêmes liaisons qu'en côte-à-côte, ré-ancrées par segment)
```
Recalculer `N_CARRIER`/`N_LIAISON` à l'écriture ; **ne pas recopier 263**.

## Équilibre chaîné — le point de soundness le plus délicat

La trace (T2) est déjà correcte et testée ; il s'agit de la CONTRAINDRE :

```
result[i]   = sel_bal · bit · (bit − 1)                      // booléen
result[i+1] = S_next − S − signe · bit · pow                 // chaînage signé
result[i+2] = sel_bal · (VACC_next − (1 − endblk)·(VACC + bit·pow))
```

`signe = 0` sur les segments `Key` et hors segments ⇒ `S` reste constant là où il
ne doit pas bouger, **sans** avoir besoin d'un gating supplémentaire (même astuce
qu'en côte-à-côte, où `signe = 0` tenait la traîne idle).

**À re-vérifier explicitement (risque §7 du spec) :**
1. `S[0] = 0` asserté à la ligne 0 ;
2. `S[used − 1] = fee` asserté ;
3. absence de wrap : ≤ 4 montants `< 2^60` ⇒ `|Σ| < 2^62 < p` ;
4. `pow` remis à zéro par segment (poids `2^local`, pas `2^global`) — sinon un
   montant pourrait être décomposé avec des poids d'un autre segment ;
5. `VACC` remis à zéro en fin de segment (`endblk` sur la dernière ligne).

## Assertions (`get_assertions`)

Mêmes assertions qu'en côte-à-côte, **ré-ancrées** via `seg_start(i) + local` :
- préambules d'éponge (`push_preamble`) de chaque segment, décalés ;
- `nf_i` à la ligne nullifier du segment IN `i` ; `oc_j` au segment OUT `j` ;
- `root` : **une seule fois** sur la porteuse `ROOT_C` (nouveauté 3z-c1 — remplace
  l'assertion de racine par `M_i`) ;
- `S = 0` en ligne 0 ; `S = fee` en `used − 1` ;
- AUCUNE assertion sur témoin. Recompter `num_assertions(depth)`.

## L'oracle de parité — l'atout de la construction côte à côte

Les deux monolithes étant vivants simultanément, on peut écrire le test que
l'approche en-place rendait impossible :

```rust
/// MÊME témoin → MÊMES publics par les deux monolithes. Oracle de parité direct.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn parite_publics_segmente_vs_cote_a_cote() {
    let w = witness_de_test();
    let (pi_seg, _) = seg_air::prove_seg_monolith(&w);
    let (pi_ref, _) = air::prove_monolith(&w);
    assert_eq!(pi_seg.root, pi_ref.root);
    assert_eq!(pi_seg.nullifiers, pi_ref.nullifiers);
    assert_eq!(pi_seg.output_commitments, pi_ref.output_commitments);
    assert_eq!(pi_seg.fee, pi_ref.fee);
}
```
À écrire DÈS que le roundtrip segmenté passe : c'est la garantie de non-régression
la plus forte disponible, et elle ne coûte rien.

## Étapes

- [ ] **1. Squelette + périodiques.** `seg_air.rs` : `SegMonolithAir`, réutilise
  `MonolithPublicInputs` (identique). Implémenter `get_periodic_column_values` avec
  le helper `par_segment`. **Test unitaire des sélecteurs** (sans prouveur, rapide) :
  `sel_key` allumé exactement sur `[0, 7)`, `signe` = +1/−1/0 aux bonnes lignes,
  `pow` cyclique par segment, `endblk` en fin de chaque segment IN/OUT, `blind_off`
  éteint à partir de `used − 1`. C'est la sécurité la moins chère : une erreur de
  sélecteur ici produirait sinon un échec de preuve illisible.
- [ ] **2. `evaluate_transition`** — familles mutualisées, dans l'ordre figé, gating
  `blind_off` global en fin de fonction (motif 3z-b1b conservé).
- [ ] **3. Équilibre chaîné** + les 5 vérifications ci-dessus.
- [ ] **4. `get_assertions`** ré-ancrées + `num_assertions`.
- [ ] **5. Degrés + blowup** : bornes supérieures, mesure empirique en `--release`
  (procédure 3z-a/3z-b1) ; consigner le blowup dans le commit.
- [ ] **6. Roundtrip `--release`** (profondeur 2) : preuve acceptée ; publics
  falsifiés (root/nf/oc/fee) rejetés.
- [ ] **7. Oracle de parité** (test ci-dessus) + suite complète + clippy.

## Rappels de garde

- Ne PAS toucher `layout.rs`/`trace.rs`/`air.rs` (côte-à-côte) : ils restent
  l'oracle jusqu'à la bascule T6.
- Retirer les `#[allow(dead_code)]` de `seg_layout`/`seg_trace` dès qu'ils sont
  consommés.
- Preuves en `--release` uniquement ; tests gatés `#[cfg_attr(debug_assertions,
  ignore = "…")]`.
- Forges segmentées = **T4**, pas ici.
