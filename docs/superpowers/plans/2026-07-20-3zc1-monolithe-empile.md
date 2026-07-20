# 3z-c1 — Monolithe empilé 2-in/2-out : plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refondre le monolithe STARK du *côte-à-côte* (colonnes parallèles par entrée/sortie) vers des **segments séquentiels** de largeur uniforme, en gardant la forme **2-in/2-out** et l'API v2 INCHANGÉES — les tests existants sont l'oracle de parité.

**Architecture:** La trace utile devient une suite ordonnée de segments `[KEY][IN0][IN1][OUT0][OUT1]` construite depuis une liste de `SegKind`, suivie des lignes de blinding. Largeur uniforme (~50–70 col vs 201) ; owner/nk/root chaînés par porteuses constantes ; équilibre `S` chaîné à travers tous les segments ; sélecteurs de type de segment routant les familles de contraintes. Witness-hiding (blinding + `blind_off`) préservé.

**Tech Stack:** Rust, winterfell 0.13 (Goldilocks + extension quadratique), Rescue-Prime, `rand`/OsRng.

## Global Constraints

- Spec de référence : `docs/superpowers/specs/2026-07-20-3zc1-monolithe-empile-design.md`.
- **Parité stricte** : `prove_tx`/`verify_tx`/`ProvedTx` v2, `ProvedInput`, `INTENT_DOMAIN`, `apply_proved_tx`, entrées publiques (root, nullifiers[2], output_commitments[2], fee), `tx_digest` v2 — TOUS inchangés. Les tests existants de `tx.rs`/ledger passent SANS modification à la fin.
- **2-in/2-out FIGÉ** (schedule `[Key, Input, Input, Output, Output]`) ; NE PAS implémenter la variabilité M/N (= 3z-c2). Mais construire le schedule depuis une liste de `SegKind` (couture 3z-c2).
- **Witness-hiding préservé** : lignes de blinding en fin, `blind_off` global, `BLIND_ROWS=40 ≥ q+4`, masquage OsRng. Le test de masquage exhaustif reste vert.
- **Équilibre chaîné** : `S` démarre à 0 (asserté), +value par segment IN / −value par segment OUT, `S_final == fee` (asserté) ; range embarqué par segment (`< 2^60`) ; pas de wrap (≤ 4 montants < 2^60, `Σ < 2^62 < p`).
- Degrés = **bornes supérieures re-calibrées empiriquement** ; blowup à re-mesurer (procédure 3z-a/3z-b1). Preuves `--release` ; tests gatés `#[cfg_attr(debug_assertions, ignore=…)]`.
- Statement/hachages/liaisons P1–P7 inchangés (Rescue-Prime) ; math des gadgets réutilisée (`sponge`, `merkle_path`, décomposition binaire).
- Code/commentaires FRANÇAIS ; commits `--author="Walid Naili <naili.walid@gmail.com>"` + trailer `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
- Tests : `cargo test -p circuit --release`, workspace `cargo test --workspace --release`, clippy `cargo clippy --workspace --release --all-targets` zéro warning.

## Fichiers touchés (le trio monolithe uniquement — tx.rs/ledger INCHANGÉS)

- `crates/circuit/src/monolith/layout.rs` — géométrie de segment + schedule `SegKind` + `trace_len`.
- `crates/circuit/src/monolith/trace.rs` — constructeur segment-par-segment + chaînage `S` + blinding.
- `crates/circuit/src/monolith/air.rs` — sélecteurs de type, routage des familles, `S` chaîné, assertions au schedule, blinding.
- `crates/circuit/examples/tx_bench.rs` — re-bench.
- `docs/STARK_STATEMENT.md`, `CLAUDE.md` — entrée journal + état.

---

### Task 1 : Géométrie de segment + schedule (layout.rs)

**Files:** Modify: `crates/circuit/src/monolith/layout.rs`

**Interfaces:**
- Produces : `enum SegKind { Key, Input, Output }` ; **longueurs variables par type** `KEY_LEN=8`, `fn in_len(depth) = max(64, 16*depth)`, `OUT_LEN=64` ; `fn seg_len(kind: SegKind, depth) -> usize` ; offsets de colonnes DANS un segment (`SEG_SPONGE_OFF=0`, `SEG_MERKLE_OFF=20`, `SEG_BALBIT_OFF=49`), largeur uniforme `SEG_WIDTH=51`, colonnes partagées (porteuses `OWNER_C/NK_C/ROOT_C/RHO_C[2]/CM_C[2]/LEAF_C[2]/VIN_C[2]/VOUT_C[2]`, accumulateur `S_COL`), `WIDTH` total (~92) ; `fn schedule_2in2out() -> [SegKind; 5]` = `[Key, Input, Input, Output, Output]` ; `fn seg_start(i: usize, depth) -> usize` (= **somme cumulée** `Σ_{j<i} seg_len(schedule[j], depth)`) ; `fn used_rows(depth) = Σ seg_len(schedule[i], depth)` ; `fn trace_len(depth) = next_pow2(used_rows(depth) + BLIND_ROWS)`.

- [ ] **Step 1 : tests géométrie** — largeur `WIDTH <= 255`, colonnes contiguës sans trou, longueurs par type (`KEY_LEN=8`, `in_len(32)=512`, `in_len(2)=64`, `OUT_LEN=64`), `used_rows(32) = 8 + 2*512 + 2*64 = 1160`, `seg_start` croissant et = somme cumulée (`seg_start(0)=0`, `seg_start(1)=8`, `seg_start(2)=8+512`, …), schedule = `[Key,Input,Input,Output,Output]`, `trace_len(32) = 2048` (power-of-two ≥ 1160+40), `in_len(depth) ≥ 56` (pile d'éponge) et `≥ 60` (range). Asserts concrets (valeurs dérivées, pas de littéral magique).
- [ ] **Step 2 : lancer** `cargo test -p circuit monolith::layout` → FAIL puis PASS après implémentation.
- [ ] **Step 3 : implémenter** la géométrie : longueurs variables par type (`seg_len(Key)=8`, `seg_len(Input)=max(64,16*depth)`, `seg_len(Output)=64`), `seg_start` par somme cumulée sur le schedule ; la pile d'éponge d'une entrée (56 lignes) et le chemin de Merkle (`16*depth`) tournent EN PARALLÈLE dans un segment IN (colonnes disjointes) → `in_len` = max des deux + couverture range. Doc de module : « segments séquentiels de longueur variable, couture SegKind pour 3z-c2 ».
- [ ] **Step 4 : lancer** `cargo test -p circuit monolith::layout` → PASS.
- [ ] **Step 5 : commit** `circuit(3z-c1a): géométrie de segment + schedule 2/2`

---

### Task 2 : Constructeur de trace segment-par-segment + sanité hors-prouveur (trace.rs)

**Files:** Modify: `crates/circuit/src/monolith/trace.rs`

**Interfaces:**
- Consumes : `layout::{SegKind, SEG_*, schedule_2in2out, seg_start, used_rows, trace_len}`.
- Produces : `build_monolith_trace_seeded(w, &mut impl rand::Rng)` reconstruit sur les segments (signature inchangée) ; le remplissage aléatoire des lignes de blinding inchangé ; helper `witness_de_test()` inchangé (profondeur 2).

- [ ] **Step 1 : test de sanité hors-prouveur** (debug) — comme 3z-a T2 mais aux positions de segment : owner/nk produits par le segment KEY, cm/leaf/nf de chaque segment IN, racine au bout de chaque chemin IN == root de l'arbre, commitments de sortie des segments OUT, `S` chaîné (0 au début, +value/−value par segment, `S = fee` à la dernière ligne utile), porteuses constantes. Comparer aux références hors-circuit (`rescue::*`, `merkle::fold`), PAS à la construction.
- [ ] **Step 2 : lancer** `cargo test -p circuit monolith::trace` → FAIL.
- [ ] **Step 3 : implémenter** le constructeur segment-par-segment : itérer le schedule, remplir chaque segment à sa ligne de début selon son `SegKind` (KEY = 2 blocs éponge ; IN = commitment→leaf→nullifier empilés + chemin de Merkle + bits de `value` ; OUT = commitment). Chaîner `S` colonne `S_COL` à travers tous les segments (contribution signée par type). Remplir porteuses (owner/nk/root/rho/cm/leaf/vin/vout) constantes. Lignes de blinding aléatoires (réutiliser la logique existante).
- [ ] **Step 4 : lancer** `cargo test -p circuit monolith::trace` (debug) → PASS.
- [ ] **Step 5 : commit** `circuit(3z-c1b): trace segmentée — sanité différentielle hors-prouveur`

---

### Task 3 : AIR segmenté + équilibre chaîné + roundtrip (air.rs)

C'est la tâche centrale. La correction de la trace (Task 2) la dé-risque ; la math des gadgets est réutilisée (`enforce_sponge_transition`, `enforce_merkle_transition`, `enforce_round_block`).

**Files:** Modify: `crates/circuit/src/monolith/air.rs`

**Interfaces:**
- Consumes : trace segmentée (Task 2), gadgets `enforce_*`, `blind_off`, `proof_options_hi`.
- Produces : `MonolithAir`, `MonolithPublicInputs` (INCHANGÉ : root/nullifiers[2]/output_commitments[2]/fee/depth), `prove_monolith`/`verify_monolith` (signatures inchangées).

- [ ] **Step 1 : test roundtrip** `#[cfg_attr(debug_assertions, ignore)]` (release, profondeur 2) : `prove_monolith(witness_de_test())` + `verify_monolith` → accepté ; publics falsifiés (root/nf/oc/fee) → rejet. Lancer → FAIL.
- [ ] **Step 2 : sélecteurs de type de segment** — `get_periodic_column_values` : construire par instance depuis le schedule des colonnes `is_key`/`is_input`/`is_output` (1 sur les lignes du segment du type, 0 ailleurs), plus les sélecteurs internes existants (round_flag, init, chain…) répliqués par segment. `blind_off` global inchangé (0 sur `[used, trace_len)`).
- [ ] **Step 3 : routage des familles** — `evaluate_transition` : pour chaque famille (rondes clé, éponges, Merkle, bits/range) écrire la contrainte gatée par le sélecteur de type approprié (KEY → rondes clé ; IN → sponge+merkle+bits ; OUT → sponge). Réutiliser les `enforce_*` avec les offsets de segment. Les liaisons (owner/nk/rho/cm/leaf) gatées aux lignes de segment via les porteuses.
- [ ] **Step 4 : équilibre chaîné** — la contrainte `S` : `S_next = S + signe_segment · value_bit_contribution` où `signe_segment` = +1 sur IN, −1 sur OUT, 0 ailleurs (via sélecteurs). `S[premier segment, ligne 0] = 0` asserté ; `S[used-1] = fee` asserté. Range embarqué (poids `pow` remis à 0 par segment, borne `< 2^60`). **Risque §7 du spec — soundness à re-vérifier : pas de wrap, contributions signées correctes.**
- [ ] **Step 5 : assertions au schedule** — `get_assertions` : préambules de chaque segment d'éponge (positions `locate` décalées par `seg_start`), `nf_i` à la ligne nullifier du segment IN i, `oc_j` au segment OUT j, `root` (une fois, porteuse), `S=0`/`S=fee`. AUCUNE assertion sur témoin. Recompter `num_assertions`.
- [ ] **Step 6 : re-calibrer les degrés** — bornes supérieures ; les sélecteurs de type ajoutent des facteurs. Mesurer le blowup en release (16 ou 32) ; si bump, `proof_options_hi` + suite complète. Enregistrer le blowup dans le commit.
- [ ] **Step 7 : lancer** `cargo test -p circuit --release monolith` → roundtrip PASS. Tests d'équilibre chaîné (déséquilibre rejeté, montant ≥ 2^60 rejeté) verts.
- [ ] **Step 8 : commit** `circuit(3z-c1c): AIR segmenté + équilibre chaîné — roundtrip vert, blowup <16|32>`

---

### Task 4 : Soundness — forges + inertie blinding sous la disposition segmentée

**Files:** Modify: `crates/circuit/src/monolith/air.rs` (tests) + `crates/circuit/src/monolith/trace.rs` (forges)

**Interfaces:** Produces : les 13 forges + l'inertie des lignes de blinding, adaptées aux positions de segment, rejettent/restent inertes.

- [ ] **Step 1 : adapter les forges** — les 13 forges de liaison (`liaison_*_mord`, secret/vacc→équilibre/padding) + `LigneBlindingArbitraire` : mettre à jour les positions ciblées (elles bougent avec le schedule). La SÉMANTIQUE de chaque forge est conservée (une valeur produite ≠ consommée doit toujours mordre). Lancer → identifier celles qui cassent en compilation, adapter.
- [ ] **Step 2 : vérifier RED** — chaque forge de liaison REJETTE (release) ; l'inertie des lignes de blinding ACCEPTE (P1–P7 inchangés). Si une forge n'exerce plus sa contrainte (position erronée), la corriger.
- [ ] **Step 3 : lancer** `cargo test -p circuit --release` → toutes les forges rouges, inertie verte.
- [ ] **Step 4 : commit** `circuit(3z-c1d): soundness — forges + inertie blinding sous segments`

---

### Task 5 : Masquage (witness-hiding) sous la disposition segmentée

**Files:** Modify: `crates/circuit/src/monolith/air.rs` (tests)

**Interfaces:** Consumes : helper `ouvertures_colonne`. Produces : test de masquage exhaustif vert sur le nouveau layout.

- [ ] **Step 1 : adapter le test de masquage** — `masquage_colonnes_temoins` : les colonnes témoins (porteuses, secret, cellule d'éponge, `S_COL`) sont aux nouveaux offsets ; adapter. Le signal reste : les porteuses constantes ne fuient pas ; deux preuves de la même tx ont des ouvertures disjointes. Conserver l'honnêteté du claim (signal dur sur porteuses constantes, qualitatif sur cellules évolutives — cf. fixup 3z-b1c).
- [ ] **Step 2 : lancer** `cargo test -p circuit --release masquage` → PASS.
- [ ] **Step 3 : commit** `circuit(3z-c1e): masquage vérifié sous disposition segmentée`

---

### Task 6 : Parité API + re-bench

**Files:** Modify: `crates/circuit/examples/tx_bench.rs` (bench uniquement — tx.rs/ledger INCHANGÉS)

**Interfaces:** L'oracle de parité = les tests existants de `tx.rs`/ledger passent sans modification.

- [ ] **Step 1 : parité** — lancer `cargo test --workspace --release` : TOUS les tests de `tx.rs` (tx valide, sabotage) et du ledger (`apply_proved_tx`, double-dépense, anchor, signature) passent SANS modification. Si l'un échoue, c'est un défaut de la refonte (pas du test) — corriger l'AIR/trace. Zéro warning.
- [ ] **Step 2 : re-bench** — `cargo run --release --example tx_bench -p circuit` (profondeur 32). Relever génération/vérification/taille. Comparer à 3z-b1 (1477,7 ms / 3,0 ms / 90,5 Kio). Mettre à jour l'affichage (rappel 3z-b1 côte-à-côte). Enregistrer l'effet largeur↓/longueur↑ (peut aller dans les deux sens — observation, pas blocage).
- [ ] **Step 3 : commit** `circuit(3z-c1f): parité API vérifiée + bench segmenté — <chiffres>`

---

### Task 7 : Docs

**Files:** Modify: `docs/STARK_STATEMENT.md`, `CLAUDE.md`

- [ ] **Step 1 : entrée journal** — STARK_STATEMENT.md : entrée « 3z-c1 (fait) » (refonte segmentée, forme 2/2 et statement inchangés, witness-hiding préservé, chiffres bench, couture 3z-c2). CLAUDE.md : État (monolithe désormais segmenté) + Prochaine étape (3z-c2 variable M/N).
- [ ] **Step 2 : relire** — cohérence, aucune affirmation nouvelle sur le statement (c'est une refonte, pas un nouveau pouvoir), chiffres réels.
- [ ] **Step 3 : commit** `docs(3z-c1): monolithe segmenté au statement`

---

## Self-review du plan

- **Couverture spec** : §2 parité → T6 (oracle) ; §3.1 schedule → T1 ; §3.2 segment uniforme → T1/T3 ; §3.3 chaînage owner/nk/root+équilibre → T2/T3 ; §3.4 layout/trace/air → T1/T2/T3 ; §5 witness-hiding → T3(blinding)/T5(masquage) ; §6 tests → T2(diff)/T3(roundtrip+équilibre)/T4(soundness)/T5(masquage)/T6(parité+bench) ; §7 risques → T3 step 4 (équilibre), T3 step 6 (degrés), T4 (positions forge).
- **Ordre de dé-risquage** : géométrie (T1) → trace correcte hors-prouveur (T2, dé-risque l'AIR) → AIR+équilibre (T3) → soundness (T4) → masquage (T5) → parité (T6).
- **Types** : `SegKind`/`SEG_*`/`schedule_2in2out`/`seg_start`/`S_COL` cohérents ; `MonolithPublicInputs`/`prove_monolith`/`verify_monolith`/`ProvedTx` v2 INCHANGÉS (parité).
- **Placeholders** : aucun — chaque étape porte un test concret ou une commande ; les offsets exacts de colonnes sont dérivés par l'implémenteur des gadgets existants (comme 3z-a/3z-b1), pas fabriqués ici.
