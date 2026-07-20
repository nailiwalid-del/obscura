# 3z-b1 — Witness-hiding du monolithe : plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rendre le monolithe STARK witness-hiding (HVZK en ROM) par des **lignes de blinding** au niveau AIR, sans fork winterfell ni migration, en préservant la structure du monolithe 3z-a.

**Architecture:** On agrandit la trace à `next_pow2(used + BLIND_ROWS)`, on remplit la région `[used, trace_len)` d'aléa frais dans toutes les colonnes témoins, et on multiplie chaque famille de contraintes de transition par un sélecteur global `blind_off` (1 sur `[0, used)`, 0 sur la région de blinding). Les `b ≥ q+2` lignes aléatoires masquent les `q` ouvertures de requête + 2 évaluations OOD par colonne. Le vérifieur reste stock (le blinding lui est transparent).

**Tech Stack:** Rust, winterfell 0.13 (Goldilocks + extension quadratique), `rand` (OsRng), Rescue-Prime.

## Global Constraints

- Spec de référence : `docs/superpowers/specs/2026-07-20-3zb1-witness-hiding-design.md`.
- **`BLIND_ROWS = 40`**, dérivé : `≥ NUM_QUERIES(32) + NUM_OOD(2) + MARGE(6)`. Assertion de construction : `BLIND_ROWS ≥ options.num_queries() + 2`.
- **Réserve capitale** : AUCUNE colonne témoin ne doit rester non blindée sur la région de blinding — une seule fuit via `f(z)`. Blinder porteuses + secret + toutes cellules d'éponge + S + VACC + bits + frères.
- **Aléa frais par preuve** (OsRng) en production ; couture à seed déterministe (`StdRng::seed_from_u64`) pour les tests de complétude/sanité ; les tests de masquage utilisent deux aléas frais distincts.
- Sélecteur global `blind_off` multiplie **toutes** les familles de transition ; les assertions (lignes fixes `< used`) inchangées.
- Degrés = **bornes supérieures re-calibrées empiriquement** ; le blowup peut devoir monter (16 → 32) — mesuré, pas supposé. Preuves `--release` ; tests gatés `#[cfg_attr(debug_assertions, ignore = "…")]`.
- Sécurité conjecturée ≥ 95 bits (`MinConjecturedSecurity(95)`), extension quadratique obligatoire.
- Code/commentaires FRANÇAIS ; commits `--author="Walid Naili <naili.walid@gmail.com>"` + trailer `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
- Tests : `cargo test -p circuit --release`, workspace `cargo test --workspace --release`, clippy `cargo clippy --workspace --release --all-targets` zéro warning.

## Fichiers touchés

- `crates/circuit/Cargo.toml` — dép `rand`.
- `crates/circuit/src/monolith/layout.rs` — `BLIND_ROWS`, `trace_len` agrandi, région de blinding.
- `crates/circuit/src/monolith/trace.rs` — remplissage aléatoire des lignes de blinding, couture seed.
- `crates/circuit/src/monolith/air.rs` — colonne périodique `blind_off`, gating de toutes les familles, re-calibration des degrés.
- `crates/circuit/src/tx.rs` — `prove_tx` tire OsRng frais (transparent au reste).
- `crates/circuit/src/lib.rs`, `docs/STARK_STATEMENT.md`, `CLAUDE.md` — bascule du langage validity-only → witness-hiding.
- `crates/circuit/examples/tx_bench.rs` — re-bench.

---

### Task 1 : De-risk blowup — BLIND_ROWS, trace agrandie, blind_off sur les porteuses

But : poser l'infrastructure (trace agrandie + `blind_off`) sur la famille la plus délicate (porteuses, seule contrainte actuellement non bornée par un sélecteur de région) et **MESURER le blowup requis** avant d'engager toutes les familles.

**Files:**
- Modify: `crates/circuit/Cargo.toml` (dép `rand = "0.8"`)
- Modify: `crates/circuit/src/monolith/layout.rs`
- Modify: `crates/circuit/src/monolith/trace.rs`
- Modify: `crates/circuit/src/monolith/air.rs`

**Interfaces:**
- Produces : `layout::{BLIND_ROWS, used_rows(depth) -> usize}` ; `trace_len(depth)` renvoie désormais `next_pow2(used_rows(depth) + BLIND_ROWS)` ; `trace::build_monolith_trace_seeded(w, &mut impl rand::Rng)` (couture) et `build_monolith_trace(w)` (OsRng) ; `air.rs` gagne la colonne périodique `blind_off` et gate la famille porteuses.

- [ ] **Step 1 : constantes layout + test** — dans `layout.rs` :

```rust
/// Lignes de blinding (witness-hiding, 3z-b1). Dérivé : ≥ q(32) + OOD(2) + marge(6).
/// `q` = nombre de requêtes de `proof_options_hi`. Assertion de cohérence dans air.rs.
pub(crate) const BLIND_ROWS: usize = 40;
/// Lignes utiles (contraintes + assertions) : l'ancienne longueur de trace.
pub(crate) fn used_rows(depth: usize) -> usize { core::cmp::max(256, 16 * depth) }
```
Remplacer l'ancien `trace_len` par :
```rust
pub(crate) fn trace_len(depth: usize) -> usize {
    (used_rows(depth) + BLIND_ROWS).next_power_of_two()
}
```
Tests :
```rust
#[test]
fn trace_len_avec_blinding() {
    assert_eq!(used_rows(32), 512);
    assert_eq!(trace_len(32), 1024); // next_pow2(512+40)
    assert_eq!(used_rows(4), 256);
    assert_eq!(trace_len(4), 512);   // next_pow2(256+40)
    assert!(BLIND_ROWS >= 32 + 2);
}
```

- [ ] **Step 2 : lancer** `cargo test -p circuit monolith::layout` → FAIL (used_rows absent) puis PASS après Step 1.

- [ ] **Step 3 : remplissage aléatoire (trace.rs)** — ajouter `rand` à Cargo.toml. Refactorer `build_monolith_trace` en `build_monolith_trace_seeded(w, rng: &mut impl rand::Rng)` + wrapper `build_monolith_trace(w) = build_monolith_trace_seeded(w, &mut rand::rngs::OsRng)`. Après le remplissage des lignes utiles, remplir les lignes `used_rows(depth)..trace_len(depth)` de **toutes les colonnes** (WIDTH) avec `BaseElement::new(rng.next_u64())` (réduit mod p par winterfell). Un felt aléatoire :
```rust
fn felt_alea(rng: &mut impl rand::Rng) -> BaseElement { BaseElement::new(rng.next_u64()) }
```
Sanité (debug) : les lignes de blinding sont non nulles et deux graines distinctes donnent des régions distinctes ; la région `[0, used)` est IDENTIQUE à seed constant (non-régression du monolithe utile).

- [ ] **Step 4 : blind_off + gating porteuses (air.rs)** — dans `get_periodic_column_values`, ajouter une colonne `blind_off` de longueur `self.l` : `1` si `r + 1 < used_rows(depth)`, sinon `0`. Dans `evaluate_transition`, récupérer `blind_off = pv[<index>]` et **multiplier la famille porteuses** : `result[idx+c] = blind_off * (next[CARRIER_OFF+c] - cur[CARRIER_OFF+c])`. Ajuster le degré de la famille porteuses : `TransitionConstraintDegree::with_cycles(1, vec![self.l])` (facteur périodique) au lieu de `new(1)`. Assertion de construction dans `MonolithAir::new` : `assert!(BLIND_ROWS >= options.num_queries() + 2)`.

- [ ] **Step 5 : mesurer le blowup** — écrire un roundtrip minimal `#[cfg_attr(debug_assertions, ignore)]` (profondeur 2) : `prove_monolith` (seed déterministe) + `verify_monolith`. Lancer `cargo test -p circuit --release monolith::air::…roundtrip`. Si le prouveur panique sur les degrés (blowup 16 insuffisant), passer `proof_options_hi` à blowup 32 et re-lancer. **ENREGISTRER dans le corps du commit le blowup retenu (16 ou 32).** C'est le livrable de dé-risquage.

- [ ] **Step 6 : lancer** `cargo test -p circuit --release monolith` → PASS (roundtrip vert avec blinding sur porteuses ; autres colonnes témoins encore à zéro sur blinding, leurs contraintes déjà éteintes par leurs sélecteurs de région).

- [ ] **Step 7 : commit** `circuit(3z-b1a): infra blinding + gating porteuses — blowup mesuré <16|32>`

---

### Task 2 : Gating global — toutes les familles + toutes les colonnes témoins blindées

**Files:**
- Modify: `crates/circuit/src/monolith/air.rs`
- Modify: `crates/circuit/src/monolith/trace.rs` (déjà remplit toutes les colonnes en Task 1 Step 3 — vérifier)

**Interfaces:**
- Consumes : `blind_off` (Task 1). Produces : monolithe pleinement witness-hiding (toutes familles gatées).

- [ ] **Step 1 : recenser les familles non couvertes** — lire `evaluate_transition`. Les sélecteurs de région existants (`sel_key`, `sel_u`, `sel_o`, `sel_m`, `sel_bal`, les one-hot de liaison `s0/s7/…`) s'annulent-ils DÉJÀ sur `[used, trace_len)` ? Ils sont construits sur `self.l` (nouvelle longueur) : vérifier que chacun vaut 0 pour `r ≥ used_rows(depth)`. Recenser ceux qui NE s'annulent pas : notamment **l'équilibre S** (`result[idx+1] = s_next - s - signe*bit*pow`, non gaté, s'appuie sur `signe=0`) et **VACC** (gaté `sel_bal` = `r<256`, donc déjà 0 au-delà — OK). Documenter le recensement en commentaire.

- [ ] **Step 2 : gater les familles restantes** — multiplier par `blind_off` toute contrainte de transition qui ne s'annule pas déjà sur la région de blinding (au minimum l'équilibre S). Pour robustesse (choix du spec : global), multiplier **chaque** `result[i]` de transition par `blind_off`. Ré-ajuster les degrés (chaque famille gagne un facteur périodique `self.l` → `with_cycles(+1)`). Re-mesurer le blowup si nécessaire (Task 1 Step 5).

- [ ] **Step 3 : masquage effectif — test white-box** — roundtrip profondeur 2 (release), puis PARSER la preuve (motif `crates/zk-spike`) : pour la colonne `OWNER_C` (constante sur `[0,used)`), confirmer qu'AUCUNE ouverture ne vaut le témoin owner. Deux preuves de la même tx (deux seeds distincts) → ouvertures disjointes.

- [ ] **Step 4 : lancer** `cargo test -p circuit --release monolith` → PASS. `cargo test --workspace --release` (non-régression : la matrice de sabotage 3z-a doit rester verte). 

- [ ] **Step 5 : commit** `circuit(3z-b1b): gating global blind_off + masquage vérifié (owner)`

---

### Task 3 : Test de masquage exhaustif (propriété witness-hiding)

**Files:**
- Modify: `crates/circuit/src/monolith/air.rs` (module de tests) ou `crates/circuit/tests/`

**Interfaces:**
- Consumes : parsing de preuve (helper depuis `zk-spike` ou recopié). Produces : test de non-régression du witness-hiding.

- [ ] **Step 1 : helper de parsing** — extraire les ouvertures d'une colonne donnée d'une `ValidityProof` (via `Queries::parse`, dépendance directe `winter-air` requise — cf. `zk-spike`). Signature : `fn column_openings(proof: &ValidityProof, depth: usize, col: usize) -> Vec<BaseElement>`.

- [ ] **Step 2 : test exhaustif** — pour un échantillon représentatif de colonnes TÉMOINS (les 8 premières porteuses `OWNER_C`/`NK_C`/…, une cellule secret KEY, une cellule de commitment d'éponge, `BAL_S`), confirmer : (a) aucune ouverture ne vaut la valeur témoin correspondante ; (b) deux preuves de la même tx ont des ouvertures disjointes sur ces colonnes. Test `masquage_colonnes_temoins`, gaté release.

- [ ] **Step 3 : lancer** `cargo test -p circuit --release masquage` → PASS.

- [ ] **Step 4 : commit** `circuit(3z-b1c): test de masquage exhaustif des colonnes témoins`

---

### Task 4 : Soundness préservée sous blinding

**Files:**
- Modify: `crates/circuit/src/monolith/air.rs` (tests) + `crates/circuit/src/monolith/trace.rs` (forge lignes de blinding)

**Interfaces:**
- Produces : preuve que les lignes de blinding non contraintes ne peuvent pas forger P1–P7.

- [ ] **Step 1 : re-vérifier la matrice 3z-a** — confirmer que toutes les forges existantes (`liaison_*_mord`, sabotages de tx) **rejettent toujours** sous la trace agrandie/blindée (elles devraient : le blinding ne touche pas `[0, used)`). Si une forge ne compile plus (longueur de trace), l'adapter mécaniquement. Lancer `cargo test -p circuit --release` complet.

- [ ] **Step 2 : forge lignes de blinding** — `Forge::LigneBlindingArbitraire` : remplir la région `[used, trace_len)` de valeurs choisies par l'attaquant (pas aléatoires) — p.ex. recopier des cellules utiles pour tenter de tromper une liaison. Test `lignes_blinding_ne_forgent_rien` : la tx reste valide (acceptée) car aucune assertion/contrainte ne lit `≥ used` → **confirme que les lignes de blinding sont inertes pour la soundness**. (C'est un test de complétude/robustesse, pas de rejet : l'attaquant ne gagne rien.)

- [ ] **Step 3 : lancer** `cargo test -p circuit --release` → PASS.

- [ ] **Step 4 : commit** `circuit(3z-b1d): soundness préservée — lignes de blinding inertes vérifié`

---

### Task 5 : OsRng frais en production (prove_tx)

**Files:**
- Modify: `crates/circuit/src/tx.rs`

**Interfaces:**
- Consumes : `build_monolith_trace` (OsRng, Task 1). Produces : `prove_tx` non-déterministe (vrai ZK).

- [ ] **Step 1 : câbler OsRng** — vérifier que `prove_tx` → `prove_monolith` → `build_monolith_trace` (wrapper OsRng) tire bien un aléa frais par appel (pas de seed figé sur le chemin de production). Aucune signature publique ne change.

- [ ] **Step 2 : test de fraîcheur** — `deux_preuves_meme_tx_disjointes` (release) : `prove_tx` deux fois sur la MÊME entrée → les deux `ProvedTx.proof` diffèrent (bytes), et les deux vérifient. Confirme la fraîcheur de l'aléa (pas d'égalité révélatrice).

- [ ] **Step 3 : lancer** `cargo test -p circuit --release tx` + `cargo test --workspace --release` → PASS.

- [ ] **Step 4 : commit** `circuit(3z-b1e): prove_tx tire un aléa de blinding frais (OsRng)`

---

### Task 6 : Re-bench

**Files:**
- Modify: `crates/circuit/examples/tx_bench.rs`

- [ ] **Step 1 : lancer** `cargo run --release --example tx_bench -p circuit` (profondeur 32). Relever génération / vérification / taille.
- [ ] **Step 2 : comparer** à 3z-a (634 ms / 1,5 ms / 85,3 Kio). Attendu ~2× (trace doublée) + surcoût si blowup monté à 32. Mettre à jour l'affichage du bench (rappel 3z-a). Si le surcoût dépasse largement l'attendu, l'enregistrer comme observation (pas un blocage).
- [ ] **Step 3 : commit** `circuit(3z-b1f): bench witness-hiding — <chiffres mesurés>`

---

### Task 7 : Argument HVZK + bascule du langage

**Files:**
- Modify: `docs/STARK_STATEMENT.md`, `CLAUDE.md`, `crates/circuit/src/lib.rs`, `crates/circuit/src/monolith/*` (avertissements), `README.md` si périmé

- [ ] **Step 1 : écrire l'argument HVZK** — dans `docs/STARK_STATEMENT.md`, section dédiée : cadre (HVZK en ROM, Fiat-Shamir, honnête-vérifieur, prototype non audité), comptage (`q+2 < b`), esquisse de simulateur (§5 du spec). En français.

- [ ] **Step 2 : bascule du langage** — retirer les avertissements « validity-only / ne jamais présenter comme zk » de `lib.rs` et `monolith/*` ; remplacer par « witness-hiding (HVZK en ROM) » avec le caveat précis. Mettre à jour l'entrée de tête de STARK_STATEMENT.md (« 3z-b1 (fait) ») et la section État/Prochaine étape de CLAUDE.md (reste : 3z-c M-in/N-out). Ne PAS sur-affirmer (« HVZK-ROM », pas « perfect ZK »).

- [ ] **Step 3 : relire** — cohérence avec le spec, aucun « perfect/malicious-verifier ZK », chiffres réels du bench (Task 6).

- [ ] **Step 4 : commit** `docs(3z-b1): witness-hiding au statement — argument HVZK, bascule du langage`

---

## Self-review du plan

- **Couverture spec** : §2.1 trace → T1 ; §2.2 BLIND_ROWS → T1 ; §2.3 blind_off global + degrés → T1 (porteuses, mesure) + T2 (global) ; §2.4 remplissage aléatoire → T1 Step 3 ; §3 OsRng/seed → T1 (seam) + T5 (prod) ; §4 API → T5 ; §5 argument HVZK → T7 ; §6 bascule langage → T7 ; §7 tests → complétude (T1/T2), masquage (T2/T3), soundness (T4), e2e+bench (T4/T6) ; §8 risques → T1 (degré/blowup mesuré tôt), T4 (soundness blinding).
- **Dé-risquage tôt** (demande utilisateur) : T1 mesure le blowup sur la famille porteuses avant d'engager toutes les familles (T2).
- **Types** : `used_rows`/`trace_len`/`BLIND_ROWS`/`blind_off`/`build_monolith_trace_seeded`/`column_openings` cohérents entre tâches. `prove_tx`/`verify_tx`/`ProvedTx` inchangés (aval intact).
- **Placeholders** : aucun — chaque étape porte du code ou une commande concrète.
