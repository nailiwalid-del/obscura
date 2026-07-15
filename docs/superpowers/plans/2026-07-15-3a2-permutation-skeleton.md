# 3a2 — Validity skeleton (AIR permutation Rp64_256) — Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Crate `crates/circuit` avec un AIR winterfell reproduisant la permutation Rp64_256, et `prove_permutation`/`verify_permutation` de bout en bout, validés contre le vecteur de référence Sage.

**Architecture:** `circuit` dépend de `winterfell` (prouveur+vérifieur), `winter-crypto` (constantes Rp64_256 publiques), `proved-hash` (types `Felt`). L'AIR est **développé contre l'exemple `rescue` de winterfell** (gestion de l'inverse S-box, colonnes périodiques ARK), pas deviné : le différentiel Sage est le garde-fou.

**Tech Stack:** Rust, `winterfell` 0.13, `winter-crypto` 0.13, `proved-hash`.

## Global Constraints

- Spec : `docs/superpowers/specs/2026-07-15-3a2-permutation-skeleton-design.md`.
- `cargo` via `& "$env:USERPROFILE\.cargo\bin\cargo.exe" ... --manifest-path "C:\Users\W47\Documents\obscura\Cargo.toml"` ; tests finaux `-D warnings`.
- Nommage **`Validity*`** (jamais `Zk*`) ; non-privé, documenté.
- L'AIR reproduit `Rp64_256::apply_round` avec les constantes **publiques** `Rp64_256::{MDS, ARK1, ARK2}` et `ALPHA=7`. **Correction = différentiel Sage** : `prove_permutation([0..11]).output == winter::apply_permutation([0..11])` (vecteur Sage de 3a1).
- **Approche exploratoire assumée (Task 2)** : le corps des contraintes de transition se développe **contre l'exemple `rescue` de winterfell** (source GitHub), en itérant jusqu'à ce que le différentiel Sage passe. Le plan fixe la structure et les invariants, pas des contraintes devinées à l'avance (même convention que l'épinglage d'API en 3a1).
- Branche `feat/3a2-permutation`. Les 51 tests existants restent verts.
- Commits : `--author="Walid Naili <naili.walid@gmail.com>"`, `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

---

### Task 1 : Scaffold `circuit` + wiring winterfell + étude de l'exemple

**Files:**
- Create: `crates/circuit/Cargo.toml`, `crates/circuit/src/lib.rs`
- Modify: `Cargo.toml` racine (workspace members + dep `winterfell`)

**Interfaces:**
- Produces: crate `circuit` qui compile ; un roundtrip prove/verify trivial (« do_work ») confirmant le câblage `Air`/`Prover`/`verify`.

- [ ] **Step 1 : Étudier l'exemple `rescue`** — WebFetch la source de l'AIR Rescue de winterfell (dépôt `facebook/winterfell`, `examples/src/rescue/`), noter : layout de trace, gestion inverse S-box (relation forward), colonnes périodiques des ARK, degrés de contrainte déclarés. **Ne pas coder encore** — recueillir le patron.

- [ ] **Step 2 : Deps workspace** — `Cargo.toml` racine : ajouter `"crates/circuit"` aux `members` et, dans `[workspace.dependencies]` :

```toml
winterfell = "0.13"
```

- [ ] **Step 3 : `crates/circuit/Cargo.toml`**

```toml
[package]
name = "circuit"
version.workspace = true
edition.workspace = true
rust-version.workspace = true

[dependencies]
winterfell = { workspace = true }
winter-crypto = { workspace = true }
winter-math = { workspace = true }
proved-hash = { path = "../proved-hash" }
```

- [ ] **Step 4 : Wiring minimal (« do_work »)** — `crates/circuit/src/lib.rs` : implémenter le petit exemple `do_work` de winterfell (AIR 1 colonne, contrainte `s' = s^3 + 42`, prove+verify) UNIQUEMENT pour confirmer que `Air`/`Prover`/`verify`/`ProofOptions` se câblent avec cette version. Inclure un test `wiring_do_work_prove_verify`.

Run: `& "$env:USERPROFILE\.cargo\bin\cargo.exe" test --manifest-path "C:\Users\W47\Documents\obscura\Cargo.toml" -p circuit`
Expected: `wiring_do_work_prove_verify` PASS (valide la chaîne prouveur/vérifieur avant d'attaquer Rescue).

- [ ] **Step 5 : Commit**

```bash
git add Cargo.toml Cargo.lock crates/circuit
git commit --author="Walid Naili <naili.walid@gmail.com>" -m "3a2 : scaffold crate circuit + wiring winterfell (do_work)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2 : AIR de la permutation Rp64_256 (itéré contre le différentiel Sage)

**Files:**
- Create: `crates/circuit/src/rescue_perm.rs` (AIR + trace builder + prover)
- Modify: `crates/circuit/src/lib.rs` (`pub mod rescue_perm;`, réexports)

**Interfaces:**
- Produces: `prove_permutation([Felt;12]) -> ([Felt;12], ValidityProof)`, `verify_permutation([Felt;12], &ValidityProof) -> bool`, type `ValidityProof`.

- [ ] **Step 1 : Trace builder** — construire la trace `8 × 12` : ligne 0 = `input` (converti en `BaseElement`), ligne `i+1` = `Rp64_256::apply_round(row_i, i)` (on peut appeler directement `apply_round` pour REMPLIR la trace ; les contraintes la vérifieront). Test intermédiaire : ligne 7 de la trace == `winter::apply_permutation(input)`.

- [ ] **Step 2 : AIR `RescuePermAir`** — implémenter `Air` en suivant l'exemple `rescue` (Task 1 Step 1) :
  - `PublicInputs { output: [BaseElement; 12] }` ;
  - colonnes périodiques = `ARK1`/`ARK2` (une valeur par ronde) ;
  - `evaluate_transition` : reproduit `apply_round` (S-box `x⁷` via `Rp64_256::MDS`/`ARK` ; inverse S-box par relation forward comme l'exemple) ; **déclarer les degrés corrects** (sinon panique en debug) ;
  - `get_assertions` : **uniquement** ligne 7 == `output` public. **Ligne 0 (témoin) non assertée.**

- [ ] **Step 3 : Prover + API** — `RescuePermProver` (impl `Prover`), puis :

```rust
pub struct ValidityProof(pub winterfell::Proof); // NON witness-hiding — validity-only

pub fn prove_permutation(input: [proved_hash::felt::Felt; 12]) -> ([proved_hash::felt::Felt; 12], ValidityProof) { /* build trace, prove, extraire output ligne 7 */ }

pub fn verify_permutation(output: [proved_hash::felt::Felt; 12], proof: &ValidityProof) -> bool { /* winterfell::verify::<RescuePermAir, ...> */ }
```

- [ ] **Step 4 : Itérer jusqu'au différentiel Sage** — écrire le test :

```rust
#[test]
fn differentiel_sage() {
    use proved_hash::felt::Felt;
    let input: [Felt; 12] = core::array::from_fn(|i| Felt::from_canonical_u64(i as u64).unwrap());
    let (output, proof) = prove_permutation(input);
    // vecteur Sage (winter::apply_permutation([0..11]))
    let sage: [u64; 12] = [
        11084501481526603421, 6291559951628160880, 13626645864671311919,
        18397438323058963117, 7443014167353970324, 17930833023906771425,
        4275355080008025761, 7676681476902901785, 3460534574143792217,
        11912731278641497187, 8104899243369883110, 674509706691634438,
    ];
    for i in 0..12 { assert_eq!(output[i].as_u64(), sage[i]); }
    assert!(verify_permutation(output, &proof));
}
```

Run en boucle jusqu'au vert : `& "$env:USERPROFILE\.cargo\bin\cargo.exe" test --manifest-path "C:\Users\W47\Documents\obscura\Cargo.toml" -p circuit differentiel_sage`
Expected: PASS. Tant que ça échoue (sortie ≠ Sage, ou mismatch de degré), corriger les contraintes contre l'exemple `rescue`. **C'est le cœur exploratoire de la tranche.**

- [ ] **Step 5 : Commit**

```bash
git add crates/circuit/src
git commit --author="Walid Naili <naili.walid@gmail.com>" -m "3a2 : AIR permutation Rp64_256 + prove/verify (différentiel Sage vert)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3 : Tests de robustesse + doc

**Files:**
- Modify: `crates/circuit/src/rescue_perm.rs` (tests)
- Modify: `docs/STARK_STATEMENT.md` (note : premier AIR = permutation, validity-only)

**Interfaces:** aucune nouvelle.

- [ ] **Step 1 : Test négatif** — une preuve valide ne vérifie pas contre une sortie altérée :

```rust
#[test]
fn output_altere_rejete() {
    use proved_hash::felt::Felt;
    let input: [Felt; 12] = core::array::from_fn(|i| Felt::from_canonical_u64((i as u64) + 1).unwrap());
    let (mut output, proof) = prove_permutation(input);
    output[0] = Felt::from_canonical_u64(output[0].as_u64() ^ 1).unwrap();
    assert!(!verify_permutation(output, &proof));
}
```

- [ ] **Step 2 : Test de cohérence** — pour quelques entrées fixes (pas de RNG), `output == winter::apply_permutation(input)` :

```rust
#[test]
fn coherence_avec_winter() {
    use proved_hash::felt::Felt;
    use winter_crypto::hashers::Rp64_256;
    use winter_math::fields::f64::BaseElement;
    for seed in [1u64, 42, 1000] {
        let input: [Felt; 12] = core::array::from_fn(|i| Felt::from_canonical_u64(seed + i as u64).unwrap());
        let (output, _) = prove_permutation(input);
        let mut st: [BaseElement; 12] = core::array::from_fn(|i| BaseElement::new(seed + i as u64));
        Rp64_256::apply_permutation(&mut st);
        for i in 0..12 { assert_eq!(output[i], Felt::from_winter(st[i]).unwrap()); }
    }
}
```

- [ ] **Step 3 : Doc `STARK_STATEMENT.md`** — sous la note validity-only existante, ajouter :

```markdown
> **3a2 (fait) :** premier AIR = la **permutation** Rp64_256 (`prove`/`verify`,
> différentiel vs référence Sage). Le hash sponge complet (`owner = H_owner(secret)`,
> P2) est la tranche suivante 3a2b.
```

- [ ] **Step 4 : Vérifier tout sous `-D warnings`**

Run: `$env:RUSTFLAGS="-D warnings"; & "$env:USERPROFILE\.cargo\bin\cargo.exe" test --manifest-path "C:\Users\W47\Documents\obscura\Cargo.toml"; Remove-Item Env:RUSTFLAGS`
Expected: 51 existants + circuit (wiring, differentiel_sage, output_altere_rejete, coherence_avec_winter) verts, **0 warning**.

- [ ] **Step 5 : Commit**

```bash
git add crates/circuit docs/STARK_STATEMENT.md
git commit --author="Walid Naili <naili.walid@gmail.com>" -m "3a2 : tests robustesse (négatif, cohérence winter) + doc

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage :** crate `circuit` + deps (§5) → Task 1. AIR permutation + statement P public / S témoin hors assertions (§3-4) → Task 2. `prove/verify` (§5) → Task 2 Step 3. Différentiel Sage + négatif + cohérence (§6) → Task 2 Step 4 + Task 3. Non-goals (§7 : pas de sponge, pas de P2 complet, pas de ledger, pas de ZK) respectés. Nommage `Validity*` (§1) → Task 2 Step 3. ✓

**Placeholder scan :** le corps des contraintes de l'AIR (Task 2 Step 2) est **explicitement exploratoire** (développé contre l'exemple `rescue`, gated par le différentiel Sage) — convention annoncée dans les contraintes globales, pas un TODO masqué. Le reste (trace, API, tests, deps) est concret. ✓

**Type consistency :** `Felt` (proved-hash), `Felt::from_winter`/`as_u64`/`to_winter`, `[Felt;12]`, `ValidityProof` cohérents entre tasks. Vecteur Sage identique à celui de 3a1. ✓
