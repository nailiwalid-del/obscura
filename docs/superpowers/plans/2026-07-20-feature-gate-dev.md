# Feature-gate des chemins de dev — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mettre le mode transparent (ledger) et les sous-circuits autonomes (circuit) derrière deux features Cargo **désactivées par défaut**, pour qu'un build/test nu n'expose QUE la surface consensus.

**Architecture:** `#[cfg(feature = "dev-circuits")]` sur les `prove_*`/`verify_*` standalone + leurs types/re-exports/tests (circuit) ; `#[cfg(feature = "dev-transparent")]` sur le mode transparent (ledger). Les modules gadgets restent compilés (le monolithe réutilise leurs helpers `pub(crate)`). Refactor **guidé par le compilateur** : on gate, on vérifie que le build par défaut compile, on corrige ce qui déborde.

**Tech Stack:** Rust, Cargo features.

## Global Constraints

- Spec de référence : `docs/superpowers/specs/2026-07-20-feature-gate-dev-design.md`.
- **On gate, on ne supprime pas.** Aucun changement de comportement.
- **Invariant central** : `cargo build` ET `cargo test` (+ `--release`) **sans aucun feature** compilent et passent avec la seule surface consensus. AUCUN code consensus ne référence du code dev gaté.
- Consensus TOUJOURS compilé — circuit : `monolith`, `prove_tx`/`verify_tx`/`verify_proved_tx_full`/`ProvedTx`/`ProvedInput`/`EncNote`/`KEM_CT_LEN`/`MAX_ENC_NOTE_LEN`/`INTENT_DOMAIN`/`SpendNote`/`RANGE_BITS`/`ValidityProof`, + les helpers `pub(crate)` des gadgets ; ledger : `proved_state`/`ProvedLedgerState`/`apply_proved_tx`, `proved_wallet`, `keys`, `LedgerError`, `Commitment`.
- Si un type « dev » se révèle utilisé par le consensus (ex. `Note`, `merkle`), il n'est PAS gaté (il devient partagé) — suivre les erreurs du build par défaut.
- Suite complète : `cargo test --all-features --release`. Tests dev gatés : `#[cfg(all(test, feature = "…"))]`.
- Code/commentaires FRANÇAIS ; commits `--author="Walid Naili <naili.walid@gmail.com>"` + trailer `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` ; clippy 0.

## Fichiers touchés
- `crates/circuit/Cargo.toml`, `crates/circuit/src/lib.rs` + modules gadgets (spend, output, key, balance, membership, range_check, merkle_level, merkle_path, owner_hash, rescue_perm, sponge).
- `crates/ledger/Cargo.toml`, `crates/ledger/src/lib.rs`, `state.rs`, `tx.rs` (+ `merkle.rs`/`note.rs` selon dépendances).
- `README.md`, `CLAUDE.md`.

---

### Task 1 : Feature `dev-circuits` (circuit)

**Files:** Modify: `crates/circuit/Cargo.toml`, `crates/circuit/src/lib.rs`, et les modules gadgets concernés.

**Interfaces:**
- Produces : feature `dev-circuits` (déclarée `[features] dev-circuits = []`, PAS dans `default`). Les fns publiques standalone `prove_*`/`verify_*` + types `SpendProof`/`OutputProof`/`MembershipProof` deviennent `#[cfg(feature = "dev-circuits")]`.

- [ ] **Step 1 : déclarer la feature** — `crates/circuit/Cargo.toml` : ajouter `[features]` avec `dev-circuits = []` (et NE PAS l'ajouter à un éventuel `default`).

- [ ] **Step 2 : gater les entrées standalone** — sur CHAQUE fonction publique standalone et son type de retour, mettre `#[cfg(feature = "dev-circuits")]` : `prove_spend`/`verify_spend`/`SpendProof` (spend.rs), `prove_output`/`verify_output`/`OutputProof` (output.rs), `prove_key`/`verify_key` (key.rs), `prove_balance`/`verify_balance` (balance.rs), `prove_membership`/`verify_membership`/`MembershipProof` (membership.rs), `prove_range`/`verify_range` (range_check.rs — MAIS garder `RANGE_BITS` UNGATED, il est lu par tx.rs), `prove_merkle_level`/`verify_merkle_level` (merkle_level.rs), `prove_merkle_path`/`verify_merkle_path` (merkle_path.rs — garder `path_rows`/`BLOCK`/`enforce_merkle_transition` pub(crate) UNGATED), `prove_owner`/`verify_owner` (owner_hash.rs), `prove_permutation`/`verify_permutation` (rescue_perm.rs), et les instances sponge standalone `prove_sponge`/`verify_sponge`/`prove_nk`/`prove_nullifier`/`prove_note_commitment`/`verify_note_commitment` (sponge.rs — garder `enforce_sponge_transition`/`sponge_rows`/`locate`/`TRACE_WIDTH` pub(crate) UNGATED). `SpendNote` + `to_bytes`/`from_bytes` restent UNGATED.
  - Gater les MÊMES symboles dans les `pub use ...` de `lib.rs` (`#[cfg(feature = "dev-circuits")]` devant chaque re-export standalone).
  - Gater les modules de tests différentiels qui appellent ces fns : `#[cfg(all(test, feature = "dev-circuits"))]` sur les `mod tests` concernés (sinon `cargo test` nu ne compile pas).

- [ ] **Step 3 : vérifier le build par défaut** — `cargo build -p circuit` (aucun feature) → compile. Corriger toute erreur : si un symbole gaté est utilisé par du code consensus (monolith/tx), c'est qu'il ne devait PAS être gaté → le dé-gater (ou dé-gater le helper pub(crate) sous-jacent, pas la fn standalone). Itérer jusqu'à `cargo build -p circuit` vert.

- [ ] **Step 4 : vérifier les deux modes** — `cargo test -p circuit --release` (défaut : seuls les tests consensus, ex. `monolith`, `tx`, tournent) → PASS. `cargo test -p circuit --release --features dev-circuits` (tous les tests différentiels tournent) → PASS. `cargo clippy -p circuit --all-targets` ET `cargo clippy -p circuit --all-targets --features dev-circuits` → 0 warning (attention aux `unused` sous un mode ou l'autre — gater aussi les `use` devenus inutilisés).

- [ ] **Step 5 : commit** `circuit(feature-gate): dev-circuits — sous-circuits standalone off par défaut`

---

### Task 2 : Feature `dev-transparent` (ledger)

**Files:** Modify: `crates/ledger/Cargo.toml`, `crates/ledger/src/lib.rs`, `state.rs`, `tx.rs` (+ `merkle.rs`/`note.rs` selon dépendances).

**Interfaces:**
- Consumes : la surface consensus de circuit (Task 1 ne l'a pas changée). Produces : feature `dev-transparent` (`dev-transparent = []`, hors `default`) gatant le mode transparent.

- [ ] **Step 1 : déclarer la feature** — `crates/ledger/Cargo.toml` : `[features] dev-transparent = []` (hors `default`).

- [ ] **Step 2 : gater le mode transparent** — `#[cfg(feature = "dev-transparent")]` sur : `pub mod state;` (LedgerState/apply_transparent) dans `lib.rs` ; la tx transparente dans `tx.rs` (`Transaction`/`TxInput`/`TxOutput`/`build_transparent_transaction`/`scan_output` + la méthode `digest` transparente + `impl` associés). Pour `merkle.rs` et `note.rs` : NE PAS gater a priori — déterminer par le build (Step 3) s'ils sont utilisés UNIQUEMENT par le transparent (alors gater le `pub mod`) ou partagés (alors laisser). `keys`, `proved_state`, `proved_wallet`, `LedgerError`, `Commitment` restent UNGATED. Tests transparents : `#[cfg(all(test, feature = "dev-transparent"))]`.

- [ ] **Step 3 : vérifier le build par défaut** — `cargo build -p ledger` (aucun feature) → compile. Résoudre les dépendances de `merkle`/`note` : si le build nu échoue parce que `proved_*`/`keys` utilisent `Note`/`merkle`, ces types sont PARTAGÉS → ne pas les gater ; sinon (utilisés que par le transparent), gater leur `pub mod`. Itérer jusqu'au vert.

- [ ] **Step 4 : vérifier les deux modes** — `cargo test -p ledger --release` (défaut : `proved_state`/`proved_wallet` seuls) → PASS. `cargo test -p ledger --release --features dev-transparent` (+ transparent) → PASS. `cargo clippy -p ledger --all-targets` et `--features dev-transparent` → 0 warning.

- [ ] **Step 5 : commit** `ledger(feature-gate): dev-transparent — mode transparent off par défaut`

---

### Task 3 : Vérification croisée + docs

**Files:** Modify: `README.md`, `CLAUDE.md`.

- [ ] **Step 1 : matrice de features** — vérifier les 4 combinaisons compilent et passent : (a) défaut `cargo test --workspace --release` (consensus seul), (b) `--features dev-circuits` (via `-p circuit`, ou `cargo test --release --features circuit/dev-circuits`), (c) `--features dev-transparent`, (d) `cargo test --workspace --all-features --release` (tout). Clippy 0 sur (a) et (d).
- [ ] **Step 2 : docs** — README : section « Build & tests » note que le défaut = surface consensus, et que `--all-features` active le mode transparent (dev) + les sous-circuits standalone. CLAUDE.md : mention des deux features (dev, off par défaut) sous « Conventions » ou « Notes de build ».
- [ ] **Step 3 : commit** `docs(feature-gate): documenter dev-transparent/dev-circuits (off par défaut)`

---

## Self-review du plan
- **Couverture spec** : §2 consensus toujours compilé → invariant vérifié T1/T2 Step 3-4 ; §3 dev-circuits → T1 ; §3 dev-transparent → T2 ; §4 invariant → T1/T2 Step 3 (build nu) ; §5 fichiers → tous ; §6 tests (défaut/all/combinaisons) → T1/T2 Step 4 + T3 Step 1 ; §7 hors-périmètre (gate pas remove) → Global Constraints.
- **Ordre** : circuit d'abord (ledger en dépend), ledger ensuite, docs enfin.
- **Nature** : refactor guidé par le compilateur — les Step 3 (build nu vert) sont le vrai juge ; les listes de symboles sont indicatives, l'implémenteur ajuste selon les erreurs réelles (règle : consensus l'utilise ⇒ ne pas gater).
- **Placeholders** : aucun — chaque étape a une commande concrète et un critère (build/test vert). Les symboles exacts à gater sont énumérés ; les cas `merkle`/`note` sont résolus par règle explicite (build nu).
