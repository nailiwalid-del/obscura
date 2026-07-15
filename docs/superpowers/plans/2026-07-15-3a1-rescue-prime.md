# 3a1 — Rescue-Prime prouvé (wrapper `Rp64_256`) — Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ajouter à `crates/proved-hash` le hash prouvé Rescue-Prime hors-circuit (`hash`/`merge`), en wrappant `winter-crypto::Rp64_256::hash_elements`, avec séparation de domaine via le `sponge_preamble` 3a0 inchangé, vecteurs figés et ancrage externe.

**Architecture:** `proved-hash` gagne une dépendance sur la couche crypto de winterfell (PAS le prouveur). `Felt` (u64 canonique) se convertit exactement en `BaseElement` (Goldilocks). Le module `rescue` fournit `hash(domain, &[Felt]) -> Digest` et `merge`. Le padding sponge est interne à winter ; notre domaine = le préambule injectif 3a0.

**Tech Stack:** Rust, `winter-crypto`, `winter-math`, s'appuie sur le crate `proved-hash` (3a0).

## Global Constraints

- Spec : `docs/superpowers/specs/2026-07-15-3a1-rescue-prime-design.md`. Contrat encodage/domaines : `...-phase3-decision-et-3a0-design.md` (**inchangé**).
- `cargo` via `& "$env:USERPROFILE\.cargo\bin\cargo.exe" ... --manifest-path "C:\Users\W47\Documents\obscura\Cargo.toml"` ; tests finaux sous `$env:RUSTFLAGS="-D warnings"`.
- **`sponge_preamble` de 3a0 reste INCHANGÉ** (signature + golden vector `[1,1,2,7,8,1]`). Le rate-padding est **interne à `Rp64_256`**.
- **Aucune dépendance au prouveur** (`winter-prover`/`winterfell`) : uniquement `winter-crypto` + `winter-math`.
- **API winter épinglée en Task 1** (probe) : les noms `hash_elements` / conversion digest→éléments sont confirmés avant d'écrire `rescue`. Si un nom diffère de ce plan, **adapter au réel** (le plan documente l'intention, pas une API devinée).
- Commentaires en français. Commits : `--author="Walid Naili <naili.walid@gmail.com>"`, terminer par `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Branche `feat/3a1-rescue`. Les 45 tests existants restent verts.

---

### Task 1 : Deps winter-crypto + `Felt ↔ BaseElement` + MSRV + probe d'API

**Files:**
- Modify: `Cargo.toml` (workspace deps + `rust-version`)
- Modify: `crates/proved-hash/Cargo.toml`
- Modify: `crates/proved-hash/src/felt.rs` (conversion + tests)

**Interfaces:**
- Produces: `Felt::to_winter() -> winter_math::fields::f64::BaseElement`, `Felt::from_winter(BaseElement) -> Result<Felt, EncodingError>`.

- [ ] **Step 1 : Ajouter les deps au workspace** — `Cargo.toml` racine, dans `[workspace.dependencies]`

```toml
winter-crypto = "0.13"
winter-math = "0.13"
```

(Si `0.13` ne résout pas, prendre la dernière version stable publiée de `winter-crypto`/`winter-math` et **aligner les deux sur la même version**.)

- [ ] **Step 2 : Deps du crate** — `crates/proved-hash/Cargo.toml`, section `[dependencies]`, ajouter

```toml
winter-crypto = { workspace = true }
winter-math = { workspace = true }
```

- [ ] **Step 3 : Probe d'API (jetable)** — créer `crates/proved-hash/src/rescue.rs` minimal pour confirmer la compilation et les noms

```rust
//! Probe temporaire : confirme l'API winter-crypto avant l'implémentation réelle.
use winter_crypto::hashers::Rp64_256;
use winter_crypto::{ElementHasher, Hasher};
use winter_math::fields::f64::BaseElement;

#[allow(dead_code)]
fn probe() {
    let elems = [BaseElement::new(1), BaseElement::new(2)];
    let digest = Rp64_256::hash_elements(&elems);
    // Confirmer la voie de conversion digest -> [BaseElement; 4] OU -> [u8; 32] :
    let _bytes = <Rp64_256 as Hasher>::Digest::as_bytes(&digest);
}
```

Ajouter `pub mod rescue;` dans `lib.rs`.

Run: `& "$env:USERPROFILE\.cargo\bin\cargo.exe" build --manifest-path "C:\Users\W47\Documents\obscura\Cargo.toml" -p proved-hash`
Expected: **compile OK** (télécharge + build winterfell, plusieurs minutes la 1re fois). **Noter** : la MSRV exigée (si le build échoue sur `rust-version`, relever la valeur), et la méthode exacte digest→éléments (`as_elements()`, `into()`, ou via `as_bytes()`).

- [ ] **Step 4 : Fixer la MSRV** — `Cargo.toml` racine, `rust-version` : mettre la valeur exigée par winter-crypto (constatée au Step 3 ; ex. `"1.84"`). Garder `>=` à ce que rustc 1.97 satisfait.

- [ ] **Step 5 : Conversion `Felt ↔ BaseElement`** — ajouter à `crates/proved-hash/src/felt.rs` (avant `#[cfg(test)]`)

```rust
use winter_math::fields::f64::BaseElement;
use winter_math::{FieldElement, StarkField};

impl Felt {
    /// Conversion exacte vers le corps de winter (déjà canonique `< p`).
    pub fn to_winter(self) -> BaseElement {
        BaseElement::new(self.0)
    }

    /// Depuis un BaseElement : `as_int()` renvoie la forme canonique `< p`.
    pub fn from_winter(be: BaseElement) -> Result<Self, EncodingError> {
        Self::from_canonical_u64(be.as_int())
    }
}
```

(Si `FieldElement`/`StarkField` ne sont pas les bons traits pour `new`/`as_int`, ajuster les imports selon le probe.)

- [ ] **Step 6 : Test de conversion** — ajouter au `mod tests` de `felt.rs`

```rust
    #[test]
    fn roundtrip_base_element() {
        for x in [0u64, 1, P - 1] {
            let f = Felt::from_canonical_u64(x).unwrap();
            assert_eq!(Felt::from_winter(f.to_winter()).unwrap(), f);
        }
    }
```

- [ ] **Step 7 : Vérifier**

Run: `& "$env:USERPROFILE\.cargo\bin\cargo.exe" test --manifest-path "C:\Users\W47\Documents\obscura\Cargo.toml" -p proved-hash felt::`
Expected: 3 tests `felt::tests::*` PASS (incl. `roundtrip_base_element`).

- [ ] **Step 8 : Commit**

```bash
git add Cargo.toml Cargo.lock crates/proved-hash
git commit --author="Walid Naili <naili.walid@gmail.com>" -m "3a1 : deps winter-crypto/winter-math + Felt<->BaseElement + MSRV

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2 : Module `rescue` — `hash` et `merge`

**Files:**
- Modify: `crates/proved-hash/src/rescue.rs` (remplacer le probe par l'implémentation réelle)

**Interfaces:**
- Consumes: `felt::Felt`, `digest::Digest`, `domain::{Domain, sponge_preamble}`, `Rp64_256::hash_elements`.
- Produces: `rescue::{hash, merge}`.

- [ ] **Step 1 : Écrire le test qui échoue** — remplacer tout `rescue.rs` par

```rust
//! Hash prouvé Rescue-Prime hors-circuit : wrapper de `winter-crypto::Rp64_256`.
//!
//! La séparation de domaine = le préambule injectif de 3a0 (sponge_preamble,
//! PAD_ONE inclus), fourni comme entrée à `hash_elements`. Le rate-padding est
//! interne à Rp64_256. Ce chemin est HORS-CIRCUIT : l'égalité avec la version
//! prouvée en AIR est un livrable de 3a2 (validity-only jusque-là).

use crate::digest::{Digest, DIGEST_FELTS};
use crate::domain::{sponge_preamble, Domain};
use crate::felt::Felt;
use winter_crypto::hashers::Rp64_256;
use winter_crypto::ElementHasher;

/// Hash prouvé domaine-séparé d'une séquence de Felts.
pub fn hash(domain: Domain, payload: &[Felt]) -> Digest {
    let input: Vec<_> = sponge_preamble(domain, payload)
        .into_iter()
        .map(Felt::to_winter)
        .collect();
    let d = Rp64_256::hash_elements(&input);
    // digest winter -> nos 4 Felts (via .as_elements() ; adapter selon le probe Task 1).
    let elems = d.as_elements();
    let mut felts = [Felt::ZERO; DIGEST_FELTS];
    for (i, felt) in felts.iter_mut().enumerate() {
        *felt = Felt::from_winter(elems[i]).expect("digest winter canonique");
    }
    Digest(felts)
}

/// Compression 2->1 domaine-séparée (nœuds de Merkle) : hash(domain, a ‖ b).
pub fn merge(domain: Domain, a: &Digest, b: &Digest) -> Digest {
    let mut payload = Vec::with_capacity(2 * DIGEST_FELTS);
    payload.extend_from_slice(&a.0);
    payload.extend_from_slice(&b.0);
    hash(domain, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn felt(x: u64) -> Felt {
        Felt::from_canonical_u64(x).unwrap()
    }

    #[test]
    fn hash_deterministe() {
        let p = [felt(1), felt(2), felt(3)];
        assert_eq!(hash(Domain::Owner, &p), hash(Domain::Owner, &p));
    }

    #[test]
    fn domaines_distincts_donnent_digests_distincts() {
        let p = [felt(1), felt(2)];
        assert_ne!(hash(Domain::Owner, &p), hash(Domain::Nk, &p));
    }

    #[test]
    fn merge_ordre_significatif() {
        let a = hash(Domain::NoteCommitment, &[felt(1)]);
        let b = hash(Domain::NoteCommitment, &[felt(2)]);
        assert_ne!(merge(Domain::MerkleNode, &a, &b), merge(Domain::MerkleNode, &b, &a));
    }
}
```

(Si `.as_elements()` n'existe pas, utiliser la voie confirmée au probe : `d.as_bytes()` → `Digest::from_bytes(&bytes)`, **à condition** que le layout octets de winter == 4×LE-canonique ; sinon rester sur les éléments.)

- [ ] **Step 2 : Vérifier**

Run: `& "$env:USERPROFILE\.cargo\bin\cargo.exe" test --manifest-path "C:\Users\W47\Documents\obscura\Cargo.toml" -p proved-hash rescue::`
Expected: 3 tests `rescue::tests::*` PASS.

- [ ] **Step 3 : Commit**

```bash
git add crates/proved-hash/src
git commit --author="Walid Naili <naili.walid@gmail.com>" -m "3a1 : rescue::hash et merge (wrapper Rp64_256, domaine-séparé)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3 : Vecteurs de hash figés + ancrage externe

**Files:**
- Modify: `crates/proved-hash/vectors/encoding_v1.json` (section `rescue_hash`)
- Modify: `crates/proved-hash/tests/golden.rs` (test des vecteurs de hash)

**Interfaces:** consomme `rescue::{hash, merge}`.

- [ ] **Step 1 : Générer les valeurs figées (jetable)** — ajouter temporairement à `tests/golden.rs`

```rust
#[test]
fn imprime_vecteurs_rescue_tmp() {
    use proved_hash::domain::Domain;
    use proved_hash::felt::Felt;
    use proved_hash::rescue::{hash, merge};
    let f = |x| Felt::from_canonical_u64(x).unwrap();
    let owner = hash(Domain::Owner, &[f(7), f(8)]);
    let a = hash(Domain::NoteCommitment, &[f(1)]);
    let b = hash(Domain::NoteCommitment, &[f(2)]);
    let node = merge(Domain::MerkleNode, &a, &b);
    eprintln!("OWNER={}", owner.to_hex());
    eprintln!("NODE={}", node.to_hex());
}
```

Run: `& "$env:USERPROFILE\.cargo\bin\cargo.exe" test --manifest-path "C:\Users\W47\Documents\obscura\Cargo.toml" -p proved-hash imprime_vecteurs_rescue_tmp -- --nocapture`
Noter les deux valeurs hex affichées.

- [ ] **Step 2 : Ajouter la section aux golden vectors** — dans `vectors/encoding_v1.json`, avant l'accolade fermante, ajouter (remplacer `<...>` par les valeurs du Step 1)

```json
  ,
  "rescue_hash": {
    "note": "Rp64_256 via sponge_preamble (PAD_ONE inclus). Hors-circuit ; l'égalité in-circuit est prouvée en 3a2.",
    "hash_owner_7_8": "<OWNER hex>",
    "merge_merklenode_of_nc1_nc2": "<NODE hex>"
  }
```

- [ ] **Step 3 : Remplacer le test jetable par le test figé** — dans `tests/golden.rs`, supprimer `imprime_vecteurs_rescue_tmp` et ajouter

```rust
#[test]
fn rescue_vecteurs_figes() {
    use proved_hash::domain::Domain;
    use proved_hash::felt::Felt;
    use proved_hash::rescue::{hash, merge};
    let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let rh = &v["rescue_hash"];
    let f = |x| Felt::from_canonical_u64(x).unwrap();

    let owner = hash(Domain::Owner, &[f(7), f(8)]);
    assert_eq!(owner.to_hex(), rh["hash_owner_7_8"].as_str().unwrap());

    let a = hash(Domain::NoteCommitment, &[f(1)]);
    let b = hash(Domain::NoteCommitment, &[f(2)]);
    let node = merge(Domain::MerkleNode, &a, &b);
    assert_eq!(node.to_hex(), rh["merge_merklenode_of_nc1_nc2"].as_str().unwrap());
}
```

- [ ] **Step 4 : Ancrage externe (§13.7)** — chercher dans le dépôt/tests publiés de winterfell un vecteur `Rp64_256` (entrée d'éléments → digest attendu) directement reproductible. S'il en existe un exploitable, ajouter un test dédié :

```rust
#[test]
fn ancrage_externe_rp64_256() {
    // Vecteur issu des tests publiés de winterfell (winter-crypto), reproduit
    // par un appel direct à Rp64_256 — garantit qu'on n'est pas auto-référentiel.
    use winter_crypto::hashers::Rp64_256;
    use winter_crypto::ElementHasher;
    use winter_math::fields::f64::BaseElement;
    let input = [BaseElement::new(0), BaseElement::new(1)]; // remplacer par le vecteur publié
    let d = Rp64_256::hash_elements(&input);
    let attendu_hex = "<digest hex du vecteur publié>";
    assert_eq!(hex::encode(d.as_bytes()), attendu_hex);
}
```

Si **aucun** vecteur publié n'est directement exploitable, **ne pas inventer** : supprimer ce test, et ajouter dans `rescue.rs` un commentaire `// TODO(3a2) : ancrage externe indépendant via le différentiel natif <-> circuit` + le noter dans le commit. (La spec 3a1 §7 prévoit ce cas.)

- [ ] **Step 5 : Vérifier tout sous `-D warnings`**

Run: `$env:RUSTFLAGS="-D warnings"; & "$env:USERPROFILE\.cargo\bin\cargo.exe" test --manifest-path "C:\Users\W47\Documents\obscura\Cargo.toml"; Remove-Item Env:RUSTFLAGS`
Expected: tous verts (45 existants + felt conv + rescue + golden rescue), **0 warning**. Golden `[1,1,2,7,8,1]` (préambule) toujours vert (inchangé).

- [ ] **Step 6 : Commit**

```bash
git add crates/proved-hash
git commit --author="Walid Naili <naili.walid@gmail.com>" -m "3a1 : vecteurs de hash figés + ancrage externe Rp64_256

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage :** deps winter-crypto/math + MSRV (§2) → Task 1. Felt↔BaseElement (§3) → Task 1 Steps 5-6. `hash`/`merge` via hash_elements + sponge_preamble inchangé (§4-5) → Task 2. Vecteurs figés + ancrage externe (§1, §7, §13.7) → Task 3. Non-goals (§6 : pas de permutation maison, pas d'AIR, pas de câblage ledger) respectés. ✓

**Placeholder scan :** les `<...>` des golden vectors sont **remplis au Step 1** de la Task 3 (valeurs générées) — process explicite, pas un TODO laissé en place. L'API winter (`as_elements`/`as_bytes`) est **épinglée au probe Task 1** avec fallback documenté — conforme à la convention annoncée. ✓

**Type consistency :** `Felt`/`Digest`/`Domain`/`sponge_preamble` réutilisés depuis 3a0 sans changement de signature. `hash`/`merge` signatures cohérentes entre Task 2 et Task 3. `DIGEST_FELTS=4`. ✓
