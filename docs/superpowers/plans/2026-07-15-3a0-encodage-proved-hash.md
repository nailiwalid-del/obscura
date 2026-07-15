# 3a0 — Encodage canonique (`crates/proved-hash`) — Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Créer le crate `crates/proved-hash` figeant les représentations canoniques (Felt, Digest, ShieldedSecret, AmountLimbs, Domain, préambule sponge) avant tout circuit, sans dépendance au prouveur ni Rescue.

**Architecture:** Newtypes canoniques sur le corps de Goldilocks. `Felt(u64)` avec invariant `< p` (encodage/validation seulement en 3a0 ; l'arithmétique Rescue = 3a1). Digests = `[Felt;4]` (32 o). Montants = `[u16;4]` (limbs 16 bits). Domaines = tags Felt distincts + préambule versionné. Golden vectors JSON cross-langage.

**Tech Stack:** Rust, `thiserror`, `hex`, `serde` (forme canonique), `zeroize` ; dev : `proptest`.

## Global Constraints

- Spec de référence : `docs/superpowers/specs/2026-07-15-phase3-decision-et-3a0-design.md`.
- Commentaires/docs **en français** (convention repo).
- `cargo` via `& "$env:USERPROFILE\.cargo\bin\cargo.exe" test --manifest-path "C:\Users\W47\Documents\obscura\Cargo.toml"` (PATH non persistant). Tests sous `$env:RUSTFLAGS="-D warnings"` puis `Remove-Item Env:RUSTFLAGS`.
- **Aucune dépendance au prouveur** (winterfell/plonky) dans `proved-hash`. **Aucune réduction modulo silencieuse** : tout décodage rejette `>= p` / `>= 2^16`.
- Naming : `validity-only` ; ne jamais nommer un type `Zk*` dans ce crate.
- `p = 0xFFFF_FFFF_0000_0001 = 18446744069414584321`.
- Les 29 tests existants doivent rester verts. Nouveau crate isolé.
- Commits : auteur `git commit --author="Walid Naili <naili.walid@gmail.com>"`, identité repo déjà configurée, terminer par `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Travailler sur une branche `feat/3a0-encodage`.

---

### Task 1 : Scaffold du crate + `Felt` canonique

**Files:**
- Create: `crates/proved-hash/Cargo.toml`
- Create: `crates/proved-hash/src/lib.rs`
- Create: `crates/proved-hash/src/felt.rs`
- Modify: `Cargo.toml` (workspace members)

**Interfaces:**
- Produces: `proved_hash::EncodingError`, `proved_hash::felt::{Felt, P}` avec `Felt::from_canonical_u64(u64)->Result`, `from_small(u32)->Felt`, `as_u64`, `to_bytes()->[u8;8]`, `from_bytes(&[u8;8])->Result`, `Felt::{ZERO,ONE}`.

- [ ] **Step 1 : Ajouter le membre au workspace**

Dans `Cargo.toml` (racine), ajouter `"crates/proved-hash"` à `members` :

```toml
members = ["crates/crypto", "crates/ledger", "crates/proved-hash"]
```

Et dans `[workspace.dependencies]`, ajouter :

```toml
zeroize = "1.7"
proptest = "1"
```

- [ ] **Step 2 : Créer `crates/proved-hash/Cargo.toml`**

```toml
[package]
name = "proved-hash"
version.workspace = true
edition.workspace = true
rust-version.workspace = true

[dependencies]
thiserror.workspace = true
hex.workspace = true
serde = { workspace = true }
zeroize.workspace = true

[dev-dependencies]
proptest.workspace = true
serde_json = "1"
```

- [ ] **Step 3 : Écrire le test qui échoue** — `crates/proved-hash/src/felt.rs` (module + tests)

```rust
//! Élément du corps de Goldilocks, forme canonique uniquement.
//! 3a0 : encodage/validation seulement — l'arithmétique (Rescue) arrive en 3a1.

use crate::EncodingError;

/// Modulus de Goldilocks : p = 2^64 - 2^32 + 1.
pub const P: u64 = 0xFFFF_FFFF_0000_0001;

/// Élément de corps en forme canonique : invariant `0 <= value < P`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Felt(u64);

impl Felt {
    pub const ZERO: Felt = Felt(0);
    pub const ONE: Felt = Felt(1);

    /// Construit un Felt canonique ; rejette toute valeur `>= P`.
    pub fn from_canonical_u64(x: u64) -> Result<Self, EncodingError> {
        if x < P {
            Ok(Felt(x))
        } else {
            Err(EncodingError::NonCanonicalFelt(x))
        }
    }

    /// Petite constante (tag de domaine, version) : garantie `< P` car `x < 2^32`.
    pub const fn from_small(x: u32) -> Self {
        Felt(x as u64)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }

    pub fn to_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    pub fn from_bytes(b: &[u8; 8]) -> Result<Self, EncodingError> {
        Self::from_canonical_u64(u64::from_le_bytes(*b))
    }
}

impl core::fmt::Debug for Felt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Felt({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_canonique() {
        for x in [0u64, 1, P - 1] {
            let f = Felt::from_canonical_u64(x).unwrap();
            assert_eq!(f.as_u64(), x);
            assert_eq!(Felt::from_bytes(&f.to_bytes()).unwrap(), f);
        }
    }

    #[test]
    fn rejet_non_canonique() {
        assert!(Felt::from_canonical_u64(P).is_err());
        assert!(Felt::from_canonical_u64(P + 1).is_err());
        assert!(Felt::from_canonical_u64(u64::MAX).is_err());
        // décodage de bytes non canoniques
        assert!(Felt::from_bytes(&P.to_le_bytes()).is_err());
    }
}
```

- [ ] **Step 4 : Écrire `crates/proved-hash/src/lib.rs`**

```rust
//! Représentations canoniques du domaine « hash prouvé » d'Obscura (validity-only).
//!
//! 3a0 : types + encodage + domaines, SANS Rescue ni prouveur. Voir
//! docs/superpowers/specs/2026-07-15-phase3-decision-et-3a0-design.md.

pub mod felt;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EncodingError {
    #[error("Felt non canonique (>= p) : {0}")]
    NonCanonicalFelt(u64),
    #[error("longueur invalide : attendu {expected}, reçu {got}")]
    InvalidLength { expected: usize, got: usize },
    #[error("limb hors range (>= 2^16) : {0}")]
    LimbOutOfRange(u64),
}
```

- [ ] **Step 5 : Vérifier**

Run: `& "$env:USERPROFILE\.cargo\bin\cargo.exe" test --manifest-path "C:\Users\W47\Documents\obscura\Cargo.toml" -p proved-hash`
Expected: 2 tests `felt::tests::*` PASS, compile OK.

- [ ] **Step 6 : Commit**

```bash
git add crates/proved-hash Cargo.toml
git commit --author="Walid Naili <naili.walid@gmail.com>" -m "3a0 : crate proved-hash + Felt canonique Goldilocks

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2 : `Digest` et `ShieldedSecret` (`[Felt;4]`, 32 o)

**Files:**
- Create: `crates/proved-hash/src/digest.rs`
- Modify: `crates/proved-hash/src/lib.rs` (ajouter `pub mod digest;`)

**Interfaces:**
- Consumes: `felt::Felt`, `EncodingError`.
- Produces: `digest::{Digest, ShieldedSecret, DIGEST_BYTES}`. `Digest([Felt;4])` avec `to_bytes()->[u8;32]`, `from_bytes(&[u8;32])->Result`, `to_hex()->String`. `ShieldedSecret` (mêmes conversions, `Debug` masqué, `Zeroize` + `Drop`, `as_felts()`, `from_felts([Felt;4])`).

- [ ] **Step 1 : Écrire le test qui échoue** — `crates/proved-hash/src/digest.rs`

```rust
//! Digest prouvé (4 Felts, 32 o) et secret shielded (même encodage, masqué).

use crate::felt::Felt;
use crate::EncodingError;
use zeroize::Zeroize;

pub const DIGEST_FELTS: usize = 4;
pub const DIGEST_BYTES: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest(pub [Felt; DIGEST_FELTS]);

fn felts_to_bytes(felts: &[Felt; DIGEST_FELTS]) -> [u8; DIGEST_BYTES] {
    let mut out = [0u8; DIGEST_BYTES];
    for (i, f) in felts.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&f.to_bytes());
    }
    out
}

fn felts_from_bytes(b: &[u8; DIGEST_BYTES]) -> Result<[Felt; DIGEST_FELTS], EncodingError> {
    let mut felts = [Felt::ZERO; DIGEST_FELTS];
    for (i, felt) in felts.iter_mut().enumerate() {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&b[i * 8..(i + 1) * 8]);
        *felt = Felt::from_bytes(&chunk)?;
    }
    Ok(felts)
}

impl Digest {
    pub fn to_bytes(&self) -> [u8; DIGEST_BYTES] {
        felts_to_bytes(&self.0)
    }
    pub fn from_bytes(b: &[u8; DIGEST_BYTES]) -> Result<Self, EncodingError> {
        Ok(Digest(felts_from_bytes(b)?))
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

impl core::fmt::Debug for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Digest({})", self.to_hex())
    }
}

/// Secret racine shielded : même encodage qu'un Digest, mais JAMAIS affiché ni logué.
#[derive(Clone, PartialEq, Eq)]
pub struct ShieldedSecret([Felt; DIGEST_FELTS]);

impl ShieldedSecret {
    pub fn from_felts(felts: [Felt; DIGEST_FELTS]) -> Self {
        ShieldedSecret(felts)
    }
    pub fn as_felts(&self) -> &[Felt; DIGEST_FELTS] {
        &self.0
    }
    pub fn to_bytes(&self) -> [u8; DIGEST_BYTES] {
        felts_to_bytes(&self.0)
    }
    pub fn from_bytes(b: &[u8; DIGEST_BYTES]) -> Result<Self, EncodingError> {
        Ok(ShieldedSecret(felts_from_bytes(b)?))
    }
}

// Debug masqué : ne jamais révéler le secret dans les logs.
impl core::fmt::Debug for ShieldedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ShieldedSecret(<redacted>)")
    }
}

// Effacement best-effort à la libération.
impl Zeroize for ShieldedSecret {
    fn zeroize(&mut self) {
        for felt in self.0.iter_mut() {
            *felt = Felt::ZERO;
        }
    }
}
impl Drop for ShieldedSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn felt(x: u64) -> Felt {
        Felt::from_canonical_u64(x).unwrap()
    }

    #[test]
    fn digest_roundtrip() {
        let d = Digest([felt(0), felt(1), felt(crate::felt::P - 1), felt(42)]);
        assert_eq!(Digest::from_bytes(&d.to_bytes()).unwrap(), d);
        assert_eq!(d.to_hex().len(), 64);
    }

    #[test]
    fn digest_rejette_felt_non_canonique() {
        let mut bytes = [0u8; DIGEST_BYTES];
        bytes[8..16].copy_from_slice(&crate::felt::P.to_le_bytes()); // 2e felt = p
        assert!(Digest::from_bytes(&bytes).is_err());
    }

    #[test]
    fn shielded_secret_roundtrip_et_masque() {
        let s = ShieldedSecret::from_felts([felt(7), felt(8), felt(9), felt(10)]);
        assert_eq!(ShieldedSecret::from_bytes(&s.to_bytes()).unwrap(), s);
        // Debug ne fuit rien.
        assert_eq!(format!("{:?}", s), "ShieldedSecret(<redacted>)");
    }

    #[test]
    fn shielded_secret_rejette_non_canonique() {
        let mut bytes = [0u8; DIGEST_BYTES];
        bytes[0..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(ShieldedSecret::from_bytes(&bytes).is_err());
    }
}
```

- [ ] **Step 2 : Déclarer le module** — dans `lib.rs`, après `pub mod felt;` ajouter `pub mod digest;`

- [ ] **Step 3 : Vérifier**

Run: `& "$env:USERPROFILE\.cargo\bin\cargo.exe" test --manifest-path "C:\Users\W47\Documents\obscura\Cargo.toml" -p proved-hash digest::`
Expected: 4 tests `digest::tests::*` PASS.

- [ ] **Step 4 : Commit**

```bash
git add crates/proved-hash/src
git commit --author="Walid Naili <naili.walid@gmail.com>" -m "3a0 : Digest et ShieldedSecret (32 o, secret masqué + zeroize)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3 : `AmountLimbs` (`[u16;4]`, range 16 bits)

**Files:**
- Create: `crates/proved-hash/src/amount.rs`
- Modify: `crates/proved-hash/src/lib.rs` (`pub mod amount;`)

**Interfaces:**
- Produces: `amount::{AmountLimbs, LIMB_BITS, LIMB_MAX}` avec `from_u64(u64)->Self`, `to_u64()->u64`, `limbs()->&[u16;4]`, `to_felts()->[Felt;4]`, `try_from_felts(&[Felt;4])->Result`.

- [ ] **Step 1 : Écrire le test qui échoue** — `crates/proved-hash/src/amount.rs`

```rust
//! Montant u64 décomposé en 4 limbs de 16 bits (little-endian, low-to-high).
//! Interdit le mapping naïf u64 -> Felt pour les contraintes de range/équilibre.

use crate::felt::Felt;
use crate::EncodingError;

pub const AMOUNT_LIMBS: usize = 4;
pub const LIMB_BITS: u32 = 16;
pub const LIMB_MAX: u64 = (1 << LIMB_BITS) - 1; // 65535

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AmountLimbs([u16; AMOUNT_LIMBS]);

impl AmountLimbs {
    pub fn from_u64(x: u64) -> Self {
        AmountLimbs([
            (x & 0xFFFF) as u16,
            ((x >> 16) & 0xFFFF) as u16,
            ((x >> 32) & 0xFFFF) as u16,
            ((x >> 48) & 0xFFFF) as u16,
        ])
    }

    pub fn to_u64(&self) -> u64 {
        let l = &self.0;
        (l[0] as u64)
            | ((l[1] as u64) << 16)
            | ((l[2] as u64) << 32)
            | ((l[3] as u64) << 48)
    }

    pub fn limbs(&self) -> &[u16; AMOUNT_LIMBS] {
        &self.0
    }

    /// Représentation circuit : 4 Felts chacun `< 2^16`.
    pub fn to_felts(&self) -> [Felt; AMOUNT_LIMBS] {
        self.0.map(|l| Felt::from_small(l as u32))
    }

    /// Reconstruit depuis des Felts, en rejetant tout limb `>= 2^16`.
    pub fn try_from_felts(felts: &[Felt; AMOUNT_LIMBS]) -> Result<Self, EncodingError> {
        let mut limbs = [0u16; AMOUNT_LIMBS];
        for (i, f) in felts.iter().enumerate() {
            let v = f.as_u64();
            if v > LIMB_MAX {
                return Err(EncodingError::LimbOutOfRange(v));
            }
            limbs[i] = v as u16;
        }
        Ok(AmountLimbs(limbs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_u64() {
        for x in [0u64, 1, (LIMB_MAX), LIMB_MAX + 1, u64::MAX] {
            assert_eq!(AmountLimbs::from_u64(x).to_u64(), x);
        }
    }

    #[test]
    fn to_felts_puis_try_from_felts() {
        let a = AmountLimbs::from_u64(0x1234_5678_9ABC_DEF0);
        assert_eq!(AmountLimbs::try_from_felts(&a.to_felts()).unwrap(), a);
    }

    #[test]
    fn rejet_limb_hors_range() {
        let felts = [Felt::from_small(0), Felt::from_canonical_u64(LIMB_MAX + 1).unwrap(), Felt::ZERO, Felt::ZERO];
        assert!(matches!(
            AmountLimbs::try_from_felts(&felts),
            Err(EncodingError::LimbOutOfRange(_))
        ));
    }
}
```

- [ ] **Step 2 : Déclarer le module** — `pub mod amount;` dans `lib.rs`.

- [ ] **Step 3 : Vérifier**

Run: `& "$env:USERPROFILE\.cargo\bin\cargo.exe" test --manifest-path "C:\Users\W47\Documents\obscura\Cargo.toml" -p proved-hash amount::`
Expected: 3 tests PASS.

- [ ] **Step 4 : Commit**

```bash
git add crates/proved-hash/src
git commit --author="Walid Naili <naili.walid@gmail.com>" -m "3a0 : AmountLimbs (u64 en 4 limbs de 16 bits)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4 : `Domain` + préambule sponge

**Files:**
- Create: `crates/proved-hash/src/domain.rs`
- Modify: `crates/proved-hash/src/lib.rs` (`pub mod domain;`)

**Interfaces:**
- Produces: `domain::{Domain, ENCODING_VERSION, RESERVED_TAG, sponge_preamble}`. `Domain` enum (`Owner=1..Nullifier=6`) avec `tag()->u32`, `tag_felt()->Felt`. `sponge_preamble(Domain, &[Felt]) -> Vec<Felt>`.

- [ ] **Step 1 : Écrire le test qui échoue** — `crates/proved-hash/src/domain.rs`

```rust
//! Séparation de domaine des hachages prouvés : tags Felt distincts + préambule
//! versionné. L'alignement PAD_ZERO* sur le rate du sponge est fixé en 3a1 ;
//! 3a0 fige la séquence logique se terminant par PAD_ONE.

use crate::felt::Felt;

pub const ENCODING_VERSION: u32 = 1;
/// Tag 0 : réservé, JAMAIS utilisé pour hasher.
pub const RESERVED_TAG: u32 = 0;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Domain {
    Owner = 1,
    Nk = 2,
    NoteCommitment = 3,
    MerkleLeaf = 4,
    MerkleNode = 5,
    Nullifier = 6,
}

impl Domain {
    pub fn tag(self) -> u32 {
        self as u32
    }
    pub fn tag_felt(self) -> Felt {
        Felt::from_small(self as u32)
    }
    /// Tous les domaines (pour tests de distinction).
    pub const ALL: [Domain; 6] = [
        Domain::Owner,
        Domain::Nk,
        Domain::NoteCommitment,
        Domain::MerkleLeaf,
        Domain::MerkleNode,
        Domain::Nullifier,
    ];
}

/// Préambule logique v1 : `[VERSION, DOMAIN_TAG, LEN_FIELDS, payload..., PAD_ONE]`.
pub fn sponge_preamble(domain: Domain, payload: &[Felt]) -> Vec<Felt> {
    let mut v = Vec::with_capacity(payload.len() + 4);
    v.push(Felt::from_small(ENCODING_VERSION));
    v.push(domain.tag_felt());
    v.push(Felt::from_small(payload.len() as u32));
    v.extend_from_slice(payload);
    v.push(Felt::ONE); // PAD_ONE ; PAD_ZERO* jusqu'au rate = 3a1
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_distincts_et_non_nuls() {
        let tags: Vec<u32> = Domain::ALL.iter().map(|d| d.tag()).collect();
        assert_eq!(tags, vec![1, 2, 3, 4, 5, 6]); // vecteur figé
        assert!(tags.iter().all(|&t| t != RESERVED_TAG));
        // unicité
        let mut sorted = tags.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), tags.len());
    }

    #[test]
    fn preambules_distincts_par_domaine() {
        let payload = [Felt::from_small(99)];
        let mut seen = std::collections::HashSet::new();
        for d in Domain::ALL {
            let pre: Vec<u64> = sponge_preamble(d, &payload).iter().map(|f| f.as_u64()).collect();
            assert!(seen.insert(pre), "préambule dupliqué pour {:?}", d);
        }
    }

    #[test]
    fn preambule_structure_figee() {
        let pre = sponge_preamble(Domain::Owner, &[Felt::from_small(7), Felt::from_small(8)]);
        let got: Vec<u64> = pre.iter().map(|f| f.as_u64()).collect();
        // [VERSION=1, tag Owner=1, LEN=2, 7, 8, PAD_ONE=1]
        assert_eq!(got, vec![1, 1, 2, 7, 8, 1]);
    }
}
```

- [ ] **Step 2 : Déclarer le module** — `pub mod domain;` dans `lib.rs`.

- [ ] **Step 3 : Vérifier**

Run: `& "$env:USERPROFILE\.cargo\bin\cargo.exe" test --manifest-path "C:\Users\W47\Documents\obscura\Cargo.toml" -p proved-hash domain::`
Expected: 3 tests PASS.

- [ ] **Step 4 : Commit**

```bash
git add crates/proved-hash/src
git commit --author="Walid Naili <naili.walid@gmail.com>" -m "3a0 : Domain (tags Felt) + préambule sponge versionné

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5 : `serde` canonique + golden vectors JSON + proptest

**Files:**
- Modify: `crates/proved-hash/src/digest.rs` (impl serde canonique pour `Digest`)
- Create: `crates/proved-hash/vectors/encoding_v1.json`
- Create: `crates/proved-hash/tests/golden.rs`

**Interfaces:**
- Consumes: `Digest`, `AmountLimbs`, `Domain`, `sponge_preamble`.
- Produces: `Digest` sérialise en **chaîne hex canonique** (serde) ; fichier de vecteurs lisible cross-langage.

- [ ] **Step 1 : serde canonique pour `Digest`** — ajouter à `digest.rs` (après l'impl Debug de Digest)

```rust
impl serde::Serialize for Digest {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // Forme canonique : chaîne hex de 64 caractères (pas de tableau d'entiers ambigu).
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for Digest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let hexs = <String as serde::Deserialize>::deserialize(d)?;
        let bytes = hex::decode(&hexs).map_err(serde::de::Error::custom)?;
        let arr: [u8; DIGEST_BYTES] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom("longueur digest != 32"))?;
        Digest::from_bytes(&arr).map_err(serde::de::Error::custom)
    }
}
```

- [ ] **Step 2 : Créer les golden vectors** — `crates/proved-hash/vectors/encoding_v1.json`

```json
{
  "encoding_version": 1,
  "goldilocks_p": "18446744069414584321",
  "felt": [
    { "value": 0, "le_bytes_hex": "0000000000000000" },
    { "value": 1, "le_bytes_hex": "0100000000000000" },
    { "value": 18446744069414584320, "le_bytes_hex": "00000000ffffffff" }
  ],
  "digest": [
    {
      "felts": [0, 1, 18446744069414584320, 42],
      "bytes_hex": "0000000000000000010000000000000000000000ffffffff2a00000000000000"
    }
  ],
  "amount_limbs": [
    { "u64": 0, "limbs": [0, 0, 0, 0] },
    { "u64": 65536, "limbs": [0, 1, 0, 0] },
    { "u64": 18446744073709551615, "limbs": [65535, 65535, 65535, 65535] }
  ],
  "domain_tags": {
    "Owner": 1, "Nk": 2, "NoteCommitment": 3, "MerkleLeaf": 4, "MerkleNode": 5, "Nullifier": 6
  },
  "preambles": [
    { "domain": "Owner", "payload": [7, 8], "fields": [1, 1, 2, 7, 8, 1] }
  ]
}
```

- [ ] **Step 3 : Écrire le test golden** — `crates/proved-hash/tests/golden.rs`

```rust
//! Vérifie que l'implémentation reproduit les golden vectors (cross-langage).

use proved_hash::amount::AmountLimbs;
use proved_hash::digest::Digest;
use proved_hash::domain::{sponge_preamble, Domain};
use proved_hash::felt::Felt;

const VECTORS: &str = include_str!("../vectors/encoding_v1.json");

#[test]
fn digest_bytes_correspondent() {
    let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let d0 = &v["digest"][0];
    let felts: Vec<Felt> = d0["felts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| Felt::from_canonical_u64(x.as_u64().unwrap()).unwrap())
        .collect();
    let digest = Digest([felts[0], felts[1], felts[2], felts[3]]);
    assert_eq!(digest.to_hex(), d0["bytes_hex"].as_str().unwrap());
    // serde round-trip canonique (hex string)
    let json = serde_json::to_string(&digest).unwrap();
    assert_eq!(serde_json::from_str::<Digest>(&json).unwrap(), digest);
}

#[test]
fn amount_limbs_correspondent() {
    let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    for a in v["amount_limbs"].as_array().unwrap() {
        let x = a["u64"].as_u64().unwrap();
        let expected: Vec<u16> = a["limbs"].as_array().unwrap().iter().map(|l| l.as_u64().unwrap() as u16).collect();
        assert_eq!(AmountLimbs::from_u64(x).limbs().to_vec(), expected);
    }
}

#[test]
fn preambules_correspondent() {
    let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let p = &v["preambles"][0];
    let payload: Vec<Felt> = p["payload"].as_array().unwrap().iter().map(|x| Felt::from_small(x.as_u64().unwrap() as u32)).collect();
    let got: Vec<u64> = sponge_preamble(Domain::Owner, &payload).iter().map(|f| f.as_u64()).collect();
    let expected: Vec<u64> = p["fields"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap()).collect();
    assert_eq!(got, expected);
}
```

- [ ] **Step 4 : proptest round-trips** — ajouter à `amount.rs` (dans `mod tests`)

```rust
    proptest::proptest! {
        #[test]
        fn prop_amount_roundtrip(x in any::<u64>()) {
            proptest::prop_assert_eq!(AmountLimbs::from_u64(x).to_u64(), x);
        }
    }
```

Et en tête du `mod tests` d'`amount.rs`, ajouter `use proptest::prelude::*;`.

- [ ] **Step 5 : Vérifier**

Run: `$env:RUSTFLAGS="-D warnings"; & "$env:USERPROFILE\.cargo\bin\cargo.exe" test --manifest-path "C:\Users\W47\Documents\obscura\Cargo.toml"; Remove-Item Env:RUSTFLAGS`
Expected: tous verts (29 existants + les nouveaux de proved-hash), **0 warning**.

- [ ] **Step 6 : Commit**

```bash
git add crates/proved-hash
git commit --author="Walid Naili <naili.walid@gmail.com>" -m "3a0 : serde canonique (hex), golden vectors JSON, proptest

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6 : Docs — Security Claims (validity-only) + gate ZK

**Files:**
- Modify: `docs/THREAT_MODEL.md` (section « Security Claims / Phase 3 validity-only »)
- Modify: `docs/STARK_STATEMENT.md` (note validity-only)
- Modify: `README.md` (mention validity-only)

**Interfaces:** aucune (documentation).

- [ ] **Step 1 : `docs/THREAT_MODEL.md`** — ajouter en fin de fichier

```markdown
## Security Claims — Phase 3 (validity-only)

Le circuit de la Phase 3 est **validity-only** : il garantit l'**intégrité**
(pas de forge, pas de double dépense, équilibre des montants, cohérence
Merkle/nullifier) mais **PAS la confidentialité**. Tant que la couche
zero-knowledge (jalon séparé « Phase 3z » : masquage trace + DEEP + permutations,
audité) n'est pas livrée :

- une preuve ne cache PAS forcément le témoin (montants, owner, secret) ;
- aucune preuve ne doit être présentée comme `zk` / `private` / `shielded production` ;
- types nommés `ValidityProof` / `ValidityCircuit` ; `ZkProof` réservé à une preuve
  witness-hiding auditée.

Voir `docs/superpowers/specs/2026-07-15-phase3-decision-et-3a0-design.md`.
```

- [ ] **Step 2 : `docs/STARK_STATEMENT.md`** — ajouter juste après le titre H1 (ligne 1)

```markdown

> **Phase 3 = validity-only.** L'implémentation initiale du circuit prouve
> l'INTÉGRITÉ (P1–P7), pas la confidentialité : un STARK n'est pas zero-knowledge
> par défaut. Le witness-hiding est un jalon séparé et gaté (« Phase 3z »). Voir
> `docs/superpowers/specs/2026-07-15-phase3-decision-et-3a0-design.md`.
```

- [ ] **Step 3 : `README.md`** — sous la ligne du titre, ajouter une phrase

Repérer la ligne `**Prototype pédagogique — pas d'audit, ne pas utiliser en production.**` et insérer juste avant :

```markdown
> Phase 3 (en cours) : circuit **validity-only** — intégrité prouvée, confidentialité
> (zero-knowledge) NON encore livrée (jalon gaté « Phase 3z »).

```

- [ ] **Step 4 : Vérifier build inchangé**

Run: `& "$env:USERPROFILE\.cargo\bin\cargo.exe" test --manifest-path "C:\Users\W47\Documents\obscura\Cargo.toml"`
Expected: tous verts (docs n'affectent pas le code).

- [ ] **Step 5 : Commit**

```bash
git add docs README.md
git commit --author="Walid Naili <naili.walid@gmail.com>" -m "3a0 : docs Security Claims (validity-only) + gate ZK Phase 3z

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage :** Felt/Digest/ShieldedSecret/AmountLimbs/Domain/préambule (§7-9) → Tasks 1-4. Rejet strict, pas de modulo (§8) → tests de rejet Tasks 1-3. serde canonique (§13.4) + golden vectors (§13.2) + proptest (§11) → Task 5. Security Claims + validity-only + gate ZK (§3, §13.1, §13.5) → Task 6. Secrets (Debug masqué/zeroize, §8.3) → Task 2. Non-goals (§10) respectés (ni Rescue, ni AIR, ni migration ledger). ✓

**Placeholder scan :** aucun TBD ; tout le code est complet. MSRV reste `1.75` (workspace) tant que le prouveur n'entre pas — cohérent avec §7 (« à fixer en 3a1 »). ✓

**Type consistency :** `Felt`/`Digest`/`ShieldedSecret`/`AmountLimbs`/`Domain` et leurs signatures identiques entre Tasks et golden test. `DIGEST_BYTES=32`, `AMOUNT_LIMBS=4`, tags 1-6 cohérents partout. ✓
