# Hiérarchie shielded_secret — Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ramener l'identité shielded d'un wallet à un secret racine de 32 o (`shielded_secret`) dont dérivent `owner` et `nk`, débloquant P2/P3/P4 du circuit STARK (fix d'audit #2).

**Architecture:** `WalletKeys` gagne un champ privé `shielded_secret`. Deux fonctions de **hash prouvé** `owner_from_secret` / `nk_from_secret` (BLAKE3 domain-séparé aujourd'hui, Rescue-Prime avec le circuit en phase 3) remplacent `owner = H(spend.public)` et le `nk` aléatoire indépendant. La signature hybride reste une enveloppe d'intention, pas une autorisation d'ownership.

**Tech Stack:** Rust (workspace 2 crates), `crypto::hash::blake3_domain`, `rand_core::OsRng`. Toolchain stable-msvc, rustc 1.97.

## Global Constraints

- Spec de référence : `docs/superpowers/specs/2026-07-14-hierarchie-shielded-secret-design.md`.
- Commentaires et docs **en français** (convention du repo).
- `cargo` n'est pas dans le PATH persistant → l'invoquer via `& "$env:USERPROFILE\.cargo\bin\cargo.exe" test --manifest-path "C:\Users\W47\Documents\obscura\Cargo.toml"` (PowerShell). Compilateur C (MSVC Build Tools 2026) requis par pqcrypto, déjà présent.
- `owner_from_secret` / `nk_from_secret` sont du **hash prouvé** : chaque fonction porte le commentaire de migration Rescue-Prime (« migre AVEC le circuit, jamais avant »), identique à `merkle.rs`. Ne JAMAIS les présenter comme des KDF wallet figés en BLAKE3.
- Domaines de hash : `"obscura/owner/v2"` et `"obscura/nk/v2"`.
- Non-régression : les 26 tests existants doivent rester verts, 0 warning.
- Commits : terminer chaque message par `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`, auteur `Walid Naili <naili.walid@gmail.com>`.

---

### Task 1: Hiérarchie `shielded_secret` dans `keys.rs` + retrait du hash mort

**Files:**
- Modify: `crates/ledger/src/keys.rs` (intégralement réécrit)
- Modify: `crates/crypto/src/sig.rs` (retrait de `SigPublicKey::hash`)
- Test: `crates/ledger/src/keys.rs` (module `#[cfg(test)]` ajouté)

**Interfaces:**
- Produces:
  - `keys::owner_from_secret(&[u8; 32]) -> [u8; 32]`
  - `keys::nk_from_secret(&[u8; 32]) -> [u8; 32]`
  - `WalletKeys { pub spend, pub receive, shielded_secret (privé), pub nk }`, `WalletKeys::generate() -> Self`, `WalletKeys::address(&self) -> Address`
- Consumes : `crypto::hash::blake3_domain`, `crypto::sig::SigKeypair`, `crypto::kem::{KemKeypair, KemPublicKey}`.
- Supprime : `crypto::sig::SigPublicKey::hash` (n'était consommé que par `keys::address`).

- [ ] **Step 1: Écrire les tests qui échouent** — remplacer tout le contenu de `crates/ledger/src/keys.rs` par la version finale (fonctions + tests inclus)

```rust
//! Clés d'un wallet : identité shielded (secret racine), signature (enveloppe
//! d'intention), réception (KEM hybride), nullifier.

use crypto::hash;
use crypto::kem::{KemKeypair, KemPublicKey};
use crypto::sig::SigKeypair;
use rand_core::{OsRng, RngCore};

pub struct WalletKeys {
    /// Signature hybride : enveloppe d'intention / anti-malléabilité sur
    /// `tx_digest`. PAS une autorisation d'ownership tant qu'elle n'est pas liée
    /// au `shielded_secret` (décision de circuit, phase 3).
    pub spend: SigKeypair,
    /// KEM hybride : réception et scan des notes.
    pub receive: KemKeypair,
    /// Secret racine de l'identité shielded (32 o), JAMAIS publié : témoin du
    /// circuit STARK. `owner` et `nk` en dérivent (P2/P4).
    shielded_secret: [u8; 32],
    /// Clé de nullifier, dérivée du secret shielded (P4). Nécessaire au calcul
    /// des nullifiers ; ne doit pas être partagée.
    pub nk: [u8; 32],
}

/// Adresse publique : (identité de la note, clé publique KEM).
/// Communiquée hors-chaîne au payeur, jamais publiée on-chain.
#[derive(Clone)]
pub struct Address {
    pub owner: [u8; 32],
    pub kem_pk: KemPublicKey,
}

/// Identité de la note à partir du secret shielded (P2 : `owner = H(secret)`).
///
/// HASH PROUVÉ (domaine consensus-en-circuit) : cette relation sera vérifiée par
/// le STARK. Elle MIGRERA vers Rescue-Prime EN MÊME TEMPS que le circuit — jamais
/// avant (même règle que merkle.rs / note.rs). BLAKE3 ici = échafaudage de dev,
/// PAS un KDF wallet figé.
pub fn owner_from_secret(shielded_secret: &[u8; 32]) -> [u8; 32] {
    hash::blake3_domain("obscura/owner/v2", shielded_secret)
}

/// Clé de nullifier à partir du secret shielded (P4 : `nk` lié à l'autorité).
///
/// HASH PROUVÉ : voir `owner_from_secret`. Migre vers Rescue-Prime avec le circuit.
pub fn nk_from_secret(shielded_secret: &[u8; 32]) -> [u8; 32] {
    hash::blake3_domain("obscura/nk/v2", shielded_secret)
}

impl WalletKeys {
    pub fn generate() -> Self {
        let mut shielded_secret = [0u8; 32];
        OsRng.fill_bytes(&mut shielded_secret);
        WalletKeys {
            spend: SigKeypair::generate(),
            receive: KemKeypair::generate(),
            nk: nk_from_secret(&shielded_secret),
            shielded_secret,
        }
    }

    pub fn address(&self) -> Address {
        Address {
            owner: owner_from_secret(&self.shielded_secret),
            kem_pk: self.receive.public.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_et_nk_derivent_du_secret_shielded() {
        let w = WalletKeys::generate();
        // P4 : nk est une fonction (prouvable) du secret racine.
        assert_eq!(w.nk, nk_from_secret(&w.shielded_secret));
        // P2 : owner = H(secret).
        assert_eq!(w.address().owner, owner_from_secret(&w.shielded_secret));
        // owner et nk sont deux dérivations distinctes (domaines séparés).
        assert_ne!(w.address().owner, w.nk);
    }

    #[test]
    fn deux_wallets_ont_des_identites_distinctes() {
        let a = WalletKeys::generate();
        let b = WalletKeys::generate();
        assert_ne!(a.shielded_secret, b.shielded_secret);
        assert_ne!(a.nk, b.nk);
        assert_ne!(a.address().owner, b.address().owner);
    }
}
```

- [ ] **Step 2: Vérifier l'échec de compilation** — à ce stade `sig.rs` a encore `SigPublicKey::hash` (inutilisé → warning), mais surtout il faut confirmer que le nouveau `keys.rs` compile seul avant de toucher sig.rs

Run: `& "$env:USERPROFILE\.cargo\bin\cargo.exe" test --manifest-path "C:\Users\W47\Documents\obscura\Cargo.toml" -p ledger keys::`
Expected: compile OK, 2 tests `keys::tests::*` PASS. (Le code étant à la fois test et implémentation, ils passent directement — le « rouge » ici serait un échec de compilation ; on valide donc que c'est vert.)

- [ ] **Step 3: Retirer le hash mort de `sig.rs`** — supprimer la méthode devenue sans usage

Dans `crates/crypto/src/sig.rs`, à l'intérieur de `impl SigPublicKey`, supprimer entièrement :

```rust
    /// Hash de l'adresse : identifie le propriétaire d'une note sans publier la clé.
    pub fn hash(&self) -> [u8; 32] {
        crate::hash::blake3_domain("obscura/addr/ed25519+dilithium3-round3/v2", &self.to_bytes())
    }
```

(Laisser `to_bytes` et `from_bytes` en place.)

- [ ] **Step 4: Lancer toute la suite + vérifier 0 warning**

Run: `& "$env:USERPROFILE\.cargo\bin\cargo.exe" test --manifest-path "C:\Users\W47\Documents\obscura\Cargo.toml"`
Expected: `test result: ok` partout, total **28 tests** (26 + 2 nouveaux), et **aucun** `warning:` dans la sortie de compilation.

- [ ] **Step 5: Commit**

```bash
git add crates/ledger/src/keys.rs crates/crypto/src/sig.rs
git commit -m "Fix audit #2 : identité shielded (shielded_secret -> owner, nk)

owner = H_owner(shielded_secret), nk = H_nk(shielded_secret) : deux hachages
prouvés (Rescue-Prime avec le circuit) d'un secret racine 32 o, au lieu de
owner = H(spend_pk) et d'un nk aléatoire indépendant. Débloque P2/P3/P4.
Retrait de SigPublicKey::hash (usage unique = ancien owner). +2 tests.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Mise à jour de la documentation

**Files:**
- Modify: `docs/PROTOCOL.md` (table des clés)
- Modify: `docs/STARK_STATEMENT.md` (ligne « hash prouvé » + note d'implémentation)
- Modify: `CLAUDE.md` (décisions v0.2)

**Interfaces:** aucune (documentation).

- [ ] **Step 1: `docs/PROTOCOL.md` — remplacer la table des clés et la ligne d'adresse**

Remplacer ce bloc :

```markdown
| Clé | Construction | Rôle |
|---|---|---|
| Autorisation de dépense `ak` | hybride Ed25519 + Dilithium3 | prouver l'autorité (en ZK, jamais publiée) |
| Réception/vue | hybride X25519 + Kyber768 | déchiffrer les notes reçues |
| Nullifier `nk` | dérivée de la graine, liée à `ak` (P4) | calculer les nullifiers |

Adresse = (hash clé d'autorisation, clé publique KEM). Jamais publiée on-chain.
```

par :

```markdown
| Clé | Construction | Rôle |
|---|---|---|
| Secret shielded `shielded_secret` | aléa 32 o, jamais publié | racine de l'identité ; témoin du circuit (P2/P4) |
| Réception/vue | hybride X25519 + Kyber768 | déchiffrer les notes reçues |
| Nullifier `nk` | `nk = H_nk(shielded_secret)` (**hash prouvé**) | calculer les nullifiers, liée à l'autorité (P4) |
| Signature `spend` | hybride Ed25519 + Dilithium3 | enveloppe d'intention / anti-malléabilité sur `tx_digest` (PAS autorisation d'ownership tant que non liée au secret — phase 3) |

Adresse = (`owner = H_owner(shielded_secret)`, clé publique KEM). Jamais publiée on-chain.
`owner` et `nk` sont des **hachages prouvés** (domaine Rescue-Prime, migration avec le circuit).
```

- [ ] **Step 2: `docs/STARK_STATEMENT.md` — étendre la ligne « hash prouvé »**

Remplacer :

```markdown
| **Hash prouvé** | commitments de notes, arbre de Merkle, PRF nullifier | **Rescue-Prime** (circuit-friendly, disponible dans winterfell) |
```

par :

```markdown
| **Hash prouvé** | commitments de notes, arbre de Merkle, `owner = H(secret)` et `nk = H(secret)`, PRF nullifier | **Rescue-Prime** (circuit-friendly, disponible dans winterfell) |
```

- [ ] **Step 3: `docs/STARK_STATEMENT.md` — corriger la note d'implémentation sur l'adresse**

Remplacer la phrase :

```markdown
Le **hash d'adresse** (`owner = H(ak)`,
`sig.rs::hash`) est BLAKE3-256 en mode transparent ; le binding `owner ↔ ak` devient
Rescue-Prime dans le circuit (P2).
```

par :

```markdown
Le **hash d'identité** (`owner = H_owner(shielded_secret)`, `keys.rs`) et la
**dérivation de `nk`** (`nk = H_nk(shielded_secret)`) relèvent du **hash prouvé**
(Rescue-Prime, migration avec le circuit), PAS d'un KDF wallet — voir la ligne
« hash prouvé » ci-dessus. BLAKE3 domain-séparé n'y est qu'un échafaudage de dev.
```

- [ ] **Step 4: `CLAUDE.md` — ajouter la décision v0.2**

Sous la section « Décisions v0.2 (revue intégrée — ne pas régresser) », ajouter après la ligne du nullifier (`- Nullifier lié au commitment : ...`) :

```markdown
- Identité shielded : secret racine `shielded_secret` (32 o, jamais publié, témoin
  STARK) ; `owner = H_owner(secret)` et `nk = H_nk(secret)` sont des hachages
  PROUVÉS (Rescue-Prime avec le circuit), pas des KDF wallet. La signature hybride
  `spend` = enveloppe d'intention / anti-malléabilité, PAS autorisation d'ownership
  tant qu'elle n'est pas liée au secret (phase 3). Voir la spec
  `docs/superpowers/specs/2026-07-14-hierarchie-shielded-secret-design.md`.
```

- [ ] **Step 5: Vérifier la cohérence build (docs n'affectent pas le code, sanity)**

Run: `& "$env:USERPROFILE\.cargo\bin\cargo.exe" test --manifest-path "C:\Users\W47\Documents\obscura\Cargo.toml"`
Expected: 28 tests verts, 0 warning (inchangé par rapport à la Task 1).

- [ ] **Step 6: Commit**

```bash
git add docs/PROTOCOL.md docs/STARK_STATEMENT.md CLAUDE.md
git commit -m "Docs : hiérarchie shielded_secret (owner/nk = hash prouvé)

Table des clés PROTOCOL, ligne hash prouvé + note STARK_STATEMENT, décision
v0.2 CLAUDE. Aligne les docs sur le fix #2.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage :**
- Modèle `shielded_secret → owner, nk` → Task 1 (keys.rs). ✓
- `owner`/`nk` = hash prouvé, commentaire migration → Task 1 Step 1 + Task 2 Steps 2-3. ✓
- Naming `shielded_secret` → Task 1. ✓
- Signature = enveloppe d'intention → Task 1 (commentaire) + Task 2 Step 1/4. ✓
- Retrait `SigPublicKey::hash` → Task 1 Step 3. ✓
- `note.rs`/`tx.rs`/`state.rs` inchangés → aucun task ne les touche. ✓
- Backup différé / racine sans `sk` → décisions de périmètre, rien à implémenter. ✓
- Tests binding + unicité + non-régression → Task 1 Steps 1-4. ✓

**Placeholder scan :** aucun TBD/TODO ; tout le code et toutes les commandes sont explicites. ✓

**Type consistency :** `owner_from_secret`/`nk_from_secret` (signatures `&[u8;32] -> [u8;32]`) définies en Task 1 et référencées de façon identique dans les tests et les docs. Champ `shielded_secret` cohérent partout. ✓
