# Design — Hiérarchie de clés shielded (`shielded_secret → owner, nk`)

- **Date** : 2026-07-14
- **Origine** : correctif d'audit #2 (« `nk` indépendant de l'autorité de dépense »), prérequis structurel de la phase 3 (circuit STARK).
- **Statut** : proposé, revue utilisateur intégrée (4 corrections).

## Problème

Aujourd'hui `WalletKeys` pose :

- `owner = H(spend.public)` — hash de la clé **publique** de signature hybride (Ed25519 + Dilithium3, ~2 Ko) ;
- `nk` = aléa **totalement indépendant**, dérivé d'une graine locale jetée.

Conséquences pour le circuit (`docs/STARK_STATEMENT.md`) :

- **P4** (« `nk` correctement liée à `ak` ») est **inconstructible** : `nk` n'a aucun lien avec l'autorité de dépense.
- **P2** (« `owner = H(ak)` ») prouvé en circuit exigerait de hacher ~2 Ko de clé publique hybride en Rescue-Prime → **prohibitif**.

## Objectif

Ramener l'identité *shielded* à un **secret court (32 o)**, témoin du STARK, dont dérivent `owner` et `nk` par des relations **circuit-friendly**, afin que P2/P3/P4 se prouvent en quelques appels de hash arithmétique au lieu de hacher de grosses clés publiques.

## Modèle (aligné Orchard)

```
shielded_secret : [u8; 32]          // secret racine, JAMAIS publié, témoin STARK
owner = H_owner_v2(shielded_secret)      // P2 : identité de la note
nk    = H_nk_v2(shielded_secret)         // clé de nullifier, liée à l'autorité (P4)
nf    = PRF_nf_v2(nk, rho ‖ cm)          // P3 : nullifier (note.rs, INCHANGÉ)
```

Référence : [Orchard nullifiers](https://zcash.github.io/orchard/design/nullifiers.html) — le nullifier dépend déterministiquement de données engagées par la note (`rho`, `cm`) et d'une clé `nk` liée à l'autorité de dépense.

### Point critique : `H_owner_v2` / `H_nk_v2` / `PRF_nf_v2` sont du **hash prouvé**

Ces trois fonctions définissent des **relations que le STARK doit vérifier**. Elles appartiennent donc au domaine **« hash prouvé »** du statement — la même catégorie que les commitments de notes et l'arbre de Merkle — et **migreront vers Rescue-Prime EN MÊME TEMPS que le circuit (phase 3), jamais avant** (règle déjà en vigueur pour `merkle.rs` et `note.rs`).

En v0.2, faute de Rescue-Prime (arrive avec `winterfell` en phase 3), elles sont implémentées en **BLAKE3 domain-séparé comme échafaudage de développement**. Ce ne sont **PAS** des KDF wallet hors-consensus : la relation `nk = H_nk(secret)` sera vérifiée dans le circuit, donc elle **ne doit jamais être figée en BLAKE3**. Le code porte le commentaire de migration explicite, identique à celui de `merkle.rs`.

## Décisions de nommage et de périmètre (revue intégrée)

1. **`shielded_secret`, pas `ak`.** Dans le vocabulaire Zcash/Orchard, `ak` désigne une clé de **validation publique** dérivée d'un secret ; ici l'objet est un secret 32 o **jamais publié**. `shielded_secret` évite la confusion en phase 3.

2. **La signature hybride externe = enveloppe d'intention / anti-malléabilité, PAS autorisation d'ownership.** La paire `spend` (Ed25519 + Dilithium) signe `tx_digest`. Tant qu'elle n'est pas liée cryptographiquement au `shielded_secret`, elle ne prouve **pas** que le propriétaire de la note a autorisé la dépense — elle scelle l'intention et interdit la malléabilité de la transaction. Le lien autorisation ↔ témoin (signature randomisée liée à `shielded_secret` façon *spendAuthSig* d'Orchard, **ou** autorisation purement in-circuit par connaissance de `shielded_secret`) est une **décision de design du circuit, différée en phase 3**. On ne qualifie donc pas cette signature de « défense en profondeur de l'ownership » avant ce lien.

3. **Backup wallet depuis une graine unique = objectif de FORMAT wallet, pas hypothèse crypto immédiate.** Les `KeyGen` publics de ML-KEM / ML-DSA ([FIPS 203](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf), [FIPS 204](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf)) génèrent leur aléa en interne. On ne suppose **aucune** keygen PQ re-dérivable d'une graine. En v0.2 les paires `spend` et `receive` restent générées indépendamment ; l'unification éventuelle d'un backup complet est un travail de format, hors de ce correctif.

4. **`shielded_secret` est la racine, pas de graine `sk` au-dessus.** YAGNI : pour P2/P3/P4, `shielded_secret → {owner, nk}` suffit.

## Changements de code

- **`crates/ledger/src/keys.rs`** :
  - `WalletKeys` gagne un champ **privé** `shielded_secret: [u8; 32]` (secret racine).
  - `generate()` tire `shielded_secret` aléatoirement, puis dérive `nk = nk_from_secret(&shielded_secret)`.
  - `address().owner = owner_from_secret(&shielded_secret)` (remplace `spend.public.hash()`).
  - Deux fonctions `owner_from_secret` / `nk_from_secret` (BLAKE3 domain-séparé « obscura/owner/v2 » et « obscura/nk/v2 »), **commentaire de migration Rescue-Prime** obligatoire.
- **`crates/crypto/src/sig.rs`** : retrait de `SigPublicKey::hash()` (seul usage = ancien `owner = H(spend_pk)`, désormais mort).
- **Inchangés** : `note.rs` (`nf = PRF_nf(nk, rho‖cm)`), `tx.rs` (`build`/`scan` via `wallet.nk` et `addr.owner`), `state.rs`.

## Docs à mettre à jour

- `docs/PROTOCOL.md` : table des clés (`nk` = fonction prouvée de `shielded_secret`, plus « aléa lié à la graine ») + note « Hiérarchie de clés shielded ».
- `docs/STARK_STATEMENT.md` : classer `owner` et la dérivation de `nk` sous le domaine **« hash prouvé »** (Rescue-Prime), aux côtés des commitments/Merkle/PRF nullifier.
- `CLAUDE.md` : ajouter la décision v0.2 (shielded_secret racine, owner/nk = hash prouvé).

## Tests

- **`keys.rs`** (nouveaux) :
  - `nk == nk_from_secret(shielded_secret)` et `owner == owner_from_secret(shielded_secret)` — binding structurel P2/P4.
  - deux wallets → `shielded_secret`, `nk`, `owner` distincts (unicité).
- **Non-régression** : les 26 tests actuels doivent rester verts (`owner` passe de `H(spend_pk)` à `H_owner(shielded_secret)`, mais reste un `[u8; 32]` cohérent entre `mint` et `scan`).
- Validation par `cargo test` avant commit.

## Ce que ça débloque

Phase 3 : le circuit prouvera `owner = H_owner(s)`, `nk = H_nk(s)`, `nf = PRF_nf(nk, rho‖cm)` pour un témoin `s` de 32 o — quelques hash Rescue-Prime — au lieu de hacher ~2 Ko de clé publique hybride. P2/P3/P4 deviennent réalistes.

## Références

- Orchard nullifiers — https://zcash.github.io/orchard/design/nullifiers.html
- FIPS 203 (ML-KEM) — https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf
- FIPS 204 (ML-DSA) — https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf
