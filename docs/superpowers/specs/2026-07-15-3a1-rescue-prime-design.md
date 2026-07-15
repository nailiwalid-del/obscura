# 3a1 — Rescue-Prime prouvé partagé (wrapper `Rp64_256`)

- Date : 2026-07-15
- Statut : design acté, implémentation à lancer
- Portée : fournir le hash prouvé Rescue-Prime hors-circuit dans `crates/proved-hash`, en wrappant la primitive auditée `winter-crypto::Rp64_256`, avec séparation de domaine et vecteurs figés. **Ne câble PAS le ledger** (migration = 3b).

## 1. Décision de sourcing

Le hash prouvé hors-circuit **wrappe `Rp64_256::hash_elements`** (implémentation auditée de winterfell). On n'implémente **pas** la permutation Rescue-Prime à la main en 3a1 : ce hand-roll est réservé à l'**AIR de 3a2**, où reproduire la permutation est inévitable et où le cross-test « notre permutation ⟷ winter » prend tout son sens.

Conséquence assumée : le « cross-test Rp64_256 » de 3a1 est quasi tautologique (on EST winter hors-circuit). La validation de 3a1 repose donc sur des **vecteurs de hash figés** (stabilité) et le round-trip de conversion. La vérification par seconde implémentation est un livrable de **3a2**.

## 2. Dépendances

Ajouter à `crates/proved-hash` :

- `winter-crypto` (hashers, dont `Rp64_256`, traits `Hasher`/`ElementHasher`) ;
- `winter-math` (corps `f64::BaseElement` = Goldilocks).

Ces crates sont la couche **crypto** de winterfell, **pas le prouveur** (`winter-prover`) → conforme à « `proved-hash` sans dépendance au prouveur ». La version exacte est épinglée à l'implémentation (dernière stable compatible), et **`rust-version` (MSRV) du workspace est bumpée** à celle exigée par `winter-crypto`.

## 3. Conversion `Felt ↔ BaseElement`

Notre `Felt` (u64 canonique `< p`, cf. 3a0) et le `BaseElement` de winter-math sont tous deux Goldilocks.

- `Felt -> BaseElement` : `BaseElement::new(felt.as_u64())` — exact, aucune réduction (déjà `< p`).
- `BaseElement -> Felt` : `Felt::from_canonical_u64(be.as_int())` — `as_int()` renvoie la forme canonique.

Test : round-trip `Felt -> BaseElement -> Felt` sur `0, 1, p-1`.

## 4. API du module `rescue`

```
pub fn hash(domain: Domain, payload: &[Felt]) -> Digest
pub fn merge(domain: Domain, a: &Digest, b: &Digest) -> Digest
```

- `hash` : construit l'entrée **domaine-préfixée** `[VERSION, tag, LEN, payload...]` (en `BaseElement`), appelle `Rp64_256::hash_elements`, convertit les 4 `BaseElement` du digest en `Digest([Felt;4])`.
- `merge` : `hash(domain, a.felts ‖ b.felts)` (8 Felts) — sert les nœuds de Merkle avec séparation de domaine (pas le `merge` 2→1 nu de winter, qui n'a pas de domaine).

Le padding/rate du sponge est **interne à `Rp64_256`** ; notre séparation de domaine = **préfixe injectif** `version ‖ tag ‖ len ‖ payload`.

## 5. Réconciliation avec 3a0

3a0 avait défini un préambule provisoire se terminant par `PAD_ONE`, avec `PAD_ZERO*` « à aligner sur le rate en 3a1 ». En Option A, le padding est interne à winter → **on retire le `PAD_ONE`** du préfixe de domaine. Changements :

- `domain::sponge_preamble` : renommé/ajusté en `domain_prefix(domain, &[Felt]) -> Vec<Felt>` = `[VERSION, tag, LEN, payload...]` (sans PAD_ONE).
- Golden vector du préambule mis à jour : `[1, 1, 2, 7, 8]` (au lieu de `[..., 1]`).
- **Ajout des vecteurs de hash** dans `vectors/encoding_v1.json` (section `rescue_hash`) : pour un `(domain, payload)` fixe, le `Digest` hex attendu.

## 6. Périmètre — ce que 3a1 NE fait PAS

- Pas de permutation Rescue-Prime maison (→ AIR 3a2).
- Pas de câblage dans `ledger` : commitments, Merkle, nullifier, owner/nk restent BLAKE3 côté `ledger` (migration Rescue = **3b**, lockstep avec le circuit, jamais avant).
- Pas d'AIR, pas de prove/verify.

## 7. Critères d'acceptation

Implémentation :

- `winter-crypto`/`winter-math` ajoutés, workspace compile, MSRV bumpée et déclarée.
- `Felt <-> BaseElement` exact (round-trip testé).
- `rescue::hash` et `rescue::merge` implémentés via `Rp64_256::hash_elements`.
- `domain_prefix` sans PAD_ONE ; golden vector préambule mis à jour.

Tests obligatoires :

- round-trip `Felt <-> BaseElement` (`0, 1, p-1`) ;
- `hash` déterministe ; deux domaines distincts sur le même payload → digests distincts ;
- `merge(d, a, b) != merge(d, b, a)` (ordre significatif) ;
- **vecteurs de hash figés** : `hash(Owner, payload_fixe)` et `merge(MerkleNode, a, b)` == valeurs hex gelées ;
- sanity : `hash` reproduit un appel direct `Rp64_256::hash_elements` sur la même entrée ;
- les 45 tests existants restent verts.

Qualité :

- vecteurs de hash ajoutés au fichier golden cross-langage ;
- note : 3a1 = primitive hors-circuit uniquement ; l'égalité in-circuit ⟷ hors-circuit est prouvée en 3a2.

## 8. Références

- Voir `docs/superpowers/specs/2026-07-15-phase3-decision-et-3a0-design.md` (§ Rescue-Prime, hash prouvé).
- winterfell / winter-crypto : https://github.com/facebook/winterfell
