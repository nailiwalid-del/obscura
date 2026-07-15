# 3a1 — Rescue-Prime prouvé partagé (wrapper `Rp64_256`)

- Date : 2026-07-15
- Statut : design acté, implémentation à lancer
- Portée : fournir le hash prouvé Rescue-Prime hors-circuit dans `crates/proved-hash`, en wrappant la primitive auditée `winter-crypto::Rp64_256`, avec séparation de domaine et vecteurs figés. **Ne câble PAS le ledger** (migration = 3b).

## 1. Décision de sourcing

Le hash prouvé hors-circuit **wrappe `Rp64_256::hash_elements`** (implémentation auditée de winterfell). On n'implémente **pas** la permutation Rescue-Prime à la main en 3a1 : ce hand-roll est réservé à l'**AIR de 3a2**, où reproduire la permutation est inévitable et où le cross-test « notre permutation ⟷ winter » prend tout son sens.

Conséquence assumée : puisqu'on wrappe winter hors-circuit, un cross-test « nous ⟷ winter » serait tautologique. Pour éviter ça (cf. spec 3a0 § 13.7, tests différentiels en 3a1), la validation de 3a1 combine **trois** ancrages : (1) **vecteurs de hash figés** (stabilité de notre wrapper) ; (2) **ancrage externe** — au moins un vecteur de la permutation/hash `Rp64_256` **publié par winterfell** (ses propres vecteurs de test), reproduit par notre chemin, pour ne pas être auto-référentiel ; (3) round-trip de conversion `Felt ↔ BaseElement`. Le différentiel **natif ⟷ circuit** (la vraie seconde implémentation) reste un livrable de **3a2**.

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

- `hash` : construit l'entrée = **`domain::sponge_preamble(domain, payload)`** (le préambule 3a0 **inchangé**, `PAD_ONE` inclus), convertit chaque `Felt` en `BaseElement`, appelle `Rp64_256::hash_elements`, puis convertit les 4 `BaseElement` du digest en `Digest([Felt;4])`.
- `merge` : `hash(domain, a.felts ‖ b.felts)` (8 Felts) — sert les nœuds de Merkle avec séparation de domaine (pas le `merge` 2→1 nu de winter, qui n'a pas de domaine).

Le padding/rate du sponge (`PAD_ZERO*`) est **réalisé en interne par `Rp64_256`** — on ne l'ajoute pas nous-mêmes. Notre séparation de domaine = le **préambule injectif** de 3a0 (`version ‖ tag ‖ len ‖ payload ‖ PAD_ONE`), fourni comme données d'entrée à `hash_elements`.

## 5. Réconciliation avec 3a0 (contrat § 9 respecté, non modifié)

3a1 **ne modifie pas** le contrat 3a0. Le préambule `sponge_preamble` (avec `PAD_ONE`) reste tel quel et devient l'**entrée** fournie à `Rp64_256::hash_elements`. Le seul point que 3a0 laissait ouvert (« `PAD_ZERO*` à aligner sur le rate en 3a1 ») est résolu ainsi : **le rate-padding est interne à `Rp64_256`**, donc on n'ajoute aucun `PAD_ZERO` nous-mêmes.

- `domain::sponge_preamble` : **inchangé** (signature et sortie identiques à 3a0).
- Golden vector du préambule : **inchangé** `[1, 1, 2, 7, 8, 1]`.
- **Ajout** (nouveau) des vecteurs de hash dans `vectors/encoding_v1.json` (section `rescue_hash`) : pour un `(domain, payload)` fixe, le `Digest` hex attendu.

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
- **ancrage externe (§ 13.7)** : au moins un vecteur `Rp64_256` **issu des vecteurs de test publiés par winterfell** (entrée → digest attendu) est reproduit par notre chemin — garantit qu'on n'est pas seulement cohérent avec nous-mêmes. Si aucun vecteur publié n'est directement exploitable, documenter le fait et le compléter en 3a2 par le différentiel natif ⟷ circuit ;
- `sponge_preamble` **inchangé** vs 3a0 (golden vector `[1,1,2,7,8,1]` toujours vert) ;
- les 45 tests existants restent verts.

Qualité :

- vecteurs de hash ajoutés au fichier golden cross-langage ;
- note : 3a1 = primitive hors-circuit uniquement ; l'égalité in-circuit ⟷ hors-circuit est prouvée en 3a2.

## 8. Références

- Voir `docs/superpowers/specs/2026-07-15-phase3-decision-et-3a0-design.md` (§ Rescue-Prime, hash prouvé).
- winterfell / winter-crypto : https://github.com/facebook/winterfell
