# 3a2b — P2 en circuit : `owner = H_owner(shielded_secret)`

- Date : 2026-07-15
- Statut : design acté, implémentation à lancer
- Portée : AIR prouvant **P2** (le vrai), en empilant le sponge de `Rp64_256::hash_elements` par-dessus l'AIR de permutation de 3a2. Différentiel contre `rescue::hash` de 3a1.

## 1. Le sponge de `hash_elements` (pinné depuis la source winter-crypto 0.13.1)

```
state = [0; 12]
state[CAPACITY.start] = len(elements)      // la LONGUEUR est injectée dans la capacité
for element in elements:                    // absorb additif
    state[RATE.start + i] += element ; i += 1
    if i % RATE_WIDTH == 0 { apply_permutation(state) ; i = 0 }
if i > 0 { apply_permutation(state) }       // sinon rien
digest = state[DIGEST_RANGE]
```

Plages : `CAPACITY = 0..4`, `RATE = 4..12` (`RATE_WIDTH = 8`), `DIGEST = 4..8`.

**Point clé** : il n'y a **aucun padding**. Winter injecte la longueur dans la capacité à la place (« adding zero elements at the end always results in a different hash »).

## 2. Conséquence : P2 = UNE seule permutation

`sponge_preamble(Owner, secret)` (3a0, inchangé) = `[VERSION, tag, LEN, s0, s1, s2, s3, PAD_ONE]` = **8 éléments = exactement 1 bloc de rate**.

Donc : capacité ← 8, absorb des 8 éléments, `i` atteint 8 → **une** permutation → `i = 0` → pas de permutation supplémentaire.

État initial (ligne 0 de la trace) :

| idx | valeur | nature |
|---|---|---|
| 0 | `8` (len) | constante publique |
| 1..3 | `0` | constante publique |
| 4 | `1` (ENCODING_VERSION) | constante publique |
| 5 | `1` (tag `Domain::Owner`) | constante publique |
| 6 | `4` (LEN payload) | constante publique |
| 7..10 | `s0..s3` | **TÉMOIN (secret)** |
| 11 | `1` (PAD_ONE) | constante publique |

Après 7 rondes : `owner = état[4..8]`.

## 3. Statement

```
Entrée PUBLIQUE : owner (4 Felts = Digest)
Témoin PRIVÉ    : shielded_secret (4 Felts)   ← JAMAIS dans les assertions publiques
La preuve établit : owner = H_owner(shielded_secret)   (P2)
```

**Vrai P2, contrairement au skeleton 3a2** : `owner` n'expose que 4 des 12 éléments de sortie → la fonction n'est pas inversible, la connaissance du préimage est un énoncé non trivial.

## 4. L'AIR

- **Contraintes de transition : réutilisées telles quelles depuis 3a2** (meet-in-the-middle, degré `ALPHA=7`, `new(7)` sans `with_cycles`). Rien à réinventer.
- **Trace** : 8 lignes × 12 colonnes (identique).
- **Assertions** (12 au total) :
  - ligne 0, idx `0..4` : capacité `[8, 0, 0, 0]` ;
  - ligne 0, idx `4, 5, 6, 11` : `VERSION=1`, `tag=1`, `LEN=4`, `PAD_ONE=1` ;
  - ligne 7, idx `4..8` : `owner` (public) ;
  - **ligne 0, idx `7..11` (le secret) : NON assertée.**
- **ProofOptions** : identiques à 3a2 — `FieldExtension::Quadratic` **obligatoire** (Goldilocks 64 bits : sans extension, sécurité conjecturée = 63 bits et `verify` refuse).

## 5. API

```
pub fn prove_owner(secret: &ShieldedSecret) -> (Digest /*owner*/, ValidityProof)
pub fn verify_owner(owner: &Digest, proof: &ValidityProof) -> bool
```

`ValidityProof` réutilisé (validity-only, **PAS** witness-hiding).

## 6. Validation — le différentiel du vrai P2

- **Différentiel natif ⟷ circuit** : `prove_owner(s).owner == proved_hash::rescue::hash(Domain::Owner, s.as_felts())` (le hash hors-circuit de 3a1). C'est **le** test qui prouve que le circuit calcule bien le même P2 que le ledger.
- **Roundtrip** : `verify_owner(owner, proof)` == vrai.
- **Négatif** : altérer `owner` → `verify` échoue. (⚠️ vérifier que ce test n'est pas un faux positif : il doit échouer pour la bonne raison, pas parce que `verify` renvoie toujours `false` — le roundtrip vert garantit ce point.)
- **Secret distinct → owner distinct**.

## 7. Périmètre — ce que 3a2b NE fait PAS

- Pas de payload de longueur ≠ 4 (multi-bloc / `i > 0` final) : la généralisation du sponge à une entrée arbitraire viendra avec les gadgets qui en ont besoin (`nk`, nullifier, commitment — 3b1/3b4).
- Pas de câblage ledger (`keys.rs` reste BLAKE3 ; migration = 3b).
- **Pas de zero-knowledge** (validity-only, gate Phase 3z).

## 8. Critères d'acceptation

- `prove_owner`/`verify_owner` fonctionnels ;
- **différentiel vs `rescue::hash` vert** ;
- négatif + secret-distinct verts ; roundtrip vert (écarte le faux positif) ;
- secret absent des assertions (revue du code + `get_assertions` ne référence que des constantes publiques et `owner`) ;
- 54 tests existants verts, `-D warnings` propre.

## 9. Risques

| Risque | Mitigation |
|---|---|
| Mauvaise réplication du sponge (capacité/len/ordre) | Différentiel vs `rescue::hash` de 3a1 — impitoyable |
| Secret fuité via une assertion | Revue explicite de `get_assertions` ; seules constantes publiques + owner |
| Faux positif du test négatif | Exiger le roundtrip vert dans le même test-suite |
| Généralisation multi-bloc supposée | Hors périmètre, documenté (§7) |

## 10. Références

- `crates/proved-hash/src/rescue.rs` (hash hors-circuit, 3a1) ; `crates/circuit/src/rescue_perm.rs` (AIR, 3a2).
- Spec amont : `docs/superpowers/specs/2026-07-15-phase3-decision-et-3a0-design.md`.
