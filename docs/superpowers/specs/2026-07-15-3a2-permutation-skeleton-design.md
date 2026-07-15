# 3a2 — Validity skeleton : AIR de la permutation Rp64_256

- Date : 2026-07-15
- Statut : design acté (Option A — skeleton permutation), implémentation à lancer
- Portée : premier AIR winterfell + prove/verify de bout en bout, sur **une permutation Rp64_256**, validé contre le vecteur de référence Sage. **Pas encore** le hash sponge complet `owner = H_owner(secret)` (= 3a2b).

## 1. Décision de découpage (Option A)

3a2 prouve **la permutation**, pas le hash complet. Raison : le vrai risque/inconnu est « sait-on écrire un AIR qui reproduit la permutation Rp64_256 et matche la sortie de winter ? ». Une fois acquis, le sponge (init capacité, padding, squeeze) par-dessus est mécanique → **3a2b**.

Étiquetage honnête : `Validity*` (pas `Zk*`), **non-privé** (winterfell n'est pas ZK), et « skeleton permutation, pas encore P2 complet ».

## 2. La permutation à reproduire (source winter-crypto 0.13.1)

`Rp64_256` expose **en public** tout le nécessaire :

- `STATE_WIDTH = 12`, `NUM_ROUNDS = 7`, `ALPHA = 7` ;
- `MDS`, `INV_MDS`, `ARK1`, `ARK2` (`pub const`, `[[BaseElement; 12]; ...]`) ;
- `apply_permutation`, `apply_round` (`pub fn`), `RATE_RANGE`, `CAPACITY_RANGE`, `DIGEST_RANGE`.

Une ronde (`apply_round`) = **Rescue-XLIX** :
1. S-box `x⁷` (composante par composante) → `MDS` → `+ ARK1[round]` ;
2. inverse S-box `x^(1/7)` → `MDS` → `+ ARK2[round]`.

L'AIR **référence directement** ces constantes (pas d'extraction fragile). Le vecteur de test Sage (déjà utilisé en 3a1, `apply_permutation([0..11])`) est le **garde-fou de correction**.

## 3. Statement (skeleton)

```
Entrée PUBLIQUE : P  (état de sortie, 12 Felts)
Témoin PRIVÉ    : S  (état d'entrée, 12 Felts)  ← JAMAIS dans les assertions publiques
La preuve établit : apply_permutation(S) = P
```

Note : une permutation est bijective, donc « connaître un préimage » est trivial ici — c'est **assumé** : le but du skeleton est de valider la chaîne AIR/prouveur/vérifieur + Rescue-en-circuit, pas la dureté du statement. La non-inversibilité (capacité, troncature) arrive avec le sponge en 3a2b.

## 4. L'AIR

- **Patron** : l'exemple `rescue` de winterfell (même construction : colonnes périodiques pour les ARK, contraintes de degré 7, gestion de l'inverse S-box par relation forward `y⁷ = x`).
- **Trace** : `NUM_ROUNDS + 1 = 8` lignes (puissance de 2 requise) × `STATE_WIDTH = 12` colonnes (+ colonnes auxiliaires si l'inverse S-box en exige). Ligne 0 = `S`, ligne 7 = `P`.
- **Contraintes de transition** : `row[i+1] = apply_round(row[i], i)` reproduit avec `MDS`/`ARK1`/`ARK2` de Rp64_256 ; ARK1/ARK2 en **colonnes périodiques** (une valeur par ronde).
- **Assertions** : ligne 7 == `P` (public). **Ligne 0 (S) N'EST PAS assertée** (témoin libre) — respecte « secret hors des assertions ».
- **Hash du protocole STARK** : `Rp64_256` (ou Blake3) comme fonction de commitment FRI (indépendant de la permutation prouvée).

## 5. API du crate `circuit`

Nouveau crate `crates/circuit` (dépend de `winterfell` — prouveur+vérifieur —, `winter-crypto`, `proved-hash`).

```
pub fn prove_permutation(input: [Felt; 12]) -> (/*output*/ [Felt; 12], ValidityProof)
pub fn verify_permutation(output: [Felt; 12], proof: &ValidityProof) -> bool
```

`ValidityProof` = wrapper du `winterfell::Proof` (nom `Validity*` imposé par la règle de nommage ; ce n'est PAS witness-hiding).

## 6. Validation (le différentiel natif ⟷ circuit, enfin concret)

- **Roundtrip** : `prove_permutation([0..11])` → `output` ; `verify_permutation(output, proof)` == vrai.
- **Ancrage Sage** : `output == ` vecteur Sage de 3a1 (= `winter::apply_permutation([0..11])`). C'est **la** vérification que notre AIR calcule bien la même permutation qu'une seconde implémentation indépendante.
- **Négatif** : altérer `output` (public) → `verify` échoue.
- **Cohérence** : `output == Rp64_256::apply_permutation(input)` pour quelques entrées aléatoires (via une graine fixe passée en dur, pas de RNG).

## 7. Périmètre — ce que 3a2 NE fait PAS

- Pas de sponge (init capacité, padding rate, squeeze) → 3a2b.
- Pas de `owner = H_owner(secret)` complet → 3a2b (sponge par-dessus cet AIR).
- Pas de câblage ledger, pas de format tx.
- **Pas de zero-knowledge** (documenté ; validity-only).

## 8. Critères d'acceptation

- crate `circuit` compile ; dépend de `winterfell`/`winter-crypto`/`proved-hash`.
- AIR reproduit `apply_round` avec les constantes publiques de Rp64_256 ; degrés déclarés corrects (pas d'erreur de degré en debug).
- `prove_permutation`/`verify_permutation` fonctionnent (roundtrip vert).
- **différentiel Sage vert** ; test négatif vert.
- les 51 tests existants restent verts ; `-D warnings` propre.

## 9. Risques

| Risque | Mitigation |
|---|---|
| Contraintes de l'inverse S-box (degré/relation) mal posées | Suivre l'exemple `rescue` de winterfell ; le différentiel Sage attrape toute divergence |
| Mauvais degré de contrainte déclaré | Tester en debug (winterfell panique sur mismatch de degré) |
| Confusion validité/ZK | Nommage `Validity*` ; doc « non-privé » ; pas de RNG masquant supposé |
| Trace non puissance de 2 | 8 lignes (2³) |

## 10. Références

- Rescue-Prime (algorithme 3) : https://eprint.iacr.org/2020/1143.pdf
- winterfell (Air/Prover/verify, exemple `rescue`) : https://github.com/facebook/winterfell
- Spec amont : `docs/superpowers/specs/2026-07-15-phase3-decision-et-3a0-design.md`
