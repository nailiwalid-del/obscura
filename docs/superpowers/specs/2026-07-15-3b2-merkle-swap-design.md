# 3b2 — P1 en circuit : chemin de Merkle (swap conditionnel)

- Date : 2026-07-15
- Statut : **partie 1 livrée** (référence hors-circuit `proved_hash::merkle`) ; **partie 2 (AIR de swap) conçue, à implémenter**.
- Portée : prouver P1 (« `cm` appartient à l'arbre de racine `root` ») en circuit. Découpé : (a) référence hors-circuit + gadget 1 niveau ; (b) déroulé profondeur 32.

## 1. Référence hors-circuit (FAIT)

`crates/proved-hash/src/merkle.rs` : `leaf(cm) = hash(MerkleLeaf, cm)`, `node(l,r) = merge(MerkleNode, l, r)`, `root(cm, path, index)` en remontant `path` selon les bits de `index`. Convention alignée sur `ledger::merkle::verify_path` (`bit 0 → (cur, sib)`). C'est **le juge** du différentiel du circuit. 4 tests verts.

## 2. Le pattern de swap (source : exemple `merkle` de winterfell)

Chaque niveau = un `node = merge(MerkleNode, gauche, droite)` (sponge B=2, réutilisé de 3b1). Le NOUVEAU = choisir `(gauche, droite)` selon le bit :

```
(gauche, droite) = bit == 0 ? (courant, frère) : (frère, courant)
```

Winterfell l'impose au **step d'init du hash** via des contraintes de transition gardées par un flag :

```
init_flag * ( (1 - bit) * (input_gauche - courant)  )   // bit=0 : courant à gauche
init_flag *   bit       * (input_droite - courant)      // bit=1 : courant à droite
```

+ contrainte **booléenne** `bit·(bit − 1) = 0` (degré 2, `TransitionConstraintDegree::new(2)`).

## 3. Adaptation à notre sponge Rp64_256 (à implémenter)

Notre `merge(l, r)` = sponge B=2 (16 lignes, 20 colonnes). Le préambule est
`[VER, tag, LEN=8, l0..l3, r0..r3, PAD_ONE]` (12 éléments), donc :

- `l0..l3` → état ligne 0, colonnes 7..10 ; `r0` → colonne 11 ;
- `r1..r3, PAD_ONE` → colonnes d'inject, ligne 7 (absorption).

Le swap `(l, r) = swap(courant, frère, bit)` est donc **réparti sur la ligne 0 (l0..l3, r0) et la ligne 7 (r1..r3)**. Deux flags d'init périodiques (position 0 et position 7 du bloc, cycle 16) portent les contraintes de swap.

**Colonnes ajoutées** (au-delà des 20 du sponge) : `bit` (1) + `courant` (4) + `frère` (4) = 9 → largeur 29. `bit`/`courant`/`frère` maintenus constants par bloc (contraintes de copie), `bit` booléen.

**Contrainte de swap** (par composante `i`), active au flag d'init :
```
gauche_i = (1 - bit)·courant_i + bit·frère_i
droite_i = (1 - bit)·frère_i  + bit·courant_i
```
imposée en liant `gauche_i`/`droite_i` aux positions d'état/inject correspondantes.

## 4. Découpage (partie 2)

- **3b2a — gadget 1 niveau** : profondeur 1 (feuille → 1 nœud) avec swap in-circuit + bit booléen. Différentiel vs `merkle::root(cm, [sib], bit)`. De-risque le swap sur 16 lignes.
- **3b2b — chemin profondeur 32** : même AIR déroulé sur 32 niveaux + la **feuille** (B=1) en tête + chaînage (sortie niveau k = `courant` du niveau k+1). Trace ≈ `next_pow2(8 + 32·16)`. Différentiel vs `merkle::root` complet. **Livre P1.**

## 5. Statement (3b2b, cible)

```
Entrée PUBLIQUE : root
Témoin PRIVÉ    : cm (commitment), path[32] (frères), index (32 bits)
La preuve établit : root = merkle_root(cm, path, index)   (P1)
```

Note : à ce stade `cm`, `path`, `index` sont témoins libres (P1 seul). Leur liaison au reste (la note engagée, les nullifiers) vient avec le circuit complet 3b5.

## 6. Validation

- Différentiel : `root` en circuit == `proved_hash::merkle::root(...)` (le juge).
- Booléen : un bit non-binaire → preuve impossible (contrainte degré 2).
- Négatif : `root` altérée → `verify` échoue (avec roundtrip vert, écarte le faux positif).
- Bits : deux `index` différents sur le même `cm`/`path` → racines différentes (le swap agit).

## 7. Risques

| Risque | Mitigation |
|---|---|
| Swap réparti ligne 0 / ligne 7 mal câblé | Différentiel vs `merkle::root` (impitoyable) ; commencer par 3b2a (1 niveau) |
| Degré du bit / du swap | `new(2)` pour le bit ; le reste suit `with_cycles` (masques multiplicatifs, cf. 3b1) ; winterfell panique en debug si faux |
| Chaînage inter-niveaux (3b2b) | Contrainte de copie sortie→`courant` ; tester d'abord profondeur 1 puis 2 puis 32 |
| Taille (32 niveaux ≈ 1024 lignes) | Perf OK (winterfell scale à 2^20) ; c'est le câblage le risque, pas la taille |

## 7bis. Mur des degrés winterfell — chaînage multi-bloc (tentative 3b2b, 2026-07-15)

Tentative d'AIR de chaînage (D merges, `leaf` public, colonnes `cur`/`sib`/`bit` par
bloc, sponge gaté par un flag `chain` aux frontières). La **trace calcule la bonne
racine** (== `merkle::fold`), mais l'AIR bute sur la vérification de degrés de
winterfell :

1. **Degrés dépendants de l'entrée** : `bit`/`cur`/`sib` deviennent CONSTANTS pour
   certains index (ex. index=0 → tous bits nuls) → degré mesuré 0 ; pour d'autres,
   > 0. Le `debug_assert` d'égalité déclaré==mesuré échoue selon l'input.
2. **Degrés croissant avec L** de façon non triviale : swap mesuré 15 à L=16, **61**
   à L=32 ; sponge 104 → 245. Une déclaration `(base, cycles)` correcte pour TOUTE
   profondeur reste à trouver.
3. **Gate `(1 - chain)`** sur le sponge monte le degré → blowup 8 insuffisant
   (blowup 16+ requis).

Pistes pour la reprise :
- soit **restructurer** pour des degrés input-indépendants (éviter les colonnes
  témoins qui peuvent devenir constantes ; p.ex. injecter `sib` via colonnes
  toujours « génériques », ou suivre exactement le layout de l'exemple `merkle` de
  winterfell qui n'a pas ce souci) ;
- soit **déclarer des bornes supérieures** `with_cycles` correctes (calibrées sur le
  cas non dégénéré, index à bits variés) et **tester en `--release`** (le
  `debug_assert` de degré est alors ignoré ; seule la borne `déclaré ≥ mesuré`
  compte pour la soundness) ;
- valider d'abord D=2 (un seul chaînage) avant le déroulé profondeur 32.

La logique de chaînage (sortie bloc k = `cur` bloc k+1 ; sponge désactivé aux
frontières ; swap réparti ligne 0/7 par bloc) est **conçue et correcte au niveau
trace** ; seul le contrat de degrés winterfell reste à établir.

## 8. Références

- Exemple `merkle` de winterfell (swap au hash-init, bit booléen) : https://github.com/facebook/winterfell/tree/main/examples/src/merkle
- `crates/proved-hash/src/merkle.rs` (référence, FAIT) ; `crates/circuit/src/sponge.rs` (merge B=2, 3b1).
- `ledger::merkle::verify_path` (convention de bit).
