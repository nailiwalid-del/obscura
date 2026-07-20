# 3z-b0 — Rapport du spike de faisabilité witness-hiding

> Rapport vivant, rempli au fil des expériences E1–E5 (voir le design
> `2026-07-20-3zb0-spike-faisabilite-design.md`). Chaque section = hypothèse +
> observation **réelle** (code/source), pas supposition.

## E1 — Carte de fuite (winterfell 0.13.1) — ✅ FAIT

### Ce que la preuve révèle réellement de la trace (source vérifiée)

`winter-air-0.13.1/src/proof/mod.rs` — `struct Proof` :
- `trace_queries: Vec<Queries>` — décommitments des valeurs de trace ÉTENDUE aux
  positions requêtées. Doc de `Queries` (`queries.rs`) : « the *i*-th vector entry
  contains evaluations of **all functions** at *xᵢ* » → **chaque position de requête
  ouvre une LIGNE ENTIÈRE de la trace LDE** (les 201 colonnes évaluées en ce point du
  domaine étendu).
- `ood_frame: OodFrame` — évaluations des polynômes de trace au point **hors-domaine**
  `z` : ligne courante ET ligne suivante (`z`, `z·g`) → 2 évaluations de plus par
  colonne.
- `constraint_queries`, `fri_proof` — n'ouvrent pas directement des cellules témoins
  (composition/quotient), mais consomment le même budget de requêtes.

Nombre de requêtes : `proof_options_hi` = 32 requêtes, blowup 16 → **q ≈ 32** ouvertures
LDE + 2 OOD ≈ **34 évaluations par colonne** exposées.

### Nature de la fuite, par type de colonne du monolithe

Chaque colonne est un polynôme de degré `< n = 512` interpolant la trace sur le domaine
d'origine `H`. Les 34 évaluations exposées sont hors de `H` (points LDE + `z`), donc des
**fonctions linéaires** des 512 valeurs de la colonne.

| Colonnes | Structure | Fuite |
|---|---|---|
| **Porteuses (165..201)** : owner, nk, rho[2], cm[2], leaf[2], montants | **CONSTANTES** sur 512 lignes (`next−cur=0`) | **TOTALE, catastrophique** : un polynôme constant vaut la constante PARTOUT → **une seule ouverture de requête révèle owner/nk/rho/cm/leaf/valeur EN CLAIR**. |
| **Secret (KEY, cols 7..11 et 19..23, lignes 0..8)** | interpole 8 lignes (dont idle), bas degré | Forte : ~34 évaluations sur un polynôme de très bas degré → récupération quasi certaine du `shielded_secret`. |
| **Cellules d'éponge témoins** (value/owner/rho/r du commitment, frères de chemin, bits) | varient, degré ≤ 511 | Partielle : 34 combinaisons linéaires des 512 valeurs → pas de récupération directe mais fuite non nulle ; à masquer pour un zk réel. |

### Verdict E1

La fuite dominante est **structurelle et totale** via les **colonnes porteuses
constantes** : le mécanisme même qui rend le monolithe sound (porteuses constantes
liant les gadgets) est ce qui fuit le plus. Le witness-hiding DOIT donc :
1. **Masquer les ouvertures** de chaque colonne témoin (porteuses + secret + cellules
   d'éponge) par blinding : remplacer le polynôme de colonne `f(x)` par
   `f(x) + Z_H(x)·r(x)` où `Z_H` s'annule sur tout `H` (valeurs aux lignes réelles
   INCHANGÉES → contraintes, y compris `next−cur=0`, préservées car `Z_H` s'annule aussi
   sur les lignes consécutives) et `r(x)` aléatoire de degré `≥ 34` (couvre le nombre
   d'ouvertures). Coût de degré : `deg ≤ n + 34 ≪ blowup·n = 8192` → **budget de blinding
   largement disponible** (blowup 16).
2. **Salage des commitments** (E3) : à évaluer — nos témoins d'éponge sont haute-entropie,
   mais les **porteuses constantes basse-entropie** rendent le commitment Merkle
   potentiellement brute-forçable SI le blinding ne les couvre pas déjà. À trancher E3.

### Raffinement décisif : la borne de degré interdit le blinding polynomial

winterfell suppose que chaque polynôme de colonne a **degré `< n`** (= `trace_len`) — le
DEEP et la composition en dépendent. Le blinding `f + Z_H·r` a degré `n + deg(r) ≥ n+34`
→ il **casse cette borne** et serait rejeté par FRI/DEEP. Surcharger `new_trace_lde`
pour injecter `Z_H·r` ne marche donc PAS sur winterfell stock.

**La voie compatible winterfell = lignes de blinding** (dans le budget de degré) :
1. Réserver `b ≥ q + 2 = 34` lignes de trace comme **lignes de blinding aléatoires**.
2. **Gater TOUTES les contraintes off** sur ces lignes (y compris la constance des
   porteuses `next−cur=0`) — via sélecteurs périodiques, mécanisme déjà utilisé partout
   dans le monolithe.
3. Remplir ces `b` lignes d'aléa.
Le polynôme de chaque colonne reste **degré `< n`** (compatible winterfell) mais est
désormais déterminé par `n−b` valeurs utiles + `b` valeurs aléatoires → les ~34
ouvertures (combinaisons linéaires incluant les lignes aléatoires) sont **masquées** dès
que `b ≥` nombre d'ouvertures. Les porteuses ne sont plus constantes partout (libres sur
les lignes de blinding) → plus de fuite triviale.

**Retombées attendues (à confirmer E2–E4)** :
- **Pas de custom TraceLde ni de fork** : changement purement AIR (sélecteurs + lignes
  aléatoires), le prouveur/vérifieur winterfell restent stock → **cap vers Voie A**.
- **Soundness préservée** : les lignes de blinding ne sont référencées par aucune
  contrainte ni assertion réelle → ne peuvent pas affecter P1–P7.
- **OOD (E4) probablement couvert** : le frame OOD en `z` est aussi une combinaison
  linéaire de toutes les `n` valeurs, incluant les lignes aléatoires → masqué par le
  même aléa. E4 pourrait se replier dans E2.
- **Salage (E3) probablement inutile** : avec `b` valeurs aléatoires par colonne, chaque
  colonne est haute-entropie → commitment Merkle non brute-forçable. E3 confirme.
- **Coût** : la trace passe de 512 à `next_pow2(512 + 34) = 1024` lignes (le chemin de
  Merkle profondeur 32 occupe déjà 512) → ~2× temps/taille de preuve. Acceptable
  (prototype).

E2 teste cette approche sur un **AIR-jouet minimal** (colonne porteuse constante +
contrainte `next−cur=0` + lignes de blinding gatées) : la technique étant générique, un
succès transfère au monolithe.

## E2 — Blinding au niveau AIR — ✅ FAIT (décisif, positif)

Expérience sur AIR-jouet réel (`crates/zk-spike`, winterfell 0.13.1 stock), preuves
parsées via `Queries::parse` :

- **Baseline (fuite)** : colonne `SECRET` constante = `s`, sans blinding →
  **31/31 ouvertures de requête == `s` en clair**. Confirme E1 empiriquement (pas
  seulement l'arithmétique du polynôme constant).
- **Blindée** : trace 128 = 88 lignes utiles + **b = 40 lignes d'aléa**, contrainte
  `next−cur=0` **gatée off** sur les lignes de blinding par un sélecteur périodique →
  la preuve **vérifie toujours** (`MinConjecturedSecurity(95)`), **0/32 ouvertures ==
  `s`**, et **deux preuves du même `s` (aléa frais) ont des ouvertures disjointes**
  (masquage randomisé, pas déterministe).
- **Coût** : ~1,4× taille, ~1,6× temps — imputable au **doublement de la trace**, pas
  au masquage lui-même.

**VERDICT E2 : la technique des lignes de blinding fonctionne sur winterfell STOCK** —
pas de custom `TraceLde`, pas de fork. `b = 40 ≥ q + 2 = 34` suffit (marge 6). Réserve
capitale relevée : **chaque colonne témoin doit être blindée** — une seule colonne
constante non blindée fuirait encore `s` via son évaluation OOD `f(z)`.

## E3 — Commitments salés — ✅ FAIT (analytique, adossé à E2) : NON NÉCESSAIRE

Hypothèse E1 confirmée. Avec `b ≥ 40` valeurs aléatoires par colonne témoin (E2) :
- chaque colonne committée est **haute-entropie** → le commitment Merkle non salé
  n'est pas brute-forçable (on ne devine pas une colonne de ≥ 40 éléments Goldilocks
  uniformes depuis sa racine) ;
- la **racine** Merkle est un hachage → ne révèle rien structurellement ;
- une **ouverture** Merkle expose le chemin d'authentification (hachages frères), PAS
  les valeurs des feuilles voisines → pas de fuite (hiding sous hachage).

Donc le salage est **inutile** dès lors que les lignes de blinding sont en place. Cela
**évite un custom `TraceLde`/`ConstraintCommitment`** et **écarte le point dur** (le
vérifieur winterfell non pluggable pour des racines salées). Confiance : haute.

## E4 — Fuite OOD/DEEP — ✅ FAIT (analytique + comptage, replié dans E2) : COUVERT

Le frame OOD évalue chaque polynôme de colonne en `z` (ligne courante) et `z·g` (ligne
suivante) — 2 évaluations de plus par colonne, combinaisons linéaires de **toutes** les
`n'` valeurs de la colonne, **y compris les `b` lignes d'aléa**. Argument de comptage
par colonne : `q + 2 = 34` équations (ouvertures + OOD) `<` `b = 40` inconnues aléatoires
→ système **sous-déterminé** → les évaluations révélées sont indépendantes du témoin. Le
DEEP interroge le polynôme de composition ; les ouvertures de trace qu'il exige sont
déjà les `q` ouvertures comptées (pas d'ouverture de trace supplémentaire par colonne).
**Le même aléa masque donc l'OOD.** Confiance : haute (à re-confirmer en lisant le
DEEP-check du vérifieur lors de 3z-b1, pour garantir qu'aucune ouverture de trace
additionnelle n'existe).

## E5 — Synthèse et recommandation — ✅ FAIT

### Recommandation : **VOIE A** — witness-hiding sur winterfell stock, monolithe préservé

Les trois briques du witness-hiding se règlent **au seul niveau AIR**, sans fork ni
custom `TraceLde` :
1. **Ouvertures masquées** (E2) : lignes de blinding gatées, `b ≥ q + #OOD + marge`.
2. **OOD couvert** (E4) : par le même aléa.
3. **Salage inutile** (E3) : les colonnes blindées sont haute-entropie.

Cela **respecte le critère de décision** (préserver l'AIR monolithe) : la structure
201 colonnes / P1–P7 / liaisons / padding est **inchangée** ; on ajoute une région de
blinding et un sélecteur global « off sur blinding » multipliant chaque famille de
contraintes. Ni Voie B (fork) ni Voie C (migration) ne sont nécessaires — écartées.

### Périmètre chiffré de 3z-b1 (implémentation)

1. **Croître la trace** du monolithe à `next_pow2(utile + b)` = **1024 lignes** (512
   utiles à profondeur 32 + région de blinding).
2. **Sélecteur global `blind_off`** : 1 sur les transitions utiles, 0 sur les lignes de
   blinding ; multiplier **toutes** les familles de contraintes (rondes, éponges,
   Merkle, équilibre, porteuses, liaisons, padding) par lui.
3. **Remplir d'aléa TOUTES les colonnes témoins** sur les lignes de blinding (porteuses,
   secret, cellules d'éponge, bits, frères). Réserve E2 : **aucune** colonne témoin ne
   doit rester non blindée (fuite via `f(z)`). Les colonnes purement publiques
   (nullifiers/oc/root — déjà publiques) n'ont pas besoin d'aléa.
4. **Choisir `b`** avec marge prouvée (`b ≥ q + #points_OOD + sécurité`) et **écrire
   l'argument de zero-knowledge** (esquisse de simulateur : les `b` lignes aléatoires
   permettent de produire des ouvertures de distribution identique sans le témoin —
   argument HVZK standard, style ethSTARK « randomized trace »).
5. **Re-lire le DEEP-check du vérifieur** winterfell pour confirmer qu'aucune ouverture
   de trace additionnelle par colonne n'existe (verrouille le comptage de `b`).
6. **Re-bencher** : attendu ~2× (≈ 170 Kio / ≈ 1,3 s à profondeur 32).

### Risques / réserves transmis à 3z-b1

- L'argument ZK doit être **écrit rigoureusement** (simulateur), pas seulement « b
  lignes masquent q ouvertures » — c'est du HVZK, pas du full-ZK, et le grinding/nombre
  de requêtes doit être verrouillé (`b` suit `q`).
- Confirmer par lecture du `winter-verifier` qu'il n'y a pas d'ouverture de trace
  cachée au-delà de `q + #OOD`.
- Le crate `crates/zk-spike` est **jetable** : soit supprimé, soit conservé comme
  banc de test de non-régression du masquage. À trancher au début de 3z-b1.

### Verdict global du spike

**Faisable, voie claire, monolithe préservé.** Le witness-hiding d'Obscura ne requiert
ni fork de winterfell ni migration de stack : c'est une extension AIR (lignes de
blinding) du monolithe existant, démontrée sur code réel. 3z-b1 = implémenter cette
extension + l'argument de sécurité + re-bench.
