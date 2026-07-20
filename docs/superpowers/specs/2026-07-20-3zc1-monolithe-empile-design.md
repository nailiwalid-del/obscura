# 3z-c1 — Monolithe empilé 2-in/2-out (parité)

> Première tranche de la **Phase 3z-c** (généralisation M-in/N-out). Ce spec ne
> généralise PAS encore le nombre d'entrées/sorties : il **refond l'architecture** du
> monolithe du *côte-à-côte* (colonnes parallèles par entrée/sortie) vers des **segments
> séquentiels** de largeur uniforme, en gardant la forme **2-in/2-out** et l'API externe
> INCHANGÉES. But : **dé-risquer la refonte** sur une réponse connue (parité
> comportementale) avant d'ajouter la variabilité M/N (3z-c2). Le witness-hiding (3z-b1)
> doit être préservé.

## 1. Pourquoi cette étape

Le côte-à-côte plafonne à ~255 colonnes ; M-in/N-out force l'empilement séquentiel
(un groupe de colonnes réutilisé sur plusieurs segments de lignes). Restructurer
d'abord à forme constante, avec les tests existants comme **oracle de parité**, isole
le risque de la refonte (chaînage d'état entre segments, sélecteurs de type, équilibre
chaîné) du risque de la variabilité. Décision utilisateur : empilement VM-like, MAX
configurable (3z-c2), segments de largeur uniforme.

## 2. Ce qui reste IDENTIQUE (contrat de parité)

- **API publique** : `prove_tx`/`verify_tx`/`ProvedTx` v2, `ProvedInput`, `INTENT_DOMAIN`,
  `apply_proved_tx` — signatures et sémantique inchangées.
- **Entrées publiques** : `root`, `nullifiers[2]`, `output_commitments[2]`, `fee` ;
  `tx_digest` v2 (même domaine, même encodage). ProvedTx v2 inchangé.
- **Statement P1–P7** : mêmes propriétés prouvées, mêmes hachages (Rescue-Prime), mêmes
  liaisons owner/nk/rho/cm/leaf/montants.
- **Witness-hiding** : lignes de blinding + `blind_off` global + masquage OsRng —
  préservés (voir §5).
- **Math des gadgets** : sponge, chemin de Merkle, décomposition binaire/range,
  différentiels contre `proved_hash` — inchangés.

## 3. Ce qui CHANGE (architecture)

### 3.1 Séquence de segments (schedule)
La trace utile devient une **suite ordonnée de segments** de **largeur uniforme** mais de
**longueur variable par type** :
`[KEY]` → `[IN0]` → `[IN1]` → `[OUT0]` → `[OUT1]` → `[blinding]`. Pour 3z-c1 le **schedule
est figé** `[KEY, IN, IN, OUT, OUT]` mais construit à partir d'une **liste de types de
segments** (`SegKind::{Key, Input, Output}`) — c'est la **couture** que 3z-c2 fera varier.

**Longueur par type** (décision : variable, pour ne pas gaspiller — un KEY de 8 lignes
n'occupe pas 512) :
- `KEY_LEN = 8` (2 blocs d'éponge owner/nk) ;
- `IN_LEN(depth) = max(64, 16·depth)` (le chemin de Merkle `16·depth` domine ; 64 au
  minimum couvre la pile d'éponge 56 et les 60 bits de range) — 512 au consensus ;
- `OUT_LEN = 64` (commitment de sortie 32 + 60 bits de range → 64).

`seg_start(i)` = **somme cumulée** des longueurs des segments précédents (frontières
irrégulières). `used_rows(depth) = Σ seg_len(kind)`. `trace_len(depth) =
next_pow2(used_rows(depth) + BLIND_ROWS)`.

Note taille : à profondeur 32, `used_rows = 8 + 2·512 + 2·64 = 1160`, `trace_len = 2048`
(≈ 2× le côte-à-côte de 1024 — les 2 chemins deviennent séquentiels au lieu de partagés),
avec une largeur **÷2,2** (~92 vs 201). L'effet net sur la taille de preuve reste **à
mesurer** (§7) : la largeur domine la partie « valeurs » de chaque ouverture, donc
×0,46 de largeur peut compenser, voire battre, ×2 de longueur. Le bench tranche.

### 3.2 Segment de largeur uniforme
Largeur = celle d'un segment d'ENTRÉE (le plus large) : colonnes d'éponge
(commitment→feuille→nullifier) + colonnes de chemin de Merkle + colonnes locales
d'équilibre (bits + contribution). Un segment KEY n'utilise que les colonnes d'éponge
(2 blocs owner/nk). Un segment OUTPUT n'utilise que l'éponge (commitment de sortie) et
laisse les colonnes de Merkle **inactives** (gatées par le sélecteur de type). Un
**sélecteur de type de segment** (`is_key`/`is_input`/`is_output`, périodique par
instance) route quelles familles de contraintes s'appliquent où.

### 3.3 Chaînage d'état entre segments
- **owner / nk** : colonnes porteuses (constantes sur toute la trace), produites par le
  segment KEY, consommées par chaque segment IN. Mécanisme des porteuses inchangé
  (elles sont constantes → lisibles partout) → généralise gratuitement.
- **root** : porteuse partagée ; chaque segment IN asserte `racine calculée du chemin ==
  root` ; `root` asserté public une seule fois. (Remplace l'assertion de racine par M_i
  du côte-à-côte.)
- **équilibre** : un accumulateur `S` **chaîné à travers TOUS les segments** (au lieu de
  la région BAL séparée) : chaque segment IN ajoute `+value`, chaque segment OUT retranche
  `−value`, `S` démarre à 0 (asserté) au premier segment et vaut `fee` (asserté) à la
  dernière ligne utile. Le range-check reste embarqué par segment (décomposition binaire
  de `value`, poids remis à zéro par segment, borne `< 2^60`). C'est le changement de
  logique le plus délicat — soundness à re-vérifier (pas de wrap : ≤ 4 montants < 2^60,
  `Σ < 2^62 < p`).

### 3.4 Layout / AIR / trace
- `monolith/layout.rs` : passe d'offsets par entrée (`U0_OFF`…`O1_OFF`) à un layout de
  **segment** (offsets de colonnes DANS un segment) + un **schedule** (rangées de début
  de chaque segment). Constantes de largeur uniforme.
- `monolith/trace.rs` : `build_monolith_trace_seeded` construit segment par segment selon
  le schedule ; le remplissage aléatoire des lignes de blinding est inchangé.
- `monolith/air.rs` : sélecteurs de type de segment (par instance), familles de
  contraintes gatées par type, chaînage `S`, assertions publiques aux lignes calculées du
  schedule. `blind_off` global inchangé. Degrés **re-calibrés empiriquement** (blowup à
  re-mesurer ; procédure identique à 3z-a/3z-b1).

## 4. Découpage en unités (fichiers, responsabilités)
- `layout.rs` : géométrie d'un segment + schedule 2/2 figé (couture `SegKind`).
- `trace.rs` : constructeur segment-par-segment + chaînage `S` + blinding (inchangé).
- `air.rs` : sélecteurs de type, routage des familles, `S` chaîné, assertions au schedule.
- `tx.rs` / ledger : **inchangés** (parité — l'API v2 tient).

## 5. Witness-hiding sous la nouvelle disposition
Les lignes de blinding restent en fin de trace, gatées par `blind_off` (0 sur la région
de blinding). Toutes les colonnes témoins (porteuses, secret, cellules d'éponge, bits,
`S`) sont blindées. `BLIND_ROWS = 40 ≥ q+4` inchangé. L'argument HVZK (STARK_STATEMENT)
ne change pas dans son principe (le comptage par colonne et la taille de la région de
blinding tiennent quelle que soit la disposition des segments) ; vérifier que le
masquage (test exhaustif) reste vert sur la nouvelle disposition.

## 6. Tests (parité = oracle)
1. **Parité comportementale** : TOUS les tests existants de `tx.rs` (tx valide, matrice
   de sabotage) et du ledger (`apply_proved_tx`, double-dépense, etc.) passent SANS
   modification — l'API v2 est inchangée, ils sont l'oracle.
2. **Différentiels** : root/nf/oc == références hors-circuit (comme aujourd'hui), sous la
   trace segmentée.
3. **Soundness** : les 13 forges + le test d'inertie des lignes de blinding **rejettent/
   restent inertes** sous la nouvelle disposition (adapter les positions de forge au
   layout de segment ; la sémantique de chaque forge est conservée).
4. **Masquage** : le test exhaustif de masquage reste vert (witness-hiding préservé).
5. **Équilibre chaîné** : tests dédiés — `S` démarre à 0, chaîne correctement +/− sur les
   4 segments, `S_final == fee` ; déséquilibre rejeté ; montant `≥ 2^60` rejeté.
6. **Re-bench** (profondeur 32) : comparer à 3z-b1 (1477,7 ms / 3,0 ms / 90,5 Kio) ;
   enregistrer l'effet largeur↓/longueur↑ (peut aller dans les deux sens).

## 7. Risques transmis à la revue
- **Équilibre chaîné** (§3.3) : le passage d'une région BAL dédiée à un accumulateur
  chaîné inter-segments est la principale source d'erreur de soundness. Re-vérifier :
  début `S=0`, contributions signées par type de segment, borne `< 2^60`, `S_final=fee`.
- **Re-calibration des degrés + blowup** : les sélecteurs de type ajoutent des facteurs ;
  mesurer, bornes supérieures conservatrices.
- **Positions de forge/assertion au schedule** : les lignes de nullifier/oc/root/`S`
  bougent (dépendent du schedule) ; les assertions et forges doivent viser les bonnes
  lignes calculées, pas des littéraux hérités du côte-à-côte.
- **Couture 3z-c2** : structurer sélecteurs et schedule pour que 3z-c2 fasse varier la
  liste de segments SANS refondre à nouveau — mais NE PAS implémenter la variabilité ici
  (YAGNI, 2/2 figé).

## 8. Hors périmètre
- Variabilité M/N ≤ MAX, publics variables, `tx_digest` v3, tx/ledger v3 = **3z-c2**.
- Le crate `zk-spike` reste tel quel.
