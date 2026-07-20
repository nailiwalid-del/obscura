# 3z-b0 — Spike de faisabilité witness-hiding

> Première tranche de la **Phase 3z-b**. Ce n'est PAS une implémentation de zk : c'est
> un **spike de faisabilité borné** qui tranche, sur du code réel, la question
> « peut-on rendre le monolithe 3z-a witness-hiding sans le réécrire ? » et produit une
> recommandation **fork winterfell vs migration** chiffrée. Il alimente le spec de
> l'implémentation (3z-b1), il ne la remplace pas.

## 1. Problème

Le monolithe 3z-a est **validity-only** : le statement ne publie plus de données de
liaison (owner/nk/cm_in/rho/montants/chemins sont témoins), mais winterfell 0.13.1
n'est pas zero-knowledge — les requêtes FRI ouvrent des cellules de trace qui peuvent
révéler ces témoins. Fait confirmé (juillet 2026) : winterfell reste en 0.13.1, le zk
est « planned » seulement ; aucun prouveur STARK Rust généraliste (winterfell,
lambdaworks, Stone/SHARP) ne garantit le witness-hiding.

## 2. Critère de décision (utilisateur)

**Préserver l'AIR monolithe** est prioritaire. Le monolithe (201 colonnes, P1–P7,
liaisons par porteuses, padding asserté) est l'actif maître. Le spike privilégie donc
la voie qui le réutilise **tel quel** ; la migration n'est recommandée qu'en cas de
blocage technique dur.

## 3. Ce que le spike doit établir

Le witness-hiding d'un FRI-STARK repose sur trois briques connues :
1. **Blinding des polynômes de trace** — ajouter de l'aléa tel que toute ouverture d'au
   plus `q` cellules soit uniformément distribuée (masque les ouvertures de requêtes).
2. **Commitments Merkle salés** — pour que le commitment lui-même ne fuie pas (pertinent
   surtout pour des colonnes basse-entropie).
3. **Nombre de requêtes borné** vis-à-vis du budget de blinding.

Point d'architecture clé : winterfell rend `TraceLde` et `ConstraintCommitment`
**surchargeables** via le trait `Prover` (le monolithe implémente déjà
`new_trace_lde`/`build_constraint_commitment` avec les versions `Default*`). Une partie
du witness-hiding pourrait donc se poser en surchargeant ces traits, sans forker le
cœur. Le **vérifieur** (`winterfell::verify`) est moins pluggable — c'est le point dur
que le spike doit sonder.

## 4. Expériences (bornées, hypothèse → observation enregistrée)

### E1 — Carte de fuite (analytique, ancrée dans le code winterfell)
Énumérer ce que la preuve révèle réellement de la trace pour le monolithe :
- ouvertures aux `q=32` positions de requête FRI (colonnes de trace committées) ;
- frame OOD/DEEP (évaluation hors-domaine en `z`) ;
- ouvertures du polynôme de composition.
Pour chaque surface : quelles cellules témoins sont exposées, avec quelle probabilité.
**Sortie** : une carte de fuite qui dit *ce qui doit être masqué* — et notamment si le
salage (brique 2) est même nécessaire (nos témoins sont des éléments Goldilocks
haute-entropie ; un Merkle non salé sur une colonne haute-entropie ne fuit pas par
force brute — la fuite qui compte est celle des **ouvertures**, pas du commitment).

### E2 — Blinding au niveau AIR (partie facile, sans toucher winterfell)
Masquer les colonnes témoins par la technique standard : ajouter à chaque colonne
témoin un multiple aléatoire d'un polynôme s'annulant à toutes les lignes réelles
(contraintes intactes aux lignes réelles, ouvertures aux positions LDE randomisées).
Variantes à tester : (a) lignes de blinding hors zone contrainte (au-delà des
sélecteurs), (b) colonnes de blinding dédiées mélangées au commitment de trace.
**Observations** : l'AIR vérifie-t-il toujours ? Les cellules ouvertes sont-elles
réellement randomisées (comparer deux preuves du même témoin) ? Le budget de degré
(blowup 16) encaisse-t-il l'aléa ajouté ?

### E3 — Commitments salés (internes prouveur, partie dure)
Implémenter un `TraceLde`/`ConstraintCommitment` custom qui sale les feuilles Merkle.
**Test critique : `winterfell::verify` accepte-t-il encore ?** Hypothèse : non (le
vérifieur recompose les racines sans le sel). Enregistrer *exactement* où ça casse.
Conditionné par E1 : si la carte de fuite montre que le salage n'est pas nécessaire
(témoins haute-entropie), E3 se réduit à confirmer ce raisonnement et le documenter.

### E4 — Fuite OOD/DEEP
Le frame hors-domaine évalue les polynômes de trace en `z` aléatoire → révèle une
combinaison linéaire potentiellement fuyante. Tester si le blinding de E2 masque aussi
le frame OOD, ou s'il faut blinder en plus la composition/DEEP. Partie la plus subtile ;
si non concluante après effort borné, enregistrer comme telle.

### E5 — Synthèse et recommandation
Classer l'issue en une des trois voies, avec effort/risque chiffrés :
- **Voie A** : blinding AIR borné (+ salage par trait-override si besoin) marchent sur
  winterfell stock → zk atteignable **en gardant le monolithe**, sans fork du cœur.
- **Voie B** : blinding OK mais salage/OOD exigent des changements vérifieur → **fork
  minimal** de winterfell, avec la liste exacte des fonctions à modifier.
- **Voie C** : blocage fondamental → **migration**, cible recommandée **Miden/RPO
  Goldilocks** (compatible champ/PQ, déjà notre fallback nommé), + chiffrage du portage
  de l'AIR.

## 5. Livrables

- **Code expérimental** : nouveau crate jetable `crates/zk-spike` (dépend de `circuit`,
  `proved-hash`, `winterfell`) contenant E2–E4. Qualité jetable mais observations
  **réelles** (compile, tourne, `verify` accepte/rejette pour de vrai). Non ajouté au
  workspace de consensus au-delà du spike.
- **Rapport de décision** : `docs/superpowers/specs/2026-07-20-3zb0-spike-rapport.md`
  (recommandation, carte de fuite E1, observations E2–E4, esquisse d'argument de
  sécurité pour la voie retenue, effort chiffré de 3z-b1).
- **Pointeur léger** : une ligne dans STARK_STATEMENT.md / CLAUDE.md renvoyant à la
  décision.

## 6. Exécution

**Inline**, piloté à la main (les expériences dépendent des trouvailles : E3/E4
dépendent de E1). Sous-agents ciblés uniquement pour des bouts de code isolés. Chaque
expérience s'arrête sur une observation enregistrée ; une expérience non concluante est
consignée « non concluant, spike plus profond requis », jamais étendue silencieusement.

## 7. Hors périmètre (YAGNI)

Le spike ne forke pas winterfell pour de vrai, ne migre pas, ne livre pas le zk de
production, ne prouve pas formellement le simulateur. Il produit **juste assez de
preuve** pour choisir la voie et chiffrer 3z-b1.

## 8. Critères de succès

- E1 produit une carte de fuite concrète (surfaces × cellules témoins).
- E2 démontre (code) si oui/non le blinding AIR randomise les ouvertures sans casser la
  vérification.
- E3 et E4 rendent un verdict clair (marche / casse ici précisément / non concluant).
- E5 recommande UNE voie (A/B/C) avec un argument étayé par les observations et un
  chiffrage de 3z-b1.
