# Backend post-quantique : évaluation des candidats de sortie de `pqcrypto`

**Date des relevés : 2026-07-22.** Toutes les données chiffrées ci-dessous viennent
de l'API de crates.io et des dépôts eux-mêmes, à cette date. Elles vieilliront —
**re-vérifier avant de décider**, la conclusion de ce document dépend de faits qui
bougent.

## Le problème

Toute la famille `pqcrypto` est marquée `unmaintained` par RUSTSEC, parce que
**PQClean est archivé en amont** :

| Avis | Crate |
|---|---|
| RUSTSEC-2026-0161 | `pqcrypto-mlkem` (celle qu'on utilise) |
| RUSTSEC-2026-0166 | `pqcrypto-mldsa` (celle qu'on utilise) |
| RUSTSEC-2026-0162 | `pqcrypto-traits` |
| RUSTSEC-2026-0163 | `pqcrypto-internals` |

La migration FIPS (T1) a **déplacé** cette dette, pas supprimée : les crates ML-KEM
et ML-DSA portent leurs propres avis, au même titre que les round-3 qu'elles
remplacent. Les avis sont ignorés nommément dans `deny.toml`, jamais par un filtre
large qui masquerait une vraie vulnérabilité de la même famille.

**Ce que « unmaintained » veut dire, précisément** : le code fonctionne, il est issu
d'une implémentation de référence largement relue, mais **personne ne corrigera une
vulnérabilité future en amont**. C'est un risque de maintenance, pas une faille
connue. La nuance compte pour arbitrer.

## Les candidats, sur données vérifiables

| | version | dernière release | téléchargements | dépôt |
|---|---|---|---|---|
| **RustCrypto** `ml-kem` | 0.3.2 | 2026-05-10 | 3 243 662 | RustCrypto/KEMs |
| **RustCrypto** `ml-dsa` | **0.1.1** | 2026-06-05 | 1 406 613 | RustCrypto/signatures |
| **libcrux** `-ml-kem` | **0.0.10** | 2026-07-15 | 1 986 004 | cryspen/libcrux |
| **libcrux** `-ml-dsa` | **0.0.10** | 2026-07-15 | 104 980 | cryspen/libcrux |
| **aws-lc-rs** | 1.17.3 | 2026-07-17 | 167 347 464 | aws/aws-lc-rs |

### RustCrypto (`ml-kem` + `ml-dsa`)

**Pour.** Pure Rust, sans dépendance C. Écosystème déjà présent dans l'arbre —
`aes-gcm` et `chacha20poly1305` en viennent, donc les conventions (traits, zeroize,
`no_std`) sont celles qu'on connaît déjà. Releases récentes et actives.

**Contre.** `ml-dsa` est en **0.1.1** — jeune pour la moitié signature du protocole,
qui est ce qui protège les scellements de blocs et les enveloppes d'intention. Le
projet documente lui-même l'absence d'audit indépendant sur ses implémentations
récentes.

### libcrux

**Pour.** Le seul candidat avec un argument de **vérification formelle** (HACL\*,
hax, F\*), ce qui est exactement le genre de garantie qu'un auditeur de circuit
apprécierait.

**Contre, et c'est lourd.** Le dépôt est en **pré-release assumée** — toutes les
crates sont versionnées `< 0.1` — et le README **recommande de contacter les
mainteneurs avant tout usage en production**. Le statut de vérification n'est pas
documenté par algorithme dans le README (des badges distinguent « pre-verification »
de « verified », sans tableau récapitulatif). Et un caveat explicite : les
exécutables produits **ne sont pas vérifiés résistants aux canaux auxiliaires**,
même si le code source vise l'indépendance au secret. Enfin `libcrux-ml-dsa` totalise
~105 k téléchargements — vingt fois moins que son pendant KEM : la moitié signature
est peu exercée.

### aws-lc-rs

**Pour.** De très loin la plus utilisée (167 M téléchargements), adossée à AWS-LC,
avec un chemin de certification **FIPS** réel — ce qui compléterait la thèse
post-quantique par un argument de conformité.

**Contre.** ML-DSA vit dans `aws_lc_rs::unstable::signature` et **n'est pas
stabilisé** : la documentation dit explicitement que ces APIs « ne sont pas
couvertes par les garanties de semver ». La stabilisation est demandée depuis
plusieurs versions sans être livrée. S'ajoutent une dépendance C (build plus lourd,
portabilité Windows/Linux à valider) et l'écart avec un projet Rust pur qui se veut
auditable ligne à ligne.

## Recommandation : NE PAS migrer maintenant

C'est une conclusion contre-intuitive pour une dette de sécurité, et elle mérite
d'être défendue explicitement.

**Aucun candidat n'est meilleur que le statu quo sur le critère qui compte ici.**
Notre problème est un risque de *maintenance future* sur du code qui marche et qui
vient d'une implémentation de référence relue. Les trois sorties possibles échangent
ce risque connu contre :

- **RustCrypto** : une crate de signature en 0.1.1 sur le chemin du consensus ;
- **libcrux** : une pré-release dont les auteurs eux-mêmes déconseillent l'usage en
  production sans les contacter ;
- **aws-lc-rs** : une API explicitement non couverte par semver, qui peut changer
  sous nos pieds — sur un format **wire** que le gel de genèse rendra définitif.

Migrer maintenant, ce serait remplacer une dette **documentée, bornée et sans
conséquence fonctionnelle** par un risque **non borné** sur le composant le moins
remplaçable du projet. Le fait que RUSTSEC affiche cinq lignes rouges ne change pas
cet arbitrage : ce sont des avis « unmaintained », pas des vulnérabilités.

## Critères de déclenchement (à re-tester, pas à ressentir)

La migration devient la bonne décision dès que **l'un** de ces faits est vrai :

1. **Une vulnérabilité réelle** (pas « unmaintained ») est publiée sur
   `pqcrypto-mlkem` ou `pqcrypto-mldsa` — alors la migration devient urgente, et
   c'est le candidat le plus mûr à ce moment-là qui gagne.
2. **`ml-dsa` de RustCrypto atteint 1.0** (ou publie un audit indépendant) — c'est
   le chemin le plus probable, et le plus cohérent avec le reste de l'arbre.
3. **aws-lc-rs stabilise ML-DSA** hors du module `unstable` — alors l'argument FIPS
   devient décisif pour un projet dont la thèse est post-quantique.
4. **libcrux passe en ≥ 0.1** et publie un tableau de vérification par algorithme.

**Avant le gel de genèse**, ce document doit être relu : le gel rend le format wire
définitif, et changer de backend après coup coûterait le même travail que T1 —
version d'algo `0x03`, refus nommé du `0x02`, nouvelle chaîne.

## Re-test avant le gel de genèse (gate de T5)

**Avant d'exécuter `obscura-genese` en production**, rejouer les critères de
déclenchement ci-dessus et **consigner le résultat dans le dépôt**, même s'il est
« toujours non ». La décision « ne pas migrer » n'est valable qu'à sa date ; la
graver dans une chaîne exige de la re-confirmer.

**Critère ACVP ajouté :** un backend permettant l'**injection d'aléa officiel**
(graine de `keyGen`) rendrait `keyGen`/`encap`/`sigGen` vérifiables par vecteurs
ACVP complets — et supprimerait le trou nommé en porte AUD (aujourd'hui seuls
`decap`/`sigVer`, déterministes, sont couverts — voir
`crates/crypto/tests/acvp_mlkem768.rs` et `acvp_mldsa65.rs`). Son apparition
**déclenche** une ré-évaluation du backend.

## Ce qu'il faudra vérifier au moment de migrer (et pas avant)

Ces points ne sont **pas vérifiés** dans ce document — les mesurer sur un candidat
qu'on ne retient pas serait du travail perdu :

- **Effacement des secrets** : la crate expose-t-elle des secrets `Zeroizing`, ou
  faut-il reconduire notre repli actuel (octets en `Zeroizing<Vec<u8>>` + type
  reconstruit à chaque usage) ?
- **Sérialisation** : `from_bytes`/`to_bytes` sur les clés et signatures, avec des
  tailles stables — c'est ce dont notre format wire dépend.
- **Vecteurs KAT** : une API dérandomisée permettant de rejouer les vecteurs
  officiels ACVP. `pqcrypto` n'en offre pas, d'où l'écart consigné en T1.6 ; un
  candidat qui le permet fermerait cette lacune.
- **Portabilité** : Windows et Linux, les deux plateformes de la CI.
- **Tailles** : ML-KEM-768 et ML-DSA-65 sont normalisés, donc les tailles ne
  devraient pas bouger — à confirmer, car tout le dimensionnement du dépôt en
  dépend (`KEM_CT_LEN`, `TAILLE_SCELLEMENT_MAX`, `MAX_OCTETS_BLOC`).

## Sources

- [crates.io — ml-kem](https://crates.io/crates/ml-kem)
- [crates.io — ml-dsa](https://crates.io/crates/ml-dsa)
- [crates.io — libcrux-ml-kem](https://crates.io/crates/libcrux-ml-kem)
- [crates.io — libcrux-ml-dsa](https://crates.io/crates/libcrux-ml-dsa)
- [crates.io — aws-lc-rs](https://crates.io/crates/aws-lc-rs)
- [cryspen/libcrux — README (statut de vérification, caveats)](https://github.com/cryspen/libcrux)
- [aws-lc-rs — ML-DSA dans le module `unstable`](https://docs.rs/aws-lc-rs/latest/aws_lc_rs/unstable/signature/constant.MLDSA_87_SIGNING.html)
- [aws/aws-lc-rs — discussion de stabilisation ML-DSA](https://github.com/aws/aws-lc-rs/issues/964)
