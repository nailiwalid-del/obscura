# Journal de stabilité de la spécification (préparation d'audit — D-A4)

> **But.** Rendre le critère « spec stable depuis ≥ 3 mois » (décision D-A4,
> `docs/superpowers/specs/2026-07-24-decisions-A-carte.md`) **objectif et daté**,
> plutôt qu'une impression. Un audit externe ne se commande qu'après **trois mois
> pleins sans aucun changement** des surfaces listées ci-dessous — **et** un budget
> disponible, **et** B ouvert et stable. Ce journal ne fait que tenir l'horloge ; il
> n'engage aucune dépense.

## Les surfaces qui remettent l'horloge à zéro

Tout changement de l'une de ces surfaces **redémarre le compteur de trois mois**
(définition stricte, D-A4) :

1. **`VERSION_BLOC`** (format du bloc de consensus).
2. **Énoncé STARK** (`docs/STARK_STATEMENT.md`, statement P1–P7, paramètres de
   preuve `proof_options_hi`).
3. **Backend post-quantique** (`docs/BACKEND_PQ.md` — migration, ou changement de
   crate ML-KEM / ML-DSA).
4. **Mécanisme économique** (règle d'émission, `emissions`, coinbase — ADR-002).
5. **Formats de fil et d'état wallet/node** (`Message`, `VERSION_ETAT`,
   `VERSION_VOTES`, `VERSION_SYNCHRO`, encodages `to_bytes`/`from_bytes` du
   protocole applicatif).
6. **Invariants de consensus** (quorum, changement de vue, changement d'autorités,
   ordre de vérification, non-réorg).

Ce qui **ne** remet **pas** l'horloge à zéro : documentation, tests, messages CLI,
outillage (`deploiement/`), refactors internes sans effet de format ni de règle.

## Horloge

- **Dernier changement d'une surface de stabilité : 2026-07-24** — le format de fil
  du protocole applicatif a changé (J3 : `TAG_VERSION` / `Message::Version`,
  négociation de version, PR #27). C'est une surface 5.
- **Compteur démarré (ou redémarré) le : 2026-07-24.**
- **Éligibilité au plus tôt : 2026-10-24**, et **seulement si** aucune ligne n'est
  ajoutée au registre ci-dessous d'ici là, **et** qu'un budget existe, **et** que B
  est ouvert et stable.

⚠️ **Cette éligibilité de date n'est PAS une décision d'acheter.** D-A4 reste une
décision d'approvisionnement, interdite tant que B n'est pas ouvert et stable
(carte des décisions A, garde-fou 1). Le compteur est une condition nécessaire, pas
suffisante.

## Registre des changements de surface

Ajouter une ligne à **chaque** changement d'une des six surfaces. La ligne la plus
récente fixe le début du compteur.

| Date | Surface | Changement | PR / commit | Effet sur l'horloge |
|---|---|---|---|---|
| 2026-07-24 | 5 (format de fil) | négociation de version applicative (`TAG_VERSION`, `Message::Version`) | #27 (J3) | **démarrage** du compteur |

## Comment s'en servir

- **En committant un changement** qui touche une des six surfaces : ajouter une
  ligne ici dans le même commit. Ne pas le faire, c'est laisser « stable » redevenir
  une impression.
- **Avant d'envisager D-A4** : vérifier que la ligne la plus récente date de **plus
  de trois mois**, et relire la définition stricte ci-dessus — un changement oublié
  au registre invaliderait l'audit qu'il financerait.
