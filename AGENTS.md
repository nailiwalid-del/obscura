# Obscura — contexte projet pour Codex

> **Ce fichier ne fait pas autorité.** Ce sont des notes de travail. La
> spécification est dans `docs/` — commencer par `docs/CONFORMITE.md`. En cas de
> divergence, **`docs/` a raison**, et la divergence est un défaut à corriger
> ici, pas là-bas. Les constantes et formats cités plus bas sont **informatifs** :
> l'autorité est le code, décrit par `docs/PROTOCOL.md`.
>
> ⚠️ Ce fichier et `CLAUDE.md` ont **divergé** par le passé — la dernière fois de
> plusieurs jalons (il annonçait encore un format de bloc et un circuit figés
> d'il y a plusieurs versions). Il est désormais **dérivé de `CLAUDE.md`, contenu
> identique, seul cet en-tête diffère.** Toute modification de l'un doit être
> répercutée sur l'autre le jour même, ou les deux redériveront — et c'est
> l'agent suivant qui paiera.

## Où est l'autorité

Ce fichier ne fait pas autorité (voir l'en-tête). La spécification vit dans
`docs/` :

- **Par où commencer :** `docs/CONFORMITE.md` (statut, où fait autorité quoi).
- **Formats et règles de consensus :** `docs/PROTOCOL.md` (bloc 0x05, vue,
  changement d'autorités, versioning, transaction, Merkle, key privacy).
- **Rôles et invariants par crate :** `docs/ARCHITECTURE.md` (crypto, net,
  ledger, circuit, wallet, node — et les ⚠️ à ne pas régresser).
- **Modèle d'adversaire :** `docs/THREAT_MODEL.md` (dont canaux auxiliaires).
- **Énoncé STARK et witness-hiding :** `docs/STARK_STATEMENT.md`.
- **Dette backend PQ :** `docs/BACKEND_PQ.md`. **Post-quantique :**
  `docs/POST_QUANTIQUE.md`.
- **Exploitation / testnet :** `docs/OPERATEUR.md`, `docs/TESTNET.md`.
- **Feuille de route :** `docs/superpowers/specs/2026-07-23-reste-a-faire-vers-B.md`.

## État en une ligne

Prototype Rust, phases 1-5 testées ; consensus BFT fédéré **J1 complet**
(finalité, liveness, reconfiguration d'autorités). Prototype pédagogique non
audité — ne pas utiliser en production.

## Conventions

- Code et commentaires : les commentaires/docs sont en français
- Tests unitaires dans chaque module + e2e dans `crates/ledger/tests/`
- Tout nouveau hash/PRF doit être séparé par domaine et non tronqué
