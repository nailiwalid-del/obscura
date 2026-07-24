# Obscura — contexte projet pour Claude Code

> **Ce fichier ne fait pas autorité.** Ce sont des notes de travail. La
> spécification est dans `docs/` — commencer par `docs/CONFORMITE.md`. En cas de
> divergence, **`docs/` a raison**, et la divergence est un défaut à corriger
> ici, pas là-bas. Les constantes et formats cités plus bas sont **informatifs** :
> l'autorité est le code, décrit par `docs/PROTOCOL.md`.

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

Prototype Rust, phases 1-5 testées ; **consensus BFT complet** (J1 : finalité,
liveness, reconfiguration d'autorités certifiée) ; économie *spécifiée* (ADR-002,
coinbase derrière A), J3 (partitions, mise à jour, négociation de version de fil) et
**machinerie d'ouverture** (T5) livrés ; état B atteint côté dépôt (chaîne pas encore
ouverte). Décisions A en conception : appartenance tranchée (ADR-003 — fédéré en
scellement, ouvert en usage). Prototype pédagogique non audité — ne pas utiliser en
production.

## Conventions

- Code et commentaires : les commentaires/docs sont en français
- Tests unitaires dans chaque module + e2e dans `crates/ledger/tests/`
- Tout nouveau hash/PRF doit être séparé par domaine et non tronqué
