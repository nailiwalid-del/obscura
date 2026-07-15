# Phase 3 — Décision système de preuve + Design de la tranche 3a0 (encodage)

- **Date** : 2026-07-15
- **Statut** : décisions actées (brainstorming + 2 deep-research spikes), design 3a0 proposé.
- **Portée** : ce document fixe (A) la stratégie de preuve de toute la Phase 3, (B) le découpage en tranches, (C) le design détaillé de la première tranche buildable **3a0**.

---

## Partie A — Décision : système de preuve et zero-knowledge

### Contraintes dures (threat model Obscura)

Transparent (aucun trusted setup) · **post-quantique** (hash/FRI, pas de courbe) · **zero-knowledge** (la preuve doit CACHER le témoin : montants, owner, secret) · circuit custom (Rescue, Merkle prof. 32, range/équilibre u64) · Rust.

### Corps + hash : **Goldilocks + Rescue-Prime Rp64_256**

Corps `p = 2^64 − 2^32 + 1`. Hash prouvé = Rescue-Prime (Rp64_256). **Portable** entre winterfell et plonky2/3 (tous FRI/Goldilocks) → l'encodage (3a0) et le hash prouvé (3a1) ne dépendent PAS du prouveur final.

### Verdict ZK (spike de faisabilité — le point décisif)

Un STARK n'est **pas** zero-knowledge par défaut. Le witness-hiding *prouvable* exige : (a) masquage de chaque colonne de trace par un polynôme aléatoire ; (b) masquage du polynôme de composition **DEEP** (qui fuit aussi) ; (c) traitement ZK dédié des arguments de permutation. Sources vérifiées :

- eprint 2024/1037 (Habock) : recipe pour ZK sur small-field FRI-STARK, **avertit que la décomposition du quotient (DEEP) est « a source for mistakes, both in literature as well as in software implementations »**.
- Plonky3 (base) = « a toolkit for an efficient implementation of a **non-hiding** STARK protocol » (audit Least Authority) ; README sans blinding/ZK ; annonce Polygon cible la soundness.
- plonky3-recursion annonce « Full support for Zero-Knowledge » mais est **non audité, déconseillé en prod**.
- Winterfell : ZK = « planned » seulement, non implémenté.
- Plonky2 : vrai flag `zero_knowledge` (blinding) mais **déprécié**, et son whitepaper juge son ZK-FRI incomplet.
- Halo2/KZG/IPA : courbes → **disqualifiés** par le post-quantique.

**Conclusion : aucune lib Rust auditée ne fournit le witness-hiding ZK pour un circuit custom.** Rouler le masquage soi-même = risque de **fuite silencieuse** (la preuve « marche » tout en fuitant) = pire cas pour une monnaie privée.

### Décision : **VALIDITÉ D'ABORD, ZK DIFFÉRÉ**

On construit un **circuit de validité** (consensus sound : pas de forge, pas de double-dépense, équilibre garanti), **explicitement étiqueté non-privé**. Le ZK est une **couche additive** : les contraintes P1–P7 sont identiques avec ou sans masquage → **aucun rework** des contraintes quand on ajoutera le ZK. Le ZK devient le **#1 open item**, gaté sur : une lib Rust ZK-STARK auditée pour circuits custom, OU un effort d'implémentation+audit dédié (recipe eprint 2024/1037).

**Honnêteté requise (THREAT_MODEL / STARK_STATEMENT)** : tant que la couche ZK n'est pas là, la confidentialité des montants/owner **n'est pas atteinte** — le circuit de validité prouve l'intégrité, pas le secret.

---

## Partie B — Découpage de la Phase 3

```
3a0  Encodage canonique Felt↔bytes + types digest + domaines + rust-version   ⟵ CE DOC
3a1  Rescue-Prime prouvé partagé (crate proved-hash) + vecteurs + cross-test Rp64_256
3a2  Validity skeleton P2 : owner = H_owner(secret), prove/verify (secret HORS assertions)
3b1  Gadgets nk / nullifier
3b2  Gadget Merkle path profondeur 32
3b3  Gadgets u64 balance / range (limbs 16 bits)
3b4  Gadget commitment de note
3b5  Circuit P1–P7 complet + binding tx_digest (+ test non-rejeu)
3c   Format tx prouvé + apply_proved
3d   Bench 2-in/2-out profondeur 32
--   [gaté] Couche ZK : masquage trace + DEEP + permutations (eprint 2024/1037), quand lib auditée
```

Structure de crates cible : **`crates/proved-hash`** (Rescue, encodage, domaines, types digest ; PAS de dépendance au prouveur) → **`crates/circuit`** (AIR/prove/verify, dépend de proved-hash) → **`crates/ledger`** (dépendra de proved-hash, pas forcément du prouveur).

---

## Partie C — Design de la tranche 3a0

**Objectif** : figer l'encodage `Felt↔bytes`, les types digest, et les domaines, AVANT tout circuit. C'est le plus gros risque de rework de la Phase 3.

### Décisions actées

| Élément | Décision |
|---|---|
| **Felt** | Goldilocks, `p = 2^64 − 2^32 + 1` |
| **Digest prouvé** | `[Felt; 4]` (~32 o). S'applique à `owner`, `nk`, `note_commitment`, `merkle_leaf`, `merkle_node`, `nullifier` |
| **Commitment** | passe de **64 o (dual) → 32 o (Rescue 4-Felt)** ; migration en lockstep 3b (Merkle, nullifier, format tx, sérialisation) |
| **`shielded_secret`** | natif `[Felt; 4]` (chaque < p, ~254 bits) ; sérialisation 4×8 o little-endian, **validation `< p` au décodage** ; adaptation du `[u8;32]` wallet en 3b |
| **Montant `u64`** | **4 limbs de 16 bits** (`[u16; 4]` → 4 Felts < 2¹⁶). Interdit le mapping naïf `u64→Felt`. Range-check 16 bits (lookup 65536 faisable) |
| **Séparation de domaine** | **tag Felt distinct par usage** (constantes documentées : `owner=1, nk=2, note_commitment=3, merkle_leaf=4, merkle_node=5, nullifier=6`), injecté dans la capacité du sponge ; entrée **préfixée en longueur** ; padding `pad10*` fixe |
| **`rust-version`** | bump `1.75` → MSRV de la lib retenue (rustc 1.97 installé ; juste le champ déclaré, valeur fixée en 3a1 quand la dép prouveur entre) |

### Portée 3a0 (crate `proved-hash`, sans Rescue ni AIR encore)

- **Types** : `Felt` (ré-export), `Digest([Felt; 4])`, `ShieldedSecret([Felt; 4])`, `AmountLimbs([u16; 4])`, enum `Domain` (tags).
- **Encodage** : `Digest ↔ [u8; 32]`, `ShieldedSecret ↔ [u8; 32]` (LE, validation `< p`), `u64 ↔ AmountLimbs`, `AmountLimbs → u64` (recomposition), `Felt ↔ [u8; 8]` canonique.
- **Domaines** : table de tags + helper de préambule sponge (tag ‖ longueur ‖ … ‖ pad10*) — la *fonction* Rescue arrive en 3a1, mais le **schéma de préambule** (ordre, padding) est figé ici.

### Ce que 3a0 NE fait PAS

La permutation Rescue-Prime (3a1), l'AIR/prove/verify (3a2+), la migration du ledger (3b), le format tx (3c).

### Tests 3a0

- round-trip : `u64 → AmountLimbs → u64` (dont `0`, `u64::MAX`) ; `Digest ↔ bytes` ; `ShieldedSecret ↔ bytes`.
- rejet : décodage d'un limb `≥ 2¹⁶`, d'un Felt `≥ p`, de longueurs invalides.
- domaines : deux usages distincts produisent des préambules distincts ; vecteurs figés des tags.
- non-régression : nouveau crate isolé → les 29 tests existants inchangés.

### Références

- eprint 2024/1037 — https://eprint.iacr.org/2024/1037
- Audit Plonky3 (Least Authority) — https://leastauthority.com/blog/audit-of-plonky3/
- Recipe ZK-STARK (masquage trace + DEEP) — https://hexens.io/blog/zk-in-starks
