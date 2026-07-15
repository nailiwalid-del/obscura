# Statement de preuve zk-STARK — v0.2

> **Phase 3 = validity-only.** L'implémentation initiale du circuit prouve
> l'INTÉGRITÉ (P1–P7), pas la confidentialité : un STARK n'est pas zero-knowledge
> par défaut. Le witness-hiding est un jalon séparé et gaté (« Phase 3z »). Voir
> `docs/superpowers/specs/2026-07-15-phase3-decision-et-3a0-design.md`.

**Ce statement EST la règle de consensus d'une dépense valide.** Tout le reste du
protocole s'organise autour de lui. Le mode transparent actuel (`apply_transparent`)
n'est qu'un échafaudage de développement et ne définit pas la validité.

## Statement

```
Entrées PUBLIQUES :
  root                  racine de l'arbre des commitments (récente)
  nullifiers[]          un par note dépensée
  output_commitments[]  un par note créée
  fee                   frais (u64, en clair)
  tx_digest             digest canonique de la transaction (lie preuve ↔ tx)

Témoins PRIVÉS :
  notes d'entrée        (value, owner, rho, r)
  chemins de Merkle     un par note d'entrée
  shielded_secret       secret racine shielded, jamais publié
  nk                    intermédiaire privé contraint par nk = H_nk(shielded_secret)
  notes de sortie       (value, owner, rho, r)

La preuve établit :
  P1. chaque commitment d'entrée appartient à l'arbre de racine `root`
  P2. pour chaque note d'entrée : note.owner = H_owner(shielded_secret)   (autorité de dépense)
  P3. chaque nullifier est correctement dérivé : nf = PRF_nk(rho ‖ commitment)
  P4. nk = H_nk(shielded_secret)   (nk contrainte par le même secret racine)
  P5. Σ valeurs d'entrée = Σ valeurs de sortie + fee
  P6. toutes les valeurs sont range-checkées dans [0, 2^64)   (pas d'overflow/underflow)
  P7. chaque output_commitment est l'engagement correct de sa note de sortie
```

La preuve est vérifiée contre `tx_digest` en entrée publique : elle est liée à CETTE
transaction (non-malléabilité, pas de rejeu de preuve sur une autre tx).

## Ce que le statement supprime par rapport au mode transparent

- `spend_pk` n'est plus publié → les dépenses d'une même clé ne sont plus reliables (point 5 de la revue).
- Le chemin de Merkle n'est plus révélé → on ne sait plus QUEL commitment est dépensé.
- Le consensus vérifie enfin ce qu'il ne pouvait pas vérifier : liaison nullifier↔note
  existante, autorité de dépense, équilibre des montants (point 1 de la revue).

## Cohérence commitment ↔ note chiffrée (P8, différé)

Prouver en circuit que `enc_note` déchiffre vers la note engagée serait idéal mais
très coûteux. Position v0.2 (identique à Zcash Sapling/Orchard) : non prouvé en
circuit. Un expéditeur malveillant qui chiffre du garbage ne lèse que son destinataire
(fonds inutilisables, pas de création de monnaie) — P5/P7 tiennent indépendamment.
Réévaluer quand le coût des circuits sera mesuré.

## Décision : hash consensus vs hash prouvé (point 3 de la revue)

`dual_hash` (BLAKE3‖SHA3) est excellent hors circuit mais prohibitif en STARK
(les deux sont hostiles à l'arithmétisation).

Décision v0.2 — deux domaines de hachage explicites :

| Domaine | Usage | Hash |
|---|---|---|
| **Hash consensus** | tx_digest, KDF, adresses, transcripts KEM/sig | dual BLAKE3‖SHA3 (inchangé) |
| **Hash prouvé** | commitments de notes, arbre de Merkle, `owner = H(secret)` et `nk = H(secret)`, PRF nullifier | **Rescue-Prime** (circuit-friendly, disponible dans winterfell) |

Conséquence assumée : les objets prouvés perdent la double-primitive et reposent sur
Rescue-Prime seul (fonction éponge algébrique, post-quantique comme tout hash, mais
moins éprouvée que SHA3). Mitigations : paramètres de sécurité conservateurs,
vecteurs de test croisés avec une seconde implémentation, et versioning explicite
(`obscura/…/rescue-prime/v1`) permettant une rotation de fonction si nécessaire.
La migration du code (merkle.rs, note.rs) se fait AVEC le circuit, jamais avant,
pour garantir que l'arbre consensus et l'arbre prouvé sont identiques.

### Précision d'implémentation (v0.2) — où `dual_hash` s'applique réellement

Au sein du domaine « hash consensus », `dual_hash` (BLAKE3‖SHA3, 64 o, jamais tronqué)
est **exigé** là où la résistance aux collisions est *directement* sécuritaire :

- **commitments de notes** (`note.rs`) — binding de la note ;
- **tx_digest** (`tx.rs`) — lie signature et preuve à CETTE transaction ; une
  collision transférerait une signature d'une tx à une autre, et la double
  signature n'y changerait rien (les deux signent le même digest). Implémenté
  en dual depuis la correction d'audit 2026-07.

Les usages en **KDF/PRF** — `derive_key` (sous-clés AEAD), combinaison du secret
KEM — reposent sur **BLAKE3 seul** (keyed / derive-key). Choix
assumé : la défense en profondeur y est portée par les deux primitives KEM/signature
sous-jacentes, pas par le hash ; un hash unique de 256 bits comme PRF/KDF y suffit et
imposer le dual n'apporterait rien. En revanche, le **hash d'identité**
(`owner = H_owner(shielded_secret)`, `keys.rs`) et la **dérivation de `nk`**
(`nk = H_nk(shielded_secret)`) relèvent du **hash prouvé** (Rescue-Prime, migration
avec le circuit), PAS d'un KDF wallet — voir la ligne « hash prouvé » ci-dessus.
BLAKE3 domain-séparé n'y est qu'un échafaudage de dev. « Dual » est donc une *exigence* pour
commitments + tx_digest, non une contrainte uniforme sur tout hachage consensus.

## Candidat d'implémentation

`winterfell` (STARK, Rust) : prouveur/vérifieur génériques, Rescue-Prime fourni,
pas de trusted setup, sécurité 100+ bits configurables, hash-based (post-quantique).
Alternative si blocage : `miden-crypto`/RPO. À benchmarker : taille de preuve et temps
de génération pour 2 entrées / 2 sorties, profondeur 32.
