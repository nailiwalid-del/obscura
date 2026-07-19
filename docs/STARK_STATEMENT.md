# Statement de preuve zk-STARK — v0.2

> **Phase 3 = validity-only.** L'implémentation initiale du circuit prouve
> l'INTÉGRITÉ (P1–P7), pas la confidentialité : un STARK n'est pas zero-knowledge
> par défaut. Le witness-hiding est un jalon séparé et gaté (« Phase 3z »). Voir
> `docs/superpowers/specs/2026-07-15-phase3-decision-et-3a0-design.md`.
>
> **3a2 (fait) :** premier AIR = la **permutation** Rp64_256 (`crates/circuit`,
> `prove`/`verify`), validée par différentiel contre le vecteur de référence Sage.
> Note : sur Goldilocks (64 bits), l'extension de corps **quadratique** est
> obligatoire — sans elle la sécurité conjecturée plafonne à ~63 bits.
>
> **3a2b (fait) — P2 EST PROUVÉ EN CIRCUIT** : `owner = H_owner(shielded_secret)`
> (`circuit::{prove_owner, verify_owner}`). Le sponge de `hash_elements` n'utilise
> aucun padding (la longueur est injectée dans la capacité) et le préambule 3a0 fait
> exactement un bloc de rate → P2 = **une** permutation. Le `shielded_secret` reste
> témoin : **aucune assertion ne le référence**. Différentiel vert contre
> `proved_hash::rescue::hash` (le hash du ledger).
>
> **3b1 (fait) — sponge MULTI-BLOC généralisé** (`circuit::sponge`) : `prove_sponge`
> prouve `digest = H_domain(payload)` pour un payload arbitraire (cycle 8 = 7 rondes
> + 1 absorption additive, masque `round_flag`). Instances : `prove_nk` (P4, B=1),
> `prove_nullifier` (P3, B=2). Différentiels verts (B=1/2/4). Précondition `B*8`
> puissance de 2 (padding B=3 → 3b4). Positions publiques du payload assertées,
> témoins jamais assertés.
>
> **3b2a (fait) — gadget d'UN niveau de Merkle** (`circuit::merkle_level`) : swap
> conditionnel in-circuit `(gauche, droite) = bit==0 ? (courant, frère) : (frère,
> courant)` + `merge` (sponge B=2). Bit **booléen** contraint ; `courant`/`frère`/`bit`
> en colonnes témoins constantes ; swap réparti ligne 0 / ligne 7 via flags d'init.
> Différentiel vert vs `proved_hash::merkle::node` (les deux bits).
>
> **3b2b intermédiaire (fait) — CHAÎNAGE inter-blocs** (`circuit::merkle_path`) :
> `prove_merkle_path(leaf, path, index)` prouve `root = fold(leaf, path, index)` en
> chaînant D merges (sortie niveau k = `cur` niveau k+1 ; sponge désactivé aux
> frontières par un flag `chain` ; bit variable par niveau). Différentiel vert vs
> `proved_hash::merkle::fold` (D=2, 4 index) + test négatif. **⚠️ preuves à générer
> en `--release`** : le `debug_assert` de degrés de winterfell est input-dépendant
> (colonnes témoins constantes) → on déclare des bornes supérieures (`déclaré ≥
> mesuré`, soundness préservée), l'assert debug étant ignoré en release ; tests
> `#[ignore]` en debug.
>
> **3b2c (fait) — P1 PROUVÉ (par composition), profondeur 32** (`circuit::membership`) :
> `prove_membership(cm, path, index)` compose la preuve du hash de feuille
> (`H_MerkleLeaf(cm)`, sponge B=1) et la preuve de chaînage (`merkle_path`), liées par
> un `leaf_digest` PUBLIC partagé. `verify_membership` vérifie les deux. Différentiel
> vert vs `proved_hash::merkle::root` à profondeur **2 ET 32** (trace chemin = 512),
> + négatif. **P1 (appartenance à l'arbre) est donc prouvable en circuit à la
> profondeur consensus.** Limite assumée : `leaf_digest` public (non privé) — la
> version monolithique privée (leaf_digest témoin, P1 fondu avec P2–P7 et lié à
> tx_digest) est le circuit complet de 3b5.
>
> **3b3a (fait) — range-check** (`circuit::range_check`, P6) : `prove_range(v)` prouve
> `0 ≤ v < 2^RANGE_BITS` par décomposition binaire accumulée (colonne `acc`, colonne
> compteur `idx` pour non-dégénérescence). **`RANGE_BITS = 60`** (raffinement assumé
> du « [0,2^64) » : sur Goldilocks `p≈2^64`, un range 2^64 est vide et l'équilibre en
> corps wrappe ; borner à 2^60 rend `Σ` sound pour ≤ 16 termes). Testé en `--release`
> (positif + hors-range rejeté).
>
> **3b3b (fait) — ÉQUILIBRE P5 PROUVÉ EN CIRCUIT** (`circuit::balance`) :
> `prove_balance(inputs, outputs, fee)` prouve `Σin = Σout + fee` **en addition de
> corps**, sur des montants TÉMOINS. AIR unique : chaque montant occupe un bloc de 64
> lignes de bits ; la colonne périodique `pow` (`2^i`, i<60, puis 0) **remet le poids
> à zéro à chaque bloc**, ce qui borne AUTOMATIQUEMENT chaque montant à `< 2^60`
> (range-check P6 embarqué, gratuit) ; un accumulateur `S` fait la somme SIGNÉE
> (`+1` entrée / `−1` sortie), `S[0]=0`, assertion finale `S = fee`. Signes publics
> assertés par bloc (structure n_in/n_out engagée). Soundness : `≤ 8` entrées ×
> `2^60 < p` → aucun wrap ne masque un déséquilibre. Précondition `n_in+n_out`
> puissance de 2 (padding = sorties de valeur 0). Différentiels verts : équilibres
> honnêtes (avec/sans fee, montants ≈ 2^59) acceptés, déséquilibre et fee falsifié
> rejetés. Montants non révélés ici (témoins), mais preuve non witness-hiding ; la
> liaison bits↔commitments est le monolithe 3b5. À générer en `--release`.
>
> **3b4 (fait) — COMMITMENT DE NOTE P7 PROUVÉ EN CIRCUIT** (`circuit::prove_note_commitment`) :
> `cm = H_NoteCommitment(value ‖ owner ‖ rho ‖ r)` (payload 13 Felts, note
> ENTIÈREMENT témoin, seul `cm` public). **Premier usage du padding PAD_ZERO\*** (le
> B=3 repoussé depuis 3b1) : le préambule logique fait 17 éléments (3 blocs) ; il est
> complété par des zéros jusqu'à un nombre de blocs PUISSANCE DE 2 (4 blocs = 32),
> exigence de la longueur de trace STARK. `absorbed_len` centralise la règle et est
> un NO-OP pour tous les hachages déjà alignés (owner/nk B=1, nullifier/merge B=2) →
> golden vectors 3a1 INCHANGÉS. La capacité du sponge = longueur absorbée (32),
> injective car `LEN=13` figure dans le préambule ; le PAD_ONE reste à sa position
> logique (index 16, découplé de `capacité−1`). Différentiel vert vs
> `proved_hash::note_commitment` (déterministe, hiding via `r`, binding) + cm altéré
> rejeté. Le sponge n'ayant pas de colonne témoin constante, la preuve tourne en
> DEBUG (contrairement aux gadgets gatés). **P7 prouvable en circuit.**

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
