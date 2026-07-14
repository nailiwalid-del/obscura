# Statement de preuve zk-STARK — v0.2

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
  nk                    clé de nullifier du dépensier
  ak                    clé d'autorisation de dépense (jamais publiée)
  notes de sortie       (value, owner, rho, r)

La preuve établit :
  P1. chaque commitment d'entrée appartient à l'arbre de racine `root`
  P2. pour chaque note d'entrée : note.owner = H(ak)   (autorité de dépense)
  P3. chaque nullifier est correctement dérivé : nf = PRF_nk(rho ‖ commitment)
  P4. nk est correctement liée à ak (même autorité)
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
| **Hash prouvé** | commitments de notes, arbre de Merkle, PRF nullifier | **Rescue-Prime** (circuit-friendly, disponible dans winterfell) |

Conséquence assumée : les objets prouvés perdent la double-primitive et reposent sur
Rescue-Prime seul (fonction éponge algébrique, post-quantique comme tout hash, mais
moins éprouvée que SHA3). Mitigations : paramètres de sécurité conservateurs,
vecteurs de test croisés avec une seconde implémentation, et versioning explicite
(`obscura/…/rescue-prime/v1`) permettant une rotation de fonction si nécessaire.
La migration du code (merkle.rs, note.rs) se fait AVEC le circuit, jamais avant,
pour garantir que l'arbre consensus et l'arbre prouvé sont identiques.

## Candidat d'implémentation

`winterfell` (STARK, Rust) : prouveur/vérifieur génériques, Rescue-Prime fourni,
pas de trusted setup, sécurité 100+ bits configurables, hash-based (post-quantique).
Alternative si blocage : `miden-crypto`/RPO. À benchmarker : taille de preuve et temps
de génération pour 2 entrées / 2 sorties, profondeur 32.
