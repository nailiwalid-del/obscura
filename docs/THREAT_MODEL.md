# Modèle de menace — Obscura (nom provisoire)

## Adversaires considérés

| Adversaire | Capacités | Contre-mesure |
|---|---|---|
| Observateur passif du réseau | Capture tout le trafic, analyse de métadonnées | Chiffrement hybride PQ de tous les liens + (phase 4) routage Dandelion++/mixnet |
| Attaquant actif (MitM) | Injection, rejeu, modification | AEAD authentifié, transcript binding dans le KEM, signatures hybrides |
| Analyste de chaîne | Lit tout le ledger public | Notes engagées, nullifiers non-liables, montants/destinataires jamais en clair |
| Nœud malveillant / Sybil | Nœuds espions | Rien de sensible en clair ; la confidentialité ne dépend pas de l'honnêteté des nœuds |
| Ordinateur quantique (futur) | Casse ECC (Shor), affaiblit les hash (Grover) | Hybride PQ partout (ML-KEM, ML-DSA), hash 256-bit, STARKs (hash uniquement) |
| Cryptanalyse d'une primitive | Casse UNE primitive (ex : Kyber ou AES) | **Défense en profondeur** : chaque fonction repose sur ≥2 primitives indépendantes |

## Principe central : défense en profondeur (choix validé)

Chaque fonction de sécurité combine deux primitives de familles mathématiques indépendantes :
la sécurité tient tant qu'AU MOINS UNE des deux tient.

- **Échange de clés** : X25519 (courbes elliptiques) + ML-KEM-768 (réseaux euclidiens), secrets combinés par KDF sur le transcript complet.
- **Signatures** : Ed25519 + ML-DSA-65 — la vérification exige les DEUX signatures.
- **Chiffrement** : cascade XChaCha20-Poly1305 ∘ AES-256-GCM, clés indépendantes dérivées.
- **Hachage / commitments** : dual_hash = BLAKE3(x) ‖ SHA3-256(x) — résistant aux collisions si l'un des deux l'est (ARX vs éponge Keccak).

Règle : la combinaison ne doit jamais être PIRE que la meilleure primitive seule
(pas de troncature du hash combiné, clés de cascade indépendantes, KDF liant tout le transcript).

## Garanties visées

1. **Confidentialité des montants** : jamais en clair on-chain (phase 3 : prouvés par STARK).
2. **Non-liabilité expéditeur/destinataire** : adresses jamais publiées, notes à usage unique.
3. **Anti double-dépense** : nullifiers déterministes mais non-liables sans la clé.
4. **Confidentialité des métadonnées réseau** : phase 4 (Dandelion++ puis mixnet).
5. **Résistance post-quantique** de bout en bout.

## Hors périmètre (assumé)

- Sécurité de l'endpoint (malware sur la machine du wallet).
- Canaux auxiliaires des implémentations (prototype).
- Économie/gouvernance du consensus (PoS simplifié).

## Limitations du mode transparent (dev) — v0.2

Le mode transparent actuel N'EST PAS le protocole : c'est un échafaudage.
Il ne peut pas vérifier la liaison nullifier↔note, l'autorité de dépense réelle,
ni l'équilibre des montants, et il révèle commitment dépensé, chemin de Merkle et
clé publique (dépenses reliables). La règle de consensus réelle est le statement
STARK (docs/STARK_STATEMENT.md) — P1 à P7. Aucun déploiement, même testnet public,
avant la phase 3.

## Garanties additionnelles exigées (v0.2)

- **Key privacy (IK-CCA)** du chiffrement des notes : une enc_note ne doit pas
  permettre de deviner le destinataire parmi des clés connues (test distingueur prévu).
- **Non-malléabilité des preuves** : la preuve STARK est liée à tx_digest.
- **Versioning d'algorithmes** dans tout transcript et toute sérialisation
  (la migration round-3 → FIPS n'est pas transparente : FIPS 203/204 + errata NIST).
- **Anti-sabotage de notes** : nullifier lié au commitment (nf = PRF_nk(rho ‖ cm)) —
  deux notes de même rho ne partagent plus le même nullifier.

## Security Claims — Phase 3 (validity-only)

Le circuit de la Phase 3 est **validity-only** : il garantit l'**intégrité**
(pas de forge, pas de double dépense, équilibre des montants, cohérence
Merkle/nullifier) mais **PAS la confidentialité**. Tant que la couche
zero-knowledge (jalon séparé « Phase 3z » : masquage trace + DEEP + permutations,
audité) n'est pas livrée :

- une preuve ne cache PAS forcément le témoin (montants, owner, secret) ;
- aucune preuve ne doit être présentée comme `zk` / `private` / `shielded production` ;
- types nommés `ValidityProof` / `ValidityCircuit` ; `ZkProof` réservé à une preuve
  witness-hiding auditée.

Voir `docs/superpowers/specs/2026-07-15-phase3-decision-et-3a0-design.md`.
