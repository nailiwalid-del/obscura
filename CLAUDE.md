# Obscura — contexte projet pour Claude Code

Monnaie numérique privée post-quantique. Prototype Rust, phases 1-2 terminées et testées.

## Principe directeur (décision utilisateur, ne pas remettre en cause)

Défense en profondeur : chaque fonction de sécurité combine 2 primitives de familles
mathématiques indépendantes (la sécurité tient si l'une des deux tient).
KEM = X25519+Kyber768 · Sig = Ed25519 ET Dilithium3 · AEAD = cascade XChaCha20∘AES-GCM ·
Hash = BLAKE3‖SHA3-256 jamais tronqué. Séparation de domaine partout ("obscura/<usage>/v1").

## État

- `crates/crypto` : hash, kem, sig, aead — testés
- `crates/ledger` : notes engagées, nullifiers, Merkle (BLAKE3, prof. 16), tx, validation — testés
- `docs/PROTOCOL.md` et `docs/THREAT_MODEL.md` : spécification de référence
- `cargo test` : 26 tests verts

## Prochaine étape : PHASE 3 — le circuit STARK EST la règle de consensus

Le statement exact (P1–P7) est dans docs/STARK_STATEMENT.md — c'est LA référence.
Le mode transparent actuel (fonctions `_transparent`) est un échafaudage de dev :
il ne définit pas la validité. Travaux phase 3 :
1. migrer commitments + Merkle + PRF nullifier vers Rescue-Prime (winterfell),
   EN MÊME TEMPS que le circuit (arbre consensus = arbre prouvé) ;
2. implémenter le circuit P1–P7, preuve liée à tx_digest ;
3. nouveau format de tx : { proof, root, nullifiers, output_commitments, enc_notes, fee } ;
4. benchmarker taille/temps de preuve (2-in/2-out, profondeur 32).
Puis phase 4 (P2P PQ + Dandelion++ + test key privacy) et phase 5 (nœud/wallet/testnet).

## Décisions v0.2 (revue intégrée — ne pas régresser)

- Nullifier lié au commitment : nf = PRF_nk(rho ‖ cm), domaine "obscura/nullifier/v2"
- Identité shielded : secret racine `shielded_secret` (32 o, jamais publié, témoin
  STARK) ; `owner = H_owner(secret)` et `nk = H_nk(secret)` sont des hachages PROUVÉS
  (Rescue-Prime avec le circuit), pas des KDF wallet. La signature hybride `spend` =
  enveloppe d'intention / anti-malléabilité, PAS autorisation d'ownership tant qu'elle
  n'est pas liée au secret (phase 3). Spec :
  `docs/superpowers/specs/2026-07-14-hierarchie-shielded-secret-design.md`
- Merkle : profondeur 32 consensus / 16 dev (`MerkleTree::consensus()` / `new_dev()`)
- Versioning d'algos partout : byte 0x01 = round-3 en tête des sérialisations
  KEM/sig ; la migration FIPS 203/204 = nouvelle version 0x02, PAS un simple import
- spend_pk publié = fuite acceptée UNIQUEMENT en mode transparent dev
- Key privacy (IK-CCA) exigée pour enc_note — test distingueur à écrire en phase 4
- Hash consensus (BLAKE3‖SHA3) ≠ hash prouvé (Rescue-Prime, migration avec le circuit)

## Notes de build

- Migration vers `pqcrypto-mlkem`/`pqcrypto-mldsa` (FIPS 203/204 finaux) : ce n'est
  PAS un simple changement d'import. FIPS 203/204 diffèrent de Kyber/Dilithium round-3
  (dérivation, encodages, errata NIST) → c'est une **nouvelle version d'algo `0x02`**
  qui cohabite avec `0x01`, pas un remplacement (voir PROTOCOL.md, versioning). Prévoir
  crates FIPS, byte de version, et vecteurs de test croisés.
- Prototype pédagogique : pas d'audit, ne pas utiliser en production.

## Conventions

- Code et commentaires : les commentaires/docs sont en français
- Tests unitaires dans chaque module + e2e dans `crates/ledger/tests/`
- Tout nouveau hash/PRF doit être séparé par domaine et non tronqué
