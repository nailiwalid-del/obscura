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
- `crates/circuit` : circuit STARK **monolithe** (`monolith/`) — P1–P7 d'une tx
  2-in/2-out en UNE SEULE trace/preuve (201 col × 512 lignes), publics minimaux
  (root, nullifiers, output_commitments, fee), `ProvedTx` v2 — testé, benché
  (≈634 ms génération, ≈1,5 ms vérification, ≈85,3 Kio/preuve). Validity-only
  (pas encore witness-hiding, voir docs/STARK_STATEMENT.md)
- `docs/PROTOCOL.md`, `docs/THREAT_MODEL.md` et `docs/STARK_STATEMENT.md` : spécification de référence
- `cargo test` : suite verte (crypto/ledger/circuit)

## Prochaine étape : PHASE 3z — witness-hiding puis généralisation

Phase 3 validity-only est terminée (statement P1–P7, monolithe, intégration
ledger, bench) — voir le journal de tête de docs/STARK_STATEMENT.md, c'est LA
référence. Reste :
1. **3z-b — witness-hiding** : le monolithe actuel prouve l'intégrité mais fuit
   potentiellement des cellules témoins (winterfell 0.13.1 sans support zk,
   confirmé). **Spike 3z-b0 fait** (`docs/superpowers/specs/2026-07-20-3zb0-spike-rapport.md`) :
   voie tranchée = **lignes de blinding au niveau AIR** (ni fork winterfell ni
   migration), démontrée sur code réel (`crates/zk-spike`). Reste 3z-b1 :
   implémenter l'extension sur le monolithe + argument de sécurité + re-bench (~2×) ;
2. **3z-c — généralisation M-in/N-out** : au-delà du 2-in/2-out figé, empilement
   accru des colonnes (levier de réduction de taille de preuve additionnel).
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
