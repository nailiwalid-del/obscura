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
  2-in/2-out en UNE SEULE trace/preuve (201 col × 1024 lignes dont 40 lignes de
  blinding), publics minimaux (root, nullifiers, output_commitments, fee),
  `ProvedTx` **v3** — **witness-hiding (HVZK en ROM)** depuis 3z-b1 (lignes de
  blinding, gating global `blind_off`, aléa OsRng frais par preuve) — testé,
  benché (≈1477,7 ms génération, ≈3,0 ms vérification, ≈90,5 Kio/preuve).
  Caveat : honnête-vérifieur, prototype non audité (voir docs/STARK_STATEMENT.md,
  « Argument HVZK »). Les gadgets autonomes du crate restent validity-only.
  `ProvedTx` v3 porte les `enc_notes` (enveloppes chiffrées des sorties, scan wallet
  via `ledger::proved_wallet`), liées dans `tx_digest` v3 (anti-substitution) ; P8
  différé, IK-CCA = phase 4. Sérialisation wire **canonique**
  `ProvedTx::{to_bytes, from_bytes}` (+`TxDecodeError`) : `from_bytes` = point
  d'entrée réseau validant (curseur borné sans panique, digests canoniques,
  bornes EncNote anti-DoS, rejet des octets résiduels), pas de serde
- `docs/PROTOCOL.md`, `docs/THREAT_MODEL.md` et `docs/STARK_STATEMENT.md` : spécification de référence
- `cargo test` : suite verte (crypto/ledger/circuit)

## Prochaine étape : durcissement pré-testnet (#7), puis généralisation 3z-c

Phase 3 validity (statement P1–P7, monolithe, intégration ledger, bench) ET
**3z-b witness-hiding sont terminés** — voir le journal de tête de
docs/STARK_STATEMENT.md, c'est LA référence. **3z-b1 fait** : lignes de blinding
au niveau AIR (voie du spike 3z-b0, ni fork winterfell ni migration) — trace
1024, gating global `blind_off`, OsRng frais par preuve, argument HVZK-ROM écrit
(STARK_STATEMENT.md, « Argument HVZK »), bench ≈2× (1477,7 ms / 3,0 ms /
90,5 Kio). Cap actuel (décision utilisateur) : **complétude/cohérence protocole
avant sophistication crypto**. Reste :
1. **Durcissement pré-testnet (#7)** — en cours : sérialisation canonique de
   `ProvedTx` **faite** ; `zeroize` des secrets au drop : spec commitée
   (`2026-07-20-zeroize-secrets-design.md`), implémentation en cours
   (`proved-hash`) ; restent Merkle frontier persistant et tests key-privacy
   IK-CCA (phase 4).
2. **3z-c — généralisation M-in/N-out** : au-delà du 2-in/2-out figé, empilement
   accru des colonnes (levier de réduction de taille de preuve additionnel).
   Statut : la 1re tranche **3z-c1** (refonte segmentée à parité) a été entamée
   puis **parquée** (commit 333e4e4, master restauré sur le monolithe 3z-b1) ;
   design/plan dans docs/superpowers et T1 dans l'historique (aa4076f, 7cceb27)
   pour reprise.
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

- **Features de dev, OFF par défaut** (le build/test nu = surface CONSENSUS seule) :
  `dev-transparent` (ledger : mode transparent non-privé, `apply_transparent`,
  `build_transparent_transaction`, `merkle`/`note` BLAKE3) et `dev-circuits` (circuit :
  sous-circuits autonomes `prove_*`/`verify_*`). La suite complète = `cargo test
  --all-features --release`. Ne jamais ajouter de dépendance du consensus vers du code
  gaté (l'invariant « défaut = consensus seul » doit tenir). Les modules gadgets restent
  compilés (le monolithe réutilise leurs helpers `pub(crate)`) ; seules leurs entrées
  publiques standalone sont gatées.
- Migration vers `pqcrypto-mlkem`/`pqcrypto-mldsa` (FIPS 203/204 finaux) : ce n'est
  PAS un simple changement d'import. FIPS 203/204 diffèrent de Kyber/Dilithium round-3
  (dérivation, encodages, errata NIST) → c'est une **nouvelle version d'algo `0x02`**
  qui cohabite avec `0x01`, pas un remplacement (voir PROTOCOL.md, versioning). Prévoir
  crates FIPS, byte de version, et vecteurs de test croisés.
- **Zeroize (durcissement #7)** : `ShieldedSecret` (volatile non élidable),
  `WalletKeys::{shielded_secret, nk}` et les clés AEAD dérivées s'effacent au drop ;
  les moitiés dalek (X25519/Ed25519) aussi. ⚠️ Les `SecretKey` pqcrypto (Kyber768/
  Dilithium3) NE s'effacent PAS (limitation crate) — à fermer à la migration FIPS 0x02.
- Prototype pédagogique : pas d'audit, ne pas utiliser en production.

## Conventions

- Code et commentaires : les commentaires/docs sont en français
- Tests unitaires dans chaque module + e2e dans `crates/ledger/tests/`
- Tout nouveau hash/PRF doit être séparé par domaine et non tronqué
