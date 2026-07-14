# Obscura — monnaie numérique privée post-quantique (prototype, v0.2)

Prototype d'une cryptomonnaie à confidentialité totale, construit sur le principe de
**défense en profondeur** : chaque fonction de sécurité combine deux primitives de
familles mathématiques indépendantes — la sécurité tient si AU MOINS UNE tient.

| Fonction | Primitive 1 | Primitive 2 |
|---|---|---|
| Échange de clés | X25519 (courbes elliptiques) | Kyber768 / ML-KEM (réseaux euclidiens) |
| Signatures | Ed25519 | Dilithium3 / ML-DSA (les DEUX exigées) |
| Chiffrement | AES-256-GCM | XChaCha20-Poly1305 (cascade) |
| Hachage | BLAKE3 | SHA3-256 (concaténés, jamais tronqués) |

## Structure

- `docs/STARK_STATEMENT.md` — **le statement de preuve = la règle de consensus** (P1–P7)
- `docs/THREAT_MODEL.md` — adversaires, garanties, périmètre
- `docs/PROTOCOL.md` — spécification v0.2 (notes, nullifiers, transactions, versioning)
- `crates/crypto` — primitives hybrides : `hash`, `kem`, `sig`, `aead`
- `crates/ledger` — ledger privé : notes engagées, arbre de Merkle, nullifiers, validation

## Modèle de confidentialité (à la Zerocash)

On-chain, il n'y a QUE des commitments (64 o) et des nullifiers (32 o).
Montants, expéditeurs, destinataires : jamais publiés. Le destinataire retrouve
ses notes en scannant le ledger avec sa clé de réception (KEM hybride + AEAD cascade).

## Build & tests

```
cargo test        # 26 tests : primitives, Merkle, paiement e2e, double dépense, altérations
```

## Feuille de route (v0.2 : le STARK est le centre, pas une option)

1. ✅ Primitives crypto hybrides (avec versioning d'algorithmes)
2. ✅ Ledger **transparent de dev** (explicitement non-privé, fonctions `_transparent`)
3. ⬜ **Circuit STARK = définition du consensus** (P1–P7, docs/STARK_STATEMENT.md)
   + migration Rescue-Prime des commitments/Merkle + retrait de spend_pk/path
4. ⬜ Réseau P2P chiffré PQ + Dandelion++ + test de key privacy
5. ⬜ Nœud, wallet CLI, testnet local multi-nœuds

**Prototype pédagogique — pas d'audit de sécurité, ne pas utiliser en production.**
