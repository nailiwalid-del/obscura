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
cargo test              # crypto, ledger, gadgets, e2e, double dépense, altérations
cargo test --release    # + les preuves STARK du monolithe (gatées --release, cf. monolith::air)
```

## Feuille de route (v0.2 : le STARK est le centre, pas une option)

1. ✅ Primitives crypto hybrides (avec versioning d'algorithmes)
2. ✅ Ledger **transparent de dev** (explicitement non-privé, fonctions `_transparent`)
3. ✅ **Circuit STARK = définition du consensus** (P1–P7 monolithe, Rescue-Prime des
   commitments/Merkle, spend_pk/path retirés, witness-hiding) — reste 3z-c (M-in/N-out)
4. ⬜ Réseau P2P chiffré PQ + Dandelion++ + test de key privacy
5. ⬜ Nœud, wallet CLI, testnet local multi-nœuds

> Phase 3 : intégrité prouvée (P1–P7, monolithe 2-in/2-out) ; depuis 3z-b1 la preuve
> de consensus est **witness-hiding (HVZK dans le modèle de l'oracle aléatoire)** —
> caveat : honnête-vérifieur, prototype non audité (docs/STARK_STATEMENT.md,
> « Argument HVZK »). `ProvedTx` v3 porte les `enc_notes` (scan wallet, liés au digest).
> Reste dans 3z : la généralisation M-in/N-out (3z-c).

**Prototype pédagogique — pas d'audit de sécurité, ne pas utiliser en production.**
