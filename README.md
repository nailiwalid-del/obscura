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
cargo test --release                 # SURFACE CONSENSUS seule : monolithe, ProvedTx, ledger prouvé
cargo test --release --all-features   # + mode transparent (dev) et sous-circuits standalone
```

Par défaut, seule la **surface consensus** est compilée. Les chemins de développement sont
derrière des features **désactivées par défaut** — pour ne pas les confondre avec le
consensus : `dev-transparent` (ledger transparent, non-privé) et `dev-circuits`
(sous-circuits autonomes `prove_*`/`verify_*`). Les preuves STARK sont gatées `--release`.

## Feuille de route (v0.2 : le STARK est le centre, pas une option)

1. ✅ Primitives crypto hybrides (avec versioning d'algorithmes)
2. ✅ Ledger **transparent de dev** (explicitement non-privé, fonctions `_transparent`)
3. ✅ **Circuit STARK = définition du consensus** (P1–P7 monolithe, Rescue-Prime des
   commitments/Merkle, spend_pk/path retirés, witness-hiding) — reste 3z-c (M-in/N-out)
4. ✅ Réseau P2P chiffré PQ + Dandelion++ + test de key privacy
5. ✅ Nœud, wallet CLI, testnet local multi-nœuds
6. 🟡 **Finalité** : bloc + application atomique + convergence entre nœuds ✅ ;
   élection du producteur et synchronisation wallet ↔ nœud ⬜

> Phase 3 : intégrité prouvée (P1–P7, monolithe 2-in/2-out) ; depuis 3z-b1 la preuve
> de consensus est **witness-hiding (HVZK dans le modèle de l'oracle aléatoire)** —
> caveat : honnête-vérifieur, prototype non audité (docs/STARK_STATEMENT.md,
> « Argument HVZK »). `ProvedTx` v3 porte les `enc_notes` (scan wallet, liés au digest).
> Reste dans 3z : la généralisation M-in/N-out (3z-c).

> Phases 4–5 : transport PQ 3 passes (forward secrecy, identités masquées), pairs
> anti-eclipse, mempool ordonné par coût, Dandelion++, nœud réel et testnet local.
> Trois binaires : `obscura-node`, `obscura-demo`, `obscura-wallet`.

## Trous de complétude connus

Une transaction devient maintenant **définitive** : elle entre dans un bloc (lot
ordonné, chaîné à son parent), le bloc s'applique **atomiquement**, et deux nœuds qui
acceptent la même chaîne convergent vers la même racine de Merkle — vérifié sur de
vraies sockets (`crates/node/tests/finalite.rs`).

Restent deux manques, tous deux consignés en détail dans docs/THREAT_MODEL.md :

1. **Personne n'a autorité pour sceller.** Aucune élection de producteur n'existe :
   tout nœud lancé avec `--sceller` fabrique des blocs. L'ordre obtenu est *convenu*
   entre participants coopératifs, pas *défendu* contre un adversaire. Testnet local
   uniquement.
2. **Un wallet peut payer, pas recevoir.** Il lui faut rejouer l'historique des
   commitments pour connaître ses index ; le nœud n'en conserve pas la trace
   (`MerkleFrontier` = bord droit seulement) et n'a rien à servir.

Et une conséquence structurelle à connaître : **aucune réorganisation n'est
possible**. L'état est append-only de bout en bout ; supporter les réorganisations
exigerait de redessiner le ledger, pas d'ajouter une fonction.

**Prototype pédagogique — pas d'audit de sécurité, ne pas utiliser en production.**
