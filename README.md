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
   synchronisation wallet ↔ nœud ✅ (le wallet REÇOIT) ; élection du producteur ⬜

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

Le wallet SAIT désormais **recevoir** : `obscura-wallet synchroniser --noeud <ip:port>`
rejoue l'historique des sorties servi par un nœud archiviste, retrouve les index des
notes, découvre les paiements reçus et récupère la monnaie rendue — le cycle payer →
sceller → recevoir → redépenser est exercé de bout en bout sur de vraies sockets
(`crates/node/tests/cycle_wallet.rs`).

Restent des manques, tous consignés en détail dans docs/THREAT_MODEL.md :

1. **Personne n'a autorité pour sceller.** Aucune élection de producteur n'existe :
   tout nœud lancé avec `--sceller` fabrique des blocs. L'ordre obtenu est *convenu*
   entre participants coopératifs, pas *défendu* contre un adversaire. Testnet local
   uniquement.
2. **Le nœud qui sert l'historique en apprend long, et peut MENTIR PAR OMISSION.** Il
   voit l'IP du wallet, la CADENCE de ses demandes et sa POSITION de chaîne ; et taire
   une sortie donne une chaîne parfaitement close dont la racine est celle qu'il annonce
   — le paiement omis reste invisible. S'en prémunir exige des identifiants de blocs
   venus d'AILLEURS (plusieurs nœuds, point de contrôle hors bande). Servir l'historique
   est en outre un rôle d'ARCHIVISTE coûteux et optionnel (`obscura-node --archiver`,
   ≈1,4 Kio/sortie, jamais élagué) : un nœud qui ne l'active pas est valide mais ne peut
   pas amorcer de wallet.
3. **La monnaie ne naît que dans la GENÈSE**, et il n'y a pas de coinbase. La règle de
   consensus est `hauteur > 0 ⇒ aucune émission` : c'est ce qui empêche l'inflation
   d'être *diffusée et acceptée*. Une chaîne s'amorce donc sur un bloc 0 paramétré
   (`obscura-node --genese <fichier>`, échec franc s'il manque) et sa monnaie initiale
   est fixée une fois pour toutes. Une récompense de producteur supposerait d'abord une
   règle qui BORNE le montant émis — or ce montant est ce que le chiffrement cache.

Et une conséquence structurelle à connaître : **aucune réorganisation n'est
possible**. L'état est append-only de bout en bout ; supporter les réorganisations
exigerait de redessiner le ledger, pas d'ajouter une fonction.

**Prototype pédagogique — pas d'audit de sécurité, ne pas utiliser en production.**
