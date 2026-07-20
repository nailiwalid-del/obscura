# Zeroize des secrets — design

> Effacer le matériel de clé de la mémoire au drop (durcissement pré-testnet #7). On
> zeroize tout ce qui est proprement effaçable ; on documente le trou pqcrypto.

## 1. Cibles zeroizées
- **`proved_hash::ShieldedSecret([Felt; 4])`** — le secret MAÎTRE (owner/nk en dérivent).
  `impl Zeroize` + `impl Drop` : écriture VOLATILE de chaque felt à `Felt::ZERO` +
  `compiler_fence` (Felt n'est pas un type `Zeroize` natif → best-effort documenté, mais
  non élidable). `zeroize` est déjà dépendance de proved-hash.
- **`ledger::keys::WalletKeys`** — `Drop` zeroizant `shielded_secret: [u8;32]` et
  `nk: [u8;32]` (`[u8;32]: Zeroize`). `spend`/`receive` : voir §2. Ajouter `zeroize` aux
  deps du ledger.
- **`crypto::aead::{encrypt, decrypt}`** — les deux clés dérivées `[u8;32]` (`k_aes`,
  `k_xc`) sont zeroizées après usage (in-scope, ce sont les clés de chiffrement des
  notes). Ajouter `zeroize` aux deps de crypto.

## 2. Limitation assumée (documentée)
Les `SecretKey` **pqcrypto** (kyber768, dilithium3, dans `KemSecretKey`/`SigKeypair`) ne
sont **PAS** effacées : pqcrypto n'expose pas de zeroize et ne l'implémente pas. Les
moitiés **dalek** (`x25519_dalek::StaticSecret`, `ed25519_dalek::SigningKey`) s'effacent
déjà au drop (dalek est zeroize-aware). → Documenter dans `crypto` (kem.rs/sig.rs) et
CLAUDE.md que la moitié PQ des clés secrètes reste en mémoire jusqu'à réutilisation de
l'allocation ; à revisiter à la **migration FIPS 0x02** (choisir des crates zeroize-aware
ou envelopper les octets). Le secret maître (`shielded_secret`) et les clés AEAD, eux,
sont couverts.

## 3. API
- `ShieldedSecret` : `impl zeroize::Zeroize` (donne `.zeroize()`) + `impl Drop`.
- `WalletKeys` : `impl Drop` (zeroize des deux `[u8;32]`).
- `aead` : `use zeroize::Zeroize;` + `k_aes.zeroize(); k_xc.zeroize();` en fin de fn.

## 4. Tests
- **Observable** : `ShieldedSecret::from_felts(...)`, `.zeroize()`, puis
  `assert_eq!(s.to_bytes(), [0u8; 32])`. Idem un test que `Drop` compile/tourne.
- **Non-régression** : les suites crypto (`aead` roundtrip) et ledger (transparent sous
  `dev-transparent`) restent vertes — les drops/zeroize ne cassent pas le chiffrement ni
  la construction des clés.
- (La mémoire post-drop n'est pas observable en safe Rust : la garantie de non-élision
  repose sur `zeroize` + la revue de code, pas un test runtime.)

## 5. Hors périmètre
- Enveloppement des octets pqcrypto (décision : documenter et accepter).
- Autres pièces de #7 (panics→Result, Merkle frontier, key-privacy IK-CCA).
