# Sérialisation canonique de `ProvedTx` — design

> Donner à `circuit::ProvedTx` un encodage **wire canonique** (`to_bytes`/`from_bytes`),
> `from_bytes` étant **le point d'entrée réseau qui valide** : c'est là que les bornes
> anti-DoS (`EncNote::within_bounds`, `value < 2^60` via la note, canonicité des digests)
> et le rejet du non-canonique s'appliquent, avant toute désérialisation coûteuse.
> Première pièce du durcissement pré-testnet (#7) ; les autres (`zeroize`, Merkle
> frontier, key-privacy) restent séparées.

## 1. Encodage (injectif, longueurs préfixées pour le variable)

Ordre canonique, `crates/circuit/src/tx.rs` :
```
anchor(32) ‖ nf₁(32) ‖ nf₂(32) ‖ oc₁(32) ‖ oc₂(32) ‖ fee(8 LE) ‖ tx_digest(64)
‖ len(signer)(4 LE) ‖ signer
‖ len(intent_sig)(4 LE) ‖ intent_sig
‖ [ pour j ∈ {0,1} : len(kem_ctⱼ)(4 LE) ‖ kem_ctⱼ ‖ len(enc_noteⱼ)(4 LE) ‖ enc_noteⱼ ]
‖ len(proof)(4 LE) ‖ proof
```
- Digests via `Digest::to_bytes` (32 o) ; `fee`/longueurs en little-endian.
- `signer`/`intent_sig` via `crypto::sig` (`SigPublicKey::to_bytes`, `HybridSignature::to_bytes`).
- `proof` via `winterfell::Proof::to_bytes` (variable, domine la taille ~85 Kio).
- Préfixes de longueur `u32` LE (les tailles réelles sont < 2^32).

## 2. API

```rust
// crates/circuit/src/tx.rs
#[derive(Debug, PartialEq, Eq)]
pub enum TxDecodeError {
    TooShort,          // moins d'octets que le minimum / champ tronqué
    TrailingBytes,     // octets résiduels après la fin (non canonique)
    BadDigest,         // digest non canonique (Digest::from_bytes échoue)
    EncNoteOutOfBounds,// kem_ct/enc_note hors bornes (anti-DoS)
    BadSigner,         // signer/intent_sig invalides
    BadProof,          // Proof::from_bytes échoue
}

impl ProvedTx {
    pub fn to_bytes(&self) -> Vec<u8>;
    pub fn from_bytes(b: &[u8]) -> Result<Self, TxDecodeError>;
}
```
Exporter `TxDecodeError` dans `lib.rs`.

## 3. Validation dans `from_bytes` (thème « Result vs panic »)
- Lecture bornée : chaque prise d'octets vérifie qu'il en reste assez → `TooShort` sinon
  (JAMAIS d'indexation qui pourrait paniquer).
- Digests par `Digest::from_bytes` → `BadDigest` si non canonique.
- Après lecture des 2 `EncNote`, vérifier `EncNote::within_bounds` pour chacun →
  `EncNoteOutOfBounds` (anti-DoS au parse, avant d'allouer/hacher).
- `SigPublicKey::from_bytes`/`HybridSignature::from_bytes` → `BadSigner`.
- `Proof::from_bytes` → `BadProof`.
- À la fin, **exiger que tous les octets soient consommés** → `TrailingBytes` sinon
  (canonicité : une seule sérialisation valide par tx).
- Aucune panique possible sur entrée arbitraire.

## 4. Tests (`crates/circuit/src/tx.rs`, gatés `--release` pour le roundtrip réel)
1. **Roundtrip** : `from_bytes(tx.to_bytes()) == tx` pour une `ProvedTx` valide
   (réutiliser `valid_tx()`). Compare champ à champ (ajouter `PartialEq` sur `ProvedTx`
   et ses champs si nécessaire, ou comparer les `to_bytes`).
2. **Rejets** (peuvent tourner en debug s'ils ne construisent pas de preuve — sinon
   partir d'un `to_bytes` réel puis le corrompre) :
   - tronqué (`b[..b.len()-1]`) → `TooShort` ;
   - octets résiduels (`b` + `vec![0]`) → `TrailingBytes` ;
   - `enc_note` géant / `kem_ct` mauvaise taille (corrompre la longueur préfixée) →
     `EncNoteOutOfBounds` ;
   - digest non canonique (mettre `0xFF..` dans une zone digest) → `BadDigest` ;
   - octets de preuve corrompus → `BadProof`.

## 5. Hors périmètre
- Autres pièces de #7 (`zeroize` sur secrets, panics→Result AILLEURS, Merkle
  frontier/persistant, tests key-privacy IK-CCA).
- Sérialisation du mode transparent (déjà en `serde`, hors consensus).
- Pas de `serde` sur `ProvedTx` (encodage manuel canonique — `serde` ne garantit pas
  l'injectivité/canonicité voulue ici).
