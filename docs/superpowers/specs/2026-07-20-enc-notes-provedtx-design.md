# enc_notes dans ProvedTx (v3) — design

> Réintégrer les **chiffrés de notes** (`enc_notes`) dans la transaction PROUVÉE, pour
> que les destinataires puissent scanner la chaîne, et les **lier dans `tx_digest`**
> (anti-substitution par un relais). Changement **tx/ledger/wallet** — **aucun
> changement d'AIR** (P8 différé, position Sapling). Cible protocole : `docs/PROTOCOL.md`
> (`Tx { proof, root, nullifiers, output_commitments, enc_notes, fee }`).

## 1. Problème

`circuit::ProvedTx` (chemin de consensus) ne porte PAS d'`enc_notes` — un wallet réel ne
peut donc pas scanner les sorties prouvées pour retrouver ses notes. Le mode transparent
du ledger a déjà tout le mécanisme (`TxOutput { commitment, kem_ct, enc_note }`,
`create_output`/`scan_output`, chiffrement `kem::encapsulate` + `aead::encrypt`, déjà lié
au digest transparent). Il faut le porter au chemin prouvé. Enjeu crypto : sans liaison
dans `tx_digest`, un relais pourrait remplacer les enc_notes par du garbage sans casser
la preuve.

## 2. Décisions (utilisateur)

- **Bundles opaques** : `prove_tx` reçoit des `EncNote` **déjà chiffrés** et les lie ; le
  crate `circuit` ne fait PAS de chiffrement KEM (couche propre, wallet responsable).
- **P8 différé** (position Sapling) : NE PAS prouver en circuit que `enc_note` déchiffre
  vers la note engagée. Un expéditeur malveillant ne lèse que son destinataire (fonds
  inutilisables), ne crée pas de monnaie. L'`aad = commitment` donne déjà un lien crypto
  partiel. C'est déjà la décision de `docs/STARK_STATEMENT.md`.

## 3. Type `EncNote` (dans `circuit`)

```rust
// crates/circuit/src/tx.rs (ou un petit module), donnée PURE (pas de logique crypto)
#[derive(Clone)]
pub struct EncNote {
    pub kem_ct: Vec<u8>,   // ciphertext KEM (le destinataire décapsule)
    pub enc_note: Vec<u8>, // aead(ss, aad = commitment de sortie, note)
}
```
Placé dans `circuit` (pas `ledger`) : `ProvedTx` y vit et `ledger` dépend de `circuit`
(mettre `EncNote` dans `ledger` créerait un cycle `circuit → ledger → circuit`). Au
niveau circuit, `EncNote` est **opaque** (des octets liés au digest) ; le chiffrement/
déchiffrement est côté ledger/wallet.

## 4. `ProvedTx` v3 et `tx_digest` v3

- `circuit::ProvedTx` gagne `pub enc_notes: [EncNote; 2]`.
- `prove_tx(secret, inputs, outputs, fee, intent, enc_notes: [EncNote; 2]) -> (Digest, ProvedTx)`
  reçoit les bundles chiffrés et les lie dans le digest.
- `TX_DOMAIN = "obscura/proved-tx/v3"`, `INTENT_DOMAIN = "obscura/proved-tx-intent/v3"`.
- **Encodage canonique v3** = v2 (`root(32) ‖ nf₁(32) ‖ nf₂(32) ‖ oc₁(32) ‖ oc₂(32) ‖
  fee(8 LE) ‖ signer`) **PUIS, pour chaque sortie j ∈ {0,1}** :
  `len(kem_ctⱼ)(8 LE) ‖ kem_ctⱼ ‖ len(enc_noteⱼ)(8 LE) ‖ enc_noteⱼ`. Injectif
  (longueurs préfixées, même motif que le digest transparent). `dual_hash` (hash
  consensus). L'ordre suit celui des `output_commitments`.
- **Anti-substitution** : `verify_tx` recalcule le digest en incluant les enc_notes ;
  `apply_proved_tx` vérifie la signature d'intention sur ce digest. Un relais qui échange
  un enc_note change le digest → la signature échoue (`InvalidSignature`), et
  `verify_tx` rejette déjà sur `expected != tx.tx_digest`.

## 5. `verify_tx` et ledger

- `verify_tx(root, depth, tx)` : recompose `tx_digest` v3 (incluant enc_notes),
  compare. La **preuve STARK est inchangée** — enc_notes = digest-only, PAS d'entrée de
  circuit (P8 différé). Le monolithe et son AIR ne bougent pas.
- `apply_proved_tx` : inchangé dans sa logique ; le digest (donc la signature
  d'intention) couvre désormais enc_notes. Le ledger relaie/stocke les enc_notes pour le
  scan wallet.

## 6. Helpers wallet (dans `ledger`, réutilisent l'existant)

```rust
// crates/ledger — réutilisent kem::encapsulate/decapsulate + aead::encrypt/decrypt
pub fn encrypt_note(recipient_kem_pk: &kem::KemPublicKey, commitment: &Digest, note: &Note)
    -> circuit::EncNote;               // (kem_ct, ss) = encapsulate ; enc_note = aead(ss, aad=commitment, note)
pub fn scan_proved_output(wallet: &WalletKeys, commitment: &Digest, e: &circuit::EncNote)
    -> Option<Note>;                   // decapsulate → decrypt(aad=commitment) → vérifie commitment+owner
```
Recopient la logique de `create_output`/`scan_output` transparents. DRY souhaitable : le
mode transparent PEUT converger sur `encrypt_note`/`scan` (mais sans casser l'API
transparente existante — convergence opportuniste, pas une réécriture).

## 7. Hors périmètre

- **P8** (prouver enc_note ↔ commitment en circuit) : différé. Documenté (Sapling).
- **Key privacy IK-CCA** : test distingueur = **phase 4** (CLAUDE.md). Noté, non écrit ici.
- **Généralisation M/N** : enc_notes reste `[_; 2]` (forme 2-out figée) ; la
  généralisation suivra 3z-c.

## 8. Tests

1. **Roundtrip prouvé** : construire une ProvedTx avec 2 sorties chiffrées vers 2
   destinataires ; chacun `scan_proved_output` retrouve SA note (commitment + owner
   vérifiés) ; un tiers échoue à déchiffrer.
2. **Anti-substitution** : dans une ProvedTx valide, remplacer un `enc_note` (ou `kem_ct`)
   par du garbage → `verify_tx` rejette (digest ≠) ET `apply_proved_tx` rejette
   (`InvalidProof`/`InvalidSignature`).
3. **Non-régression** : les tests ProvedTx (`tx.rs`) et ledger (`apply_proved_tx`,
   double-dépense, etc.) passent avec le digest v3 (mettre à jour les constructions de tx
   de test pour fournir des enc_notes ; le contenu peut être un chiffrement réel vers une
   clé de test).
4. **e2e ledger** : appliquer une ProvedTx portant ses enc_notes ; vérifier que les
   sorties insérées + enc_notes permettent au destinataire de scanner.

## 9. Fichiers

- `crates/circuit/src/tx.rs` : `EncNote`, `ProvedTx` v3, `tx_digest_bytes` v3,
  `prove_tx`/`verify_tx`, `TX_DOMAIN`/`INTENT_DOMAIN` v3.
- `crates/ledger/src/…` : `encrypt_note`/`scan_proved_output` (réutilisent l'existant),
  `apply_proved_tx` (inchangé sauf passage des enc_notes déjà dans `ProvedTx`).
- `crates/circuit/src/lib.rs` : export `EncNote`.
- `docs/STARK_STATEMENT.md`/`PROTOCOL.md` : note « enc_notes liés dans tx_digest v3,
  P8 toujours différé ».
