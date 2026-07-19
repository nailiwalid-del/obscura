# 3b5d — Transaction prouvée (`ProvedTx`) : le validateur complet

> Phase 3, validity-only. DERNIÈRE tranche de l'assemblage 3b5. Assemble
> `prove_key` (3b5a) + 2 `prove_spend` (3b5b) + 2 `prove_output` (3b5c) + équilibre
> natif + `tx_digest` → le **validateur de transaction complet** 2-in/2-out.

## 1. Forme fixe

2 entrées / 2 sorties, un seul propriétaire (une clé). Profondeur d'arbre = paramètre
`depth` (32 en consensus). Extensible plus tard ; figé ici pour un seul plan.

## 2. Ce que `verify_tx` établit (P1–P7 pour la tx entière)

- **Clé** : `verify_key(owner, nk, ·)` → `owner`/`nk` d'un même secret (P2 ∧ P4).
- **Chaque entrée i** : `verify_spend(root, owner, nk, depth, spends[i])` → P7ᵢₙ ∧ P1 ∧
  P3 ∧ P6, avec `owner`/`nk` LIÉS à la clé (mêmes valeurs passées). `nullifiers[i] =
  spends[i].nullifier`.
- **Chaque sortie j** : `verify_output(output_commitments[j], output_values[j],
  outputs[j])` → P7 ∧ P6.
- **Équilibre (P5, natif)** : `Σ spends[i].value == Σ outputs[j].value + fee` (montants
  publics → vérif native ; P5 est prouvé isolément en 3b3b, redondant à re-STARKer ici).
- **`tx_digest` (non-rejeu)** : recalculé par dual_hash sur l'encodage canonique de
  TOUTES les données publiques et comparé à `tx.tx_digest`. La signature hybride
  (hors périmètre, côté ledger) signe ce digest → lie la preuve à CETTE tx.

## 3. Encodage canonique de `tx_digest`

`dual_hash("obscura/proved-tx/v1", bytes)` où `bytes` concatène, dans cet ordre fixe :
`root(32)` ‖ pour chaque entrée `nullifier(32) ‖ cm_in(32) ‖ rho(32) ‖ value(8 LE)` ‖
pour chaque sortie `oc(32) ‖ value(8 LE)` ‖ `owner(32) ‖ nk(32) ‖ fee(8 LE)`.
Injectif (tailles fixes). `dual_hash` (BLAKE3‖SHA3, hash consensus) est correct ici :
le `tx_digest` est un objet consensus, pas prouvé en circuit.

## 4. API

```rust
// crates/circuit/src/tx.rs  (dépend de circuit + proved_hash + crypto)
pub struct ProvedInput { pub note: SpendNote, pub path: Vec<Digest>, pub index: u64 }

pub struct ProvedTx {
    pub owner: Digest, pub nk: Digest,
    pub key: ValidityProof,
    pub spends: [SpendProof; 2],
    pub outputs: [OutputProof; 2],
    pub output_commitments: [Digest; 2],
    pub fee: u64,
    pub tx_digest: [u8; 64],
}

/// Construit la tx prouvée. `outputs` = notes de sortie (destinataires). Précondition :
/// notes d'entrée possédées par `secret`, chemins cohérents avec un même arbre,
/// équilibre respecté, montants < 2^60.
pub fn prove_tx(secret: &ShieldedSecret, inputs: [ProvedInput; 2],
                outputs: [SpendNote; 2], fee: u64) -> (Digest /*root*/, ProvedTx);

/// Vérifie la tx contre l'arbre public `root` (profondeur `depth`).
pub fn verify_tx(root: &Digest, depth: usize, tx: &ProvedTx) -> bool;
```

`prove_tx` : dérive `(owner, nk)` par `prove_key` ; les notes d'entrée DOIVENT avoir
cet `owner` (sinon verify échoue via la liaison du commitment). Chaque `prove_spend`
retourne une racine ; toutes doivent être égales → `root` retourné.

## 5. Tests (`--release`)

Construire un petit arbre (profondeur modeste, ex. 4) contenant les 2 cm d'entrée,
2 notes de sortie équilibrées.
1. **Tx valide** acceptée ; `tx_digest` reproductible.
2. **Déséquilibre** (`Σin ≠ Σout+fee`) → rejet (équilibre natif).
3. **Entrée d'un autre owner** (note owner ≠ owner de la clé) → rejet (liaison commitment).
4. **nk incohérent** (clé prouvée avec s, spend avec nk d'un autre s) → rejet.
5. **`output_commitment` faux** → `verify_output` rejette.
6. **`tx_digest` falsifié** → rejet.
7. **Racine erronée** → `verify_spend` rejette.

## 6. Hors périmètre → 3c / 3z

- `apply_proved_tx` sur `ledger::state` (dépense des nullifiers, insertion des
  commitments) = 3c. Signature hybride sur `tx_digest` = ledger. Bench = 3d.
- Généralisation M-in/N-out, witness-hiding, monolithe privé = Phase 3z.
