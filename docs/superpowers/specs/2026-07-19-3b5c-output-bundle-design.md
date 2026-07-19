# 3b5c — Bundle de sortie (Output) par composition

> Phase 3, validity-only. Simplification stricte de 3b5b (Spend) : une note de
> SORTIE n'a ni appartenance ni nullifier — seulement **P7 ∧ P6**.

## Objet

Pour une note de sortie, établir :
- **P7** : `oc = H_NoteCommitment(value ‖ owner ‖ rho ‖ r)` (`oc` = output_commitment public)
- **P6** : `value < 2^60`

## Public vs témoin

| Valeur | Statut |
|---|---|
| `oc` | public (statement) |
| `value` | public (lié à l'équilibre P5 du bundle) |
| `owner`, `rho`, `r` | **témoin** (destinataire, usage unique — aucun lien externe) |

Contrairement à Spend, `owner`/`rho` de la sortie ne se lient à RIEN d'autre → ils
restent témoins ; seul `value` est exposé.

## API

```rust
// crates/circuit/src/output.rs  (réutilise SpendNote comme forme de note prouvée)
pub struct OutputProof { pub value: u64, pub commit: ValidityProof, pub range: ValidityProof }

pub fn prove_output(note: &SpendNote) -> (Digest /*oc*/, OutputProof);
pub fn verify_output(oc: &Digest, value: u64, proof: &OutputProof) -> bool;
```

- commit : `prove_sponge(NoteCommitment, payload, public_idx=[0])` (expose `value`).
- range : `prove_range(value)`.
- verify : `verify_sponge(NoteCommitment, 13, oc, [(0,value)], commit) && verify_range(value, range)`.

## Tests (`--release` : range gaté)

1. Sortie valide acceptée + `oc == rescue::note_commitment(...)`.
2. `value` faux à la vérification → rejet (commitment + range).
3. `oc` falsifié → rejet.

## Hors périmètre

3b5d Bundle (2-in/2-out + équilibre natif + `tx_digest`).
