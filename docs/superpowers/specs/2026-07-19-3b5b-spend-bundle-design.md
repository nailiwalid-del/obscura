# 3b5b — Bundle de dépense (Spend) par COMPOSITION liée

> **Phase 3, validity-only.** Deuxième tranche de l'assemblage 3b5. Décision d'archi
> (AskUserQuestion 2026-07-19) : **composition liée** — pas de mini-monolithe. Un
> STARK validity-only n'étant PAS witness-hiding (il fuit ses témoins), garder
> `cm_in` hors des entrées publiques ne le cache pas ; l'unlinkability et le circuit
> fusionné rejoignent la **Phase 3z**. Ici on LIE les preuves déjà bâties par des
> valeurs publiques partagées.

## 1. Objet

Pour UNE note d'entrée, établir P7ᵢₙ ∧ P1 ∧ P3 ∧ P6 en composant les preuves
existantes, liées par des valeurs publiques partagées :

- **P7ᵢₙ** commitment : `cm_in = H_NoteCommitment(value ‖ owner ‖ rho ‖ r)`
- **P1** appartenance : `cm_in ∈ arbre(root)`
- **P3** nullifier : `nf = H_nullifier(nk ‖ rho ‖ cm_in)`
- **P6** range : `value < 2^60`

## 2. Public vs témoin (validity-only)

| Valeur | Rôle | Statut |
|---|---|---|
| `root` | statement (arbre) | public (entrée) |
| `nf` | statement (nullifier) | public (entrée) |
| `owner` | lié à la preuve de clé (P2) — autorité de dépense | public (entrée) |
| `nk` | lié à la preuve de clé (P4) | public (entrée) |
| `value` | lié à l'équilibre (P5, bundle) | public (dans `SpendProof`) |
| `cm_in` | lie commitment ↔ membership ↔ nullifier | public (dans `SpendProof`) |
| `rho` | lie commitment ↔ nullifier | public (dans `SpendProof`) |
| `r`, `path`, `index` | usage unique / chemin | **témoin** |

`owner`/`nk` viennent du bundle (sortie de `prove_key`, 3b5a). `r` reste caché
(usage unique), de même que le chemin de Merkle (mais `cm_in` public → « quelle note »
n'est PAS caché ici — c'est assumé, l'unlinkability = 3z).

## 3. Mécanique de liaison (le cœur)

Chaque sous-preuve EXPOSE en payload public les positions partagées ; `verify_spend`
passe la MÊME valeur partout → liaison sound (données publiques, pas de témoin caché
à lier — le cas du secret maître, lui, est déjà traité en 3b5a).

- **Commitment** : `prove_sponge(NoteCommitment, [value,owner,rho,r], public_idx=0..9)`
  → expose `value` (idx 0), `owner` (1..5), `rho` (5..9) ; `r` (9..13) témoin.
  Digest public = `cm_in`.
- **Membership** : `prove_membership(cm_in, path, index)` (leaf_digest public). Liaison :
  `verify_membership(root, 32, ·)` **ET** `mp.leaf_digest == merkle::leaf(cm_in)` (le
  vérifieur recalcule le leaf natif ; collision-résistance → même `cm_in`).
- **Nullifier** : `prove_sponge(Nullifier, [nk,rho,cm_in], public_idx=0..12)` → nf public
  = `nf`. Liaison : les 3 digests publics == `nk`/`rho`/`cm_in` déjà liés.
- **Range** : `verify_range(value, ·)` (lie `value < 2^60`, `value` public).

## 4. API

```rust
// crates/circuit/src/spend.rs  (dépend de circuit + proved_hash, PAS de crypto)
pub struct SpendNote { pub value: u64, pub owner: Digest, pub rho: Digest, pub r: Digest }

pub struct SpendProof {
    pub cm_in: Digest, pub value: u64, pub rho: Digest, pub nullifier: Digest,
    pub commit: ValidityProof,
    pub membership: MembershipProof,
    pub nf_proof: ValidityProof,
    pub range: ValidityProof,
}

/// Retourne (root prouvé, SpendProof). Le bundle vérifie `root == tx.root`.
pub fn prove_spend(note: &SpendNote, path: &[Digest], index: u64, nk: &Digest)
    -> (Digest, SpendProof);

pub fn verify_spend(root: &Digest, owner: &Digest, nk: &Digest, spend: &SpendProof) -> bool;
```

`note.owner` sert au commitment ; `verify_spend` reçoit `owner` (du statement/clé) et
la liaison est que le commitment a été prouvé AVEC cet owner (payload public).

## 5. Tests (à générer en `--release` : membership + range sont gatés)

1. **Différentiel/heureux** : `prove_spend` d'une note dans un arbre construit
   (`merkle::root`), `verify_spend(root, owner, nk, ·)` accepte ; `cm_in`/`nf`
   cohérents avec `proved_hash` (`note_commitment`, `hash(Nullifier,·)`).
2. **Mauvais owner** (≠ owner de la note) → commitment ne lie pas → rejet.
3. **Mauvais nk** → nullifier ne lie pas → rejet.
4. **Mauvaise racine** (note pas dans l'arbre) → membership rejette.
5. **Nullifier falsifié** → rejet.
6. **`cm_in` incohérent** (membership sur un autre cm) → `leaf_digest != leaf(cm_in)` → rejet.

## 6. Hors périmètre

- 3b5c Output (P6+P7 par sortie), 3b5d Bundle (2-in/2-out + équilibre natif +
  `tx_digest`). Witness-hiding / cm_in caché = Phase 3z.

## 7. Livrables

`crates/circuit/src/spend.rs` + exports + tests (`--release`) verts, 0 warning, note
`STARK_STATEMENT.md`, mémoire, mergé + poussé.
