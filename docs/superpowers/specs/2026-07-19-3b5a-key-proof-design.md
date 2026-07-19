# 3b5a — Preuve de clé (P2 + P4 liés par un secret partagé)

> **Phase 3, validity-only.** Première tranche de l'assemblage 3b5. Établit
> **en circuit** que `owner` et `nk` dérivent d'UN SEUL `shielded_secret`, ce que la
> composition pure de preuves séparées ne peut pas faire de façon sound (voir §1).

## 1. Pourquoi ce circuit existe (le mur de liaison)

Les 7 propriétés P1–P7 sont prouvables isolément (3a2b→3b4). L'assemblage 3b5 doit
les faire **partager des témoins**. Certains témoins partagés doivent rester
**cachés** et ne peuvent donc PAS être liés par une valeur publique :

- **`shielded_secret` (s)** : P2 prouve `owner = H_owner(s₁)`, P4 prouve
  `nk = H_nk(s₂)`. Rien ne force `s₁ = s₂` si les deux preuves sont séparées. Rendre
  `s` public est **exclu** (secret maître : le publier = quiconque forge). Donc
  **P2 ∧ P4 dérivés d'un même secret ne se lient que dans UNE trace** partageant les
  cellules de `s`.

Conséquence : l'unité *sound* de composition n'est pas « une propriété » mais un
**circuit d'action** (à la Zcash) — une petite trace à témoin partagé. 3b5 se
décompose donc en : **3b5a Key (P2+P4)**, 3b5b Spend (P1+P3+P6+P7ᵢₙ, par entrée),
3b5c Output (P6+P7, par sortie), 3b5d Bundle (câblage public + équilibre +
`tx_digest`). Cette tranche = **3b5a**.

## 2. Énoncé (statement) de 3b5a

```
Entrées PUBLIQUES :
  owner   digest (4 Felts)  = H_owner(shielded_secret)
  nk      digest (4 Felts)  = H_nk(shielded_secret)

Témoin PRIVÉ :
  shielded_secret  s (4 Felts)  — JAMAIS assertée à une valeur publique

La preuve établit :
  owner = H_owner(s)  ∧  nk = H_nk(s)   pour LE MÊME s
```

`owner` et `nk` sont des sorties publiques ; `s` reste témoin. La liaison
(`même s`) est le cœur de la tranche.

## 3. Conception de l'AIR

Deux éponges B=1 (owner et nk) partageant le secret, dans **une seule trace**.

- Chaque dérivation est une éponge `Rp64_256` d'un bloc (payload `s` = 4 Felts →
  préambule 8 = 1 bloc → 8 lignes, UNE permutation), identique à 3a2b, seul le
  **tag de domaine** diffère (`Owner=1` vs `Nk=2`).
- **Disposition parallèle** : largeur de trace = 2 blocs d'état côte à côte
  (`owner_state` cols `0..12`, `nk_state` cols `12..24`), longueur 8. Le même
  ordonnancement de rondes (colonnes périodiques ARK partagées) s'applique aux deux
  blocs en lockstep. Contrainte de ronde par bloc = celle de 3a2b (meet-in-the-middle,
  degré `ALPHA=7`, `new(7)` — les ARK sont additionnées dans la S-box, pas de
  multiplication par un masque).
- **Contrainte de liaison** : les 4 cellules du secret occupent, à la ligne 0, les
  mêmes positions de rate relatives dans les deux blocs (préambule `[V, tag, LEN,
  s0..s3, PAD_ONE]`, `RATE_START=4` → `s0..s3` aux colonnes `7,8,9,10` du bloc,
  `PAD_ONE` en `11`). Une contrainte de
  transition **gatée par un flag d'init périodique** (1 à la ligne 0) impose
  `owner_state[7+k] − nk_state[(12)+7+k] = 0` pour `k = 0..3`. Degré 1 × flag
  périodique → `with_cycles(1, [8])`. C'est CETTE contrainte qui prouve « même `s` ».

### Assertions
- Ligne 0, bloc owner : capacité `[8,0,0,0]` + `V=1`, `tag=1 (Owner)`, `LEN=4`,
  `PAD_ONE=1` (constantes publiques). Les cellules `s0..s3` (cols 7..10) **non
  assertées**.
- Ligne 0, bloc nk : idem avec `tag=2 (Nk)`. `s0..s3` **non assertées**.
- Ligne 7 : `owner` = `owner_state[4..8]` (public), `nk` = `nk_state[4..8]` (public).

### Ce qui garantit la soundness de la liaison
La contrainte de liaison force les secrets des deux blocs égaux à la ligne 0 ; aucune
des deux copies n'est assertée à une valeur publique → `s` reste libre/caché, mais
UNIQUE. Un prouveur ne peut pas utiliser `s₁ ≠ s₂`.

## 4. Référence hors-circuit (le juge du différentiel)

`proved_hash::rescue::hash` existe déjà. Le juge : pour tout `s`,
`(owner, nk)` prouvés == `(rescue::hash(Owner, s), rescue::hash(Nk, s))`.
Ajouter éventuellement `proved_hash::keys`-style helper si utile (sinon direct).

## 5. API

```rust
// crates/circuit/src/key.rs
pub fn prove_key(secret: &ShieldedSecret) -> (Digest /*owner*/, Digest /*nk*/, ValidityProof);
pub fn verify_key(owner: &Digest, nk: &Digest, proof: &ValidityProof) -> bool;
```

Export depuis `circuit::lib`.

## 6. Tests (différentiel impitoyable)

1. **Différentiel** : `prove_key(s)` → `(owner, nk)` == `(rescue::hash(Owner, s),
   rescue::hash(Nk, s))`, et `verify_key(owner, nk, proof)` accepte. Plusieurs `s`.
2. **owner altéré** → rejeté ; **nk altéré** → rejeté.
3. **Liaison (white-box)** : construire à la main une trace où les deux blocs
   utilisent des secrets DIFFÉRENTS (owner de `s`, nk de `s'≠s`) et vérifier que la
   preuve est **rejetée** (la contrainte de liaison mord). Si la construction
   manuelle d'une trace invalide est trop lourde, se rabattre sur un argument
   documenté + le fait que verify recalcule les deux hachages indépendamment.
4. Non-régression : `owner`/`nk` produits == ceux de `prove_owner`/`prove_nk` isolés
   (même `s`).

Le sponge n'a pas de colonne témoin constante problématique (l'état évolue) → **les
preuves tournent en DEBUG** (comme 3a2b/3b1/3b4), pas besoin de `--release`.

## 7. Hors périmètre (différé)

- Spend/Output/Bundle (3b5b/c/d), `tx_digest`, équilibre inter-actions.
- Witness-hiding (Phase 3z). Ici `owner`/`nk` sont publics ; seul `s` est témoin.

## 8. Livrables

`crates/circuit/src/key.rs` + exports + tests verts (workspace debug), 0 warning,
note de progression dans `STARK_STATEMENT.md`, mémoire projet, mergé + poussé sur
`master`.
