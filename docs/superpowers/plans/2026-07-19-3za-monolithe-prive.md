# 3z-a — Monolithe privé : plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fusionner les 15 preuves STARK de `ProvedTx` en UNE SEULE trace/preuve, où
`cm_in`, `rho`, `owner`, `nk`, les montants et les chemins de Merkle deviennent des
témoins ; seuls `root`, `nullifiers[2]`, `output_commitments[2]`, `fee` (+ `tx_digest`
natif) restent publics.

**Architecture:** Un nouvel AIR `monolith` (crates/circuit/src/monolith/) juxtapose en
colonnes les gadgets 3b existants — clé (3b5a), éponge multi-segments par dépense
(commitment→feuille→nullifier EMPILÉS dans 20 colonnes), chemin de Merkle (3b2b),
commitment de sortie, équilibre (3b3b) — sur une trace de 512 lignes (profondeur 32).
Les liaisons inter-gadgets passent par des colonnes porteuses CONSTANTES + égalités
gatées à des lignes précises (technique 3b2/3b5a). `tx.rs` est réécrit sur ce
monolithe (mêmes noms d'API), le ledger et le bench suivent.

**Tech Stack:** Rust, winterfell 0.13 (STARK, Goldilocks + extension quadratique),
Rescue-Prime (`proved-hash`), BLAKE3‖SHA3 (`crypto`) pour `tx_digest`.

## Global Constraints

- Spec de référence : `docs/superpowers/specs/2026-07-19-3za-monolithe-prive-design.md`.
- **Validity-only** : ne JAMAIS présenter la preuve comme `zk`/`private`/`shielded` ;
  le witness-hiding est la Phase 3z-b. Avertissement en tête de chaque module.
- **Aucune assertion ne référence un témoin** (`shielded_secret`, notes, montants,
  chemins, `cm_in`, `rho`, `owner`, `nk`, porteuses) — revue systématique à chaque tâche.
- Largeur de trace ≤ 255 (limite winterfell `TraceInfo::MAX_TRACE_WIDTH`).
- Preuves à générer en `--release` (colonnes constantes → `debug_assert` de degrés
  winterfell input-dépendant) ; tests concernés : `#[cfg_attr(debug_assertions, ignore = "…")]`.
- Sécurité conjecturée ≥ 95 bits (`AcceptableOptions::MinConjecturedSecurity(95)`),
  extension quadratique OBLIGATOIRE (Goldilocks 64 bits).
- Code/commentaires en français ; commits `--author="Walid Naili <naili.walid@gmail.com>"`
  + trailer `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
- Commandes de test : `cargo test -p circuit --release` (les tests AIR gatés ne
  tournent PAS en debug) ; suite complète `cargo test --release`.

---

## Layout de référence (source de vérité pour toutes les tâches)

Trace : **512 lignes** (profondeur consensus 32 → chemin de Merkle 32 blocs × 16).
Profondeur paramétrable `depth` (tests en profondeur 4 → 64 lignes, mêmes offsets de
colonnes ; la longueur = `max(256, 16*depth)` car l'équilibre occupe 256 lignes).

| Groupe | Colonnes (offset..offset+n) | Lignes actives | Contenu |
|---|---|---|---|
| `KEY` | 0..24 | 0..8 | 2 blocs B=1 côte à côte (owner cols 0..12, nk cols 12..24), comme `key.rs` |
| `U0` (éponge dépense 0) | 24..44 | 0..56 | segments EMPILÉS : commitment 0..32 (B=4), feuille 32..40 (B=1), nullifier 40..56 (B=2) |
| `M0` (chemin 0) | 44..73 | 0..16·depth | motif `merkle_path` (20 sponge + cur 4 + sib 4 + bit 1) |
| `U1` | 73..93 | 0..56 | idem U0, entrée 1 |
| `M1` | 93..122 | 0..16·depth | idem M0, entrée 1 |
| `O0` (sortie 0) | 122..142 | 0..32 | commitment B=4 |
| `O1` (sortie 1) | 142..162 | 0..32 | commitment B=4 |
| `BAL` | 162..165 | 0..256 | `bit`, `S` (somme signée), `VACC` (valeur du bloc) ; signe = colonne PÉRIODIQUE |
| Porteuses | 165..201 | constantes | `OWNER`(4), `NK`(4), `RHO0`(4), `CM0`(4), `LEAF0`(4), `RHO1`(4), `CM1`(4), `LEAF1`(4), `VIN0`, `VIN1`, `VOUT0`, `VOUT1` |

**Largeur totale : 201 ≤ 255.** (Le côte-à-côte pur du spec donnait 246 + 36
porteuses = 282 > 255 → le fallback d'empilement intra-dépense du spec s'applique
d'emblée ; c'est CE layout.)

Positions clés dans un segment d'éponge (préambule 3a0 `[V, tag, LEN] ++ payload ++
PAD_ONE`, bloc 0 en colonnes rate de la ligne 0, blocs suivants via inject ligne
`8k−1` — cf. `sponge::locate`) :

- **Commitment** (payload `value‖owner‖rho‖r`, 13 felts, préambule 17 → 4 blocs) :
  ligne 0 rate : `[V, tag, LEN, value, owner0..3]` (cols relatives 4..12) ; inject
  ligne 7 : `[rho0..3, r0..3]` ; inject ligne 15 : `[PAD_ONE, 0…]` ; digest `cm` en
  ligne 31, cols rate 4..8.
- **Feuille** (payload `cm`, 4 felts, 1 bloc) : ligne 0 rate `[V, tag, LEN, cm0..3,
  PAD_ONE]` ; digest `leaf` ligne 7 (ligne absolue 39 dans U_i).
- **Nullifier** (payload `nk‖rho‖cm`, 12 felts, 2 blocs) : ligne 0 rate `[V, tag,
  LEN, nk0..3, rho0]` ; inject ligne 7 : `[rho1..3, cm0..3, PAD_ONE]` ; digest `nf`
  ligne 15 (absolue 55), **asserté PUBLIC** — pas de porteuse.
- **Clé** : secret aux cols 7..10 de chaque bloc, ligne 0 ; `owner`/`nk` produits
  ligne 7, cols rate 4..8 de chaque bloc (**liés aux porteuses, PAS assertés**).

Égalités de liaison (contraintes gatées par sélecteurs pleine longueur, une famille
par porteuse ; `≡@r` = « égalité contrainte à la ligne r ») :

```
OWNER  ≡@7  KEY.state_owner[4..8]        ≡@0  U0[8..12], U1[8..12]      (consommé par les 2 commitments)
NK     ≡@7  KEY.state_nk[4..8]           ≡@40 U0[7..11], U1[7..11]      (consommé par les 2 nullifiers)
RHOi   ≡@7  Ui.inject[12..16] (rho dans cm) ≡@40 Ui[11] (rho0) ≡@47 Ui.inject[12..15] (rho1..3)
CMi    ≡@31 Ui.rate[4..8] (produit)       ≡@32 Ui[7..11] (feuille) ≡@47 Ui.inject[15..19] (nullifier)
LEAFi  ≡@39 Ui.rate[4..8] (produit)       ≡@0  Mi.cur[0..4]            (remplace l'assertion leaf publique de merkle_path)
VINi   ≡@0  Ui[7] (value du commitment)   ≡@fin-bloc-BAL correspondant (VACC)
VOUTj  ≡@0  Oj[7]                         ≡@fin-bloc-BAL correspondant (VACC)
```

Assertions PUBLIQUES : constantes de préambule de chaque segment (V/tag/LEN/PAD_ONE/
capacité), `nf_i` (Ui ligne 55), `oc_j` (Oj ligne 31), `root` (M0 ET M1, dernière
ligne), `S=0` (BAL ligne 0), `S=fee` (BAL dernière ligne), zéros initiaux capacité.
RIEN d'autre.

---

### Task 1 : Layout — constantes et budget de colonnes

**Files:**
- Create: `crates/circuit/src/monolith/mod.rs`
- Create: `crates/circuit/src/monolith/layout.rs`
- Modify: `crates/circuit/src/lib.rs` (déclarer `pub mod monolith;`)

**Interfaces:**
- Produces: module `layout` avec `pub(crate) const` : `KEY_OFF=0`, `U0_OFF=24`,
  `M0_OFF=44`, `U1_OFF=73`, `M1_OFF=93`, `O0_OFF=122`, `O1_OFF=142`, `BAL_OFF=162`,
  `CARRIER_OFF=165`, `WIDTH=201` ; offsets porteuses `OWNER_C`, `NK_C`, `RHO_C[2]`,
  `CM_C[2]`, `LEAF_C[2]`, `VIN_C[2]`, `VOUT_C[2]` ; lignes de segments `CM_ROWS=0..32`,
  `LEAF_ROWS=32..40`, `NF_ROWS=40..56` ; `fn trace_len(depth: usize) -> usize`.

- [ ] **Step 1 : test qui échoue** — dans `layout.rs` :

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn budget_colonnes_respecte() {
        assert!(WIDTH <= winterfell::TraceInfo::MAX_TRACE_WIDTH);
        assert_eq!(WIDTH, CARRIER_OFF + 36);
        // Groupes contigus, sans chevauchement.
        assert_eq!(U0_OFF, KEY_OFF + 24);
        assert_eq!(M0_OFF, U0_OFF + 20);
        assert_eq!(U1_OFF, M0_OFF + 29);
        assert_eq!(M1_OFF, U1_OFF + 20);
        assert_eq!(O0_OFF, M1_OFF + 29);
        assert_eq!(O1_OFF, O0_OFF + 20);
        assert_eq!(BAL_OFF, O1_OFF + 20);
        assert_eq!(CARRIER_OFF, BAL_OFF + 3);
    }
    #[test]
    fn longueur_de_trace() {
        assert_eq!(trace_len(32), 512); // consensus : le chemin domine
        assert_eq!(trace_len(4), 256);  // dev : l'équilibre (4 blocs × 64) domine
    }
}
```

- [ ] **Step 2 : lancer** `cargo test -p circuit monolith::layout` → FAIL (module absent)
- [ ] **Step 3 : implémenter** `layout.rs` (constantes du tableau ci-dessus, dérivées
  les unes des autres par addition, PAS de littéraux magiques) et `mod.rs`
  (`pub(crate) mod layout;` + doc de module avec l'avertissement validity-only)
- [ ] **Step 4 : lancer** `cargo test -p circuit monolith::layout` → PASS
- [ ] **Step 5 : commit** `circuit(3z-a1): layout du monolithe — 201 colonnes, budget vérifié`

---

### Task 2 : Constructeur de trace + sanité hors-prouveur

**Files:**
- Create: `crates/circuit/src/monolith/trace.rs`
- Modify: `crates/circuit/src/merkle_path.rs` (extraire `pub(crate) fn path_rows(leaf, path, index) -> Vec<[BaseElement; 29]>` du corps de `build_path_trace`, qui la réutilise — refactor sans changement de comportement)
- Modify: `crates/circuit/src/monolith/mod.rs` (`pub(crate) mod trace;`)

**Interfaces:**
- Consumes: `sponge::sponge_rows` (pub(crate)), `sponge_preamble`, `merkle_path::path_rows` (nouveau), `layout::*`.
- Produces: `pub(crate) struct MonolithWitness { pub secret: ShieldedSecret, pub inputs: [ProvedInput; 2], pub outputs: [SpendNote; 2], pub fee: u64 }` et
  `pub(crate) fn build_monolith_trace(w: &MonolithWitness) -> TraceTable<BaseElement>` ;
  helpers `pub(crate) fn segment(trace, rows: &[[BaseElement; 20]], row_off, col_off)`.

- [ ] **Step 1 : test de sanité qui échoue** (tourne en DEBUG — pas de prouveur) :

```rust
#[cfg(test)]
mod tests {
    use super::*;
    // setup identique à tx.rs::tests::valid_tx (arbre profondeur 2 via merkle::leaf/node,
    // notes 1000/500 → sorties 900/580 + fee 20) — recopier le helper build_tree.
    #[test]
    fn trace_reproduit_les_references_hors_circuit() {
        let (w, root) = witness_de_test(); // helper local, arbre profondeur 2
        let t = build_monolith_trace(&w);
        let d = |col: usize, row: usize| Felt::from_winter(t.get(col, row)).unwrap();
        // owner/nk produits par la clé (ligne 7) == hash hors-circuit.
        let owner = rescue::hash(Domain::Owner, w.secret.as_felts());
        for k in 0..4 { assert_eq!(d(KEY_OFF + 4 + k, 7), owner.0[k]); }
        // cm, leaf, nf de l'entrée 0 aux positions du layout.
        let n = &w.inputs[0].note;
        let cm = rescue::note_commitment(n.value, &n.owner, &n.rho, &n.r);
        for k in 0..4 { assert_eq!(d(U0_OFF + 4 + k, 31), cm.0[k]); }
        for k in 0..4 { assert_eq!(d(U0_OFF + 4 + k, 39), merkle::leaf(&cm).0[k]); }
        // racine au bout du chemin M0 == root de l'arbre.
        let last = t.length() - 1;
        for k in 0..4 { assert_eq!(d(M0_OFF + 4 + k, 16 * w.inputs[0].path.len() - 1), root.0[k]); }
        // porteuses constantes : mêmes valeurs ligne 0 et dernière ligne.
        for c in CARRIER_OFF..WIDTH { assert_eq!(t.get(c, 0), t.get(c, last)); }
        // équilibre : S final == fee.
        assert_eq!(d(BAL_OFF + 1, last), Felt::from_canonical_u64(w.fee).unwrap());
    }
}
```

- [ ] **Step 2 : lancer** `cargo test -p circuit monolith::trace` → FAIL
- [ ] **Step 3 : implémenter** `build_monolith_trace` :
  - clé : 2 blocs `initial_state`-style (recopier la logique de `key.rs::build_key_trace` en local, 8 lignes, cols 0..24) ;
  - `U_i` : trois appels à `sponge_rows(preamble)` (commitment paddé PAD_ZERO* via `absorbed_len`, feuille, nullifier) copiés aux lignes 0/32/40, col `Ui_OFF` ;
  - `M_i` : `path_rows(leaf_i, path, index)` copié col `Mi_OFF` ;
  - `O_j` : `sponge_rows` du commitment de sortie, lignes 0..32 ;
  - `BAL` : 4 blocs de 64 lignes `[bit, S, VACC]` (S = somme signée avant contribution, signe +1/+1/−1/−1 par bloc ; VACC = valeur partielle du bloc, remise à 0 à chaque début de bloc) ;
  - porteuses : valeur répétée sur les 512 lignes ;
  - lignes idle : zéros.
- [ ] **Step 4 : lancer** `cargo test -p circuit monolith::trace` puis `cargo test -p circuit --release` (non-régression merkle_path après refactor `path_rows`) → PASS
- [ ] **Step 5 : commit** `circuit(3z-a2): trace du monolithe — sanité différentielle hors-prouveur`

---

### Task 3 : AIR v0 — segments contraints, liaisons absentes

L'AIR contraint chaque groupe DANS ses lignes actives (rondes Rescue + absorption +
préambules assertés + bit booléen + swap Merkle + équilibre) via des **sélecteurs
pleine longueur** (`get_periodic_column_values` retourne des vecteurs de longueur
`trace_len`, motif déjà utilisé par `merkle_path`). Les porteuses sont contraintes
constantes (`next − cur = 0`, non gaté). Les liaisons porteuse↔gadget arrivent en
Task 4.

**Files:**
- Create: `crates/circuit/src/monolith/air.rs`
- Modify: `crates/circuit/src/monolith/mod.rs` (`pub(crate) mod air;` + API interne)

**Interfaces:**
- Consumes: `sponge::enforce_sponge_transition`, `key.rs`-style `enforce_round_block`
  (extraire en `pub(crate)` dans `rescue_round.rs` si besoin), `layout::*`, `trace::*`.
- Produces: `MonolithAir` (winterfell::Air), `MonolithPublicInputs { root, nullifiers: [_;2], output_commitments: [_;2], fee }`, `pub(crate) fn prove_monolith(w) -> (MonolithPublicInputs, ValidityProof)`, `pub(crate) fn verify_monolith(pi, depth, proof) -> bool`.

- [ ] **Step 1 : test roundtrip qui échoue** :

```rust
#[test]
#[cfg_attr(debug_assertions, ignore = "AIR gaté : générer en --release")]
fn roundtrip_monolithe() {
    let (w, root) = witness_de_test();
    let (pi, proof) = prove_monolith(&w);
    assert_eq!(Digest::from_winter(pi.root), root);
    assert!(verify_monolith(&pi, 2, &proof));
    // publics falsifiés → rejet.
    let mut faux = pi.clone();
    faux.fee += 1;
    assert!(!verify_monolith(&faux, 2, &proof));
}
```

- [ ] **Step 2 : lancer** `cargo test -p circuit --release monolith::air` → FAIL
- [ ] **Step 3 : implémenter** `MonolithAir` :
  - `evaluate_transition` : réutiliser `enforce_sponge_transition` par groupe
    (slices `&cur[OFF..OFF+20]`) multiplié par le sélecteur du groupe ; rondes clé
    via `enforce_round_block` ×2 ; contraintes Merkle recopiées de
    `merkle_path::evaluate_transition` (offsets décalés) ×2 ; équilibre
    `S_next − S − signe·bit·pow` avec `signe` et `pow` périodiques, `bit` booléen,
    `VACC_next − (1−endblk)·(VACC + bit·pow)` ; porteuses `next − cur` ;
  - `get_assertions` : préambules de CHAQUE segment (recopier le style
    `merkle_path::get_assertions` avec `locate` décalé), `nf_i`@55, `oc_j`@31,
    `root`@dernière ligne de M0 ET M1, `S`@0 = 0, `S`@dernière = fee ;
  - degrés : BORNES SUPÉRIEURES calibrées release (partir de celles de
    `merkle_path` : sponge gaté ≤ `with_cycles(8, vec![8,16])`+marge, copies 2,
    swap 3, équilibre `with_cycles(3, …)`) ; blowup 16 (`options_hi` de
    `merkle_path`, à extraire en `pub(crate)` dans `lib.rs`) ;
  - prouveur : recopier le boilerplate `Prover` de `merkle_path.rs`.
- [ ] **Step 4 : lancer** `cargo test -p circuit --release monolith` → PASS
- [ ] **Step 5 : commit** `circuit(3z-a3): AIR v0 du monolithe — segments contraints, roundtrip vert`

---

### Task 4 : Liaisons par porteuses — une famille à la fois, test white-box chacune

Chaque étape ajoute UNE famille d'égalités gatées (tableau « Égalités de liaison »
du layout) + son test négatif white-box : une trace forgée où producteur ≠
consommateur DOIT être rejetée (motif exact de `key.rs::liaison_secret_partage_mord` —
la forge passe par un paramètre de test du constructeur de trace, p.ex.
`build_monolith_trace_forge(w, Forge::OwnerConsomme(autre_digest))`).

**Files:**
- Modify: `crates/circuit/src/monolith/air.rs` (contraintes + degrés)
- Modify: `crates/circuit/src/monolith/trace.rs` (helper de forge `#[cfg(test)]`)

**Interfaces:**
- Produces: l'AIR complet ; aucun changement d'API.

- [ ] **Step 1 : OWNER** — égalités `@7` (production clé) et `@0` (consommation U0/U1) ;
  test `liaison_owner_mord` : commitment construit avec un owner ≠ sortie de la clé → rejet. Lancer avant (FAIL : la preuve forgée passe), après (PASS : rejetée).
- [ ] **Step 2 : commit** `circuit(3z-a4a): liaison owner — la clé gouverne les commitments d'entrée`
- [ ] **Step 3 : NK** — `@7` clé, `@40` nullifiers ; test `liaison_nk_mord` (nullifier calculé avec nk d'un autre secret → rejet). Commit `circuit(3z-a4b): liaison nk`.
- [ ] **Step 4 : RHO0/RHO1** — `@7` (inject commitment), `@40`/`@47` (nullifier) ; test `liaison_rho_mord` (rho du nullifier ≠ rho du commitment → rejet ; c'est la propriété v0.2 « nullifier lié au commitment »). Commit `circuit(3z-a4c): liaison rho`.
- [ ] **Step 5 : CM0/CM1** — `@31` (production), `@32` (feuille), `@47` (nullifier) ; test `liaison_cm_mord` (feuille d'un autre commitment → rejet = P1 ne peut plus être détourné). Commit `circuit(3z-a4d): liaison cm_in`.
- [ ] **Step 6 : LEAF0/LEAF1** — `@39` (production), `@0` (cur du chemin, REMPLACE l'assertion publique leaf de merkle_path) ; test `liaison_leaf_mord` (chemin prouvé sur une autre feuille → rejet). Commit `circuit(3z-a4e): liaison feuille↔chemin`.
- [ ] **Step 7 : VIN/VOUT** — `@0` (cellule value des commitments), fin de bloc BAL (VACC) ; test `liaison_valeurs_mord` (commitment déclarant 1000 mais bloc d'équilibre à 900 → rejet = P5 réellement lié à P7). Commit `circuit(3z-a4f): liaison montants — P5 lié aux commitments`.
- [ ] **Step 8 : revue « aucune assertion sur témoin »** — relire `get_assertions`,
  vérifier que seuls préambules/nf/oc/root/S y figurent ; lancer la suite complète
  `cargo test -p circuit --release` → PASS. Commit `circuit(3z-a4g): monolithe complet — P1–P7 dans une seule preuve`.

---

### Task 5 : `ProvedTx` v2 — tx.rs réécrit sur le monolithe

**Files:**
- Modify: `crates/circuit/src/tx.rs` (réécriture complète)
- Modify: `crates/circuit/src/lib.rs` (exports inchangés : `prove_tx`, `verify_tx`, `ProvedTx`, `ProvedInput`, `INTENT_DOMAIN`)

**Interfaces:**
- Consumes: `monolith::{prove_monolith, verify_monolith, MonolithWitness}`.
- Produces:

```rust
pub const INTENT_DOMAIN: &str = "obscura/proved-tx-intent/v2";
const TX_DOMAIN: &str = "obscura/proved-tx/v2";

pub struct ProvedTx {
    pub anchor: Digest,
    pub proof: ValidityProof,               // LA preuve monolithique
    pub nullifiers: [Digest; 2],
    pub output_commitments: [Digest; 2],
    pub fee: u64,
    pub signer: SigPublicKey,
    pub tx_digest: [u8; 64],
    pub intent_sig: HybridSignature,
}
pub fn prove_tx(secret: &ShieldedSecret, inputs: [ProvedInput; 2],
                outputs: [SpendNote; 2], fee: u64, intent: &SigKeypair) -> (Digest, ProvedTx);
pub fn verify_tx(root: &Digest, depth: usize, tx: &ProvedTx) -> bool;
```

- [ ] **Step 1 : tests qui échouent** — réécrire le module de tests de `tx.rs` :
  `transaction_valide`, `desequilibre_rejete` (reconstruire une tx avec sorties
  déséquilibrées → `prove_monolith` produit une preuve dont `S ≠ fee` → rejet),
  `nullifier_falsifie_rejete`, `output_commitment_falsifie_rejete`,
  `tx_digest_falsifie_rejete`, `racine_erronee_rejetee`,
  `entree_d_un_autre_owner_rejetee` (note d'entrée dont owner ≠ H(secret) → rejet
  via liaison owner). Le digest v2 :

```rust
fn tx_digest_bytes(root: &Digest, nullifiers: &[Digest; 2],
                   output_commitments: &[Digest; 2], fee: u64,
                   signer: &SigPublicKey) -> [u8; 64] {
    let mut b = Vec::new();
    b.extend_from_slice(&root.to_bytes());
    for nf in nullifiers { b.extend_from_slice(&nf.to_bytes()); }
    for oc in output_commitments { b.extend_from_slice(&oc.to_bytes()); }
    b.extend_from_slice(&fee.to_le_bytes());
    b.extend_from_slice(&signer.to_bytes());
    dual_hash(TX_DOMAIN, &b)
}
```

- [ ] **Step 2 : lancer** `cargo test -p circuit --release tx` → FAIL
- [ ] **Step 3 : implémenter** `prove_tx` (construit `MonolithWitness`, appelle
  `prove_monolith`, calcule `tx_digest`, signe) et `verify_tx` (`verify_monolith`
  avec `pi` reconstruit depuis les champs publics de la tx + racine passée en
  argument, puis recompare `tx_digest`). Supprimer l'assemblage v1 (`key/spends/
  outputs` de l'ancienne struct, l'ancien `tx_digest_bytes` 8-arguments).
- [ ] **Step 4 : lancer** `cargo test -p circuit --release` → PASS
- [ ] **Step 5 : commit** `circuit(3z-a5): ProvedTx v2 — une preuve, publics minimaux, tx_digest v2`

---

### Task 6 : Ledger — `apply_proved_tx` sur la v2 + e2e

**Files:**
- Modify: `crates/ledger/src/proved_state.rs`

**Interfaces:**
- Consumes: `ProvedTx` v2 (`tx.nullifiers` remplace `tx.spends[i].nullifier`).

- [ ] **Step 1 : adapter les tests** — `setup()` inchangé dans l'esprit ; les
  sabotages deviennent : `preuve_falsifiee_rejetee` corrompt `tx.nullifiers[0]`
  (les montants ne sont plus visibles) ; ajouter
  `nullifier_ne_peut_etre_substitue` (remplacer `nullifiers[0]` par un digest
  arbitraire → `InvalidProof` car asserté dans la preuve ET lié dans le digest).
  Lancer `cargo test -p ledger --release` → FAIL (compilation : champs disparus)
- [ ] **Step 2 : implémenter** — boucles sur `tx.nullifiers` au lieu de `tx.spends` ;
  aucune autre logique ne change (anchor → verify_tx → intent_sig → nullifiers →
  application atomique).
- [ ] **Step 3 : lancer** `cargo test --release` (workspace ENTIER, non-régression) → PASS
- [ ] **Step 4 : commit** `ledger(3z-a6): apply_proved_tx sur ProvedTx v2 — nullifiers top-level`

---

### Task 7 : Bench — mesurer le gain

**Files:**
- Modify: `crates/circuit/examples/tx_bench.rs`

- [ ] **Step 1 : adapter** le bench à l'API v2 (une seule preuve : taille =
  `tx.proof.0.to_bytes().len()`, plus de somme sur 15 preuves), profondeur 32,
  mêmes mesures (génération, vérification, taille).
- [ ] **Step 2 : lancer** `cargo run --release --example tx_bench -p circuit` →
  noter génération/vérification/taille. Attendu : taille de l'ordre de 15-60 Kio
  (vs ~219 Kio) ; si hors de cet ordre, investiguer avant de continuer.
- [ ] **Step 3 : commit** `circuit(3z-a7): bench ProvedTx v2 — <chiffres mesurés>`

---

### Task 8 : Documentation — statement, CLAUDE.md

**Files:**
- Modify: `docs/STARK_STATEMENT.md` (entrée « 3z-a (fait) » dans le journal de tête :
  monolithe, publics réduits, chiffres du bench, rappel validity-only/3z-b ;
  mettre à jour la ligne « Reste hors Phase-3-validity »)
- Modify: `CLAUDE.md` (section État : 3z-a fait ; Prochaine étape : 3z-b witness-hiding,
  3z-c M-in/N-out)
- Modify: `README.md` si les chiffres 219 Kio y figurent

- [ ] **Step 1 : rédiger** les mises à jour (chiffres RÉELS du bench Task 7, pas d'estimation)
- [ ] **Step 2 : relire** — cohérence avec le spec 3z-a, aucun langage « zk/private »
- [ ] **Step 3 : commit** `docs(3z-a): monolithe privé au statement — publics minimaux, chiffres bench`

---

## Self-review du plan (fait à la rédaction)

- **Couverture spec** : §2 statement v2 → Tasks 3/5 ; §3 layout+fallback → Tasks 1-4
  (fallback adopté d'emblée, budget recalculé 201) ; §4 API/remplacement → Tasks 5-6 ;
  bench → Task 7 ; §5 tests → sanité (T2), différentiels+sabotage (T3/T5), white-box
  par porteuse (T4), e2e (T6), revue assertions (T4 step 8).
- **Écart assumé vs spec** : le spec demandait de « mesurer d'abord le côte-à-côte
  pur » ; le chiffrage exact (246 + 36 porteuses = 282 > 255) est fait ICI — le plan
  applique donc directement le fallback prévu. Documenté en tête de layout.
- **Types** : `MonolithWitness`/`MonolithPublicInputs`/`ProvedTx` v2 cohérents entre
  T2/T3/T5/T6 ; exports `lib.rs` inchangés pour l'aval.
