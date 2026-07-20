# enc_notes dans ProvedTx (v3) — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Porter les chiffrés de notes (`enc_notes`) au chemin PROUVÉ (`circuit::ProvedTx`) et les lier dans `tx_digest` v3 (anti-substitution), avec les helpers wallet de chiffrement/scan dans le ledger.

**Architecture:** `EncNote {kem_ct, enc_note}` (donnée opaque) rejoint `ProvedTx` ; `tx_digest` passe en v3 en concaténant les enc_notes préfixés-longueur ; `prove_tx` reçoit les bundles déjà chiffrés ; `verify_tx` recompose le digest. Le chiffrement/scan (kem+aead) vit dans le ledger, réutilisant le mécanisme transparent existant. **Aucun changement d'AIR** (P8 différé).

**Tech Stack:** Rust, `crypto::{kem, aead, hash::dual_hash}`, structures ledger existantes.

## Global Constraints

- Spec de référence : `docs/superpowers/specs/2026-07-20-enc-notes-provedtx-design.md`.
- **Aucun changement d'AIR / de monolithe** : enc_notes = digest-only ; la preuve STARK est inchangée. P8 (cohérence enc_note↔commitment) et IK-CCA restent différés.
- `EncNote` vit dans `circuit` (pas `ledger` — sinon cycle `circuit→ledger→circuit`). Donnée pure, pas de logique crypto.
- `TX_DOMAIN = "obscura/proved-tx/v3"`, `INTENT_DOMAIN = "obscura/proved-tx-intent/v3"`.
- **Encodage digest v3** = v2 (`root(32)‖nf₁(32)‖nf₂(32)‖oc₁(32)‖oc₂(32)‖fee(8 LE)‖signer`) PUIS pour chaque sortie j : `len(kem_ctⱼ)(8 LE)‖kem_ctⱼ‖len(enc_noteⱼ)(8 LE)‖enc_noteⱼ`. Injectif. `dual_hash`.
- Anti-substitution : `verify_tx` rejette si digest recomposé ≠ `tx.tx_digest` ; `apply_proved_tx` rejette via la signature d'intention (sur le digest).
- Code/commentaires FRANÇAIS ; commits `--author="Walid Naili <naili.walid@gmail.com>"` + trailer `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
- Tests : `cargo test -p circuit --release`, `cargo test -p ledger --release`, workspace `cargo test --workspace --release`, clippy 0 warning.

## Fichiers touchés

- `crates/circuit/src/tx.rs` — `EncNote`, `ProvedTx` v3, `tx_digest_bytes` v3, `prove_tx`/`verify_tx`, domaines v3.
- `crates/circuit/src/lib.rs` — export `EncNote`.
- `crates/ledger/src/tx.rs` (ou module wallet) — `encrypt_note`/`scan_proved_output`.
- `crates/ledger/src/proved_state.rs` — tests e2e (logique inchangée).
- `docs/STARK_STATEMENT.md`, `docs/PROTOCOL.md` — note enc_notes v3.

---

### Task 1 : `EncNote` + `tx_digest` v3 + `prove_tx`/`verify_tx` (circuit)

**Files:** Modify: `crates/circuit/src/tx.rs`, `crates/circuit/src/lib.rs`

**Interfaces:**
- Produces : `pub struct EncNote { pub kem_ct: Vec<u8>, pub enc_note: Vec<u8> }` (derive Clone) ; `ProvedTx` gagne `pub enc_notes: [EncNote; 2]` ; `prove_tx(secret, inputs, outputs, fee, intent, enc_notes: [EncNote; 2]) -> (Digest, ProvedTx)` ; `verify_tx` inchangé en signature ; `TX_DOMAIN`/`INTENT_DOMAIN` = v3. Export `EncNote` dans lib.rs.

- [ ] **Step 1 : test anti-substitution qui échoue** (dans le module de tests de tx.rs, gaté `--release` comme les autres). Construire une ProvedTx valide avec 2 enc_notes non triviaux (`EncNote { kem_ct: vec![1,2,3], enc_note: vec![4,5,6] }` et un autre) ; vérifier `verify_tx` accepte ; puis remplacer `tx.enc_notes[0].enc_note` par `vec![9,9,9]` → `verify_tx` doit REJETER (digest recomposé ≠). Réutiliser le setup `valid_tx()` existant, en lui ajoutant des enc_notes.

```rust
#[test]
#[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
fn enc_note_substitue_rejete() {
    let (_s, root, mut tx) = valid_tx(); // valid_tx fournit désormais des enc_notes
    assert!(verify_tx(&root, DEPTH, &tx));
    tx.enc_notes[0].enc_note = vec![9, 9, 9];
    assert!(!verify_tx(&root, DEPTH, &tx), "un enc_note substitué doit casser le digest");
}
```

- [ ] **Step 2 : lancer** `cargo test -p circuit --release tx` → FAIL (EncNote/champ absent).
- [ ] **Step 3 : implémenter** :
  - `EncNote` struct (Clone) ;
  - `ProvedTx { …, pub enc_notes: [EncNote; 2] }` ;
  - `tx_digest_bytes(...)` gagne un paramètre `enc_notes: &[EncNote; 2]` et, après le bloc v2, ajoute pour chaque sortie j : `b.extend_from_slice(&(enc_notes[j].kem_ct.len() as u64).to_le_bytes()); b.extend_from_slice(&enc_notes[j].kem_ct); b.extend_from_slice(&(enc_notes[j].enc_note.len() as u64).to_le_bytes()); b.extend_from_slice(&enc_notes[j].enc_note);` ; domaine `"obscura/proved-tx/v3"` ;
  - `prove_tx` gagne `enc_notes: [EncNote; 2]`, les passe à `tx_digest_bytes`, les stocke dans `ProvedTx` ;
  - `verify_tx` passe `&tx.enc_notes` à `tx_digest_bytes` ;
  - `INTENT_DOMAIN` = `"obscura/proved-tx-intent/v3"` ;
  - `lib.rs` : ajouter `EncNote` à `pub use tx::{…}`.
  - Mettre à jour `valid_tx()` (helper de test) pour fournir 2 enc_notes non triviaux.
- [ ] **Step 4 : lancer** `cargo test -p circuit --release tx` → PASS (anti-substitution + tous les tests tx existants adaptés au v3).
- [ ] **Step 5 : commit** `circuit(enc-notes): EncNote + tx_digest v3 liant enc_notes + anti-substitution`

---

### Task 2 : Helpers wallet `encrypt_note`/`scan_proved_output` (ledger)

**Files:** Modify: `crates/ledger/src/tx.rs` (ou un module dédié)

**Interfaces:**
- Consumes : `circuit::EncNote`, `crypto::{kem, aead}`, `Note`, `Digest`, `keys::{WalletKeys, Address}`.
- Produces : `pub fn encrypt_note(recipient_kem_pk: &kem::KemPublicKey, commitment: &Digest, note: &Note) -> circuit::EncNote` ; `pub fn scan_proved_output(wallet: &WalletKeys, commitment: &Digest, e: &circuit::EncNote) -> Option<Note>`.

- [ ] **Step 1 : test roundtrip qui échoue** :

```rust
#[test]
fn enc_note_roundtrip_prouve() {
    let alice = WalletKeys::generate();
    let bob = WalletKeys::generate();
    let note = Note::new(1_000, alice.address().owner);
    let cm = note.commitment();
    let e = encrypt_note(&alice.address().kem_pk, &cm, &note);
    // Le destinataire retrouve sa note.
    assert_eq!(scan_proved_output(&alice, &cm, &e), Some(note));
    // Un tiers échoue.
    assert_eq!(scan_proved_output(&bob, &cm, &e), None);
}
```

(Adapter aux vrais noms : `WalletKeys::generate`, `address().kem_pk`, `address().owner`, `Note::new` — les lire dans `keys.rs`/`note.rs` ; le test doit refléter l'API réelle.)

- [ ] **Step 2 : lancer** `cargo test -p ledger encrypt_note` (ou le nom du module) → FAIL.
- [ ] **Step 3 : implémenter** en recopiant la logique transparente (`create_output` lignes ~128-133, `scan_output` lignes ~152-159) :
  - `encrypt_note` : `let (kem_ct, ss) = kem::encapsulate(recipient_kem_pk); let enc_note = aead::encrypt(&ss, &commitment.to_bytes(), &note.to_bytes()); circuit::EncNote { kem_ct: kem_ct.to_bytes(), enc_note }` ;
  - `scan_proved_output` : `let ct = kem::KemCiphertext::from_bytes(&e.kem_ct).ok()?; let ss = kem::decapsulate(&wallet.receive, &ct); let pt = aead::decrypt(&ss, &commitment.to_bytes(), &e.enc_note).ok()?; let note = Note::from_bytes(&pt).ok()?; (note.commitment() == *commitment && note.owner == wallet.address().owner).then_some(note)`.
  - DRY opportuniste : le mode transparent PEUT réutiliser `encrypt_note`/`scan_proved_output` — seulement si ça ne casse pas son API ; sinon laisser tel quel et noter.
- [ ] **Step 4 : lancer** `cargo test -p ledger --release` → PASS.
- [ ] **Step 5 : commit** `ledger(enc-notes): helpers encrypt_note/scan_proved_output (réutilisent kem+aead)`

---

### Task 3 : e2e ledger + non-régression `apply_proved_tx`

**Files:** Modify: `crates/ledger/src/proved_state.rs` (tests) ; `crates/circuit/…` si le setup de test proved partagé doit fournir des enc_notes

**Interfaces:** `apply_proved_tx` logique INCHANGÉE ; le `ProvedTx` porte désormais ses enc_notes.

- [ ] **Step 1 : adapter le setup** — le `setup()` des tests `proved_state.rs` construit un `ProvedTx` via `prove_tx` : lui fournir 2 enc_notes réels (`encrypt_note` vers 2 destinataires de test). Les tests existants (`applique_une_tx_prouvee`, double-dépense, anchor, signature) doivent passer avec le digest v3.
- [ ] **Step 2 : test e2e + anti-substitution ledger** :
  - `applique_puis_scanne` : appliquer une ProvedTx ; un destinataire `scan_proved_output` sur `(output_commitments[j], enc_notes[j])` retrouve sa note.
  - `enc_note_substitue_rejete_au_ledger` : corrompre `tx.enc_notes[0]` après `prove_tx` → `apply_proved_tx` rejette (`InvalidProof` via digest ≠, ou `InvalidSignature`). Documenter quelle défense mord.
- [ ] **Step 3 : lancer** `cargo test --workspace --release` → PASS (tous crates). Clippy 0.
- [ ] **Step 4 : commit** `ledger(enc-notes): e2e scan + anti-substitution au ledger, non-régression v3`

---

### Task 4 : Docs

**Files:** Modify: `docs/STARK_STATEMENT.md`, `docs/PROTOCOL.md`, `CLAUDE.md`

- [ ] **Step 1 : rédiger** — STARK_STATEMENT.md : note « enc_notes portés par `ProvedTx` v3 et liés dans `tx_digest` v3 (anti-substitution) ; P8 (cohérence enc_note↔commitment) TOUJOURS différé (Sapling) ». PROTOCOL.md : confirmer que la Tx prouvée porte `enc_notes` (déjà dans la cible, marquer « implémenté »). CLAUDE.md : État (ProvedTx v3 avec enc_notes).
- [ ] **Step 2 : relire** — cohérence ; ne PAS affirmer que P8 est prouvé ; digest v3 correct.
- [ ] **Step 3 : commit** `docs(enc-notes): ProvedTx v3 avec enc_notes liés, P8 différé`

---

## Self-review du plan

- **Couverture spec** : §3 EncNote → T1 ; §4 ProvedTx/digest v3 → T1 ; §5 verify_tx/ledger → T1/T3 ; §6 helpers → T2 ; §7 différés → T4 (docs) ; §8 tests → anti-substitution (T1/T3), roundtrip (T2), e2e (T3), non-régression (T1/T3) ; §9 fichiers → tous couverts.
- **Types** : `EncNote {kem_ct, enc_note}`, `prove_tx(..., enc_notes)`, `encrypt_note`/`scan_proved_output` cohérents T1↔T2↔T3. `verify_tx`/`ProvedTx`(v3) export.
- **Placeholders** : aucun — code concret par étape ; les noms d'API ledger (`WalletKeys::generate`, `address().kem_pk`, `wallet.receive`) sont à confirmer dans keys.rs par l'implémenteur (indiqué explicitement en T2 Step 1).
- **Pas d'AIR** : confirmé — aucune tâche ne touche `monolith/`.
