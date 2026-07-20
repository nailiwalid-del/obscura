# Feature-gate des chemins de dev — design

> Mettre le **mode transparent** (ledger dev) et les **sous-circuits autonomes**
> (`prove_*`/`verify_*` standalone) derrière des features Cargo **désactivées par
> défaut**, pour que la surface **consensus** soit non-ambiguë : un `cargo build` nu
> n'expose QUE le chemin de consensus. On **gate**, on ne supprime pas. Aucun changement
> de comportement — uniquement de visibilité par défaut.

## 1. Décisions (utilisateur)
- **Deux features** : `dev-transparent` (ledger), `dev-circuits` (circuit).
- **OFF par défaut** : le build/test par défaut = surface consensus seule ; la suite
  complète tourne en `cargo test --all-features`.

## 2. Ce qui reste TOUJOURS compilé (consensus, aucun feature)
- **circuit** : `monolith`, `prove_tx`/`verify_tx`/`verify_proved_tx_full`, `ProvedTx`,
  `ProvedInput`, `EncNote` (+ `KEM_CT_LEN`/`MAX_ENC_NOTE_LEN`/`within_bounds`),
  `INTENT_DOMAIN`, `SpendNote` (type des notes du consensus), `RANGE_BITS`,
  `ValidityProof`, `proof_options`/`proof_options_hi` (pub(crate)).
- **Les modules gadgets restent compilés** : le monolithe réutilise leurs helpers
  `pub(crate)` (`enforce_sponge_transition`, `sponge_rows`, `path_rows`,
  `enforce_merkle_transition`, `enforce_round_block`, `note_commit_payload`, etc.). Seules
  les **fonctions publiques standalone** sont gatées.
- **ledger** : `proved_state` (`ProvedLedgerState`/`apply_proved_tx`), `proved_wallet`,
  `keys` (`WalletKeys`/`Address` — partagé), `LedgerError`, `Commitment`.

## 3. Ce qui est gaté

### `dev-circuits` (circuit)
Les entrées publiques standalone `prove_*`/`verify_*` et leurs types de retour, NON
utilisés par le consensus (le monolithe utilise les helpers internes, pas ces
compositions) :
- `prove_spend`/`verify_spend`/`SpendProof`, `prove_output`/`verify_output`/`OutputProof`,
  `prove_key`/`verify_key`, `prove_balance`/`verify_balance`,
  `prove_membership`/`verify_membership`/`MembershipProof`, `prove_range`/`verify_range`,
  `prove_merkle_level`/`verify_merkle_level`, `prove_merkle_path`/`verify_merkle_path`,
  `prove_owner`/`verify_owner`, `prove_permutation`/`verify_permutation`,
  et les instances sponge standalone : `prove_sponge`/`verify_sponge`,
  `prove_nk`, `prove_nullifier`, `prove_note_commitment`/`verify_note_commitment`.
- Leurs re-exports dans `lib.rs` : `#[cfg(feature = "dev-circuits")]`.
- Leurs tests différentiels : `#[cfg(all(test, feature = "dev-circuits"))]`.
- `SpendNote` (spend.rs) reste **ungated** (consensus). Ses méthodes
  `to_bytes`/`from_bytes` restent ungated. Ne gater QUE `prove_spend`/`verify_spend`/
  `SpendProof`.

### `dev-transparent` (ledger)
Le mode transparent complet, non-consensus :
- `state` (`LedgerState`/`apply_transparent`) ;
- la tx transparente dans `tx.rs` : `Transaction`/`TxInput`/`TxOutput`/
  `build_transparent_transaction`/`scan_output` (+ méthode `digest` transparente) ;
- ce qui n'est utilisé QUE par le transparent : `ledger::merkle` (Merkle BLAKE3) et
  `ledger::note::Note` (owner BLAKE3) — **à confirmer par les dépendances réelles**
  (le chemin prouvé utilise `proved_hash::ProvedMerkleTree` et `circuit::SpendNote`).
- Re-exports/`pub mod` concernés : `#[cfg(feature = "dev-transparent")]`. Tests
  transparents : `#[cfg(all(test, feature = "dev-transparent"))]`.

## 4. Invariant central (à vérifier absolument)
Un `cargo build` **et** `cargo test` **nus** (aucun feature) doivent **compiler et
passer** avec **uniquement la surface consensus** : AUCUN code consensus ne référence du
code dev gaté. Si un type « dev » se révèle utilisé par le consensus (ex. `Note`,
`merkle`), il n'est PAS gaté (il devient « partagé ») — l'implémenteur suit les erreurs
de compilation du build par défaut pour placer les gates exactement.

## 5. Découpage en unités
- `crates/circuit/Cargo.toml` + `crates/ledger/Cargo.toml` : déclaration des features.
- `crates/circuit/src/lib.rs` + modules gadgets : gates sur les fns/re-exports/tests.
- `crates/ledger/src/lib.rs` + `state.rs`/`tx.rs`/(`merkle.rs`/`note.rs` selon dépendances) :
  gates.
- Docs : README/CLAUDE.

## 6. Tests
1. **Défaut = consensus seul** : `cargo build` (aucun feature) compile ; `cargo test`
   (défaut, + `--release` pour les preuves gatées) passe avec les seuls tests consensus
   (proved_state, tx monolithe, proved_wallet, gadgets internes s'il y en a d'ungated).
2. **Tout activé** : `cargo test --all-features --release` passe (tous les tests, dont
   transparent + sous-circuits standalone) — non-régression complète.
3. **Combinaisons** : `--features dev-circuits` seul et `--features dev-transparent` seul
   compilent (indépendance des deux features).
4. **Vérif structurelle** : `cargo build` par défaut n'expose PAS `apply_transparent`,
   `prove_spend`, etc. (un petit test/exemple qui les référence ne compile QUE sous
   feature — ou vérification manuelle documentée).

## 7. Hors périmètre
- Aucune suppression de code, aucun changement de comportement.
- Pas de refonte des chemins dev (juste leur visibilité).
- CI : mentionner `--all-features` pour la suite complète (pas de fichier CI à créer ici
  si le repo n'en a pas).
