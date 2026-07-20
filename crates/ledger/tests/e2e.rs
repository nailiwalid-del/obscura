//! Test de bout en bout : Alice reçoit une émission, paie Bob, Bob scanne et retrouve
//! sa note ; la double dépense et les altérations sont rejetées.
//!
//! MODE TRANSPARENT (dev uniquement) : ne compile que sous `dev-transparent`.
#![cfg(feature = "dev-transparent")]

use ledger::keys::WalletKeys;
use ledger::note::Note;
use ledger::state::LedgerState;
use ledger::tx::{build_transparent_transaction, scan_output, SpendInfo};
use ledger::LedgerError;

#[test]
fn paiement_complet_et_double_depense() {
    let alice = WalletKeys::generate();
    let bob = WalletKeys::generate();
    let mut state = LedgerState::new();

    // Émission : 100 unités pour Alice.
    let note_alice = Note::new(100, alice.address().owner);
    let idx = state.mint(&note_alice.commitment());

    // Alice paie 60 à Bob, 39 de monnaie pour elle-même, 1 de fee.
    let tx = build_transparent_transaction(
        &alice,
        &state.tree,
        &[SpendInfo {
            note: note_alice.clone(),
            index: idx,
        }],
        &[(bob.address(), 60), (alice.address(), 39)],
        1,
    )
    .unwrap();

    state.apply_transparent(&tx).unwrap();

    // Bob scanne le ledger et retrouve SA note (et pas celle d'Alice).
    let notes_bob: Vec<_> = tx
        .outputs
        .iter()
        .filter_map(|o| scan_output(&bob, o))
        .collect();
    assert_eq!(notes_bob.len(), 1);
    assert_eq!(notes_bob[0].value, 60);

    let notes_alice: Vec<_> = tx
        .outputs
        .iter()
        .filter_map(|o| scan_output(&alice, o))
        .collect();
    assert_eq!(notes_alice.len(), 1);
    assert_eq!(notes_alice[0].value, 39);

    // Rejouer la même tx = double dépense -> rejet.
    assert!(matches!(
        state.apply_transparent(&tx),
        Err(LedgerError::DoubleSpend)
    ));
}

#[test]
fn transaction_desequilibree_refusee() {
    let alice = WalletKeys::generate();
    let bob = WalletKeys::generate();
    let mut state = LedgerState::new();
    let note = Note::new(50, alice.address().owner);
    let idx = state.mint(&note.commitment());

    let res = build_transparent_transaction(
        &alice,
        &state.tree,
        &[SpendInfo { note, index: idx }],
        &[(bob.address(), 60)], // > 50 : création de monnaie interdite
        0,
    );
    assert!(matches!(res, Err(LedgerError::Unbalanced)));
}

#[test]
fn alteration_de_tx_rejetee() {
    let alice = WalletKeys::generate();
    let bob = WalletKeys::generate();
    let mut state = LedgerState::new();
    let note = Note::new(10, alice.address().owner);
    let idx = state.mint(&note.commitment());

    let mut tx = build_transparent_transaction(
        &alice,
        &state.tree,
        &[SpendInfo { note, index: idx }],
        &[(bob.address(), 10)],
        0,
    )
    .unwrap();

    // Un attaquant modifie la fee après signature -> digest change -> signature invalide.
    tx.fee = 5;
    assert!(matches!(
        state.apply_transparent(&tx),
        Err(LedgerError::InvalidSignature)
    ));
}
