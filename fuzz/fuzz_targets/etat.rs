//! `ProvedLedgerState::from_bytes` — l'état de CONSENSUS relu au démarrage.
//!
//! Anneau 2 (disque) : l'entrée n'est pas fournie par un inconnu du réseau, mais
//! un fichier corrompu par une panne de courant ou un disque défaillant ne doit
//! jamais faire paniquer un nœud au démarrage — il doit REFUSER, bruyamment.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ledger::proved_state::ProvedLedgerState::from_bytes(data);
});
