//! `HistoriqueSorties::from_bytes` — l'archive des sorties (journal en ajout).
//!
//! Le décodeur tolère une QUEUE PARTIELLE (crash en plein ajout) mais refuse une
//! corruption interne. Ces deux comportements se ressemblent assez pour qu'un
//! fuzzer soit le bon outil : il produira les deux formes indistinctement.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ledger::historique::HistoriqueSorties::from_bytes(data);
});
