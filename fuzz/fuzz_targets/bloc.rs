//! `Bloc::from_bytes` — transactions, émissions, autorités, extension,
//! scellement : chaque section est bornée AVANT allocation. Jamais de panique.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ledger::bloc::Bloc::from_bytes(data);
});
