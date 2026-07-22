//! `ProvedTx::from_bytes` — le décodeur le plus riche du dépôt (curseur borné,
//! digests canoniques, bornes EncNote). Jamais de panique.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = circuit::ProvedTx::from_bytes(data);
});
