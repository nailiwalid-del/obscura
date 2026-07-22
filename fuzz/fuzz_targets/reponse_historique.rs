//! `ReponseHistorique::from_bytes` — le décodeur qui RECALCULE le découpage
//! canonique (morceaux, décalage, comptes). Jamais de panique.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = node::synchro::ReponseHistorique::from_bytes(data);
});
