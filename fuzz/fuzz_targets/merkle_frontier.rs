//! `MerkleFrontier::from_bytes` — le bord droit de l'arbre, côté NŒUD.
//!
//! Structure à mémoire bornée : le décodage doit refuser une profondeur ou un
//! nombre de nœuds absurdes AVANT d'allouer, sinon un fichier de quelques octets
//! réserverait des gigaoctets au démarrage.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = proved_hash::merkle::MerkleFrontier::from_bytes(data);
});
