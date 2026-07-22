//! `ProvedMerkleTree::from_bytes` — l'arbre COMPLET, celui du wallet.
//!
//! C'est lui qui produit les chemins d'appartenance : un arbre relu de travers
//! donnerait des preuves refusées pour « ancre inconnue », sans que rien ne
//! désigne le fichier comme cause.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = proved_hash::merkle::ProvedMerkleTree::from_bytes(data);
});
