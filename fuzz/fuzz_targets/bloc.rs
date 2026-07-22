//! `Bloc::from_bytes` — transactions, émissions, autorités, extension, vue,
//! scellement, CERTIFICAT DE QUORUM : chaque section est bornée AVANT allocation.
//! Jamais de panique.
//!
//! # Corpus semé (`fuzz/corpus/bloc/`)
//!
//! Le fuzzing est guidé par la couverture, donc l'octet de version se trouve seul.
//! Ce qui reste hors de portée d'une mutation aveugle, ce sont les chemins
//! PROFONDS : une émission aux longueurs exactes, ou un certificat dont le masque
//! et le nombre de signatures CONCORDENT — cette dernière contrainte ne s'obtient
//! pas par hasard.
//!
//! Le corpus est donc semé de blocs VALIDES (`cargo run -p node --example
//! semer-corpus-fuzz`) et VERSIONNÉ : les mutations partent alors de blocs presque
//! valides, c'est-à-dire de la forme qu'un adversaire fabriquerait réellement.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ledger::bloc::Bloc::from_bytes(data);
});
