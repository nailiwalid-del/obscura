//! `Message::from_bytes` — LE point d'entrée applicatif : tout octet déchiffré
//! d'un pair passe par lui. Jamais de panique, bornes avant allocation.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = node::message::Message::from_bytes(data);
});
