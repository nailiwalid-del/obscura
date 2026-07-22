//! `Wallet::from_bytes_secret` — le fichier le plus sensible du projet.
//!
//! Il porte l'AUTORITÉ DE DÉPENSE. Un fichier abîmé doit rendre une erreur, jamais
//! paniquer et jamais produire un wallet silencieusement FAUX : un octet retourné
//! dans un montant donnerait un solde erroné sans le moindre message. C'est
//! précisément ce que l'empreinte `dual_hash` non tronquée est censée attraper —
//! le fuzzing éprouve ce contrat.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = wallet::Wallet::from_bytes_secret(data);
});
