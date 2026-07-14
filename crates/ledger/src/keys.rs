//! Clés d'un wallet : dépense (signature hybride), réception (KEM hybride), nullifier.

use crypto::hash;
use crypto::kem::{KemKeypair, KemPublicKey};
use crypto::sig::SigKeypair;
use rand_core::{OsRng, RngCore};

pub struct WalletKeys {
    pub spend: SigKeypair,
    pub receive: KemKeypair,
    /// Clé de nullifier : jamais partagée, dérivée d'une graine locale.
    pub nk: [u8; 32],
}

/// Adresse publique : (hash de la clé de dépense, clé publique KEM).
/// Communiquée hors-chaîne au payeur, jamais publiée on-chain.
#[derive(Clone)]
pub struct Address {
    pub owner: [u8; 32],
    pub kem_pk: KemPublicKey,
}

impl WalletKeys {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        WalletKeys {
            spend: SigKeypair::generate(),
            receive: KemKeypair::generate(),
            nk: hash::derive_key("obscura/nk/v1", &seed),
        }
    }

    pub fn address(&self) -> Address {
        Address {
            owner: self.spend.public.hash(),
            kem_pk: self.receive.public.clone(),
        }
    }
}
