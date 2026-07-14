//! Clés d'un wallet : identité shielded (secret racine), signature (enveloppe
//! d'intention), réception (KEM hybride), nullifier.

use crypto::hash;
use crypto::kem::{KemKeypair, KemPublicKey};
use crypto::sig::SigKeypair;
use rand_core::{OsRng, RngCore};

pub struct WalletKeys {
    /// Signature hybride : enveloppe d'intention / anti-malléabilité sur
    /// `tx_digest`. PAS une autorisation d'ownership tant qu'elle n'est pas liée
    /// au `shielded_secret` (décision de circuit, phase 3).
    pub spend: SigKeypair,
    /// KEM hybride : réception et scan des notes.
    pub receive: KemKeypair,
    /// Secret racine de l'identité shielded (32 o), JAMAIS publié : témoin du
    /// circuit STARK. `owner` et `nk` en dérivent (P2/P4).
    shielded_secret: [u8; 32],
    /// Clé de nullifier, dérivée du secret shielded (P4). Nécessaire au calcul
    /// des nullifiers ; ne doit pas être partagée.
    pub nk: [u8; 32],
}

/// Adresse publique : (identité de la note, clé publique KEM).
/// Communiquée hors-chaîne au payeur, jamais publiée on-chain.
#[derive(Clone)]
pub struct Address {
    pub owner: [u8; 32],
    pub kem_pk: KemPublicKey,
}

/// Identité de la note à partir du secret shielded (P2 : `owner = H(secret)`).
///
/// HASH PROUVÉ (domaine consensus-en-circuit) : cette relation sera vérifiée par
/// le STARK. Elle MIGRERA vers Rescue-Prime EN MÊME TEMPS que le circuit — jamais
/// avant (même règle que merkle.rs / note.rs). BLAKE3 ici = échafaudage de dev,
/// PAS un KDF wallet figé.
pub fn owner_from_secret(shielded_secret: &[u8; 32]) -> [u8; 32] {
    hash::blake3_domain("obscura/owner/v2", shielded_secret)
}

/// Clé de nullifier à partir du secret shielded (P4 : `nk` lié à l'autorité).
///
/// HASH PROUVÉ : voir `owner_from_secret`. Migre vers Rescue-Prime avec le circuit.
pub fn nk_from_secret(shielded_secret: &[u8; 32]) -> [u8; 32] {
    hash::blake3_domain("obscura/nk/v2", shielded_secret)
}

impl WalletKeys {
    pub fn generate() -> Self {
        let mut shielded_secret = [0u8; 32];
        OsRng.fill_bytes(&mut shielded_secret);
        WalletKeys {
            spend: SigKeypair::generate(),
            receive: KemKeypair::generate(),
            nk: nk_from_secret(&shielded_secret),
            shielded_secret,
        }
    }

    pub fn address(&self) -> Address {
        Address {
            owner: owner_from_secret(&self.shielded_secret),
            kem_pk: self.receive.public.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_et_nk_derivent_du_secret_shielded() {
        let w = WalletKeys::generate();
        // P4 : nk est une fonction (prouvable) du secret racine.
        assert_eq!(w.nk, nk_from_secret(&w.shielded_secret));
        // P2 : owner = H(secret).
        assert_eq!(w.address().owner, owner_from_secret(&w.shielded_secret));
        // owner et nk sont deux dérivations distinctes (domaines séparés).
        assert_ne!(w.address().owner, w.nk);
    }

    #[test]
    fn derivations_deterministes_et_domaines_figes() {
        // Secret fixe : les dérivations sont déterministes et séparées par domaine.
        let s = [42u8; 32];
        assert_eq!(
            owner_from_secret(&s),
            hash::blake3_domain("obscura/owner/v2", &s)
        );
        assert_eq!(nk_from_secret(&s), hash::blake3_domain("obscura/nk/v2", &s));
        assert_ne!(owner_from_secret(&s), nk_from_secret(&s));

        // Vecteurs hex figés : gèlent les domaines "obscura/{owner,nk}/v2" (hash prouvé)
        // jusqu'à la migration Rescue-Prime. Toute rupture ici = changement de consensus.
        assert_eq!(
            hex::encode(owner_from_secret(&s)),
            "5b80b1f4e8ba8686ad9a3286de1792547bd139bbe9d6c5a9c2380e888e3a41c7"
        );
        assert_eq!(
            hex::encode(nk_from_secret(&s)),
            "bfce49be96ce47ee0a22b2951a52cb7b43dc2ee40ffa95d038d17ee4cebfb4c6"
        );
    }

    #[test]
    fn deux_wallets_ont_des_identites_distinctes() {
        let a = WalletKeys::generate();
        let b = WalletKeys::generate();
        assert_ne!(a.shielded_secret, b.shielded_secret);
        assert_ne!(a.nk, b.nk);
        assert_ne!(a.address().owner, b.address().owner);
    }
}
