//! Clés d'un wallet : identité shielded (secret racine), signature (enveloppe
//! d'intention), réception (KEM hybride), nullifier.
//!
//! MODE TRANSPARENT (dev uniquement, feature `dev-transparent`) : ne compile pas
//! dans le build nu. L'identité du CONSENSUS n'est pas celle-ci — elle est
//! Rescue-Prime (`rescue::hash(Domain::Owner | Domain::Nk, …)`, prouvée par le
//! bloc clé du monolithe `circuit::monolith`) et le wallet du chemin prouvé la
//! dérive lui-même, sans jamais passer par ce module (cf. `crates/wallet/src/lib.rs`
//! et `proved_wallet`).

use crypto::hash;
use crypto::kem::{KemKeypair, KemPublicKey};
use crypto::sig::SigKeypair;
use rand_core::{OsRng, RngCore};

pub struct WalletKeys {
    /// Signature hybride : enveloppe d'intention / anti-malléabilité sur
    /// `tx_digest`. PAS une autorisation d'ownership : la décision de circuit est
    /// tranchée et le chemin prouvé ne lie NI `tx_digest` NI `signer` au
    /// `shielded_secret` — l'ownership vient de la preuve, pas de la signature
    /// (cf. `circuit::tx`).
    pub spend: SigKeypair,
    /// KEM hybride : réception et scan des notes.
    pub receive: KemKeypair,
    /// Secret racine de l'identité shielded (32 o), JAMAIS publié. `owner` et `nk`
    /// en dérivent (P2/P4). Le témoin du circuit STARK est son homologue prouvé,
    /// `proved_hash::digest::ShieldedSecret` (felts), pas ces 32 octets.
    shielded_secret: [u8; 32],
    /// Clé de nullifier, dérivée du secret shielded (P4). Nécessaire au calcul
    /// des nullifiers ; ne doit pas être partagée.
    pub nk: [u8; 32],
}

// Effacement des secrets bruts au drop (durcissement #7). Les moitiés dalek de `spend`
// (Ed25519) et `receive` (X25519) s'effacent déjà d'elles-mêmes au drop ; les moitiés
// pqcrypto (ML-KEM/ML-DSA) sont effacées depuis T1 — octets en `Zeroizing`, type
// pqcrypto reconstruit à chaque usage (cf. crypto/{kem,sig}.rs).
impl Drop for WalletKeys {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.shielded_secret.zeroize();
        self.nk.zeroize();
    }
}

/// Adresse publique : (identité de la note, clé publique KEM).
/// Communiquée hors-chaîne au payeur, jamais publiée on-chain.
#[derive(Clone)]
pub struct Address {
    pub owner: [u8; 32],
    pub kem_pk: KemPublicKey,
}

/// Identité de la note à partir du secret shielded (P2 : `owner = H(secret)`),
/// version MODE TRANSPARENT.
///
/// ⚠️ Ce n'est PAS le hash du consensus. La migration vers Rescue-Prime a eu lieu
/// côté circuit : l'`owner` prouvé est `rescue::hash(Domain::Owner, s)` sur les
/// felts du secret (`circuit::monolith`, et `circuit::key` en version autonome).
/// Cette dérivation-ci ne migrera JAMAIS — elle ne sert qu'au mode transparent et
/// disparaîtra avec lui.
pub fn owner_from_secret(shielded_secret: &[u8; 32]) -> [u8; 32] {
    hash::blake3_domain("obscura/owner/v2", shielded_secret)
}

/// Clé de nullifier à partir du secret shielded (P4 : `nk` lié à l'autorité),
/// version MODE TRANSPARENT.
///
/// ⚠️ Voir `owner_from_secret` : le `nk` du consensus est
/// `rescue::hash(Domain::Nk, s)`, lié au MÊME secret que l'owner par la contrainte
/// de liaison du bloc clé (ligne 0, cf. `circuit::key`). Cette dérivation-ci ne
/// migrera JAMAIS.
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

        // Vecteurs hex figés : gèlent les domaines "obscura/{owner,nk}/v2" du mode
        // transparent. HORS CONSENSUS — une rupture ici ne casse pas la chaîne (dont
        // l'identité est Rescue), seulement les fixtures et scénarios de dev.
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
