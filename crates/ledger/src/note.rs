//! Note : l'unité de valeur privée. Seul son commitment apparaît on-chain.

use crate::{Commitment, LedgerError};
use crypto::hash;
use rand_core::{OsRng, RngCore};

pub const NOTE_LEN: usize = 8 + 32 + 32 + 32;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Note {
    pub value: u64,
    pub owner: [u8; 32],
    pub rho: [u8; 32],
    pub r: [u8; 32],
}

impl Note {
    /// Nouvelle note pour `owner` avec aléa frais (rho unique, r hiding).
    pub fn new(value: u64, owner: [u8; 32]) -> Self {
        let mut rho = [0u8; 32];
        let mut r = [0u8; 32];
        OsRng.fill_bytes(&mut rho);
        OsRng.fill_bytes(&mut r);
        Note {
            value,
            owner,
            rho,
            r,
        }
    }

    /// Encodage canonique fixe (déterminisme du commitment).
    pub fn to_bytes(&self) -> [u8; NOTE_LEN] {
        let mut b = [0u8; NOTE_LEN];
        b[..8].copy_from_slice(&self.value.to_le_bytes());
        b[8..40].copy_from_slice(&self.owner);
        b[40..72].copy_from_slice(&self.rho);
        b[72..104].copy_from_slice(&self.r);
        b
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, LedgerError> {
        if b.len() != NOTE_LEN {
            return Err(LedgerError::Encoding);
        }
        let mut value = [0u8; 8];
        value.copy_from_slice(&b[..8]);
        let mut owner = [0u8; 32];
        owner.copy_from_slice(&b[8..40]);
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&b[40..72]);
        let mut r = [0u8; 32];
        r.copy_from_slice(&b[72..104]);
        Ok(Note {
            value: u64::from_le_bytes(value),
            owner,
            rho,
            r,
        })
    }

    /// Commitment dual (BLAKE3 ‖ SHA3) : hiding (grâce à r), binding (double collision-résistance).
    pub fn commitment(&self) -> Commitment {
        Commitment::from_bytes64(&hash::dual_hash("obscura/note/v1", &self.to_bytes()))
    }

    /// Nullifier v2 : PRF de (rho ‖ commitment) sous la clé nk du propriétaire.
    ///
    /// Lier le commitment neutralise le sabotage « deux notes de même rho pour le
    /// même destinataire → même nullifier → l'une devient indépensable ».
    pub fn nullifier(&self, nk: &[u8; 32]) -> [u8; 32] {
        let cm = self.commitment().to_bytes();
        let mut data = Vec::with_capacity(32 + 64);
        data.extend_from_slice(&self.rho);
        data.extend_from_slice(&cm);
        hash::prf(nk, "obscura/nullifier/v2", &data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_deterministe_et_hiding() {
        let n = Note::new(42, [1u8; 32]);
        assert_eq!(n.commitment(), n.commitment());
        // même valeur, même owner, aléa différent => commitment différent (hiding)
        let n2 = Note::new(42, [1u8; 32]);
        assert_ne!(n.commitment(), n2.commitment());
    }

    #[test]
    fn nullifier_depend_de_nk() {
        let n = Note::new(1, [0u8; 32]);
        assert_ne!(n.nullifier(&[1u8; 32]), n.nullifier(&[2u8; 32]));
    }

    #[test]
    fn meme_rho_nullifiers_differents() {
        // Sabotage v0.1 : deux notes de même rho partageaient le même nullifier.
        // v0.2 : le nullifier est lié au commitment, donc distinct si r diffère.
        let nk = [3u8; 32];
        let a = Note::new(5, [1u8; 32]);
        let mut b = a.clone();
        b.r = [9u8; 32]; // même value/owner/rho, aléa différent
        assert_ne!(a.commitment(), b.commitment());
        assert_ne!(a.nullifier(&nk), b.nullifier(&nk));
    }

    #[test]
    fn roundtrip_encodage() {
        let n = Note::new(7, [9u8; 32]);
        assert_eq!(Note::from_bytes(&n.to_bytes()).unwrap(), n);
    }
}
