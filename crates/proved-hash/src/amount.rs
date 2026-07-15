//! Montant u64 décomposé en 4 limbs de 16 bits (little-endian, low-to-high).
//! Interdit le mapping naïf u64 -> Felt pour les contraintes de range/équilibre.

use crate::felt::Felt;
use crate::EncodingError;

pub const AMOUNT_LIMBS: usize = 4;
pub const LIMB_BITS: u32 = 16;
pub const LIMB_MAX: u64 = (1 << LIMB_BITS) - 1; // 65535

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AmountLimbs([u16; AMOUNT_LIMBS]);

impl AmountLimbs {
    pub fn from_u64(x: u64) -> Self {
        AmountLimbs([
            (x & 0xFFFF) as u16,
            ((x >> 16) & 0xFFFF) as u16,
            ((x >> 32) & 0xFFFF) as u16,
            ((x >> 48) & 0xFFFF) as u16,
        ])
    }

    pub fn to_u64(&self) -> u64 {
        let l = &self.0;
        (l[0] as u64) | ((l[1] as u64) << 16) | ((l[2] as u64) << 32) | ((l[3] as u64) << 48)
    }

    pub fn limbs(&self) -> &[u16; AMOUNT_LIMBS] {
        &self.0
    }

    /// Représentation circuit : 4 Felts chacun `< 2^16`.
    pub fn to_felts(&self) -> [Felt; AMOUNT_LIMBS] {
        self.0.map(|l| Felt::from_small(l as u32))
    }

    /// Reconstruit depuis des Felts, en rejetant tout limb `>= 2^16`.
    pub fn try_from_felts(felts: &[Felt; AMOUNT_LIMBS]) -> Result<Self, EncodingError> {
        let mut limbs = [0u16; AMOUNT_LIMBS];
        for (i, f) in felts.iter().enumerate() {
            let v = f.as_u64();
            if v > LIMB_MAX {
                return Err(EncodingError::LimbOutOfRange(v));
            }
            limbs[i] = v as u16;
        }
        Ok(AmountLimbs(limbs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn roundtrip_u64() {
        for x in [0u64, 1, LIMB_MAX, LIMB_MAX + 1, u64::MAX] {
            assert_eq!(AmountLimbs::from_u64(x).to_u64(), x);
        }
    }

    #[test]
    fn to_felts_puis_try_from_felts() {
        let a = AmountLimbs::from_u64(0x1234_5678_9ABC_DEF0);
        assert_eq!(AmountLimbs::try_from_felts(&a.to_felts()).unwrap(), a);
    }

    #[test]
    fn rejet_limb_hors_range() {
        let felts = [
            Felt::from_small(0),
            Felt::from_canonical_u64(LIMB_MAX + 1).unwrap(),
            Felt::ZERO,
            Felt::ZERO,
        ];
        assert!(matches!(
            AmountLimbs::try_from_felts(&felts),
            Err(EncodingError::LimbOutOfRange(_))
        ));
    }

    proptest! {
        #[test]
        fn prop_amount_roundtrip(x in any::<u64>()) {
            prop_assert_eq!(AmountLimbs::from_u64(x).to_u64(), x);
        }
    }
}
