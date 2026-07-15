//! Élément du corps de Goldilocks, forme canonique uniquement.
//! 3a0 : encodage/validation seulement — l'arithmétique (Rescue) arrive en 3a1.

use crate::EncodingError;

/// Modulus de Goldilocks : p = 2^64 - 2^32 + 1.
pub const P: u64 = 0xFFFF_FFFF_0000_0001;

/// Élément de corps en forme canonique : invariant `0 <= value < P`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Felt(u64);

impl Felt {
    pub const ZERO: Felt = Felt(0);
    pub const ONE: Felt = Felt(1);

    /// Construit un Felt canonique ; rejette toute valeur `>= P`.
    pub fn from_canonical_u64(x: u64) -> Result<Self, EncodingError> {
        if x < P {
            Ok(Felt(x))
        } else {
            Err(EncodingError::NonCanonicalFelt(x))
        }
    }

    /// Petite constante (tag de domaine, version) : garantie `< P` car `x < 2^32`.
    pub const fn from_small(x: u32) -> Self {
        Felt(x as u64)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }

    pub fn to_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    pub fn from_bytes(b: &[u8; 8]) -> Result<Self, EncodingError> {
        Self::from_canonical_u64(u64::from_le_bytes(*b))
    }
}

impl core::fmt::Debug for Felt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Felt({})", self.0)
    }
}

// Pont vers le corps de winter-math (Goldilocks) pour le hash prouvé (3a1).
use winter_math::fields::f64::BaseElement;

impl Felt {
    /// Conversion exacte vers le corps de winter (déjà canonique `< p`).
    pub fn to_winter(self) -> BaseElement {
        BaseElement::new(self.0)
    }

    /// Depuis un BaseElement : `as_int()` renvoie la forme canonique `< p`.
    pub fn from_winter(be: BaseElement) -> Result<Self, EncodingError> {
        Self::from_canonical_u64(be.as_int())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_canonique() {
        for x in [0u64, 1, P - 1] {
            let f = Felt::from_canonical_u64(x).unwrap();
            assert_eq!(f.as_u64(), x);
            assert_eq!(Felt::from_bytes(&f.to_bytes()).unwrap(), f);
        }
    }

    #[test]
    fn rejet_non_canonique() {
        assert!(Felt::from_canonical_u64(P).is_err());
        assert!(Felt::from_canonical_u64(P + 1).is_err());
        assert!(Felt::from_canonical_u64(u64::MAX).is_err());
        // décodage de bytes non canoniques
        assert!(Felt::from_bytes(&P.to_le_bytes()).is_err());
    }

    #[test]
    fn roundtrip_base_element() {
        for x in [0u64, 1, P - 1] {
            let f = Felt::from_canonical_u64(x).unwrap();
            assert_eq!(Felt::from_winter(f.to_winter()).unwrap(), f);
        }
    }
}
