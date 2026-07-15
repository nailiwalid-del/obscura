//! Digest prouvé (4 Felts, 32 o) et secret shielded (même encodage, masqué).

use crate::felt::Felt;
use crate::EncodingError;
use zeroize::Zeroize;

pub const DIGEST_FELTS: usize = 4;
pub const DIGEST_BYTES: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest(pub [Felt; DIGEST_FELTS]);

fn felts_to_bytes(felts: &[Felt; DIGEST_FELTS]) -> [u8; DIGEST_BYTES] {
    let mut out = [0u8; DIGEST_BYTES];
    for (i, f) in felts.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&f.to_bytes());
    }
    out
}

fn felts_from_bytes(b: &[u8; DIGEST_BYTES]) -> Result<[Felt; DIGEST_FELTS], EncodingError> {
    let mut felts = [Felt::ZERO; DIGEST_FELTS];
    for (i, felt) in felts.iter_mut().enumerate() {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&b[i * 8..(i + 1) * 8]);
        *felt = Felt::from_bytes(&chunk)?;
    }
    Ok(felts)
}

impl Digest {
    pub fn to_bytes(&self) -> [u8; DIGEST_BYTES] {
        felts_to_bytes(&self.0)
    }
    pub fn from_bytes(b: &[u8; DIGEST_BYTES]) -> Result<Self, EncodingError> {
        Ok(Digest(felts_from_bytes(b)?))
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

impl core::fmt::Debug for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Digest({})", self.to_hex())
    }
}

impl serde::Serialize for Digest {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // Forme canonique : chaîne hex de 64 caractères (pas de tableau d'entiers ambigu).
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for Digest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let hexs = <String as serde::Deserialize>::deserialize(d)?;
        let bytes = hex::decode(&hexs).map_err(serde::de::Error::custom)?;
        let arr: [u8; DIGEST_BYTES] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom("longueur digest != 32"))?;
        Digest::from_bytes(&arr).map_err(serde::de::Error::custom)
    }
}

/// Secret racine shielded : même encodage qu'un Digest, mais JAMAIS affiché ni logué.
#[derive(Clone, PartialEq, Eq)]
pub struct ShieldedSecret([Felt; DIGEST_FELTS]);

impl ShieldedSecret {
    pub fn from_felts(felts: [Felt; DIGEST_FELTS]) -> Self {
        ShieldedSecret(felts)
    }
    pub fn as_felts(&self) -> &[Felt; DIGEST_FELTS] {
        &self.0
    }
    pub fn to_bytes(&self) -> [u8; DIGEST_BYTES] {
        felts_to_bytes(&self.0)
    }
    pub fn from_bytes(b: &[u8; DIGEST_BYTES]) -> Result<Self, EncodingError> {
        Ok(ShieldedSecret(felts_from_bytes(b)?))
    }
}

// Debug masqué : ne jamais révéler le secret dans les logs.
impl core::fmt::Debug for ShieldedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ShieldedSecret(<redacted>)")
    }
}

// Effacement best-effort à la libération.
impl Zeroize for ShieldedSecret {
    fn zeroize(&mut self) {
        for felt in self.0.iter_mut() {
            *felt = Felt::ZERO;
        }
    }
}
impl Drop for ShieldedSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn felt(x: u64) -> Felt {
        Felt::from_canonical_u64(x).unwrap()
    }

    #[test]
    fn digest_roundtrip() {
        let d = Digest([felt(0), felt(1), felt(crate::felt::P - 1), felt(42)]);
        assert_eq!(Digest::from_bytes(&d.to_bytes()).unwrap(), d);
        assert_eq!(d.to_hex().len(), 64);
    }

    #[test]
    fn digest_rejette_felt_non_canonique() {
        let mut bytes = [0u8; DIGEST_BYTES];
        bytes[8..16].copy_from_slice(&crate::felt::P.to_le_bytes()); // 2e felt = p
        assert!(Digest::from_bytes(&bytes).is_err());
    }

    #[test]
    fn shielded_secret_roundtrip_et_masque() {
        let s = ShieldedSecret::from_felts([felt(7), felt(8), felt(9), felt(10)]);
        assert_eq!(ShieldedSecret::from_bytes(&s.to_bytes()).unwrap(), s);
        // Debug ne fuit rien.
        assert_eq!(format!("{:?}", s), "ShieldedSecret(<redacted>)");
    }

    #[test]
    fn shielded_secret_rejette_non_canonique() {
        let mut bytes = [0u8; DIGEST_BYTES];
        bytes[0..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(ShieldedSecret::from_bytes(&bytes).is_err());
    }
}
