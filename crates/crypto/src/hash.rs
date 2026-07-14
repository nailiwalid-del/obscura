//! Hachage à double primitive : BLAKE3 (ARX) + SHA3-256 (éponge Keccak).
//! `dual_hash` reste résistant aux collisions tant que L'UN des deux l'est.

use sha3::{Digest, Sha3_256};

pub const DIGEST_LEN: usize = 32;
pub const DUAL_DIGEST_LEN: usize = 64;

/// BLAKE3 avec séparation de domaine.
pub fn blake3_domain(domain: &str, data: &[u8]) -> [u8; 32] {
    blake3::derive_key(domain, data)
}

/// SHA3-256 avec séparation de domaine (préfixe longueur pour éviter toute ambiguïté).
pub fn sha3_domain(domain: &str, data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update((domain.len() as u64).to_le_bytes());
    h.update(domain.as_bytes());
    h.update(data);
    h.finalize().into()
}

/// Hash dual : BLAKE3 ‖ SHA3-256 (64 octets, jamais tronqué).
pub fn dual_hash(domain: &str, data: &[u8]) -> [u8; DUAL_DIGEST_LEN] {
    let mut out = [0u8; DUAL_DIGEST_LEN];
    out[..32].copy_from_slice(&blake3_domain(domain, data));
    out[32..].copy_from_slice(&sha3_domain(domain, data));
    out
}

/// PRF à clé (BLAKE3 keyed) avec séparation de domaine.
pub fn prf(key: &[u8; 32], domain: &str, data: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(&(domain.len() as u64).to_le_bytes());
    h.update(domain.as_bytes());
    h.update(data);
    *h.finalize().as_bytes()
}

/// Dérivation de sous-clé depuis une graine (KDF).
pub fn derive_key(context: &str, seed: &[u8]) -> [u8; 32] {
    blake3::derive_key(context, seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dual_hash_deterministe_et_sensible() {
        let a = dual_hash("test/v1", b"bonjour");
        let b = dual_hash("test/v1", b"bonjour");
        let c = dual_hash("test/v1", b"bonjout");
        let d = dual_hash("test/v2", b"bonjour");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d); // séparation de domaine
        assert_ne!(a[..32], a[32..]); // les deux moitiés sont indépendantes
    }

    #[test]
    fn prf_depend_de_la_cle() {
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        assert_ne!(prf(&k1, "t", b"x"), prf(&k2, "t", b"x"));
        assert_eq!(prf(&k1, "t", b"x"), prf(&k1, "t", b"x"));
    }
}
