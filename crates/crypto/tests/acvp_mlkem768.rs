//! Conformité ACVP CIBLÉE — ML-KEM-768, opération de DÉCAPSULATION.
//!
//! # Pourquoi ce test appelle `pqcrypto` en direct
//!
//! `crypto::kem::decapsulate` est HYBRIDE : il fait un Diffie-Hellman X25519, une
//! décapsulation ML-KEM, puis combine les deux par KDF sur le transcript. Il ne
//! peut donc pas consommer un vecteur ACVP, qui porte sur la primitive BRUTE.
//! Ce test valide le BACKEND (`pqcrypto-mlkem`), pas la couche hybride.
//!
//! Ce n'est pas un pis-aller : le backend est précisément ce qui est marqué
//! `unmaintained` (cf. `docs/BACKEND_PQ.md`), donc ce test est le filet du jour où
//! il sera remplacé. Un backend substitué qui ne rejoue pas ces vecteurs est
//! refusé avant d'atteindre le consensus.
//!
//! # Ce qui n'est PAS couvert, et pourquoi
//!
//! `keyGen` et `encap` exigent d'injecter l'aléa officiel. `mlkem768::keypair()`
//! ne prend AUCUN argument : l'injection est impossible avec ce backend. Voir
//! `vecteurs/PROVENANCE.md`.

use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{Ciphertext as _, SecretKey as _, SharedSecret as _};

const FICHIER: &str = include_str!("vecteurs/mlkem768-decap.txt");

/// Tailles FIPS 203 pour ML-KEM-768. Codées en dur ICI et nulle part ailleurs :
/// un vecteur officiel qui ne les respecte pas n'est pas un vecteur ML-KEM-768.
const DK_LEN: usize = 2400;
const CT_LEN: usize = 1088;
const SS_LEN: usize = 32;

/// Un vecteur : clé de décapsulation, chiffré, secret partagé attendu.
struct Vecteur {
    dk: Vec<u8>,
    c: Vec<u8>,
    k: Vec<u8>,
}

/// Charge les vecteurs. Toute ligne malformée est une ERREUR FRANCHE : un fichier
/// de vecteurs à moitié lu donnerait un test vert sur trois vecteurs au lieu de
/// dix, ce qui est pire que pas de test du tout.
fn charger() -> Vec<Vecteur> {
    let mut v = Vec::new();
    for (n, ligne) in FICHIER.lines().enumerate() {
        let ligne = ligne.trim();
        if ligne.is_empty() || ligne.starts_with('#') {
            continue;
        }
        let champs: Vec<&str> = ligne.split(':').collect();
        assert_eq!(
            champs.len(),
            3,
            "ligne {} : attendu 3 champs séparés par ':', reçu {}",
            n + 1,
            champs.len()
        );
        let dk = hex::decode(champs[0])
            .unwrap_or_else(|e| panic!("ligne {} : dk non hexadécimal ({e})", n + 1));
        let c = hex::decode(champs[1])
            .unwrap_or_else(|e| panic!("ligne {} : c non hexadécimal ({e})", n + 1));
        let k = hex::decode(champs[2])
            .unwrap_or_else(|e| panic!("ligne {} : k non hexadécimal ({e})", n + 1));
        assert_eq!(dk.len(), DK_LEN, "ligne {} : dk fait {} o", n + 1, dk.len());
        assert_eq!(c.len(), CT_LEN, "ligne {} : c fait {} o", n + 1, c.len());
        assert_eq!(k.len(), SS_LEN, "ligne {} : k fait {} o", n + 1, k.len());
        v.push(Vecteur { dk, c, k });
    }
    v
}

/// Le fichier doit contenir les 10 vecteurs du groupe retenu. Sans cette
/// assertion, supprimer le fichier rendrait la suite VERTE — l'échec silencieux
/// le plus coûteux possible pour un test dont l'unique raison d'être est de
/// convaincre un auditeur.
#[test]
fn le_fichier_de_vecteurs_est_peuple() {
    let v = charger();
    assert_eq!(
        v.len(),
        10,
        "le groupe ML-KEM-768 / decapsulation / expanded compte 10 tests ACVP ; \
         {} trouvés — voir vecteurs/PROVENANCE.md",
        v.len()
    );
}

#[test]
fn acvp_mlkem768_decapsulation() {
    for (i, vec) in charger().iter().enumerate() {
        // `{e:?}` et non `{e}` : l'erreur de `pqcrypto-traits` garantit `Debug`,
        // pas `Display`.
        let sk = mlkem768::SecretKey::from_bytes(&vec.dk)
            .unwrap_or_else(|e| panic!("vecteur {i} : dk refusé par le backend ({e:?})"));
        let ct = mlkem768::Ciphertext::from_bytes(&vec.c)
            .unwrap_or_else(|e| panic!("vecteur {i} : c refusé par le backend ({e:?})"));
        let ss = mlkem768::decapsulate(&ct, &sk);
        assert_eq!(
            ss.as_bytes(),
            &vec.k[..],
            "vecteur {i} : secret partagé différent du vecteur officiel"
        );
    }
}
