//! KEM hybride : X25519 (courbes elliptiques) + ML-KEM-768 (réseaux euclidiens,
//! FIPS 203, byte 0x02). Le secret partagé combine les deux via KDF sur le
//! transcript complet : il reste sûr tant que L'UN des deux problèmes tient.
//!
//! Migration T1 (plan Testnet 0) : la version round-3 (Kyber768, 0x01) est REFUSÉE
//! PAR SON NOM (`CryptoError::AlgoPerime`), jamais réinterprétée — aucun réseau
//! public n'a existé en round-3, il n'y avait rien à migrer sauf des fichiers
//! locaux. Tailles identiques à round-3 (pk 1184, ct 1088) : aucun format aval ne
//! bouge, seuls la version, l'identifiant et le domaine de dérivation changent.
//!
//! Zeroize : la moitié X25519 (`StaticSecret` dalek) s'efface au drop ; la moitié
//! ML-KEM est stockée en `Zeroizing<Vec<u8>>` et le type pqcrypto est RECONSTRUIT à
//! chaque décapsulation (repli T1.5, choisi : pqcrypto-mlkem n'expose pas de
//! zeroize — coût, un `from_bytes` de 2400 o par usage, hors chemin chaud).

use crate::CryptoError;
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const X25519_PK_LEN: usize = 32;

/// Identifiant d'algorithme (versioning explicite). `0x01` = round-3, PÉRIMÉ et
/// refusé par son nom ; `0x02` = FIPS 203 (courant).
pub const KEM_ALGO_ID: &str = "x25519+mlkem768-fips203";
pub const KEM_ALGO_VERSION: u8 = 0x02;
const KEM_ALGO_VERSION_PERIMEE: u8 = 0x01;

/// Contrôle de version d'un objet sérialisé : la version courante passe, la version
/// round-3 est refusée PAR SON NOM, tout le reste est un encodage invalide.
fn verifier_version(b: &[u8], quoi: &'static str) -> Result<(), CryptoError> {
    match b.first() {
        Some(&KEM_ALGO_VERSION) => Ok(()),
        Some(&KEM_ALGO_VERSION_PERIMEE) => Err(CryptoError::AlgoPerime {
            quoi,
            version: KEM_ALGO_VERSION_PERIMEE,
        }),
        _ => Err(CryptoError::InvalidEncoding(quoi)),
    }
}

#[derive(Clone)]
pub struct KemPublicKey {
    pub x25519: [u8; 32],
    pub mlkem: mlkem768::PublicKey,
}

pub struct KemSecretKey {
    x25519: StaticSecret,
    /// Octets du secret ML-KEM, effacés au drop ; le type pqcrypto est reconstruit
    /// à chaque décapsulation (cf. tête de module).
    mlkem: Zeroizing<Vec<u8>>,
}

pub struct KemKeypair {
    pub public: KemPublicKey,
    pub secret: KemSecretKey,
}

#[derive(Clone)]
pub struct KemCiphertext {
    pub x25519_eph: [u8; 32],
    pub mlkem_ct: mlkem768::Ciphertext,
}

impl KemKeypair {
    pub fn generate() -> Self {
        let mut xb = [0u8; 32];
        OsRng.fill_bytes(&mut xb);
        let xsk = StaticSecret::from(xb);
        let xpk = XPublicKey::from(&xsk);
        let (mpk, msk) = mlkem768::keypair();
        KemKeypair {
            public: KemPublicKey {
                x25519: *xpk.as_bytes(),
                mlkem: mpk,
            },
            secret: KemSecretKey {
                x25519: xsk,
                mlkem: Zeroizing::new(msk.as_bytes().to_vec()),
            },
        }
    }
}

/// Combine les deux secrets en liant tout le transcript (clés publiques + ciphertexts) :
/// empêche les attaques par mélange de sessions.
fn combine(ss1: &[u8], ss2: &[u8], eph_pk: &[u8], mlkem_ct: &[u8], pk: &KemPublicKey) -> [u8; 32] {
    let mut t = Vec::with_capacity(
        ss1.len() + ss2.len() + eph_pk.len() + mlkem_ct.len() + 32 + mlkem768::public_key_bytes(),
    );
    t.extend_from_slice(ss1);
    t.extend_from_slice(ss2);
    t.extend_from_slice(eph_pk);
    t.extend_from_slice(mlkem_ct);
    t.extend_from_slice(&pk.x25519);
    t.extend_from_slice(pk.mlkem.as_bytes());
    t.push(KEM_ALGO_VERSION);
    // Le domaine PORTE l'identifiant d'algo : une confusion inter-versions est
    // structurellement impossible (T1.2) — les clés dérivées changent avec lui.
    crate::hash::derive_key("obscura/kem/x25519+mlkem768-fips203/combine/v1", &t)
}

/// Encapsule vers `pk` : retourne (ciphertext, secret partagé 32 o).
///
/// **Rejette un `pk` X25519 d'ordre faible** (`CryptoError::NonContributif`) : sans ce
/// contrôle, le DH rendrait un secret nul et la moitié courbes du KEM disparaîtrait en
/// silence, laissant ML-KEM porter seul la sécurité. Voir `NonContributif`.
pub fn encapsulate(pk: &KemPublicKey) -> Result<(KemCiphertext, [u8; 32]), CryptoError> {
    let mut eb = [0u8; 32];
    OsRng.fill_bytes(&mut eb);
    let esk = StaticSecret::from(eb);
    let epk = XPublicKey::from(&esk);
    let ss1 = esk.diffie_hellman(&XPublicKey::from(pk.x25519));
    if !ss1.was_contributory() {
        return Err(CryptoError::NonContributif);
    }
    let (ss2, ct2) = mlkem768::encapsulate(&pk.mlkem);
    let ss = combine(
        ss1.as_bytes(),
        ss2.as_bytes(),
        epk.as_bytes(),
        ct2.as_bytes(),
        pk,
    );
    Ok((
        KemCiphertext {
            x25519_eph: *epk.as_bytes(),
            mlkem_ct: ct2,
        },
        ss,
    ))
}

/// Décapsule avec la paire de clés du destinataire.
///
/// **Rejette un éphémère X25519 d'ordre faible** : c'est le sens ADVERSE du même
/// contrôle. Un expéditeur hostile qui place un point d'ordre faible dans `ct` force un
/// secret nul côté receveur — le chiffrement des notes reposerait alors sur ML-KEM seul,
/// à l'insu du receveur.
pub fn decapsulate(kp: &KemKeypair, ct: &KemCiphertext) -> Result<[u8; 32], CryptoError> {
    let ss1 = kp
        .secret
        .x25519
        .diffie_hellman(&XPublicKey::from(ct.x25519_eph));
    if !ss1.was_contributory() {
        return Err(CryptoError::NonContributif);
    }
    // Reconstruction du type pqcrypto depuis les octets zeroizés — validés à la
    // construction, l'échec est donc un bug interne et non une entrée hostile.
    let msk = mlkem768::SecretKey::from_bytes(&kp.secret.mlkem)
        .map_err(|_| CryptoError::InvalidEncoding("mlkem sk (interne)"))?;
    let ss2 = mlkem768::decapsulate(&ct.mlkem_ct, &msk);
    Ok(combine(
        ss1.as_bytes(),
        ss2.as_bytes(),
        &ct.x25519_eph,
        ct.mlkem_ct.as_bytes(),
        &kp.public,
    ))
}

impl KemKeypair {
    /// Sérialise la paire COMPLÈTE, **clé secrète comprise**.
    ///
    /// ⚠️ DANGER : le résultat est du MATÉRIEL DE CLÉ EN CLAIR. Quiconque l'obtient
    /// peut DÉCHIFFRER toutes les notes reçues par ce wallet — c'est-à-dire découvrir
    /// quels paiements lui sont destinés, et leurs montants. À n'écrire que dans un
    /// fichier aux permissions restreintes, jamais en journal, jamais sur le réseau.
    ///
    /// Existe pour qu'un wallet retrouve sa clé de RÉCEPTION entre deux lancements :
    /// une clé de réception régénérée rendrait indéchiffrables toutes les notes déjà
    /// reçues — donc les fonds correspondants irrécupérables.
    ///
    /// Format : `version ‖ x25519_sk (32 o) ‖ mlkem_pk ‖ mlkem_sk`. La publique
    /// X25519 est DÉRIVÉE de la secrète ; celle de ML-KEM ne l'est pas avec cette
    /// crate, elle doit donc être stockée — asymétrie du format qui tient à la
    /// bibliothèque, pas au protocole (même situation que `SigKeypair`).
    pub fn to_bytes_secret(&self) -> Vec<u8> {
        let mut v = vec![KEM_ALGO_VERSION];
        v.extend_from_slice(&self.secret.x25519.to_bytes());
        v.extend_from_slice(self.public.mlkem.as_bytes());
        v.extend_from_slice(&self.secret.mlkem);
        v
    }

    /// Restaure une paire depuis `to_bytes_secret`. Un fichier round-3 (0x01) est
    /// refusé PAR SON NOM — le wallet dit quoi regénérer au lieu d'un « illisible ».
    pub fn from_bytes_secret(b: &[u8]) -> Result<Self, CryptoError> {
        verifier_version(b, "KemKeypair")?;
        let n_pk = mlkem768::public_key_bytes();
        let n_sk = mlkem768::secret_key_bytes();
        if b.len() != 1 + 32 + n_pk + n_sk {
            return Err(CryptoError::InvalidEncoding("KemKeypair"));
        }
        let mut x = [0u8; 32];
        x.copy_from_slice(&b[1..33]);
        let xsk = StaticSecret::from(x);
        let xpk = *XPublicKey::from(&xsk).as_bytes();
        let mpk = mlkem768::PublicKey::from_bytes(&b[33..33 + n_pk])
            .map_err(|_| CryptoError::InvalidEncoding("mlkem pk"))?;
        // Validé ici une fois pour toutes : la reconstruction à l'usage ne revalide
        // que par cohérence interne.
        mlkem768::SecretKey::from_bytes(&b[33 + n_pk..])
            .map_err(|_| CryptoError::InvalidEncoding("mlkem sk"))?;
        Ok(KemKeypair {
            public: KemPublicKey {
                x25519: xpk,
                mlkem: mpk,
            },
            secret: KemSecretKey {
                x25519: xsk,
                mlkem: Zeroizing::new(b[33 + n_pk..].to_vec()),
            },
        })
    }
}

impl KemPublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = vec![KEM_ALGO_VERSION];
        v.extend_from_slice(&self.x25519);
        v.extend_from_slice(self.mlkem.as_bytes());
        v
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        verifier_version(b, "KemPublicKey")?;
        if b.len() != 1 + 32 + mlkem768::public_key_bytes() {
            return Err(CryptoError::InvalidEncoding("KemPublicKey"));
        }
        let mut x = [0u8; 32];
        x.copy_from_slice(&b[1..33]);
        let m = mlkem768::PublicKey::from_bytes(&b[33..])
            .map_err(|_| CryptoError::InvalidEncoding("mlkem pk"))?;
        Ok(KemPublicKey {
            x25519: x,
            mlkem: m,
        })
    }
}

impl KemCiphertext {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = vec![KEM_ALGO_VERSION];
        v.extend_from_slice(&self.x25519_eph);
        v.extend_from_slice(self.mlkem_ct.as_bytes());
        v
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        verifier_version(b, "KemCiphertext")?;
        if b.len() != 1 + 32 + mlkem768::ciphertext_bytes() {
            return Err(CryptoError::InvalidEncoding("KemCiphertext"));
        }
        let mut x = [0u8; 32];
        x.copy_from_slice(&b[1..33]);
        let m = mlkem768::Ciphertext::from_bytes(&b[33..])
            .map_err(|_| CryptoError::InvalidEncoding("mlkem ct"))?;
        Ok(KemCiphertext {
            x25519_eph: x,
            mlkem_ct: m,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Points d'ordre faible de X25519 (RFC 7748 §6.1) : tout DH avec eux rend un
    /// secret NUL. `u = 0` et `u = 1` suffisent à couvrir le cas.
    const ORDRE_FAIBLE: [[u8; 32]; 2] = [[0u8; 32], {
        let mut u = [0u8; 32];
        u[0] = 1;
        u
    }];

    /// ADVERSE — un destinataire dont la moitié X25519 est d'ordre faible doit être
    /// REFUSÉ : sinon on chiffrerait vers lui en ne reposant que sur ML-KEM, sans que
    /// rien ne le signale.
    #[test]
    fn encapsuler_vers_un_point_dordre_faible_est_rejete() {
        let bob = KemKeypair::generate();
        for u in ORDRE_FAIBLE {
            let hostile = KemPublicKey {
                x25519: u,
                mlkem: bob.public.mlkem,
            };
            assert!(
                matches!(encapsulate(&hostile), Err(CryptoError::NonContributif)),
                "un pk d'ordre faible doit être rejeté (u = {:?})",
                &u[..4]
            );
        }
    }

    /// ADVERSE — le sens qui compte vraiment : un EXPÉDITEUR hostile place un éphémère
    /// d'ordre faible dans le ciphertext pour annuler la moitié courbes chez le
    /// receveur. Le receveur doit refuser.
    #[test]
    fn decapsuler_un_ephemere_dordre_faible_est_rejete() {
        let bob = KemKeypair::generate();
        let (ct, _) = encapsulate(&bob.public).unwrap();
        for u in ORDRE_FAIBLE {
            let hostile = KemCiphertext {
                x25519_eph: u,
                mlkem_ct: ct.mlkem_ct,
            };
            assert!(
                matches!(
                    decapsulate(&bob, &hostile),
                    Err(CryptoError::NonContributif)
                ),
                "un éphémère d'ordre faible doit être rejeté (u = {:?})",
                &u[..4]
            );
        }
    }

    /// NON-RÉGRESSION : le rejet ne doit pas mordre sur des clés honnêtes.
    #[test]
    fn les_cles_honnetes_restent_acceptees() {
        for _ in 0..8 {
            let kp = KemKeypair::generate();
            let (ct, a) = encapsulate(&kp.public).expect("clé générée = contributive");
            assert_eq!(a, decapsulate(&kp, &ct).expect("éphémère honnête"));
        }
    }

    #[test]
    fn roundtrip() {
        let kp = KemKeypair::generate();
        let (ct, ss_a) = encapsulate(&kp.public).unwrap();
        let ss_b = decapsulate(&kp, &ct).unwrap();
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn mauvaise_cle_donne_secret_different() {
        let kp1 = KemKeypair::generate();
        let kp2 = KemKeypair::generate();
        let (ct, ss_a) = encapsulate(&kp1.public).unwrap();
        let ss_mauvais = decapsulate(
            &kp2,
            &KemCiphertext {
                x25519_eph: ct.x25519_eph,
                mlkem_ct: ct.mlkem_ct,
            },
        )
        .unwrap();
        assert_ne!(ss_a, ss_mauvais);
    }

    #[test]
    fn serialisation() {
        let kp = KemKeypair::generate();
        let (ct, _) = encapsulate(&kp.public).unwrap();
        let pk2 = KemPublicKey::from_bytes(&kp.public.to_bytes()).unwrap();
        let ct2 = KemCiphertext::from_bytes(&ct.to_bytes()).unwrap();
        assert_eq!(pk2.x25519, kp.public.x25519);
        assert_eq!(ct2.to_bytes(), ct.to_bytes());
    }

    /// La paire RESTAURÉE doit DÉCHIFFRER ce qui a été chiffré vers l'originale.
    ///
    /// C'est la seule propriété qui compte : un wallet rechargé dont la clé de
    /// réception ne déchiffre plus ses notes a perdu ses fonds. Comparer les octets
    /// ne suffirait pas — on éprouve donc la capacité de décapsulation elle-même.
    #[test]
    fn secret_restaure_dechiffre_ce_qui_etait_chiffre_vers_lorigine() {
        let kp = KemKeypair::generate();
        let (ct, ss) = encapsulate(&kp.public).unwrap();

        let restaure = KemKeypair::from_bytes_secret(&kp.to_bytes_secret()).unwrap();
        assert_eq!(
            decapsulate(&restaure, &ct).unwrap(),
            ss,
            "la paire rechargée doit décapsuler ce qui visait l'originale"
        );
        // Publique identique : c'est la MÊME adresse de réception.
        assert_eq!(restaure.public.to_bytes(), kp.public.to_bytes());
        // Encodage canonique : même paire ⇒ mêmes octets.
        assert_eq!(restaure.to_bytes_secret(), kp.to_bytes_secret());
    }

    /// Un fichier de clé corrompu, tronqué ou d'une autre version est REJETÉ, jamais
    /// accepté au rabais : accepter une clé partielle produirait un wallet qui ne
    /// déchiffre plus rien, sans dire pourquoi.
    #[test]
    fn secret_malforme_rejete() {
        let kp = KemKeypair::generate();
        let bon = kp.to_bytes_secret();

        assert!(KemKeypair::from_bytes_secret(&[]).is_err());
        assert!(KemKeypair::from_bytes_secret(&bon[..bon.len() - 1]).is_err());
        let mut trop = bon.clone();
        trop.push(0);
        assert!(KemKeypair::from_bytes_secret(&trop).is_err());
        let mut autre_version = bon.clone();
        autre_version[0] = 0x03; // version FUTURE inconnue
        assert!(
            KemKeypair::from_bytes_secret(&autre_version).is_err(),
            "une version d'algo inconnue ne doit pas être lue comme du FIPS 203"
        );

        // Un objet ROUND-3 (0x01) est refusé PAR SON NOM (T1.1) — jamais
        // réinterprété, et l'erreur dit quoi regénérer.
        let mut round3 = bon.clone();
        round3[0] = 0x01;
        assert!(matches!(
            KemKeypair::from_bytes_secret(&round3),
            Err(crate::CryptoError::AlgoPerime { version: 0x01, .. })
        ));
        let mut pk_round3 = kp.public.to_bytes();
        pk_round3[0] = 0x01;
        assert!(matches!(
            KemPublicKey::from_bytes(&pk_round3),
            Err(crate::CryptoError::AlgoPerime { version: 0x01, .. })
        ));
    }
}
