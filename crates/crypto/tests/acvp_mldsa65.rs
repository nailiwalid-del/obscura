//! Conformité ACVP CIBLÉE — ML-DSA-65, opération de VÉRIFICATION.
//!
//! Même raison qu'en ML-KEM d'appeler `pqcrypto` en direct : `crypto::sig::verify`
//! est hybride (Ed25519 ET ML-DSA) et encadre le message par domaine et
//! identifiant d'algorithme. Un vecteur ACVP porte sur le message BRUT.
//!
//! # La variante, établie expérimentalement
//!
//! FIPS 204 définit plusieurs interfaces, et le backend n'annonce pas la sienne.
//! Elle a été DÉTERMINÉE, pas supposée, en rejouant les deux candidats :
//!
//! - `internal` : le backend rejette **les 3 signatures attendues valides** ;
//! - `external` / `pure` à contexte vide : accord.
//!
//! ⚠️ Le piège que cette mesure a évité : la variante `internal` affichait
//! « 12/15 d'accord », un score entièrement produit par les cas NÉGATIFS — que
//! n'importe quelle fonction refusant tout obtiendrait. Sans cas négatifs
//! étiquetés, on aurait conclu à l'inverse.
//!
//! # Pourquoi si peu de vecteurs officiels
//!
//! L'API du backend ne prend pas de chaîne de contexte et préfixe la sienne
//! (vide). Or **un seul** test ACVP `external`/`pure` de ML-DSA-65 a un contexte
//! vide. Les 14 autres ne sont pas faux : ils sont invérifiables ici.
//!
//! Le jeu est donc complété par des cas négatifs **DÉRIVÉS** — mutations d'un bit
//! du vecteur officiel valide. Ils sont étiquetés `derive-*` et ne sont jamais
//! comptés comme officiels. Voir `vecteurs/PROVENANCE.md`.

use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

const FICHIER: &str = include_str!("vecteurs/mldsa65-sigver.txt");

/// Tailles FIPS 204 pour ML-DSA-65.
const PK_LEN: usize = 1952;
const SIG_LEN: usize = 3309;

struct Vecteur {
    /// `officiel` (NIST) ou `derive-<mutation>`.
    origine: String,
    pk: Vec<u8>,
    msg: Vec<u8>,
    sig: Vec<u8>,
    /// `true` si le vecteur attend une signature VALIDE.
    attendu: bool,
}

impl Vecteur {
    fn est_officiel(&self) -> bool {
        self.origine == "officiel"
    }
}

/// Même discipline qu'en ML-KEM : toute ligne malformée est une erreur franche.
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
            5,
            "ligne {} : attendu 5 champs séparés par ':', reçu {}",
            n + 1,
            champs.len()
        );
        let pk = hex::decode(champs[1])
            .unwrap_or_else(|e| panic!("ligne {} : pk non hexadécimale ({e})", n + 1));
        let msg = hex::decode(champs[2])
            .unwrap_or_else(|e| panic!("ligne {} : message non hexadécimal ({e})", n + 1));
        let sig = hex::decode(champs[3])
            .unwrap_or_else(|e| panic!("ligne {} : signature non hexadécimale ({e})", n + 1));
        let attendu = match champs[4] {
            "1" => true,
            "0" => false,
            autre => panic!("ligne {} : attendu '0' ou '1', reçu {autre:?}", n + 1),
        };
        assert_eq!(pk.len(), PK_LEN, "ligne {} : pk fait {} o", n + 1, pk.len());
        assert_eq!(
            sig.len(),
            SIG_LEN,
            "ligne {} : signature fait {} o",
            n + 1,
            sig.len()
        );
        v.push(Vecteur {
            origine: champs[0].to_string(),
            pk,
            msg,
            sig,
            attendu,
        });
    }
    v
}

/// Le jeu doit contenir au moins un vecteur OFFICIEL. Sans cette assertion, un
/// fichier ne contenant que des cas dérivés passerait — et ne prouverait plus
/// aucune conformité à FIPS 204, seulement une cohérence interne.
#[test]
fn le_jeu_contient_du_vecteur_officiel() {
    let v = charger();
    let officiels = v.iter().filter(|x| x.est_officiel()).count();
    assert!(
        officiels >= 1,
        "aucun vecteur officiel : le fichier ne démontre plus rien de FIPS 204"
    );
}

/// Le jeu doit contenir des cas NÉGATIFS. Sans eux, le test ne distingue pas une
/// implémentation correcte d'une fonction qui accepte tout.
#[test]
fn le_jeu_contient_des_cas_negatifs() {
    let v = charger();
    let negatifs = v.iter().filter(|x| !x.attendu).count();
    assert!(
        negatifs > 0,
        "aucun vecteur à signature invalide : le jeu ne teste pas le REJET"
    );
}

/// Symétriquement : sans cas POSITIF, une fonction qui refuse tout passerait.
/// C'est exactement l'erreur qu'aurait produite la variante `internal`.
#[test]
fn le_jeu_contient_des_cas_positifs() {
    let v = charger();
    let positifs = v.iter().filter(|x| x.attendu).count();
    assert!(
        positifs > 0,
        "aucun vecteur à signature valide : une fonction qui refuse tout passerait"
    );
}

#[test]
fn acvp_mldsa65_verification() {
    for vec in charger() {
        // `{e:?}` : voir la note dans `acvp_mlkem768.rs`.
        let pk = mldsa65::PublicKey::from_bytes(&vec.pk)
            .unwrap_or_else(|e| panic!("{} : pk refusée par le backend ({e:?})", vec.origine));
        // Une signature invalide peut l'être par sa STRUCTURE : le décodage
        // échoue alors, et c'est un rejet légitime — pas un défaut du test.
        let obtenu = match mldsa65::DetachedSignature::from_bytes(&vec.sig) {
            Ok(sig) => mldsa65::verify_detached_signature(&sig, &vec.msg, &pk).is_ok(),
            Err(_) => false,
        };
        assert_eq!(
            obtenu, vec.attendu,
            "{} : le backend dit {obtenu}, le vecteur dit {}",
            vec.origine, vec.attendu
        );
    }
}
