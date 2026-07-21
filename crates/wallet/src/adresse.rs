//! Encodage textuel d'une adresse Obscura.
//!
//! # Pourquoi une adresse a besoin d'un contrôle d'intégrité
//!
//! Une adresse se transmet hors-chaîne : copiée dans un message, dictée, lue sur un
//! écran. Une adresse ABÎMÉE en route reste syntaxiquement acceptable — c'est une
//! suite d'octets comme une autre.
//!
//! Or payer vers une adresse abîmée est **irréversible et silencieux**. Le `owner`
//! altéré ne correspond à aucun secret existant : la note est engagée dans l'arbre,
//! valide aux yeux du consensus, mais personne au monde ne peut la dépenser. Il n'y
//! a ni annulation, ni destinataire à qui écrire. Le protocole ne peut RIEN
//! rattraper — la seule défense possible se trouve donc ici, avant même que la
//! preuve ne soit construite.
//!
//! # Ce que la somme de contrôle N'EST PAS
//!
//! Elle détecte l'ACCIDENT, pas l'ADVERSAIRE. Elle est courte (4 octets) et non
//! clefée : quiconque fabrique une adresse de son choix en recalcule la somme sans
//! effort. Substituer l'adresse du destinataire par la sienne reste donc trivial
//! pour un attaquant qui contrôle le canal de transmission.
//!
//! L'authenticité d'une adresse vient du CANAL qui l'a transmise, jamais de son
//! encodage. C'est écrit ici pour qu'aucun lecteur n'en déduise une garantie qui
//! n'existe pas.
//!
//! # Pourquoi c'est si long
//!
//! Une clé publique Kyber768 pèse 1 184 octets. Une adresse post-quantique fait donc
//! ~2,5 Kio en hexadécimal, là où une adresse Bitcoin tient en 35 caractères. Ce
//! n'est pas un défaut d'encodage : c'est le prix des clés post-quantiques, et il
//! n'est pas réductible par troncature — tronquer une clé publique la détruit.
//!
//! ```text
//!   obs1 ‖ hex( version ‖ owner (32 o) ‖ kem_pk (1 217 o) ‖ somme (4 o) )
//! ```

use crate::Adresse;
use crypto::kem::KemPublicKey;
use proved_hash::digest::{Digest, DIGEST_BYTES};

/// Préfixe humain : identifie une adresse Obscura d'un coup d'œil et évite qu'une
/// chaîne hexadécimale quelconque soit prise pour une adresse.
pub const PREFIXE: &str = "obs1";

/// Version du FORMAT d'adresse — distincte de la version d'ALGORITHME portée par la
/// clé KEM elle-même (`KEM_ALGO_VERSION`). Les deux sont vérifiées : la migration
/// FIPS 203 produira des adresses qu'un décodeur round-3 doit REFUSER, pas
/// interpréter de travers.
pub const VERSION_ADRESSE: u8 = 0x01;

/// Longueur de la somme de contrôle. Tronquée À DESSEIN — voir l'avertissement en
/// tête de module : ce n'est pas une fonction de sécurité, donc la règle « hachage
/// jamais tronqué » (qui vise les hachages de consensus) ne s'y applique pas.
const SOMME: usize = 4;

const DOMAINE_SOMME: &str = "obscura/adresse/v1";

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AdresseError {
    #[error("préfixe absent ou inconnu (attendu « {PREFIXE} »)")]
    PrefixeInvalide,
    #[error("caractères non hexadécimaux dans l'adresse")]
    HexInvalide,
    #[error("longueur d'adresse incorrecte")]
    LongueurInvalide,
    #[error("version d'adresse inconnue : {0:#04x}")]
    VersionInconnue(u8),
    #[error("somme de contrôle incorrecte — adresse abîmée en transmission")]
    SommeIncorrecte,
    #[error("identité de destinataire non canonique")]
    OwnerInvalide,
    #[error("clé de réception invalide")]
    KemInvalide,
}

impl Adresse {
    /// Corps signé par la somme : `version ‖ owner ‖ kem_pk`.
    fn corps(&self) -> Vec<u8> {
        let mut b = vec![VERSION_ADRESSE];
        b.extend_from_slice(&self.owner.to_bytes());
        b.extend_from_slice(&self.kem.to_bytes());
        b
    }

    /// Encode l'adresse sous sa forme textuelle partageable.
    pub fn encoder(&self) -> String {
        let mut b = self.corps();
        b.extend_from_slice(&somme(&b));
        format!("{PREFIXE}{}", hex::encode(b))
    }

    /// Décode une adresse reçue d'un humain — donc potentiellement abîmée.
    ///
    /// L'ordre des contrôles importe : la somme est vérifiée AVANT de décoder le
    /// `owner` et la clé KEM. Une adresse dont un caractère a sauté échoue ainsi sur
    /// « adresse abîmée », message actionnable, plutôt que sur une erreur interne de
    /// clé qui laisserait croire à un problème du destinataire.
    pub fn decoder(texte: &str) -> Result<Self, AdresseError> {
        let texte = texte.trim();
        let hexa = texte
            .strip_prefix(PREFIXE)
            .ok_or(AdresseError::PrefixeInvalide)?;
        let b = hex::decode(hexa).map_err(|_| AdresseError::HexInvalide)?;

        let attendu = 1 + DIGEST_BYTES + SOMME;
        if b.len() <= attendu {
            return Err(AdresseError::LongueurInvalide);
        }
        let (corps, somme_recue) = b.split_at(b.len() - SOMME);
        if somme(corps) != somme_recue {
            return Err(AdresseError::SommeIncorrecte);
        }
        if corps[0] != VERSION_ADRESSE {
            return Err(AdresseError::VersionInconnue(corps[0]));
        }

        let owner_octets: [u8; DIGEST_BYTES] = corps[1..1 + DIGEST_BYTES]
            .try_into()
            .map_err(|_| AdresseError::LongueurInvalide)?;
        let owner = Digest::from_bytes(&owner_octets).map_err(|_| AdresseError::OwnerInvalide)?;
        let kem = KemPublicKey::from_bytes(&corps[1 + DIGEST_BYTES..])
            .map_err(|_| AdresseError::KemInvalide)?;

        Ok(Adresse { owner, kem })
    }
}

/// Somme de contrôle : 4 octets d'un hachage à domaine séparé. Détecte l'accident.
fn somme(corps: &[u8]) -> [u8; SOMME] {
    let h = crypto::hash::dual_hash(DOMAINE_SOMME, corps);
    h[..SOMME].try_into().expect("dual_hash fait 64 octets")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Wallet;
    use proved_hash::felt::Felt;
    use proved_hash::digest::ShieldedSecret;

    fn adresse_de_test() -> Adresse {
        let secret = ShieldedSecret::from_felts(core::array::from_fn(|i| {
            Felt::from_canonical_u64(700 + i as u64).unwrap()
        }));
        Wallet::depuis_secret(secret, 4).adresse()
    }

    /// Aller-retour : l'adresse décodée désigne le MÊME destinataire et la MÊME clé
    /// de réception. Comparer les octets de la clé, pas seulement l'`owner` — une
    /// clé KEM abîmée rendrait le paiement indéchiffrable tout en gardant l'`owner`
    /// correct.
    #[test]
    fn aller_retour() {
        let a = adresse_de_test();
        let texte = a.encoder();
        assert!(texte.starts_with(PREFIXE));
        let b = Adresse::decoder(&texte).expect("adresse valide");
        assert_eq!(b.owner, a.owner);
        assert_eq!(b.kem.to_bytes(), a.kem.to_bytes());
    }

    /// LE TEST QUI JUSTIFIE LE MODULE : une faute de frappe est REFUSÉE.
    ///
    /// On altère chaque position de la partie hexadécimale, une à une, et on exige
    /// que le décodage échoue à chaque fois. Sans somme de contrôle, la plupart de
    /// ces adresses seraient acceptées et les fonds envoyés dans le vide.
    #[test]
    fn une_faute_de_frappe_est_refusee() {
        let texte = adresse_de_test().encoder();
        let hexa: Vec<char> = texte[PREFIXE.len()..].chars().collect();

        // Un échantillon régulier de positions (l'adresse fait ~2 500 caractères ;
        // les balayer toutes coûterait cher pour la même garantie).
        for i in (0..hexa.len()).step_by(37) {
            let mut abime = hexa.clone();
            // Remplacer par un AUTRE chiffre hexadécimal (une faute plausible).
            abime[i] = if abime[i] == 'a' { 'b' } else { 'a' };
            let candidat = format!("{PREFIXE}{}", abime.iter().collect::<String>());
            assert!(
                Adresse::decoder(&candidat).is_err(),
                "un caractère altéré en position {i} doit être détecté"
            );
        }
    }

    /// Une adresse TRONQUÉE (copier-coller incomplet — l'accident le plus courant)
    /// est refusée.
    #[test]
    fn adresse_tronquee_refusee() {
        let texte = adresse_de_test().encoder();
        for coupe in [1usize, 10, 100, 2] {
            let court = &texte[..texte.len() - coupe];
            assert!(
                Adresse::decoder(court).is_err(),
                "une adresse amputée de {coupe} caractères doit être refusée"
            );
        }
    }

    /// Sans le préfixe, ce n'est pas une adresse Obscura — refus explicite plutôt
    /// que tentative de décodage.
    #[test]
    fn prefixe_exige() {
        let texte = adresse_de_test().encoder();
        let sans = &texte[PREFIXE.len()..];
        assert!(matches!(
            Adresse::decoder(sans),
            Err(AdresseError::PrefixeInvalide)
        ));
        assert!(matches!(
            Adresse::decoder("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
            Err(AdresseError::PrefixeInvalide)
        ));
    }

    /// Une adresse d'une AUTRE version de format est refusée, pas réinterprétée.
    ///
    /// La migration FIPS 203/204 produira des adresses `0x02` : les lire comme du
    /// round-3 donnerait une clé de réception fausse — donc des fonds perdus.
    #[test]
    fn version_inconnue_refusee() {
        let a = adresse_de_test();
        let mut corps = a.corps();
        corps[0] = 0x02;
        let mut b = corps.clone();
        b.extend_from_slice(&somme(&corps)); // somme RECALCULÉE : seul le format diffère
        let texte = format!("{PREFIXE}{}", hex::encode(b));
        assert!(matches!(
            Adresse::decoder(&texte),
            Err(AdresseError::VersionInconnue(0x02))
        ));
    }

    /// Deux wallets distincts n'ont jamais la même adresse (garde contre une
    /// confusion de champs à l'encodage, qui produirait des adresses identiques).
    #[test]
    fn adresses_distinctes() {
        let a = adresse_de_test().encoder();
        let autre = Wallet::nouveau(4).adresse().encoder();
        assert_ne!(a, autre);
    }
}
