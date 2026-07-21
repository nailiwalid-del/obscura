//! Cadrage sur le fil : délimitation des messages d'un flux d'octets.
//!
//! Un flux TCP n'a pas de frontières de message — il faut les poser. Chaque cadre
//! est préfixé par sa longueur (`u32` LE) :
//!
//! ```text
//! [ longueur u32 LE ] [ charge utile ]
//! ```
//!
//! # Le format de fil est l'artefact durable
//!
//! Ce module est volontairement SYNCHRONE (`std::io::{Read, Write}`) : il ne fixe
//! que le FORMAT, pas la stratégie d'E/S. Passer à un runtime asynchrone plus tard
//! ne changera pas un octet sur le fil, et n'imposer aucun runtime à ce stade évite
//! une dépendance structurante prise trop tôt.
//!
//! # Surface hostile
//!
//! La longueur annoncée est vérifiée **avant toute allocation** : un pair hostile ne
//! peut pas nous faire réserver 4 Gio en envoyant 4 octets. C'est la vulnérabilité
//! classique du décodage préfixé par longueur.

use crate::NetError;
use std::io::{Read, Write};

/// Taille maximale d'un cadre. Généreuse devant les besoins réels (une `ProvedTx`
/// fait ~70 Kio, une passe de handshake ~5 Kio) mais BORNÉE : c'est elle qui
/// transforme « allocation dictée par l'attaquant » en « rejet ».
pub const MAX_CADRE: usize = 1024 * 1024;

/// Écrit un cadre préfixé par sa longueur.
pub fn ecrire_cadre<W: Write>(flux: &mut W, charge: &[u8]) -> Result<(), NetError> {
    if charge.len() > MAX_CADRE {
        return Err(NetError::TailleInvalide);
    }
    flux.write_all(&(charge.len() as u32).to_le_bytes())
        .map_err(|e| NetError::Io(e.kind()))?;
    flux.write_all(charge).map_err(|e| NetError::Io(e.kind()))?;
    flux.flush().map_err(|e| NetError::Io(e.kind()))?;
    Ok(())
}

/// Lit un cadre. Bloque jusqu'à disposer du cadre COMPLET (`read_exact` gère les
/// lectures partielles, inévitables sur un flux réel).
///
/// Distingue une fermeture PROPRE (`Io(UnexpectedEof)` sur l'en-tête, avant tout
/// octet de charge) d'une TRONCATURE en cours de cadre : la première est un pair qui
/// raccroche, la seconde une anomalie.
pub fn lire_cadre<R: Read>(flux: &mut R) -> Result<Vec<u8>, NetError> {
    let mut entete = [0u8; 4];
    flux.read_exact(&mut entete)
        .map_err(|e| NetError::Io(e.kind()))?;
    let n = u32::from_le_bytes(entete) as usize;

    // Contrôle AVANT allocation : c'est tout l'enjeu du décodage préfixé.
    if n > MAX_CADRE {
        return Err(NetError::TailleInvalide);
    }
    let mut charge = vec![0u8; n];
    flux.read_exact(&mut charge)
        .map_err(|_| NetError::Tronque)?;
    Ok(charge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn aller_retour_de_cadres() {
        let mut tampon = Vec::new();
        ecrire_cadre(&mut tampon, b"premier").unwrap();
        ecrire_cadre(&mut tampon, b"deuxieme").unwrap();
        ecrire_cadre(&mut tampon, b"").unwrap(); // cadre vide : légitime

        let mut flux = Cursor::new(tampon);
        assert_eq!(lire_cadre(&mut flux).unwrap(), b"premier");
        assert_eq!(lire_cadre(&mut flux).unwrap(), b"deuxieme");
        assert_eq!(lire_cadre(&mut flux).unwrap(), b"");
    }

    /// ANTI-DoS : une longueur aberrante est rejetée SANS allouer. Le test se
    /// contente de 4 octets d'entrée — si le code allouait d'abord, il tenterait
    /// de réserver 4 Gio.
    #[test]
    fn longueur_aberrante_rejetee_sans_allouer() {
        let mut flux = Cursor::new(u32::MAX.to_le_bytes().to_vec());
        assert_eq!(lire_cadre(&mut flux), Err(NetError::TailleInvalide));

        // Juste au-dessus de la borne : rejeté aussi.
        let mut trop = Cursor::new(((MAX_CADRE + 1) as u32).to_le_bytes().to_vec());
        assert_eq!(lire_cadre(&mut trop), Err(NetError::TailleInvalide));
    }

    /// TRONCATURE : un cadre annoncé plus long que ce qui suit est rejeté.
    #[test]
    fn cadre_tronque_rejete() {
        let mut tampon = (100u32).to_le_bytes().to_vec();
        tampon.extend_from_slice(b"seulement quelques octets");
        let mut flux = Cursor::new(tampon);
        assert_eq!(lire_cadre(&mut flux), Err(NetError::Tronque));
    }

    /// FERMETURE PROPRE : flux vide → EOF sur l'en-tête, distinct d'une troncature.
    #[test]
    fn fermeture_propre_distincte_de_la_troncature() {
        let mut vide = Cursor::new(Vec::new());
        assert_eq!(
            lire_cadre(&mut vide),
            Err(NetError::Io(std::io::ErrorKind::UnexpectedEof)),
            "un flux fermé proprement doit être distinguable d'un cadre tronqué"
        );
    }

    /// En-tête partiel (2 octets sur 4) : EOF, pas de panique ni de lecture hors bornes.
    #[test]
    fn entete_partiel_rejete() {
        let mut flux = Cursor::new(vec![0u8, 0]);
        assert!(matches!(lire_cadre(&mut flux), Err(NetError::Io(_))));
    }

    /// Un cadre à la borne exacte passe ; au-delà, `ecrire_cadre` refuse plutôt que
    /// d'émettre quelque chose que le pair rejettera.
    #[test]
    fn borne_exacte_acceptee_au_dela_refusee() {
        let mut tampon = Vec::new();
        assert!(ecrire_cadre(&mut tampon, &vec![0u8; MAX_CADRE]).is_ok());
        let mut t2 = Vec::new();
        assert_eq!(
            ecrire_cadre(&mut t2, &vec![0u8; MAX_CADRE + 1]),
            Err(NetError::TailleInvalide)
        );
    }
}
