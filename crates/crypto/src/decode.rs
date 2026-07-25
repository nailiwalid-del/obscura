//! Curseur de lecture BORNÉ, partagé par les décodeurs sérialisés d'Obscura.
//!
//! # Pourquoi un helper partagé
//!
//! Le même curseur — `prendre(n)` qui vérifie ce qui reste AVANT de trancher, et
//! ne panique jamais — était réimplémenté à l'identique dans chaque décodeur
//! (`bloc`, `historique`, `wallet`, `synchro`). Quatre copies d'une borne
//! anti-DoS, c'est quatre endroits où une correction doit être répliquée, et
//! quatre chances d'en oublier un. La borne est ici, en un seul point.
//!
//! # Une seule erreur, convertie au site d'appel
//!
//! Chaque décodeur a son propre type d'erreur (`BlocDecodeError`,
//! `WalletFichierError`, …) parce que le message qu'un porteur doit lire dépend
//! de ce qu'il décodait. Le curseur ne connaît qu'un échec — [`Tronque`] — et le
//! décodeur le convertit vers SON erreur en implémentant `From<Tronque>` :
//! l'opérateur `?` fait la conversion. Le type d'erreur reste local ; seule la
//! MÉCANIQUE de borne est partagée.
//!
//! (On renvoie le type concret `Tronque` plutôt qu'un paramètre générique
//! `E: From<Tronque>` : ce dernier rend `?` ambigu, car `From<T> for T` réflexif
//! satisfait aussi la borne, et le compilateur ne peut plus inférer `E`.)
//!
//! # Ce que ce module ne fait pas
//!
//! Il ne borne pas les COMPTEURS : « cet en-tête annonce N entrées » se confronte
//! aux octets présents (`N × TAILLE_MIN > restant`) au cas par cas, car `TAILLE_MIN`
//! et le plafond constant éventuel dépendent du format. Le curseur garantit
//! seulement qu'aucune PRISE ne lit hors des octets reçus.

/// Signale qu'une prise a manqué d'octets : la position visée dépasse la fin du
/// tampon, ou le calcul de cette position a débordé `usize`.
///
/// Marqueur volontairement sans détail : le décodeur qui le reçoit le convertit,
/// via son `impl From<Tronque>`, en son propre `Tronque` porteur du contexte utile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tronque;

/// Prend `n` octets à partir de `*pos`, avance le curseur, ou échoue sans paniquer.
///
/// La borne est calculée avec `checked_add` (un `n` adverse proche de `usize::MAX`
/// ne déborde pas silencieusement) puis confrontée à la longueur réelle via `get`.
/// Sur échec, le curseur ne bouge pas.
#[inline]
pub fn prendre<'a>(b: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], Tronque> {
    let fin = pos.checked_add(n).ok_or(Tronque)?;
    let s = b.get(*pos..fin).ok_or(Tronque)?;
    *pos = fin;
    Ok(s)
}

/// Prend exactement `N` octets et les copie dans un tableau de taille fixe.
///
/// `N` s'infère de l'annotation du site d'appel (`let id: [u8; TAILLE_ID] = …`).
/// Le `try_into().unwrap()` est INFAILLIBLE : `prendre` a renvoyé une tranche de
/// longueur `N` exactement — c'est l'unique point où cette conversion vit.
#[inline]
pub fn tableau<const N: usize>(b: &[u8], pos: &mut usize) -> Result<[u8; N], Tronque> {
    Ok(prendre(b, pos, N)?.try_into().unwrap())
}

/// Lit un octet.
#[inline]
pub fn lire_u8(b: &[u8], pos: &mut usize) -> Result<u8, Tronque> {
    Ok(prendre(b, pos, 1)?[0])
}

/// Lit un `u16` petit-boutiste.
#[inline]
pub fn lire_u16(b: &[u8], pos: &mut usize) -> Result<u16, Tronque> {
    Ok(u16::from_le_bytes(tableau::<2>(b, pos)?))
}

/// Lit un `u32` petit-boutiste.
#[inline]
pub fn lire_u32(b: &[u8], pos: &mut usize) -> Result<u32, Tronque> {
    Ok(u32::from_le_bytes(tableau::<4>(b, pos)?))
}

/// Lit un `u64` petit-boutiste.
#[inline]
pub fn lire_u64(b: &[u8], pos: &mut usize) -> Result<u64, Tronque> {
    Ok(u64::from_le_bytes(tableau::<8>(b, pos)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Une erreur locale minimale, comme celle de chaque décodeur réel, pour
    // exercer la conversion via `?`.
    #[derive(Debug, PartialEq)]
    struct MonErreur;
    impl From<Tronque> for MonErreur {
        fn from(_: Tronque) -> Self {
            MonErreur
        }
    }

    fn decode_via_from(b: &[u8]) -> Result<u32, MonErreur> {
        let mut pos = 0;
        // `?` convertit `Tronque` en `MonErreur` : c'est le motif de chaque décodeur.
        Ok(lire_u32(b, &mut pos)?)
    }

    #[test]
    fn prend_et_avance() {
        let b = [1u8, 2, 3, 4, 5];
        let mut pos = 0;
        assert_eq!(prendre(&b, &mut pos, 2).unwrap(), &[1, 2]);
        assert_eq!(pos, 2);
        assert_eq!(prendre(&b, &mut pos, 3).unwrap(), &[3, 4, 5]);
        assert_eq!(pos, 5);
    }

    #[test]
    fn refuse_au_dela_de_la_fin() {
        let b = [1u8, 2, 3];
        let mut pos = 0;
        assert_eq!(prendre(&b, &mut pos, 4), Err(Tronque));
        // Le curseur ne bouge pas sur un échec.
        assert_eq!(pos, 0);
    }

    #[test]
    fn refuse_le_debordement_usize() {
        let b = [1u8, 2, 3];
        let mut pos = 1;
        assert_eq!(prendre(&b, &mut pos, usize::MAX), Err(Tronque));
    }

    #[test]
    fn lecteurs_le() {
        let b = [
            0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut pos = 0;
        assert_eq!(lire_u16(&b, &mut pos).unwrap(), 1);
        assert_eq!(lire_u32(&b, &mut pos).unwrap(), 2);
        assert_eq!(lire_u64(&b, &mut pos).unwrap(), 3);
        assert_eq!(pos, 14);
    }

    #[test]
    fn tableau_de_taille_fixe() {
        let b = [9u8, 8, 7, 6];
        let mut pos = 0;
        let t: [u8; 3] = tableau::<3>(&b, &mut pos).unwrap();
        assert_eq!(t, [9, 8, 7]);
        assert_eq!(pos, 3);
    }

    #[test]
    fn conversion_via_from_au_site_dappel() {
        assert_eq!(decode_via_from(&[7, 0, 0, 0]), Ok(7));
        assert_eq!(decode_via_from(&[7, 0]), Err(MonErreur));
    }
}
