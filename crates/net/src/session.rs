//! Canal établi après le handshake : chiffrement authentifié, bidirectionnel,
//! avec anti-rejeu par compteur de séquence.

use crate::NetError;
use crypto::aead;

/// Canal chiffré entre deux pairs authentifiés.
///
/// Deux clés DIRECTIONNELLES distinctes : un message ne peut pas être réfléchi vers
/// son émetteur (il serait déchiffré avec la mauvaise clé), ce qui ferme les
/// attaques par réflexion sans vérification supplémentaire.
///
/// Le numéro de séquence n'est **pas transmis** : il sert d'`aad` et est déduit du
/// compteur LOCAL. Un message rejoué ou hors-ordre est donc indéchiffrable — pas
/// besoin d'une fenêtre de rejeu explicite. Le compteur n'avance qu'en cas de
/// SUCCÈS, pour qu'un message corrompu ne désynchronise pas le canal.
pub struct Session {
    k_envoi: [u8; 32],
    k_reception: [u8; 32],
    seq_envoi: u64,
    seq_reception: u64,
}

impl Session {
    pub(crate) fn nouvelle(k_envoi: [u8; 32], k_reception: [u8; 32]) -> Self {
        Session {
            k_envoi,
            k_reception,
            seq_envoi: 0,
            seq_reception: 0,
        }
    }

    /// Chiffre `message` pour le pair. `SessionEpuisee` si le compteur est saturé —
    /// on ferme la session plutôt que de réutiliser un numéro de séquence (ce qui
    /// rejouerait un `aad` et casserait l'anti-rejeu).
    pub fn chiffrer(&mut self, message: &[u8]) -> Result<Vec<u8>, NetError> {
        if self.seq_envoi == u64::MAX {
            return Err(NetError::SessionEpuisee);
        }
        let cadre = aead::encrypt(&self.k_envoi, &self.seq_envoi.to_le_bytes(), message);
        self.seq_envoi += 1;
        Ok(cadre)
    }

    /// Déchiffre un cadre reçu. Échoue si le cadre est altéré, rejoué, hors-ordre,
    /// ou réfléchi (mauvaise direction).
    pub fn dechiffrer(&mut self, cadre: &[u8]) -> Result<Vec<u8>, NetError> {
        if self.seq_reception == u64::MAX {
            return Err(NetError::SessionEpuisee);
        }
        let clair = aead::decrypt(&self.k_reception, &self.seq_reception.to_le_bytes(), cadre)
            .map_err(|_| NetError::DechiffrementEchoue)?;
        // Le compteur n'avance QUE sur succès : un cadre corrompu ne désynchronise pas.
        self.seq_reception += 1;
        Ok(clair)
    }

    /// Numéros de séquence courants (diagnostic et tests).
    pub fn compteurs(&self) -> (u64, u64) {
        (self.seq_envoi, self.seq_reception)
    }

    /// Scinde le canal en deux moitiés INDÉPENDANTES : émission et réception.
    ///
    /// Rendu possible par les clés directionnelles : les deux sens ne partagent
    /// aucun état, donc rien ne les couple. C'est ce qui permet à un thread de
    /// LIRE en continu pendant qu'un autre ÉCRIT, sans qu'un verrou de lecture
    /// bloque les envois — le nœud pourrait sinon se figer en attendant un pair
    /// silencieux.
    pub fn separer(self) -> (Emetteur, Recepteur) {
        (
            Emetteur {
                cle: self.k_envoi,
                seq: self.seq_envoi,
            },
            Recepteur {
                cle: self.k_reception,
                seq: self.seq_reception,
            },
        )
    }
}

/// Moitié ÉMISSION d'un canal scindé.
pub struct Emetteur {
    cle: [u8; 32],
    seq: u64,
}

impl Emetteur {
    pub fn chiffrer(&mut self, message: &[u8]) -> Result<Vec<u8>, NetError> {
        if self.seq == u64::MAX {
            return Err(NetError::SessionEpuisee);
        }
        let cadre = aead::encrypt(&self.cle, &self.seq.to_le_bytes(), message);
        self.seq += 1;
        Ok(cadre)
    }
}

/// Moitié RÉCEPTION d'un canal scindé.
pub struct Recepteur {
    cle: [u8; 32],
    seq: u64,
}

impl Recepteur {
    pub fn dechiffrer(&mut self, cadre: &[u8]) -> Result<Vec<u8>, NetError> {
        if self.seq == u64::MAX {
            return Err(NetError::SessionEpuisee);
        }
        let clair = aead::decrypt(&self.cle, &self.seq.to_le_bytes(), cadre)
            .map_err(|_| NetError::DechiffrementEchoue)?;
        self.seq += 1;
        Ok(clair)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deux sessions appairées (les clés d'envoi de l'une sont les clés de réception
    /// de l'autre), comme après un handshake réussi.
    fn paire() -> (Session, Session) {
        let k_i2r = [1u8; 32];
        let k_r2i = [2u8; 32];
        (
            Session::nouvelle(k_i2r, k_r2i),
            Session::nouvelle(k_r2i, k_i2r),
        )
    }

    #[test]
    fn aller_retour_bidirectionnel() {
        let (mut i, mut r) = paire();
        let c = i.chiffrer(b"bonjour").unwrap();
        assert_eq!(r.dechiffrer(&c).unwrap(), b"bonjour");
        let c2 = r.chiffrer(b"salut").unwrap();
        assert_eq!(i.dechiffrer(&c2).unwrap(), b"salut");
        assert_eq!(i.compteurs(), (1, 1));
    }

    /// REJEU : renvoyer un cadre déjà consommé échoue — le compteur a avancé, donc
    /// l'`aad` attendu a changé.
    #[test]
    fn rejeu_rejete() {
        let (mut i, mut r) = paire();
        let c = i.chiffrer(b"paiement").unwrap();
        assert!(r.dechiffrer(&c).is_ok());
        assert_eq!(
            r.dechiffrer(&c),
            Err(NetError::DechiffrementEchoue),
            "un cadre rejoué doit être rejeté"
        );
    }

    /// HORS-ORDRE : livrer le 2ᵉ cadre avant le 1ᵉʳ échoue.
    #[test]
    fn hors_ordre_rejete() {
        let (mut i, mut r) = paire();
        let c0 = i.chiffrer(b"un").unwrap();
        let c1 = i.chiffrer(b"deux").unwrap();
        assert_eq!(
            r.dechiffrer(&c1),
            Err(NetError::DechiffrementEchoue),
            "le cadre 1 ne doit pas être accepté avant le cadre 0"
        );
        // Et le canal n'est pas désynchronisé : le cadre 0 passe toujours.
        assert_eq!(r.dechiffrer(&c0).unwrap(), b"un");
    }

    /// RÉFLEXION : renvoyer à l'émetteur son propre cadre échoue, grâce aux clés
    /// directionnelles distinctes.
    #[test]
    fn reflexion_rejetee() {
        let (mut i, _r) = paire();
        let c = i.chiffrer(b"ordre").unwrap();
        assert_eq!(
            i.dechiffrer(&c),
            Err(NetError::DechiffrementEchoue),
            "un cadre réfléchi vers son émetteur doit être rejeté"
        );
    }

    /// ALTÉRATION : un octet modifié fait échouer l'AEAD.
    #[test]
    fn alteration_rejetee() {
        let (mut i, mut r) = paire();
        let mut c = i.chiffrer(b"montant").unwrap();
        let dernier = c.len() - 1;
        c[dernier] ^= 1;
        assert_eq!(r.dechiffrer(&c), Err(NetError::DechiffrementEchoue));
    }

    /// Le canal scindé se comporte EXACTEMENT comme le canal entier : mêmes cadres,
    /// mêmes compteurs, mêmes rejets. Sans cette équivalence, scinder introduirait
    /// une seconde implémentation du protocole — donc une occasion de divergence.
    #[test]
    fn canal_scinde_equivaut_au_canal_entier() {
        let (i, r) = paire();
        let (mut em_i, _rc_i) = i.separer();
        let (_em_r, mut rc_r) = r.separer();

        let c = em_i.chiffrer(b"message").unwrap();
        assert_eq!(rc_r.dechiffrer(&c).unwrap(), b"message");

        // L'anti-rejeu tient aussi sur les moitiés.
        assert_eq!(rc_r.dechiffrer(&c), Err(NetError::DechiffrementEchoue));
    }

    /// Cadre tronqué / vide : `Result`, jamais de panique.
    #[test]
    fn cadre_malforme_rejete_sans_panique() {
        let (mut i, mut r) = paire();
        let c = i.chiffrer(b"x").unwrap();
        assert_eq!(r.dechiffrer(&[]), Err(NetError::DechiffrementEchoue));
        assert_eq!(
            r.dechiffrer(&c[..c.len() / 2]),
            Err(NetError::DechiffrementEchoue)
        );
    }

    /// Le compteur n'avance pas sur échec : après un cadre corrompu, le cadre
    /// LÉGITIME suivant reste déchiffrable (pas de déni de service par injection).
    #[test]
    fn echec_ne_desynchronise_pas_le_canal() {
        let (mut i, mut r) = paire();
        let c = i.chiffrer(b"legitime").unwrap();
        let mut corrompu = c.clone();
        corrompu[0] ^= 0xFF;
        assert!(r.dechiffrer(&corrompu).is_err());
        assert_eq!(
            r.dechiffrer(&c).unwrap(),
            b"legitime",
            "un cadre injecté ne doit pas désynchroniser le canal"
        );
    }
}
