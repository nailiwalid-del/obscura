//! Connexion chiffrée de bout en bout : handshake sur un flux, puis canal cadré.
//!
//! Assemble les trois couches déjà livrées — cadrage (`frame`), handshake
//! (`handshake`), canal (`session`) — en une API utilisable par les briques
//! suivantes (pairs, relais, Dandelion++) sans qu'elles aient à connaître le détail
//! du protocole.
//!
//! Générique sur `Read + Write` : fonctionne sur un `TcpStream`, sur un tuyau
//! mémoire (tests), ou sur tout transport futur. Le protocole ne dépend pas du
//! support.

use crate::frame::{ecrire_cadre, lire_cadre};
use crate::handshake::{Initiateur, Repondeur};
use crate::session::Session;
use crate::NetError;
use crypto::sig::{SigKeypair, SigPublicKey};
use std::io::{Read, Write};

/// Connexion établie : le pair est authentifié et le canal est chiffré.
pub struct Connexion<S: Read + Write> {
    flux: S,
    session: Session,
    pair: SigPublicKey,
}

impl<S: Read + Write> Connexion<S> {
    /// Établit une connexion en tant qu'INITIATEUR (côté sortant).
    ///
    /// ⚠️ L'identité du répondeur n'est connue qu'À L'ISSUE du handshake : rien ne
    /// garantit *a priori* qu'on parle au pair voulu (cf. la limite de masquage
    /// documentée dans `handshake`). L'appelant DOIT comparer `pair()` à l'identité
    /// attendue quand il en a une — d'où le fait que cette méthode la retourne
    /// plutôt que de la garder pour elle.
    pub fn connecter(mut flux: S, identite: &SigKeypair) -> Result<Self, NetError> {
        let (init, passe1) = Initiateur::commencer();
        ecrire_cadre(&mut flux, &passe1)?;
        let passe2 = lire_cadre(&mut flux)?;
        let final_i = init.recevoir_passe2(&passe2, identite)?;
        let (passe3, session, pair) = final_i.terminer();
        ecrire_cadre(&mut flux, &passe3)?;
        Ok(Connexion { flux, session, pair })
    }

    /// Établit une connexion en tant que RÉPONDEUR (côté entrant).
    pub fn accepter(mut flux: S, identite: &SigKeypair) -> Result<Self, NetError> {
        let passe1 = lire_cadre(&mut flux)?;
        let (rep, passe2) = Repondeur::repondre(&passe1, identite)?;
        ecrire_cadre(&mut flux, &passe2)?;
        let passe3 = lire_cadre(&mut flux)?;
        let (session, pair) = rep.recevoir_passe3(&passe3)?;
        Ok(Connexion { flux, session, pair })
    }

    /// Identité AUTHENTIFIÉE du pair (signature vérifiée sur le transcript).
    pub fn pair(&self) -> &SigPublicKey {
        &self.pair
    }

    /// Envoie un message applicatif (chiffré puis cadré).
    pub fn envoyer(&mut self, message: &[u8]) -> Result<(), NetError> {
        let cadre = self.session.chiffrer(message)?;
        ecrire_cadre(&mut self.flux, &cadre)
    }

    /// Reçoit un message applicatif. Échoue si le cadre est altéré, rejoué ou
    /// hors-ordre (cf. `Session`).
    pub fn recevoir(&mut self) -> Result<Vec<u8>, NetError> {
        let cadre = lire_cadre(&mut self.flux)?;
        self.session.dechiffrer(&cadre)
    }

    /// Scinde la connexion en une moitié LECTURE et une moitié ÉCRITURE, chacune
    /// avec son propre flux (`cloner_flux`) et sa moitié de canal.
    ///
    /// Permet à un thread de lire en continu pendant qu'un autre écrit : sans cela,
    /// un lecteur bloqué sur un pair silencieux figerait aussi les envois vers lui.
    pub fn separer<F>(self, cloner_flux: F) -> Result<(Lecteur<S>, Ecrivain<S>), NetError>
    where
        F: FnOnce(&S) -> std::io::Result<S>,
    {
        let flux_lecture = cloner_flux(&self.flux).map_err(|e| NetError::Io(e.kind()))?;
        let (emetteur, recepteur) = self.session.separer();
        Ok((
            Lecteur { flux: flux_lecture, recepteur },
            Ecrivain { flux: self.flux, emetteur },
        ))
    }
}

/// Moitié LECTURE d'une connexion scindée.
pub struct Lecteur<S: Read> {
    flux: S,
    recepteur: crate::session::Recepteur,
}

impl<S: Read> Lecteur<S> {
    pub fn recevoir(&mut self) -> Result<Vec<u8>, NetError> {
        let cadre = lire_cadre(&mut self.flux)?;
        self.recepteur.dechiffrer(&cadre)
    }
}

/// Moitié ÉCRITURE d'une connexion scindée.
pub struct Ecrivain<S: Write> {
    flux: S,
    emetteur: crate::session::Emetteur,
}

impl<S: Write> Ecrivain<S> {
    pub fn envoyer(&mut self, message: &[u8]) -> Result<(), NetError> {
        let cadre = self.emetteur.chiffrer(message)?;
        ecrire_cadre(&mut self.flux, &cadre)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::{self, Read, Write};
    use std::sync::{Arc, Mutex};

    /// Tuyau bidirectionnel en mémoire : deux files partagées, une par sens.
    /// Permet de faire tourner un handshake COMPLET sans socket ni thread — donc
    /// des tests déterministes et instantanés.
    #[derive(Clone)]
    struct Tuyau {
        lecture: Arc<Mutex<VecDeque<u8>>>,
        ecriture: Arc<Mutex<VecDeque<u8>>>,
    }

    impl Tuyau {
        fn paire() -> (Tuyau, Tuyau) {
            let a = Arc::new(Mutex::new(VecDeque::new()));
            let b = Arc::new(Mutex::new(VecDeque::new()));
            (
                Tuyau { lecture: a.clone(), ecriture: b.clone() },
                Tuyau { lecture: b, ecriture: a },
            )
        }
    }

    impl Read for Tuyau {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut f = self.lecture.lock().unwrap();
            if f.is_empty() {
                // Rien à lire : côté test, cela signifie fin de flux (pas d'attente).
                return Ok(0);
            }
            let n = buf.len().min(f.len());
            for o in buf.iter_mut().take(n) {
                *o = f.pop_front().expect("n <= f.len()");
            }
            Ok(n)
        }
    }

    impl Write for Tuyau {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.ecriture.lock().unwrap().extend(buf.iter().copied());
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Handshake complet À TRAVERS LE CADRAGE, puis échange applicatif.
    ///
    /// Le handshake étant en 3 passes strictement alternées, on peut le dérouler
    /// sans thread : chaque côté n'écrit que lorsque l'autre a fini.
    fn etablir(
        id_i: &SigKeypair,
        id_r: &SigKeypair,
    ) -> (Connexion<Tuyau>, Connexion<Tuyau>) {
        let (mut ti, mut tr) = Tuyau::paire();

        // Passe 1 (I) puis passe 2 (R) : on pilote les deux machines à la main pour
        // éviter tout parallélisme dans les tests.
        let (init, passe1) = Initiateur::commencer();
        ecrire_cadre(&mut ti, &passe1).unwrap();
        let recue1 = lire_cadre(&mut tr).unwrap();
        let (rep, passe2) = Repondeur::repondre(&recue1, id_r).unwrap();
        ecrire_cadre(&mut tr, &passe2).unwrap();
        let recue2 = lire_cadre(&mut ti).unwrap();
        let final_i = init.recevoir_passe2(&recue2, id_i).unwrap();
        let (passe3, sess_i, pair_i) = final_i.terminer();
        ecrire_cadre(&mut ti, &passe3).unwrap();
        let recue3 = lire_cadre(&mut tr).unwrap();
        let (sess_r, pair_r) = rep.recevoir_passe3(&recue3).unwrap();

        (
            Connexion { flux: ti, session: sess_i, pair: pair_i },
            Connexion { flux: tr, session: sess_r, pair: pair_r },
        )
    }

    #[test]
    fn connexion_bout_en_bout_sur_tuyau() {
        let id_i = SigKeypair::generate();
        let id_r = SigKeypair::generate();
        let (mut ci, mut cr) = etablir(&id_i, &id_r);

        // Identités mutuellement authentifiées.
        assert_eq!(ci.pair().to_bytes(), id_r.public.to_bytes());
        assert_eq!(cr.pair().to_bytes(), id_i.public.to_bytes());

        // Échange applicatif dans les deux sens, plusieurs messages (le compteur de
        // séquence doit rester synchrone).
        for n in 0..3u8 {
            let msg = vec![n; 10];
            ci.envoyer(&msg).unwrap();
            assert_eq!(cr.recevoir().unwrap(), msg);
        }
        cr.envoyer(b"reponse").unwrap();
        assert_eq!(ci.recevoir().unwrap(), b"reponse");
    }

    /// Un message de grande taille (ordre de grandeur d'une `ProvedTx`) passe le
    /// cadrage sans découpe manuelle.
    #[test]
    fn gros_message_traverse_le_cadrage() {
        let id_i = SigKeypair::generate();
        let id_r = SigKeypair::generate();
        let (mut ci, mut cr) = etablir(&id_i, &id_r);

        let gros = vec![0xA5u8; 70 * 1024]; // ~ taille d'une preuve
        ci.envoyer(&gros).unwrap();
        assert_eq!(cr.recevoir().unwrap(), gros);
    }

    /// Le canal reste anti-rejeu À TRAVERS le cadrage : réinjecter des octets déjà
    /// consommés échoue.
    #[test]
    fn rejeu_a_travers_le_cadrage_rejete() {
        let id_i = SigKeypair::generate();
        let id_r = SigKeypair::generate();
        let (mut ci, mut cr) = etablir(&id_i, &id_r);

        // On capture le cadre chiffré tel qu'il passe sur le fil.
        ci.envoyer(b"paiement").unwrap();
        let sur_le_fil: Vec<u8> = {
            let f = cr.flux.lecture.lock().unwrap();
            f.iter().copied().collect()
        };
        assert_eq!(cr.recevoir().unwrap(), b"paiement");

        // Réinjection des MÊMES octets : le compteur a avancé → rejet.
        cr.flux.lecture.lock().unwrap().extend(sur_le_fil.iter().copied());
        assert_eq!(cr.recevoir(), Err(NetError::DechiffrementEchoue));
    }
}
