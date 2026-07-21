//! Handshake hybride post-quantique en 3 passes (PFS + masquage d'identité).
//!
//! ```text
//! 1.  I → R :  eph_pk_I
//! 2.  R → I :  eph_pk_R ‖ ct_R ‖ AEAD_k1{ id_pk_R ‖ sig_R(T₂) }
//! 3.  I → R :  ct_I ‖ AEAD_k2{ id_pk_I ‖ sig_I(T₃) }
//! ```
//!
//! Les états sont des TYPES distincts et les transitions CONSOMMENT `self`
//! (typestate) : utiliser un handshake hors séquence, ou récupérer une session avant
//! la fin, est une erreur de COMPILATION — pas une vérification à l'exécution qu'on
//! pourrait oublier.

use crate::session::Session;
use crate::{NetError, Transcript, D_HS1, D_HS2, D_IDENTITE, D_SESS_I2R, D_SESS_R2I};
use crypto::kem::{self, KemCiphertext, KemKeypair, KemPublicKey};
use crypto::sig::{self, HybridSignature, SigKeypair, SigPublicKey};

/// Borne de taille d'un champ préfixé (anti-DoS mémoire au décodage). Généreuse
/// devant les tailles réelles (clé KEM hybride ≈ 1,2 Kio, signature ≈ 3,4 Kio) mais
/// bornée : un pair hostile ne peut pas nous faire allouer arbitrairement.
const MAX_CHAMP: usize = 16 * 1024;

/// Lit un champ préfixé par sa longueur (`u32` LE) sans jamais paniquer.
fn lire_champ<'a>(b: &'a [u8], pos: &mut usize) -> Result<&'a [u8], NetError> {
    let fin_len = pos.checked_add(4).ok_or(NetError::Tronque)?;
    if fin_len > b.len() {
        return Err(NetError::Tronque);
    }
    let n = u32::from_le_bytes(b[*pos..fin_len].try_into().unwrap()) as usize;
    if n > MAX_CHAMP {
        return Err(NetError::TailleInvalide);
    }
    let fin = fin_len.checked_add(n).ok_or(NetError::Tronque)?;
    if fin > b.len() {
        return Err(NetError::Tronque);
    }
    *pos = fin;
    Ok(&b[fin_len..fin])
}

fn ecrire_champ(dst: &mut Vec<u8>, champ: &[u8]) {
    dst.extend_from_slice(&(champ.len() as u32).to_le_bytes());
    dst.extend_from_slice(champ);
}

/// Contenu chiffré d'une passe d'identité : clé publique + signature du transcript.
fn sceller_identite(cle: &[u8; 32], aad: &[u8], id: &SigPublicKey, s: &HybridSignature) -> Vec<u8> {
    let mut clair = Vec::new();
    ecrire_champ(&mut clair, &id.to_bytes());
    ecrire_champ(&mut clair, &s.to_bytes());
    crypto::aead::encrypt(cle, aad, &clair)
}

/// Ouvre et VALIDE une passe d'identité : déchiffre, décode, vérifie la signature
/// contre le transcript attendu.
fn ouvrir_identite(
    cle: &[u8; 32],
    aad: &[u8],
    scelle: &[u8],
    transcript_signe: &[u8; 64],
) -> Result<SigPublicKey, NetError> {
    let clair =
        crypto::aead::decrypt(cle, aad, scelle).map_err(|_| NetError::DechiffrementEchoue)?;
    let mut pos = 0usize;
    let id = SigPublicKey::from_bytes(lire_champ(&clair, &mut pos)?)
        .map_err(|_| NetError::EncodageInvalide)?;
    let signature = HybridSignature::from_bytes(lire_champ(&clair, &mut pos)?)
        .map_err(|_| NetError::EncodageInvalide)?;
    if pos != clair.len() {
        return Err(NetError::OctetsResiduels);
    }
    if !sig::verify(&id, D_IDENTITE, transcript_signe, &signature) {
        return Err(NetError::SignatureInvalide);
    }
    Ok(id)
}

// ================================================================================
// INITIATEUR
// ================================================================================

/// Initiateur ayant émis la passe 1 et attendant la passe 2.
pub struct Initiateur {
    ephemere: KemKeypair,
    transcript: Transcript,
}

/// Initiateur ayant vérifié le répondeur : il ne reste qu'à émettre la passe 3.
pub struct InitiateurFinal {
    session: Session,
    pair: SigPublicKey,
    passe3: Vec<u8>,
}

impl Initiateur {
    /// Passe 1 : génère un éphémère frais (forward secrecy) et publie sa clé
    /// publique. Aucune identité n'est révélée à ce stade.
    pub fn commencer() -> (Self, Vec<u8>) {
        let ephemere = KemKeypair::generate();
        let mut message = Vec::new();
        ecrire_champ(&mut message, &ephemere.public.to_bytes());
        let mut transcript = Transcript::neuf();
        transcript.absorber(&message);
        (
            Initiateur {
                ephemere,
                transcript,
            },
            message,
        )
    }

    /// Reçoit la passe 2, authentifie le répondeur, et prépare la passe 3.
    pub fn recevoir_passe2(
        mut self,
        passe2: &[u8],
        identite: &SigKeypair,
    ) -> Result<InitiateurFinal, NetError> {
        let mut pos = 0usize;
        let eph_r = KemPublicKey::from_bytes(lire_champ(passe2, &mut pos)?)
            .map_err(|_| NetError::EncodageInvalide)?;
        let ct_r = KemCiphertext::from_bytes(lire_champ(passe2, &mut pos)?)
            .map_err(|_| NetError::EncodageInvalide)?;
        let scelle = lire_champ(passe2, &mut pos)?;
        if pos != passe2.len() {
            return Err(NetError::OctetsResiduels);
        }

        // ss₁ : le répondeur a encapsulé vers NOTRE éphémère.
        let ss1 =
            kem::decapsulate(&self.ephemere, &ct_r).map_err(|_| NetError::KemNonContributif)?;

        // Le transcript signé par le répondeur couvre la passe 1 ET les parties
        // publiques de la passe 2 (éphémère + ciphertext), donc tout ce qui précède
        // son identité. On le reconstruit à l'identique avant de vérifier.
        let mut entete2 = Vec::new();
        ecrire_champ(&mut entete2, &eph_r.to_bytes());
        ecrire_champ(&mut entete2, &ct_r.to_bytes());
        self.transcript.absorber(&entete2);
        let k1 = self.transcript.deriver(D_HS1, &[&ss1]);
        let pair = ouvrir_identite(
            &k1,
            self.transcript.octets(),
            scelle,
            self.transcript.octets(),
        )?;

        // La partie scellée entre à son tour dans le transcript : la passe 3 s'y lie.
        self.transcript.absorber(scelle);

        // ss₂ : nous encapsulons vers l'éphémère du répondeur (contribution mutuelle).
        let (ct_i, ss2) = kem::encapsulate(&eph_r).map_err(|_| NetError::KemNonContributif)?;
        let mut entete3 = Vec::new();
        ecrire_champ(&mut entete3, &ct_i.to_bytes());
        self.transcript.absorber(&entete3);

        let k2 = self.transcript.deriver(D_HS2, &[&ss1, &ss2]);
        let signature = identite.sign(D_IDENTITE, self.transcript.octets());
        let scelle_i =
            sceller_identite(&k2, self.transcript.octets(), &identite.public, &signature);

        let mut passe3 = entete3;
        ecrire_champ(&mut passe3, &scelle_i);
        self.transcript.absorber(&scelle_i);

        // Clés de session : dérivées du transcript FINAL et des DEUX secrets.
        let session = Session::nouvelle(
            self.transcript.deriver(D_SESS_I2R, &[&ss1, &ss2]),
            self.transcript.deriver(D_SESS_R2I, &[&ss1, &ss2]),
        );
        Ok(InitiateurFinal {
            session,
            pair,
            passe3,
        })
    }
}

impl InitiateurFinal {
    /// Passe 3 à émettre, puis la session établie et l'identité authentifiée du pair.
    pub fn terminer(self) -> (Vec<u8>, Session, SigPublicKey) {
        (self.passe3, self.session, self.pair)
    }
}

// ================================================================================
// RÉPONDEUR
// ================================================================================

/// Répondeur ayant émis la passe 2 et attendant la passe 3.
pub struct Repondeur {
    ephemere: KemKeypair,
    transcript: Transcript,
    ss1: [u8; 32],
}

impl Repondeur {
    /// Passe 2 : encapsule vers l'éphémère de l'initiateur, publie son propre
    /// éphémère, et joint son identité CHIFFRÉE (masquage contre un observateur
    /// passif) signée sur le transcript.
    pub fn repondre(passe1: &[u8], identite: &SigKeypair) -> Result<(Self, Vec<u8>), NetError> {
        let mut pos = 0usize;
        let eph_i = KemPublicKey::from_bytes(lire_champ(passe1, &mut pos)?)
            .map_err(|_| NetError::EncodageInvalide)?;
        if pos != passe1.len() {
            return Err(NetError::OctetsResiduels);
        }
        let mut transcript = Transcript::neuf();
        transcript.absorber(passe1);

        let ephemere = KemKeypair::generate();
        let (ct_r, ss1) = kem::encapsulate(&eph_i).map_err(|_| NetError::KemNonContributif)?;

        let mut entete2 = Vec::new();
        ecrire_champ(&mut entete2, &ephemere.public.to_bytes());
        ecrire_champ(&mut entete2, &ct_r.to_bytes());
        transcript.absorber(&entete2);

        let k1 = transcript.deriver(D_HS1, &[&ss1]);
        let signature = identite.sign(D_IDENTITE, transcript.octets());
        let scelle = sceller_identite(&k1, transcript.octets(), &identite.public, &signature);

        let mut passe2 = entete2;
        ecrire_champ(&mut passe2, &scelle);
        transcript.absorber(&scelle);

        Ok((
            Repondeur {
                ephemere,
                transcript,
                ss1,
            },
            passe2,
        ))
    }

    /// Reçoit la passe 3, authentifie l'initiateur, établit la session.
    pub fn recevoir_passe3(mut self, passe3: &[u8]) -> Result<(Session, SigPublicKey), NetError> {
        let mut pos = 0usize;
        let ct_i = KemCiphertext::from_bytes(lire_champ(passe3, &mut pos)?)
            .map_err(|_| NetError::EncodageInvalide)?;
        let scelle = lire_champ(passe3, &mut pos)?;
        if pos != passe3.len() {
            return Err(NetError::OctetsResiduels);
        }

        let ss2 =
            kem::decapsulate(&self.ephemere, &ct_i).map_err(|_| NetError::KemNonContributif)?;
        let mut entete3 = Vec::new();
        ecrire_champ(&mut entete3, &ct_i.to_bytes());
        self.transcript.absorber(&entete3);

        let k2 = self.transcript.deriver(D_HS2, &[&self.ss1, &ss2]);
        let pair = ouvrir_identite(
            &k2,
            self.transcript.octets(),
            scelle,
            self.transcript.octets(),
        )?;
        self.transcript.absorber(scelle);

        // Miroir de l'initiateur : mêmes domaines, rôles d'envoi/réception inversés.
        let session = Session::nouvelle(
            self.transcript.deriver(D_SESS_R2I, &[&self.ss1, &ss2]),
            self.transcript.deriver(D_SESS_I2R, &[&self.ss1, &ss2]),
        );
        Ok((session, pair))
    }
}
