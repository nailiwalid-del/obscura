//! Transport chiffré post-quantique entre nœuds Obscura (phase 4, brique 1).
//!
//! Fournit un canal **authentifié, chiffré, avec forward secrecy et masquage
//! d'identité**, monté sur les primitives hybrides existantes — `crypto::{kem, sig,
//! aead, hash}`. **Aucune primitive cryptographique nouvelle** : la défense en
//! profondeur (deux familles mathématiques indépendantes par fonction) est héritée
//! telle quelle, sans arbitrage à refaire.
//!
//! # Ce que le transport garantit
//!
//! - **Confidentialité** : AEAD cascade sous des clés issues de DEUX encapsulations
//!   KEM hybrides (contribution mutuelle — aucun pair ne choisit seul le secret).
//! - **Authentification mutuelle** : signatures hybrides sur le TRANSCRIPT complet.
//! - **Forward secrecy** : les clés d'échange sont éphémères et jetées ; compromettre
//!   une clé d'identité long terme ne déchiffre AUCUNE session passée.
//! - **Anti-rejeu** : transcript unique par session (éphémères frais) ; compteur de
//!   séquence par direction sur le canal établi.
//!
//! # Masquage d'identité — portée EXACTE
//!
//! | adversaire | identité de l'initiateur | identité du répondeur |
//! |---|---|---|
//! | observateur PASSIF | masquée | masquée |
//! | MitM ACTIF | masquée | **RÉVÉLÉE** |
//!
//! Un nœud en écoute révèle son identité à quiconque se connecte : c'est inhérent au
//! rôle de répondeur, PAS un défaut d'implémentation. Le fermer exigerait que
//! l'initiateur connaisse la clé du répondeur à l'avance (motif type Noise-IK),
//! envisageable pour les connexions SORTANTES vers des pairs connus.
//!
//! **Hors périmètre** : l'analyse de trafic (tailles, horaires, volumes). Padding et
//! cover traffic relèvent de Dandelion++/mixnet (briques 3-4).
//!
//! # Couches
//!
//! | module | rôle |
//! |---|---|
//! | [`frame`] | cadrage sur le fil (longueur préfixée, borne anti-DoS) |
//! | [`handshake`] | les 3 passes, en typestate |
//! | [`session`] | canal chiffré anti-rejeu |
//! | [`connexion`] | assemblage des trois, générique sur `Read + Write` |
//! | [`pairs`] | table de pairs et sélection résistante à l'ECLIPSE |
//! | [`dandelion`] | Dandelion++ : anonymisation de l'ORIGINE des transactions |
//!
//! Le cadrage est SYNCHRONE délibérément : il fixe le FORMAT DE FIL, qui est
//! l'artefact durable, pas la stratégie d'E/S. Passer à un runtime asynchrone plus
//! tard ne changera pas un octet sur le fil.
//!
//! # Surface hostile
//!
//! Tout décodage est un point d'entrée réseau : curseur borné, longueurs vérifiées
//! AVANT allocation, `Result` partout, aucune panique sur entrée arbitraire — même
//! discipline que `circuit::ProvedTx::from_bytes`.

use crypto::hash::{derive_key, dual_hash};

pub mod connexion;
pub mod dandelion;
pub mod frame;
pub mod handshake;
pub mod pairs;
pub mod session;

pub use connexion::{Connexion, Ecrivain, Lecteur};
pub use dandelion::{Dandelion, Routage};
pub use frame::{ecrire_cadre, lire_cadre, MAX_CADRE};
pub use handshake::{Initiateur, Repondeur};
pub use pairs::{GroupeReseau, Pair, PeerId, TablePairs};
pub use session::{Emetteur, Recepteur, Session};

/// Erreur du transport. Aucune variante n'implique de panique : le décodage ne fait
/// jamais confiance à son entrée.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum NetError {
    #[error("message tronqué")]
    Tronque,
    #[error("octets résiduels après la fin du message")]
    OctetsResiduels,
    #[error("taille de champ invalide ou hors bornes")]
    TailleInvalide,
    #[error("échec de déchiffrement (altération, rejeu ou hors-ordre)")]
    DechiffrementEchoue,
    #[error("signature d'identité invalide")]
    SignatureInvalide,
    #[error("encodage invalide")]
    EncodageInvalide,
    #[error("compteur de séquence épuisé : session à renouveler")]
    SessionEpuisee,
    /// Le pair a présenté un point X25519 d'ordre faible : le DH aurait rendu un secret
    /// nul et la moitié courbes du KEM hybride serait tombée en silence. Un pair honnête
    /// ne produit jamais ce cas — c'est donc soit une implémentation cassée, soit une
    /// tentative de dégrader la défense en profondeur.
    #[error("KEM non contributif : le pair a présenté un point d'ordre faible")]
    KemNonContributif,
    /// Erreur d'E/S sous-jacente. On ne conserve que le `ErrorKind` : cela garde
    /// `NetError` comparable (tests lisibles) et suffit à distinguer une fermeture
    /// propre (`UnexpectedEof` sur l'en-tête) d'une anomalie.
    #[error("erreur d'E/S : {0:?}")]
    Io(std::io::ErrorKind),
}

// ================================================================================
// Domaines de séparation — un par usage, jamais réutilisés.
// ================================================================================

const D_TRANSCRIPT: &str = "obscura/net/transcript/v1";
const D_HS1: &str = "obscura/net/hs1/v1";
const D_HS2: &str = "obscura/net/hs2/v1";
const D_SESS_I2R: &str = "obscura/net/sess-i2r/v1";
const D_SESS_R2I: &str = "obscura/net/sess-r2i/v1";
/// Domaine des signatures d'identité du handshake.
pub(crate) const D_IDENTITE: &str = "obscura/net/identite/v1";

/// Transcript du handshake : haché incrémentalement sur TOUS les octets échangés,
/// dans l'ordre.
///
/// C'est lui qui lie tout : les signatures portent sur le transcript courant, donc
/// sur l'intégralité de ce qui précède. Modifier n'importe quel champ en vol fait
/// diverger le transcript et invalide la signature.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Transcript([u8; 64]);

impl Transcript {
    pub(crate) fn neuf() -> Self {
        Transcript(dual_hash(D_TRANSCRIPT, &[]))
    }

    /// Absorbe un message : `T ← H(T ‖ message)`.
    pub(crate) fn absorber(&mut self, message: &[u8]) {
        let mut buf = Vec::with_capacity(64 + message.len());
        buf.extend_from_slice(&self.0);
        buf.extend_from_slice(message);
        self.0 = dual_hash(D_TRANSCRIPT, &buf);
    }

    pub(crate) fn octets(&self) -> &[u8; 64] {
        &self.0
    }

    /// Dérive une clé de `domaine` sur `transcript ‖ secrets`.
    pub(crate) fn deriver(&self, domaine: &str, secrets: &[&[u8]]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(64 + secrets.iter().map(|s| s.len()).sum::<usize>());
        buf.extend_from_slice(&self.0);
        for s in secrets {
            buf.extend_from_slice(s);
        }
        derive_key(domaine, &buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le transcript est un engagement : absorber des messages DIFFÉRENTS, ou les
    /// mêmes dans un ORDRE différent, donne des états distincts.
    #[test]
    fn transcript_engage_contenu_et_ordre() {
        let mut a = Transcript::neuf();
        let mut b = Transcript::neuf();
        assert_eq!(a, b, "même état initial");

        a.absorber(b"un");
        b.absorber(b"deux");
        assert_ne!(a, b, "contenus différents → transcripts différents");

        let mut c = Transcript::neuf();
        c.absorber(b"un");
        c.absorber(b"deux");
        let mut d = Transcript::neuf();
        d.absorber(b"deux");
        d.absorber(b"un");
        assert_ne!(
            c, d,
            "l'ORDRE doit compter (sinon réordonnancement possible)"
        );
    }

    /// Deux domaines distincts sur le MÊME transcript et les MÊMES secrets donnent
    /// des clés différentes — c'est ce qui rend les clés directionnelles sûres.
    #[test]
    fn derivation_separee_par_domaine() {
        let mut t = Transcript::neuf();
        t.absorber(b"handshake");
        let ss = [7u8; 32];
        let i2r = t.deriver(D_SESS_I2R, &[&ss]);
        let r2i = t.deriver(D_SESS_R2I, &[&ss]);
        assert_ne!(i2r, r2i, "les clés directionnelles doivent différer");

        // Et un transcript différent donne des clés différentes (liaison à la session).
        let mut t2 = Transcript::neuf();
        t2.absorber(b"autre");
        assert_ne!(i2r, t2.deriver(D_SESS_I2R, &[&ss]));
    }
}
