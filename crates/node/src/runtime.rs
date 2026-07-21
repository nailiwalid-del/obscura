//! Boucle d'événements et sockets : l'exécution des décisions (phase 5).
//!
//! L'orchestration (`crate::orchestration`) DÉCIDE sans faire d'E/S ; ce module
//! EXÉCUTE. La séparation est nette et volontaire : ici il n'y a plus une seule
//! décision de protocole à prendre, seulement de la plomberie — sockets, threads,
//! files. Tout ce qui pouvait être testé sans réseau l'a déjà été.
//!
//! # Modèle de concurrence
//!
//! Un **thread de lecture par connexion**, qui pousse les messages reçus dans une
//! file commune. La boucle principale dépile, appelle `Noeud::traiter`, et exécute
//! les actions en écrivant sur les connexions.
//!
//! Lecture et écriture d'une même connexion sont **découplées** (`Connexion::separer`) :
//! sans cela, un thread bloqué en lecture sur un pair silencieux empêcherait aussi
//! d'écrire vers lui — un pair muet suffirait à figer le nœud.

use crate::message::Message;
use crate::orchestration::{Action, Noeud};
use crypto::sig::SigKeypair;
use net::pairs::PeerId;
use net::{Connexion, Ecrivain, NetError};
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

/// Événement remonté à la boucle principale par un thread de lecture.
pub enum Evenement {
    /// Message reçu d'un pair (octets applicatifs déjà déchiffrés).
    Recu(PeerId, Vec<u8>),
    /// La connexion s'est terminée (fermeture propre ou erreur).
    Deconnecte(PeerId),
}

/// Ensemble des liens sortants ouverts, adressables par pair.
type Liens = Arc<Mutex<HashMap<PeerId, Ecrivain<TcpStream>>>>;

/// Nœud en fonctionnement : sockets, threads de lecture, exécution des actions.
pub struct Runtime {
    noeud: Noeud,
    liens: Liens,
    evenements: Receiver<Evenement>,
    emetteur_evenements: Sender<Evenement>,
}

impl Runtime {
    pub fn new(noeud: Noeud) -> Self {
        let (tx, rx) = channel();
        Runtime {
            noeud,
            liens: Arc::new(Mutex::new(HashMap::new())),
            evenements: rx,
            emetteur_evenements: tx,
        }
    }

    pub fn noeud(&self) -> &Noeud {
        &self.noeud
    }

    pub fn noeud_mut(&mut self) -> &mut Noeud {
        &mut self.noeud
    }

    /// Ouvre une écoute et retourne l'adresse RÉELLEMENT liée.
    ///
    /// Retourner l'adresse effective permet d'écouter sur le port 0 (« attribue-moi
    /// un port libre »), ce qui rend les tests d'intégration exécutables en
    /// parallèle sans collision de ports.
    pub fn ecouter(adresse: SocketAddr) -> io::Result<TcpListener> {
        let l = TcpListener::bind(adresse)?;
        Ok(l)
    }

    /// Accepte une connexion entrante, fait le handshake, et enregistre le lien.
    pub fn accepter(&mut self, flux: TcpStream, identite: &SigKeypair) -> Result<PeerId, NetError> {
        let connexion = Connexion::accepter(flux, identite)?;
        self.enregistrer(connexion)
    }

    /// Se connecte à un pair sortant, fait le handshake, et enregistre le lien.
    pub fn connecter(
        &mut self,
        adresse: SocketAddr,
        identite: &SigKeypair,
    ) -> Result<PeerId, NetError> {
        let flux = TcpStream::connect(adresse).map_err(|e| NetError::Io(e.kind()))?;
        let connexion = Connexion::connecter(flux, identite)?;
        let id = self.enregistrer(connexion)?;
        // Le pair est authentifié : on le retient avec son adresse, pour que la
        // sélection anti-eclipse (groupes réseau) puisse en tenir compte.
        self.noeud.pairs.ajouter(id, adresse);
        Ok(id)
    }

    /// Scinde la connexion, lance son thread de lecture, mémorise l'écrivain.
    fn enregistrer(&mut self, connexion: Connexion<TcpStream>) -> Result<PeerId, NetError> {
        let id = PeerId::depuis_identite(connexion.pair());
        let (mut lecteur, ecrivain) = connexion.separer(|f| f.try_clone())?;

        let vers_boucle = self.emetteur_evenements.clone();
        thread::spawn(move || {
            loop {
                match lecteur.recevoir() {
                    Ok(octets) => {
                        if vers_boucle.send(Evenement::Recu(id, octets)).is_err() {
                            break; // la boucle principale s'est arrêtée
                        }
                    }
                    Err(_) => {
                        // Fermeture propre ou erreur : dans les deux cas le lien est
                        // fini. On le signale plutôt que de boucler à vide.
                        let _ = vers_boucle.send(Evenement::Deconnecte(id));
                        break;
                    }
                }
            }
        });

        self.liens.lock().unwrap().insert(id, ecrivain);
        Ok(id)
    }

    /// Traite les événements EN ATTENTE sans bloquer, et exécute les actions.
    /// Retourne le nombre d'événements traités.
    pub fn pomper(&mut self, maintenant_ms: u64) -> usize {
        let mut traites = 0;
        while let Ok(ev) = self.evenements.try_recv() {
            traites += 1;
            match ev {
                Evenement::Recu(de, octets) => match Message::from_bytes(&octets) {
                    Ok(message) => {
                        let actions = self.noeud.traiter(de, message, maintenant_ms);
                        self.executer(actions);
                    }
                    // Message indécodable : le pair ne parle pas le protocole.
                    Err(_) => self.noeud.message_invalide(&de),
                },
                Evenement::Deconnecte(de) => {
                    self.liens.lock().unwrap().remove(&de);
                }
            }
        }
        traites
    }

    /// Exécute les actions décidées par l'orchestration.
    ///
    /// Une écriture qui échoue retire simplement le lien : un pair injoignable ne
    /// doit ni faire paniquer le nœud, ni bloquer les autres envois.
    pub fn executer(&mut self, actions: Vec<Action>) {
        let mut liens = self.liens.lock().unwrap();
        for action in actions {
            match action {
                Action::Envoyer(vers, message) => {
                    let octets = message.to_bytes();
                    if let Some(e) = liens.get_mut(&vers) {
                        if e.envoyer(&octets).is_err() {
                            liens.remove(&vers);
                        }
                    }
                }
                Action::Diffuser(message) => {
                    let octets = message.to_bytes();
                    let mut morts: Vec<PeerId> = Vec::new();
                    for (id, e) in liens.iter_mut() {
                        if e.envoyer(&octets).is_err() {
                            morts.push(*id);
                        }
                    }
                    for m in morts {
                        liens.remove(&m);
                    }
                }
            }
        }
    }

    /// Tick périodique : diffuse les embargos Dandelion++ expirés.
    pub fn tick(&mut self, maintenant_ms: u64) {
        let actions = self.noeud.tick(maintenant_ms);
        self.executer(actions);
    }

    /// Nombre de liens ouverts.
    pub fn liens_ouverts(&self) -> usize {
        self.liens.lock().unwrap().len()
    }

    /// Envoie des octets APPLICATIFS bruts (sans passer par `Message`).
    ///
    /// Réservé aux tests : permet d'injecter du bruit décodable au niveau TRANSPORT
    /// mais pas au niveau applicatif, afin d'éprouver la robustesse du nœud face à
    /// un pair authentifié mais non conforme.
    pub fn envoyer_octets_bruts(&mut self, vers: PeerId, octets: &[u8]) {
        let mut liens = self.liens.lock().unwrap();
        if let Some(e) = liens.get_mut(&vers) {
            let _ = e.envoyer(octets);
        }
    }
}
