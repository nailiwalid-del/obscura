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
//! file commune. La boucle principale dépile, appelle `Noeud::traiter`, et DÉPOSE
//! les actions dans la file d'envoi de chaque lien — un **thread d'écriture par
//! connexion** (file bornée) fait les E/S. La boucle principale ne touche donc
//! JAMAIS une socket : un pair lent ne peut retarder ni `pomper`, ni `tick`, ni
//! le scellement.
//!
//! Lecture et écriture d'une même connexion sont **découplées** (`Connexion::separer`) :
//! sans cela, un thread bloqué en lecture sur un pair silencieux empêcherait aussi
//! d'écrire vers lui — un pair muet suffirait à figer le nœud.

use crate::message::Message;
use crate::orchestration::{Action, Noeud};
use crypto::sig::SigKeypair;
use net::pairs::PeerId;
use net::{Connexion, NetError};
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{channel, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;

/// Événement remonté à la boucle principale par un thread de lecture.
pub enum Evenement {
    /// Message reçu d'un pair (octets applicatifs déjà déchiffrés).
    Recu(PeerId, Vec<u8>),
    /// La connexion s'est terminée (fermeture propre ou erreur).
    Deconnecte(PeerId),
}

/// Profondeur de la file d'envoi d'UN lien, en messages.
///
/// Elle borne deux choses à la fois : la mémoire qu'un pair LENT peut nous faire
/// retenir (≤ `FILE_ENVOI × MAX_CADRE` ≈ 16 Mio par lien, au pire), et la patience
/// qu'on lui accorde — une file pleine signifie qu'il n'absorbe plus depuis
/// longtemps, et le lien est coupé comme le ferait une erreur d'écriture. C'est le
/// remplacement de l'ancienne politique « échéance d'écriture de 20 s sous le
/// verrou global », qui figeait la boucle PRINCIPALE en attendant.
const FILE_ENVOI: usize = 16;

/// Ensemble des liens ouverts, adressables par pair. La valeur est la FILE
/// d'envoi du lien, pas l'écrivain : celui-ci vit dans son thread d'écriture,
/// et la boucle principale ne fait que déposer (jamais d'E/S sous ce verrou).
type Liens = Arc<Mutex<HashMap<PeerId, SyncSender<Vec<u8>>>>>;

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

    /// Échéances posées sur CHAQUE flux, avant même le handshake.
    ///
    /// # Sans elles, un pair muet fige le nœud ENTIER
    ///
    /// Les lectures et écritures d'un `TcpStream` sont bloquantes et sans limite de
    /// temps par défaut. Trois conséquences, toutes réelles :
    ///
    /// - un pair qui ouvre une connexion puis n'envoie jamais la première passe du
    ///   handshake bloque la boucle principale dans `read_exact` — plus d'`accept`,
    ///   plus de `pomper`, plus de `tick` Dandelion++ (les embargos n'expirent plus),
    ///   plus de scellement, plus de sauvegarde d'état ;
    /// - un pair qui cesse de LIRE fait bloquer notre `write_all` une fois les
    ///   tampons pleins — le thread d'écriture de CE lien s'arrête dessus (la
    ///   boucle principale, elle, continue : elle ne fait que déposer en file) ;
    /// - dans les deux cas le nœud reste debout et silencieux : rien ne le distingue
    ///   d'un nœud au repos.
    ///
    /// L'échéance transforme ces blocages définitifs en une erreur d'E/S, que le
    /// reste du code traite déjà comme un lien mort. C'est un préalable à tout
    /// service volumineux : sans elle, la protection la mieux conçue ne s'applique
    /// qu'APRÈS le point de blocage.
    const ECHEANCE: std::time::Duration = std::time::Duration::from_secs(20);

    fn poser_echeances(flux: &TcpStream) -> Result<(), NetError> {
        flux.set_read_timeout(Some(Self::ECHEANCE))
            .and_then(|_| flux.set_write_timeout(Some(Self::ECHEANCE)))
            .map_err(|e| NetError::Io(e.kind()))
    }

    /// Accepte une connexion entrante, fait le handshake, et enregistre le lien.
    pub fn accepter(&mut self, flux: TcpStream, identite: &SigKeypair) -> Result<PeerId, NetError> {
        Self::poser_echeances(&flux)?;
        // Relevée AVANT le handshake (le flux part ensuite dans `Connexion`). C'est
        // l'adresse SOURCE : son port est éphémère et sans intérêt, seul le préfixe
        // compte — c'est lui qui donne le `GroupeReseau` auquel imputer le coût du
        // service d'historique.
        let adresse = flux.peer_addr().ok();
        let connexion = Connexion::accepter(flux, identite)?;
        let id = self.enregistrer(connexion)?;
        // Volontairement PAS `pairs.ajouter` : la table de pairs sert la sélection
        // SORTANTE anti-eclipse, et y verser les entrants offrirait à un attaquant un
        // moyen d'entrer dans nos emplacements sortants en nous appelant.
        if let Some(a) = adresse {
            self.noeud.noter_adresse(id, a);
        }
        Ok(id)
    }

    /// Se connecte à un pair sortant, fait le handshake, et enregistre le lien.
    pub fn connecter(
        &mut self,
        adresse: SocketAddr,
        identite: &SigKeypair,
    ) -> Result<PeerId, NetError> {
        let flux = TcpStream::connect(adresse).map_err(|e| NetError::Io(e.kind()))?;
        Self::poser_echeances(&flux)?;
        let connexion = Connexion::connecter(flux, identite)?;
        let id = self.enregistrer(connexion)?;
        // Le pair est authentifié : on le retient avec son adresse, pour que la
        // sélection anti-eclipse (groupes réseau) puisse en tenir compte.
        self.noeud.pairs.ajouter(id, adresse);
        self.noeud.noter_adresse(id, adresse);
        Ok(id)
    }

    /// Scinde la connexion, lance ses threads de LECTURE et d'ÉCRITURE, mémorise
    /// la file d'envoi.
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
                    // Une ÉCHÉANCE de lecture écoulée ne veut pas dire « lien mort » :
                    // elle veut dire « ce pair est silencieux ». Un protocole piloté
                    // par les événements passe l'essentiel de son temps silencieux —
                    // confondre les deux couperait tous les liens toutes les 20
                    // secondes et détruirait le réseau, en toute discrétion.
                    Err(NetError::Io(
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut,
                    )) => continue,
                    Err(_) => {
                        // Fermeture propre ou erreur : dans les deux cas le lien est
                        // fini. On le signale plutôt que de boucler à vide.
                        let _ = vers_boucle.send(Evenement::Deconnecte(id));
                        break;
                    }
                }
            }
        });

        // Thread d'ÉCRITURE : seul propriétaire de l'écrivain (donc du chiffrement
        // et du compteur de séquence de cette direction). Il meurt quand la file
        // est fermée (lien retiré de la table) ou quand l'écriture échoue — auquel
        // cas il le SIGNALE, comme le fait le thread de lecture.
        let (file_envoi, a_envoyer) = std::sync::mpsc::sync_channel::<Vec<u8>>(FILE_ENVOI);
        let vers_boucle = self.emetteur_evenements.clone();
        let mut ecrivain = ecrivain;
        thread::spawn(move || {
            while let Ok(octets) = a_envoyer.recv() {
                if ecrivain.envoyer(&octets).is_err() {
                    let _ = vers_boucle.send(Evenement::Deconnecte(id));
                    break;
                }
            }
        });

        self.liens.lock().unwrap().insert(id, file_envoi);
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
                    // Une version que NOUS ne connaissons pas n'est pas une faute du
                    // pair : le pénaliser bannirait, en cours de mise à jour, les
                    // nœuds restés en arrière — et avec eux la diversité de groupes
                    // réseau dont dépend l'anti-eclipse. On l'ignore, comme un bloc
                    // qui ne s'enchaîne pas.
                    Err(e) if e.version_inconnue() => {}
                    // Malformation dans une version connue : là, le pair ne parle
                    // pas le protocole.
                    Err(_) => self.noeud.message_invalide(&de),
                },
                Evenement::Deconnecte(de) => {
                    self.liens.lock().unwrap().remove(&de);
                    // L'adresse ne survit pas au lien : sans cela, la table croîtrait
                    // d'une entrée par identité de transport éphémère — et le wallet en
                    // tire une neuve à chaque commande. Le crédit, lui, RESTE : il est
                    // indexé sur le groupe réseau, pas sur le pair, précisément pour
                    // qu'une reconnexion ne le remette pas à plein.
                    self.noeud.oublier_adresse(&de);
                }
            }
        }
        traites
    }

    /// Exécute les actions décidées par l'orchestration — en DÉPOSANT, jamais en
    /// écrivant : les E/S appartiennent aux threads d'écriture. Le verrou des
    /// liens n'est donc tenu que le temps d'un `try_send`, et un pair lent ne
    /// retarde plus la boucle principale.
    ///
    /// Une file PLEINE vaut lien mort : le pair n'absorbe plus depuis
    /// `FILE_ENVOI` messages, on coupe — même politique que l'erreur d'écriture,
    /// décidée ici plutôt que subie 20 s plus tard sous échéance. Le thread
    /// d'écriture meurt de lui-même quand sa file est fermée.
    pub fn executer(&mut self, actions: Vec<Action>) {
        let mut liens = self.liens.lock().unwrap();
        for action in actions {
            match action {
                Action::Envoyer(vers, message) => {
                    let octets = message.to_bytes();
                    if let Some(file) = liens.get(&vers) {
                        if file.try_send(octets).is_err() {
                            liens.remove(&vers);
                        }
                    }
                }
                Action::Diffuser(message) => {
                    let octets = message.to_bytes();
                    let mut morts: Vec<PeerId> = Vec::new();
                    for (id, file) in liens.iter() {
                        if file.try_send(octets.clone()).is_err() {
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
    /// un pair authentifié mais non conforme. Passe par la MÊME file que le trafic
    /// normal (l'ordre relatif des envois vers un pair est préservé).
    pub fn envoyer_octets_bruts(&mut self, vers: PeerId, octets: &[u8]) {
        let liens = self.liens.lock().unwrap();
        if let Some(file) = liens.get(&vers) {
            let _ = file.try_send(octets.to_vec());
        }
    }
}
