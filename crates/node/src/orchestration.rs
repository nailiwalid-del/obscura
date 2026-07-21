//! Orchestration : ce qu'un nœud FAIT d'un message reçu (phase 5).
//!
//! C'est ici que les six briques se rencontrent — état, mempool, pairs,
//! Dandelion++, protocole applicatif, transport.
//!
//! # Décider n'est pas agir
//!
//! `traiter` est une fonction **pure** : elle consulte l'état, le met à jour, et
//! **retourne des actions** — sans ouvrir de socket ni écrire un octet. La boucle
//! d'événements se contente d'exécuter ces actions.
//!
//! Ce découpage n'est pas cosmétique : il rend TOUTE la politique du nœud testable
//! sans réseau, de façon déterministe. La logique de propagation, le scoring des
//! pairs et le routage Dandelion++ sont les endroits où les bugs coûtent cher ; les
//! enfermer dans une fonction sans E/S est ce qui permet de les éprouver.
//!
//! # Le scoring branche enfin l'asymétrie de coût
//!
//! `ledger::mempool::Refus::couteux()` distingue les refus ayant brûlé du CPU
//! (~4 ms de vérification STARK) des refus gratuits. C'est ici que cette distinction
//! devient une sanction : une preuve invalide pénalise lourdement, un doublon ne
//! pénalise PAS.
//!
//! **Piège évité** : dans un protocole de gossip, recevoir des doublons est le cas
//! NORMAL — plusieurs pairs annoncent légitimement la même transaction. Les
//! pénaliser bannirait les pairs honnêtes, et d'autant plus vite qu'ils sont bien
//! connectés.

use crate::message::Message;
use circuit::ProvedTx;
use crypto::sig::SigKeypair;
use ledger::bloc::Bloc;
use ledger::mempool::Mempool;
use ledger::proved_state::{BlocRefus, ProvedLedgerState};
use net::dandelion::{Dandelion, Routage};
use net::pairs::{PeerId, TablePairs};

/// Pénalité pour un refus COÛTEUX (preuve invalide). Quelques-uns suffisent à
/// franchir le seuil de bannissement : faire brûler 4 ms de CPU à répétition est
/// une attaque, pas une maladresse.
pub const PENALITE_PREUVE_INVALIDE: i32 = -34;

/// Pénalité pour un message indécodable (le pair ne parle pas le protocole).
pub const PENALITE_MESSAGE_INVALIDE: i32 = -10;

/// Pénalité pour un bloc dont une transaction est invalide.
///
/// Aussi lourde qu'une preuve invalide isolée : faire vérifier tout un bloc avant de
/// le rejeter coûte bien plus cher qu'une transaction seule. En revanche un bloc qui
/// ne s'enchaîne PAS à notre tête ne pénalise pas — c'est le cas normal quand deux
/// nœuds scellent en même temps, ou quand on est simplement en retard.
pub const PENALITE_BLOC_INVALIDE: i32 = -34;

/// Action à exécuter par la boucle d'événements. Aucune E/S n'est faite ici.
pub enum Action {
    /// Envoyer un message à UN pair (relais de tige Dandelion++, ou réponse).
    Envoyer(PeerId, Message),
    /// Diffuser à tous les pairs (phase floraison, ou embargo expiré).
    Diffuser(Message),
}

/// Un nœud : état de consensus + réserve + vue du réseau.
pub struct Noeud {
    pub identite: SigKeypair,
    pub etat: ProvedLedgerState,
    pub mempool: Mempool,
    pub pairs: TablePairs,
    pub dandelion: Dandelion,
    /// Blocs refusés faute de s'enchaîner à notre tête, depuis le démarrage.
    ///
    /// Ne PAS sanctionner un tel bloc est correct (deux scellements simultanés, ou
    /// simple retard). Mais se taire l'était moins : un nœud qui a manqué UN bloc
    /// refuse ensuite tous les suivants, en silence, et reste figé pour toujours —
    /// indiscernable d'un nœud au repos. Ce compteur est le seul signal qui les
    /// distingue tant qu'aucun protocole de rattrapage n'existe.
    blocs_desaccordes: u64,
}

impl Noeud {
    pub fn new(
        identite: SigKeypair,
        etat: ProvedLedgerState,
        secret_dandelion: [u8; 32],
    ) -> Self {
        Noeud {
            identite,
            etat,
            mempool: Mempool::new(),
            pairs: TablePairs::new(),
            dandelion: Dandelion::new(secret_dandelion),
            blocs_desaccordes: 0,
        }
    }

    /// Nombre de blocs refusés faute de s'enchaîner. Non nul et qui croît = ce nœud
    /// n'est PAS au repos, il est sur une autre chaîne ou il a manqué un bloc.
    pub fn blocs_desaccordes(&self) -> u64 {
        self.blocs_desaccordes
    }

    /// Soumet une transaction ÉMISE PAR CE NŒUD (depuis le wallet).
    ///
    /// Point d'entrée distinct de la réception : il n'y a pas de pair à pénaliser,
    /// et c'est ici que Dandelion++ protège l'ORIGINE — la transaction part en tige
    /// vers un unique successeur plutôt qu'en diffusion, ce qui empêche un
    /// observateur de distinguer l'émetteur d'un relais.
    ///
    /// Retourne les actions à exécuter, ou le refus si notre propre transaction est
    /// invalide (état périmé, double-dépense locale…).
    pub fn soumettre(
        &mut self,
        tx: ProvedTx,
        maintenant_ms: u64,
    ) -> Result<Vec<Action>, ledger::mempool::Refus> {
        let digest = tx.tx_digest;
        // Emprunts disjoints de `self.mempool` et `self.etat` — possible ici parce
        // qu'on est DANS la méthode : c'est ce qui rend ce point d'entrée nécessaire.
        self.mempool.admettre(&self.etat, tx)?;
        Ok(match self.dandelion.router(&digest, maintenant_ms) {
            Routage::Stem(vers) => self.relayer_en_tige(vers, &digest),
            Routage::Fluff => vec![Action::Diffuser(Message::Annonce(vec![digest]))],
        })
    }

    /// Traite un message reçu de `de` et retourne les actions à exécuter.
    pub fn traiter(&mut self, de: PeerId, message: Message, maintenant_ms: u64) -> Vec<Action> {
        match message {
            Message::Annonce(digests) => self.sur_annonce(de, digests),
            Message::Demande(digests) => self.sur_demande(de, digests),
            Message::Transaction(tx) => self.sur_transaction(de, *tx, maintenant_ms),
            Message::Bloc(bloc) => self.sur_bloc(de, *bloc),
        }
    }

    /// Scelle un bloc avec les transactions du mempool, l'applique, et le diffuse.
    ///
    /// # Personne n'a autorité pour faire cela — et c'est assumé
    ///
    /// Aucune élection de producteur n'existe (hors périmètre : docs/THREAT_MODEL.md).
    /// N'importe quel nœud peut donc sceller, à n'importe quel moment. La chaîne qui
    /// en résulte est un ordre CONVENU entre participants coopératifs, pas un ordre
    /// DÉFENDU contre un adversaire. C'est utilisable pour un testnet local, pas au
    /// delà.
    ///
    /// # L'ordre est déterministe, à dessein
    ///
    /// Les transactions sont triées par `tx_digest`. Deux nœuds scellant le même
    /// mempool produisent alors le MÊME bloc — ce qui rend les collisions inoffensives
    /// au lieu de provoquer une divergence.
    ///
    /// ⚠️ Un tri par digest est *grindable* : un émetteur peut faire varier sa
    /// transaction jusqu'à obtenir un digest favorable. Sans marché de frais ni
    /// compétition pour l'espace, cela n'achète rien aujourd'hui ; le jour où l'ordre
    /// aura de la valeur (MEV), ce critère devra changer.
    ///
    /// # La borne est portée par la CONSTRUCTION, pas seulement par le décodage
    ///
    /// Le mempool tient jusqu'à `CAPACITE_DEFAUT` (5 000) transactions, très au-delà
    /// de `MAX_TX_PAR_BLOC` (512). Sceller sans plafonner produisait un bloc
    /// localement valide, **indiffusable** (le cadre réseau le refuse) et
    /// **inacceptable par quiconque** (`from_bytes` rend `TropDeTransactions`) : le
    /// nœud avançait seul sur une chaîne que personne ne pouvait rejoindre, et l'état
    /// étant append-only, la partition était définitive.
    ///
    /// Règle générale qui en découle : **toute borne vérifiée dans `from_bytes` doit
    /// l'être aussi dans le constructeur**, sinon elle ne protège que l'entrant.
    ///
    /// Le surplus n'est pas perdu : il reste au mempool pour le bloc suivant.
    ///
    /// Retourne le bloc scellé et l'action de diffusion, ou `None` si le mempool ne
    /// contient rien à sceller.
    pub fn sceller(&mut self) -> Option<(Bloc, Vec<Action>)> {
        let mut digests = self.mempool.digests();
        if digests.is_empty() {
            return None;
        }
        digests.sort_unstable();
        digests.truncate(ledger::bloc::MAX_TX_PAR_BLOC);

        let transactions: Vec<circuit::ProvedTx> = digests
            .iter()
            .filter_map(|d| self.mempool.get(d))
            .filter_map(|tx| ProvedTx::from_bytes(&tx.to_bytes()).ok())
            .collect();
        if transactions.is_empty() {
            return None;
        }

        let bloc = Bloc::sceller(&self.etat.tete(), self.etat.hauteur() + 1, transactions);
        // On applique à NOTRE état avant de diffuser : diffuser un bloc qu'on n'a pas
        // su appliquer soi-même reviendrait à demander aux autres de nous croire.
        match self.etat.appliquer_bloc(&bloc) {
            Ok(_) => {
                for d in &digests {
                    self.mempool.retirer(d);
                }
                let octets = bloc.to_bytes();
                let copie = Bloc::from_bytes(&octets).ok()?;
                Some((bloc, vec![Action::Diffuser(Message::Bloc(Box::new(copie)))]))
            }
            // Notre propre mempool contenait une transaction devenue inapplicable
            // (état avancé entre-temps). On purge et on réessaiera au tour suivant.
            Err(_) => {
                self.mempool.purger(&self.etat);
                None
            }
        }
    }

    /// Un bloc arrive : on l'applique s'il prolonge NOTRE chaîne.
    ///
    /// Trois issues distinctes, et la distinction compte :
    ///
    /// - il s'enchaîne et s'applique → on purge le mempool et on relaie ;
    /// - il ne s'enchaîne pas (parent ou hauteur) → **aucune sanction** : c'est le cas
    ///   normal de deux nœuds qui scellent en même temps, ou d'un nœud en retard.
    ///   Pénaliser ici bannirait les pairs les plus actifs ;
    /// - il s'enchaîne mais contient une transaction invalide → **sanction lourde** :
    ///   nous a fait vérifier tout un bloc pour rien.
    fn sur_bloc(&mut self, de: PeerId, bloc: Bloc) -> Vec<Action> {
        match self.etat.appliquer_bloc(&bloc) {
            Ok(_) => {
                // Les transactions du bloc ne sont plus en attente ; celles qui sont
                // devenues inapplicables (double-dépense) partent avec la purge.
                for tx in &bloc.transactions {
                    self.mempool.retirer(&tx.tx_digest);
                }
                self.mempool.purger(&self.etat);
                match Bloc::from_bytes(&bloc.to_bytes()) {
                    Ok(copie) => vec![Action::Diffuser(Message::Bloc(Box::new(copie)))],
                    Err(_) => Vec::new(),
                }
            }
            Err(BlocRefus::Transaction { .. }) => {
                self.pairs.ajuster_score(&de, PENALITE_BLOC_INVALIDE);
                Vec::new()
            }
            // Chaînage : ni faute ni relais. Ne pas sanctionner est la bonne réponse
            // (deux scellements simultanés, ou un simple retard), et relayer un bloc
            // qu'on n'a pas appliqué propagerait une chaîne qu'on ne suit pas.
            //
            // ⚠️ MAIS on le COMPTE. Un nœud qui a manqué un bloc refuse ensuite tous
            // les suivants et reste figé indéfiniment ; sans ce compteur, rien ne le
            // distingue d'un nœud au repos. Le rattrapage de bloc (redemander la
            // hauteur manquante) reste à écrire — c'est un manque du protocole, pas
            // de cette fonction.
            Err(_) => {
                self.blocs_desaccordes += 1;
                Vec::new()
            }
        }
    }

    /// Un pair annonce des transactions : on ne demande QUE celles qu'on n'a pas.
    ///
    /// C'est ce filtre qui empêche la propagation de dégénérer en téléchargements
    /// redondants : sans lui, chaque annonce d'un pair déclencherait un transfert de
    /// 68 Kio même pour une transaction déjà connue.
    fn sur_annonce(&mut self, de: PeerId, digests: Vec<[u8; 64]>) -> Vec<Action> {
        let manquants: Vec<[u8; 64]> = digests
            .into_iter()
            .filter(|d| !self.mempool.contient(d))
            .collect();
        if manquants.is_empty() {
            return Vec::new();
        }
        vec![Action::Envoyer(de, Message::Demande(manquants))]
    }

    /// Un pair demande des transactions : on envoie celles qu'on possède, en
    /// ignorant silencieusement les autres (une demande pour une transaction qu'on
    /// a purgée entre-temps est légitime, pas malveillante).
    fn sur_demande(&mut self, de: PeerId, digests: Vec<[u8; 64]>) -> Vec<Action> {
        let mut actions = Vec::new();
        for d in digests {
            if let Some(tx) = self.mempool.get(&d) {
                match ProvedTx::from_bytes(&tx.to_bytes()) {
                    Ok(copie) => {
                        actions.push(Action::Envoyer(de, Message::Transaction(Box::new(copie))))
                    }
                    // Une transaction du mempool qui ne se ré-encode pas serait un bug
                    // interne, pas une attaque : on l'ignore plutôt que de paniquer.
                    Err(_) => continue,
                }
            }
        }
        actions
    }

    /// Une transaction arrive : admission (contrôles ordonnés par coût), puis
    /// routage Dandelion++ si elle est acceptée, ou sanction du pair sinon.
    fn sur_transaction(
        &mut self,
        de: PeerId,
        tx: ProvedTx,
        maintenant_ms: u64,
    ) -> Vec<Action> {
        let digest = tx.tx_digest;
        match self.mempool.admettre(&self.etat, tx) {
            Ok(()) => {
                // Nouvelle transaction : Dandelion++ décide tige ou floraison.
                match self.dandelion.router(&digest, maintenant_ms) {
                    Routage::Stem(vers) => self.relayer_en_tige(vers, &digest),
                    Routage::Fluff => vec![Action::Diffuser(Message::Annonce(vec![digest]))],
                }
            }
            Err(refus) => {
                // Ici seulement, l'asymétrie de coût devient une sanction.
                if refus.couteux() {
                    self.pairs.ajuster_score(&de, PENALITE_PREUVE_INVALIDE);
                }
                // Les refus bon marché (dont le doublon, cas NORMAL en gossip) ne
                // pénalisent pas : sanctionner un doublon bannirait les pairs
                // honnêtes les mieux connectés.
                Vec::new()
            }
        }
    }

    /// Relaie une transaction en phase TIGE : au successeur uniquement.
    fn relayer_en_tige(&self, vers: PeerId, digest: &[u8; 64]) -> Vec<Action> {
        match self.mempool.get(digest) {
            Some(tx) => match ProvedTx::from_bytes(&tx.to_bytes()) {
                Ok(copie) => vec![Action::Envoyer(vers, Message::Transaction(Box::new(copie)))],
                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        }
    }

    /// À appeler périodiquement : diffuse les transactions dont l'embargo a expiré.
    ///
    /// Sans cela, un successeur malveillant qui avale nos tiges les ferait
    /// disparaître silencieusement (*black-holing*).
    pub fn tick(&mut self, maintenant_ms: u64) -> Vec<Action> {
        let expirees = self.dandelion.embargos_expires(maintenant_ms);
        if expirees.is_empty() {
            return Vec::new();
        }
        vec![Action::Diffuser(Message::Annonce(expirees))]
    }

    /// Signale qu'une transaction a été revue sur le réseau : l'embargo tombe.
    pub fn transaction_revue(&mut self, digest: &[u8; 64]) {
        self.dandelion.transaction_revue(digest);
    }

    /// Pénalise un pair dont le message était indécodable.
    pub fn message_invalide(&mut self, de: &PeerId) {
        self.pairs.ajuster_score(de, PENALITE_MESSAGE_INVALIDE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net::pairs::SEUIL_BANNISSEMENT;
    use std::net::{Ipv4Addr, SocketAddr};

    fn noeud_de_test() -> Noeud {
        Noeud::new(
            SigKeypair::generate(),
            ProvedLedgerState::with_depth(4),
            [7u8; 32],
        )
    }

    fn pair(n: u8) -> (PeerId, SocketAddr) {
        let id = PeerId::depuis_identite(&SigKeypair::generate().public);
        (id, SocketAddr::from((Ipv4Addr::new(203, n, 113, 1), 8333)))
    }

    fn dg(n: u8) -> [u8; 64] {
        [n; 64]
    }

    /// Un nœud dont l'état contient deux notes émises, et une transaction valide
    /// contre cet état.
    #[cfg(test)]
    fn noeud_avec_transaction() -> (Noeud, ProvedTx) {
        use circuit::{prove_tx, ProvedInput, SpendNote};
        use ledger::proved_wallet::encrypt_note;
        use proved_hash::digest::{Digest, ShieldedSecret};
        use proved_hash::domain::Domain;
        use proved_hash::felt::Felt;
        use proved_hash::{merkle, rescue};

        let d = |seed: u64| {
            Digest(core::array::from_fn(|i| {
                Felt::from_canonical_u64(seed + i as u64).unwrap()
            }))
        };
        let secret = ShieldedSecret::from_felts(core::array::from_fn(|i| {
            Felt::from_canonical_u64(700 + i as u64).unwrap()
        }));
        let owner = rescue::hash(Domain::Owner, secret.as_felts());
        let n0 = SpendNote { value: 1_000, owner, rho: d(20), r: d(30) };
        let n1 = SpendNote { value: 500, owner, rho: d(40), r: d(50) };
        let cm0 = rescue::note_commitment(n0.value, &n0.owner, &n0.rho, &n0.r);
        let cm1 = rescue::note_commitment(n1.value, &n1.owner, &n1.rho, &n1.r);

        let mut noeud = noeud_de_test();
        let mut arbre = merkle::ProvedMerkleTree::new(4);
        let i0 = noeud.etat.mint(&cm0).unwrap();
        let i1 = noeud.etat.mint(&cm1).unwrap();
        arbre.append(&cm0);
        arbre.append(&cm1);

        let o0 = SpendNote { value: 900, owner: d(60), rho: d(61), r: d(62) };
        let o1 = SpendNote { value: 580, owner: d(70), rho: d(71), r: d(72) };
        let oc0 = rescue::note_commitment(o0.value, &o0.owner, &o0.rho, &o0.r);
        let oc1 = rescue::note_commitment(o1.value, &o1.owner, &o1.rho, &o1.r);
        let (r0, r1) = (crypto::kem::KemKeypair::generate(), crypto::kem::KemKeypair::generate());
        let enc = [encrypt_note(&r0.public, &oc0, &o0), encrypt_note(&r1.public, &oc1, &o1)];
        let inputs = [
            ProvedInput { note: n0, path: arbre.path(i0).unwrap(), index: i0 },
            ProvedInput { note: n1, path: arbre.path(i1).unwrap(), index: i1 },
        ];
        let intent = SigKeypair::generate();
        let (_root, tx) = prove_tx(&secret, inputs, [o0, o1], 20, &intent, enc);
        (noeud, tx)
    }

    /// Une transaction quelconque forcée au digest donné : sert à simuler un
    /// DOUBLON (même identifiant) sans avoir à cloner une `ProvedTx`.
    #[cfg(test)]
    fn transaction_au_digest(digest: [u8; 64]) -> ProvedTx {
        let (_n, mut tx) = noeud_avec_transaction();
        tx.tx_digest = digest;
        tx
    }

    /// Une annonce ne déclenche une demande QUE pour ce qu'on n'a pas.
    #[test]
    fn annonce_inconnue_declenche_une_demande() {
        let mut n = noeud_de_test();
        let (p, _) = pair(1);
        let actions = n.traiter(p, Message::Annonce(vec![dg(1), dg(2)]), 0);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::Envoyer(vers, Message::Demande(d)) => {
                assert_eq!(*vers, p);
                assert_eq!(d.len(), 2, "les deux sont inconnues");
            }
            _ => panic!("attendu une demande"),
        }
    }

    /// Une demande pour une transaction absente est ignorée SILENCIEUSEMENT — elle
    /// peut avoir été purgée entre l'annonce et la demande, ce qui est légitime.
    #[test]
    fn demande_inconnue_ignoree_sans_sanction() {
        let mut n = noeud_de_test();
        let (p, adr) = pair(1);
        n.pairs.ajouter(p, adr);
        let actions = n.traiter(p, Message::Demande(vec![dg(9)]), 0);
        assert!(actions.is_empty());
        assert_eq!(
            n.pairs.get(&p).unwrap().score,
            0,
            "une demande pour une tx purgée n'est PAS une faute"
        );
    }

    /// LE PIÈGE DU GOSSIP, sur de VRAIES transactions dupliquées.
    ///
    /// Recevoir plusieurs fois la même transaction est le cas NORMAL : plusieurs
    /// pairs l'annoncent légitimement. Pénaliser ces doublons bannirait les pairs
    /// honnêtes — et d'autant plus vite qu'ils sont bien connectés, donc utiles.
    ///
    /// Le test soumet une transaction DÉJÀ présente (même `tx_digest`) et exige que
    /// le score reste intact, même après de nombreuses répétitions.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
    fn doublon_de_transaction_ne_penalise_pas() {
        let (mut n, tx) = noeud_avec_transaction();
        let (p, adr) = pair(1);
        n.pairs.ajouter(p, adr);
        let digest = tx.tx_digest;

        // La transaction est déjà dans le mempool.
        assert!(n.mempool.admettre(&n.etat, tx).is_ok());

        // Un pair nous la renvoie 50 fois : refus BON MARCHÉ à chaque coup.
        for _ in 0..50 {
            let jumelle = transaction_au_digest(digest);
            let actions = n.traiter(p, Message::Transaction(Box::new(jumelle)), 0);
            assert!(actions.is_empty(), "un doublon ne déclenche aucun relais");
        }
        assert_eq!(
            n.pairs.get(&p).unwrap().score,
            0,
            "50 doublons ne doivent PAS pénaliser : c'est le cas normal du gossip"
        );
        assert!(!n.pairs.get(&p).unwrap().banni());
    }

    /// SCELLER vide le mempool dans l'état : c'est le chaînon qui manquait entre
    /// « la transaction est reçue » et « la transaction est définitive ».
    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
    fn sceller_finalise_les_transactions_du_mempool() {
        let (mut n, tx) = noeud_avec_transaction();
        let nf = tx.nullifiers[0];
        n.mempool.admettre(&n.etat, tx).expect("admission");
        assert_eq!(n.mempool.len(), 1);
        assert_eq!(n.etat.hauteur(), 0);

        let (bloc, actions) = n.sceller().expect("un bloc à sceller");
        assert_eq!(bloc.hauteur, 1);
        assert_eq!(n.etat.hauteur(), 1, "notre chaîne a avancé");
        assert_eq!(n.etat.tete(), bloc.id());
        assert!(n.etat.is_spent(&nf), "le nullifier est DÉFINITIVEMENT dépensé");
        assert_eq!(n.mempool.len(), 0, "la transaction n'est plus en attente");
        assert!(matches!(actions.as_slice(), [Action::Diffuser(Message::Bloc(_))]));
    }

    /// Un mempool vide ne produit pas de bloc : une chaîne au repos ne doit pas
    /// s'allonger de blocs vides que chaque nœud devrait ensuite propager.
    #[test]
    fn sceller_sans_rien_ne_produit_pas_de_bloc() {
        let mut n = noeud_de_test();
        assert!(n.sceller().is_none());
        assert_eq!(n.etat.hauteur(), 0);
    }

    /// Un bloc qui ne s'enchaîne PAS ne pénalise pas.
    ///
    /// C'est le cas NORMAL : deux nœuds scellent en même temps, ou nous sommes en
    /// retard. Sanctionner ici bannirait les pairs les plus actifs — la même erreur
    /// que pénaliser les doublons de gossip, dans un contexte où elle est plus facile
    /// encore à commettre.
    #[test]
    fn bloc_non_chaine_ne_penalise_pas() {
        let mut n = noeud_de_test();
        let (p, adr) = pair(1);
        n.pairs.ajouter(p, adr);

        let etranger = Bloc::sceller(&[9u8; 64], 1, Vec::new());
        let actions = n.traiter(p, Message::Bloc(Box::new(etranger)), 0);
        assert!(actions.is_empty(), "on ne relaie pas un bloc qu'on n'applique pas");
        assert_eq!(
            n.pairs.get(&p).unwrap().score,
            0,
            "un bloc concurrent ou en avance n'est PAS une faute"
        );
        assert_eq!(n.etat.hauteur(), 0, "notre chaîne n'a pas bougé");
    }

    /// Un bloc bien chaîné mais contenant une transaction invalide pénalise
    /// lourdement : il nous a fait vérifier tout un bloc pour rien.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
    fn bloc_a_transaction_invalide_penalise() {
        let (mut n, mut tx) = noeud_avec_transaction();
        // Un commitment de sortie falsifié invalide la preuve du monolithe.
        tx.output_commitments[0] = proved_hash::digest::Digest(core::array::from_fn(|i| {
            proved_hash::felt::Felt::from_canonical_u64(999_000 + i as u64).unwrap()
        }));
        let (p, adr) = pair(1);
        n.pairs.ajouter(p, adr);

        let bloc = Bloc::sceller(&n.etat.tete(), 1, vec![tx]);
        n.traiter(p, Message::Bloc(Box::new(bloc)), 0);
        assert_eq!(n.pairs.get(&p).unwrap().score, PENALITE_BLOC_INVALIDE);
        assert_eq!(n.etat.hauteur(), 0, "aucune trace du bloc refusé");
    }

    /// Un message indécodable pénalise — le pair ne parle pas le protocole.
    #[test]
    fn message_invalide_penalise() {
        let mut n = noeud_de_test();
        let (p, adr) = pair(1);
        n.pairs.ajouter(p, adr);
        n.message_invalide(&p);
        assert_eq!(n.pairs.get(&p).unwrap().score, PENALITE_MESSAGE_INVALIDE);
    }

    /// La pénalité de preuve invalide est calibrée pour BANNIR en quelques
    /// occurrences : faire brûler 4 ms de CPU à répétition est une attaque.
    #[test]
    fn penalite_preuve_invalide_bannit_en_quelques_coups() {
        let mut n = noeud_de_test();
        let (p, adr) = pair(1);
        n.pairs.ajouter(p, adr);
        for _ in 0..3 {
            n.pairs.ajuster_score(&p, PENALITE_PREUVE_INVALIDE);
        }
        assert!(
            n.pairs.get(&p).unwrap().banni(),
            "3 preuves invalides doivent suffire à bannir (3 × {PENALITE_PREUVE_INVALIDE} ≤ {SEUIL_BANNISSEMENT})"
        );
    }

    /// EMBARGO : le tick diffuse ce que le successeur n'a pas relayé.
    #[test]
    fn tick_diffuse_les_embargos_expires() {
        let mut n = noeud_de_test();
        for i in 0..8u8 {
            let (id, adr) = pair(i);
            n.pairs.ajouter(id, adr);
        }
        n.dandelion.nouvelle_epoque(1, &n.pairs);

        // Armer un embargo directement (le routage d'une vraie tx est testé ailleurs).
        let d = dg(42);
        if let Routage::Stem(_) = n.dandelion.router(&d, 1_000) {
            let actions = n.tick(1_000 + net::dandelion::EMBARGO_MS);
            assert_eq!(actions.len(), 1);
            match &actions[0] {
                Action::Diffuser(Message::Annonce(v)) => assert_eq!(v, &vec![d]),
                _ => panic!("attendu une diffusion"),
            }
        }
    }

    /// Rien à diffuser → aucune action (le tick ne doit pas générer de bruit).
    #[test]
    fn tick_sans_embargo_ne_produit_rien() {
        let mut n = noeud_de_test();
        assert!(n.tick(1_000_000).is_empty());
    }

    /// Une transaction revue lève l'embargo : pas de double diffusion.
    #[test]
    fn transaction_revue_annule_la_diffusion() {
        let mut n = noeud_de_test();
        for i in 0..8u8 {
            let (id, adr) = pair(i);
            n.pairs.ajouter(id, adr);
        }
        n.dandelion.nouvelle_epoque(1, &n.pairs);
        let d = dg(42);
        if let Routage::Stem(_) = n.dandelion.router(&d, 0) {
            n.transaction_revue(&d);
            assert!(
                n.tick(net::dandelion::EMBARGO_MS * 10).is_empty(),
                "une transaction revue ne doit pas être re-diffusée"
            );
        }
    }
}
