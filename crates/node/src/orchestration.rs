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

use crate::archive::ArchiveBlocs;
use crate::etranglement::Etrangleur;
use crate::message::Message;
use crate::synchro::ReponseHistorique;
use circuit::ProvedTx;
use crypto::sig::SigKeypair;
use ledger::bloc::Bloc;
use ledger::mempool::Mempool;
use ledger::proved_state::{BlocRefus, ProvedLedgerState};
use net::dandelion::{Dandelion, Routage};
use net::pairs::{GroupeReseau, PeerId, TablePairs};
use std::collections::HashMap;
use std::net::SocketAddr;

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
    /// distingue quand le rattrapage échoue (pair sans archive, fork réel).
    blocs_desaccordes: u64,
    /// Les N derniers blocs appliqués, pour SERVIR un pair qui rattrape.
    ///
    /// Bornée deux fois (nombre et octets) et distincte de l'état de consensus :
    /// voir [`crate::archive`].
    archive: ArchiveBlocs,
    /// Plus haute hauteur de bloc VUE sur le réseau, appliquée ou non.
    ///
    /// C'est le seul « je sais que je suis en retard » dont dispose le nœud, et il
    /// sert à savoir quand ARRÊTER de rattraper : sans lui, soit on redemande la
    /// hauteur suivante après chaque bloc appliqué (une demande inutile par bloc et
    /// par pair, à jamais), soit le rattrapage s'arrête au premier bloc rendu et un
    /// nœud en retard de trois blocs n'en récupère qu'un.
    ///
    /// ⚠️ Valeur NON vérifiée : un pair peut annoncer une hauteur mensongère. Le
    /// dégât est borné à une demande supplémentaire par bloc reçu — jamais une
    /// boucle, puisque seule l'arrivée d'un bloc peut déclencher une demande, et
    /// qu'un pair sans le bloc répond par le silence.
    hauteur_max_vue: u64,
    /// Adresse observée de chaque pair CONNECTÉ, dans les deux sens.
    ///
    /// Distincte de [`TablePairs`] à dessein. `pairs` sert la sélection SORTANTE
    /// anti-eclipse : y verser les pairs entrants les rendrait candidats à nos propres
    /// emplacements sortants, ce qui offrirait à un attaquant un moyen d'y entrer en
    /// nous appelant. Ici on ne veut qu'une chose : à quel GROUPE RÉSEAU imputer le
    /// coût d'une requête.
    ///
    /// Fail-closed : un pair dont l'adresse est inconnue n'est pas servi. Sans groupe,
    /// pas d'étranglement possible — et servir sans étrangler reviendrait à n'avoir
    /// rien écrit.
    adresses: HashMap<PeerId, SocketAddr>,
    /// Seaux à jetons du service d'historique, indexés sur le GROUPE RÉSEAU.
    etrangleur: Etrangleur,
}

/// Nombre maximal d'adresses de pairs mémorisées.
///
/// Le `PeerId` est gratuit : sans borne, une rotation d'identité par connexion ferait
/// croître cette table indéfiniment. Elle est de toute façon purgée à la déconnexion
/// ([`Noeud::oublier_adresse`]) ; la borne est là pour le cas où le nettoyage serait
/// manqué. À saturation, un pair de plus n'est simplement pas servi.
pub const MAX_ADRESSES_SUIVIES: usize = 4_096;

impl Noeud {
    pub fn new(identite: SigKeypair, etat: ProvedLedgerState, secret_dandelion: [u8; 32]) -> Self {
        let hauteur_max_vue = etat.hauteur();
        Noeud {
            identite,
            etat,
            mempool: Mempool::new(),
            pairs: TablePairs::new(),
            dandelion: Dandelion::new(secret_dandelion),
            blocs_desaccordes: 0,
            archive: ArchiveBlocs::new(),
            hauteur_max_vue,
            adresses: HashMap::new(),
            etrangleur: Etrangleur::new(),
        }
    }

    /// Mémorise l'adresse OBSERVÉE d'un pair connecté (entrant comme sortant).
    ///
    /// Appelée par le runtime au moment où le handshake réussit. C'est la seule source
    /// du groupe réseau auquel imputer le coût d'une demande d'historique : un pair
    /// dont l'adresse n'est pas connue ne sera pas servi.
    pub fn noter_adresse(&mut self, id: PeerId, adresse: SocketAddr) {
        if !self.adresses.contains_key(&id) && self.adresses.len() >= MAX_ADRESSES_SUIVIES {
            return;
        }
        self.adresses.insert(id, adresse);
    }

    /// Oublie l'adresse d'un pair déconnecté.
    pub fn oublier_adresse(&mut self, id: &PeerId) {
        self.adresses.remove(id);
    }

    /// Seaux du service d'historique (diagnostic et tests).
    pub fn etrangleur(&self) -> &Etrangleur {
        &self.etrangleur
    }

    /// Nombre de blocs refusés faute de s'enchaîner. Non nul et qui croît = ce nœud
    /// n'est PAS au repos, il est sur une autre chaîne ou il a manqué un bloc.
    pub fn blocs_desaccordes(&self) -> u64 {
        self.blocs_desaccordes
    }

    /// Archive des blocs récents — ce que ce nœud peut encore servir à un pair qui
    /// rattrape. Vide ne signifie pas fautif : l'archive est un service, pas une
    /// obligation de consensus.
    pub fn archive(&self) -> &ArchiveBlocs {
        &self.archive
    }

    /// Plus haute hauteur de bloc vue sur le réseau. Supérieure à
    /// `etat.hauteur()` = ce nœud se sait en retard et rattrape.
    pub fn hauteur_max_vue(&self) -> u64 {
        self.hauteur_max_vue
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
            Message::DemandeBloc { hauteur } => self.sur_demande_bloc(de, hauteur, maintenant_ms),
            Message::DemandeHistorique { hauteur } => {
                self.sur_demande_historique(de, hauteur, maintenant_ms)
            }
            // Une réponse d'historique arrivant chez un NŒUD : ignorée, sans sanction.
            //
            // Un nœud n'en demande jamais (c'est un message de wallet), mais en recevoir
            // une n'a rien d'anormal en soi — c'est ce que produirait une réponse
            // tardive après qu'un wallet a renoncé, ou un pair qui parle à la mauvaise
            // adresse. Sanctionner ici ferait payer un décalage de calendrier. Le coût
            // reste borné par le cadre réseau (1 Mio), déjà décodé à ce stade.
            Message::Historique(_) => Vec::new(),
        }
    }

    /// Scelle un bloc avec les transactions du mempool, l'applique, et le diffuse.
    ///
    /// # Qui a autorité pour faire cela dépend de la GENÈSE
    ///
    /// Sur une chaîne dont la genèse grave des AUTORITÉS, le producteur légitime de
    /// la hauteur `h` est `autorites[(h−1) mod n]` : ce nœud refuse de sceller hors
    /// de son tour (rien ne part) et SIGNE à son tour, de son identité persistante.
    ///
    /// Sur une chaîne OUVERTE (genèse sans autorités — le défaut), n'importe quel
    /// nœud peut sceller à n'importe quel moment. L'ordre qui en résulte est CONVENU
    /// entre participants coopératifs, pas DÉFENDU contre un adversaire : utilisable
    /// pour un testnet local, pas au delà.
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
        // ÉLECTION DE PRODUCTEUR : sur une chaîne à autorités, on ne scelle QUE si
        // la prochaine hauteur nous revient. Produire hors de son tour ne serait
        // même pas diffusable — chaque récepteur le refuse avant tout coût STARK —
        // donc on n'y brûle pas un cycle. Chaîne OUVERTE : comportement historique.
        let prochaine = self.etat.hauteur() + 1;
        // VUE 0 : J1-a ne livre pas le protocole de vue (c'est J1-b). Le nœud ne
        // produit donc que des blocs de vue 0, et n'en accepte pas d'autre tant que
        // rien ne fait avancer la vue.
        let vue = 0u32;
        let doit_signer = match self.etat.producteur_attendu(prochaine, vue) {
            Some(attendu) => {
                if attendu.to_bytes() != self.identite.public.to_bytes() {
                    return None;
                }
                true
            }
            None => false,
        };

        let mut digests = self.mempool.digests();
        if digests.is_empty() {
            return None;
        }
        digests.sort_unstable();

        // SÉLECTION SOUS DOUBLE BUDGET : nombre ET octets. Le second est le seul qui
        // garantisse un bloc DIFFUSABLE — à ≈68 Kio la transaction, la borne de 512
        // est atteinte des dizaines de fois après le cadre réseau. On s'arrête au
        // premier dépassement plutôt que de continuer à chercher plus petit : l'ordre
        // est celui du digest, le fausser ici rendrait deux nœuds divergents.
        let mut octets = ledger::bloc::SURCOUT_BLOC_VIDE;
        let mut transactions: Vec<circuit::ProvedTx> = Vec::new();
        let mut retenus: Vec<[u8; 64]> = Vec::new();
        for d in &digests {
            if transactions.len() >= ledger::bloc::MAX_TX_PAR_BLOC {
                break;
            }
            let Some(brute) = self.mempool.get(d) else {
                continue;
            };
            let o = brute.to_bytes();
            let cout = ledger::bloc::cout_transaction(o.len());
            if octets + cout > ledger::bloc::MAX_OCTETS_BLOC {
                break;
            }
            let Ok(tx) = ProvedTx::from_bytes(&o) else {
                continue;
            };
            octets += cout;
            transactions.push(tx);
            retenus.push(*d);
        }
        if transactions.is_empty() {
            return None;
        }
        // Seuls les RETENUS quittent le mempool : ce qui n'entrait pas dans ce bloc
        // doit rester candidat pour le suivant, sinon sceller PERDRAIT des paiements.
        let digests = retenus;

        let mut bloc =
            Bloc::sceller(&self.etat.tete(), self.etat.hauteur() + 1, transactions).ok()?;
        if doit_signer {
            bloc.signer_scellement(&self.identite);
            // NOTRE VOTE (ADR J1). Sans lui, on produirait un bloc que nous-mêmes
            // refuserions pour quorum insuffisant — et qu'aucun pair n'accepterait.
            //
            // ⚠️ À `n ≥ 4`, le quorum vaut `2f+1 ≥ 3` : notre seul vote NE SUFFIT
            // PAS, et `appliquer_bloc` juste en dessous rejettera le bloc. C'est le
            // comportement attendu de J1-a — rassembler les votes des autres est le
            // travail de J1-b. À `n ≤ 3` (`f = 0`, quorum 1), l'auto-vote suffit et
            // la chaîne avance.
            let index =
                ((self.etat.hauteur() + vue as u64) % self.etat.autorites().len() as u64) as usize;
            bloc.signer_vote(index, &self.identite);
        }
        // On applique à NOTRE état avant de diffuser : diffuser un bloc qu'on n'a pas
        // su appliquer soi-même reviendrait à demander aux autres de nous croire.
        match self.etat.appliquer_bloc(&bloc) {
            Ok(_) => {
                for d in &digests {
                    self.mempool.retirer(d);
                }
                // Un bloc que NOUS produisons n'est connu de personne : c'est celui
                // que des pairs en retard demanderont le plus probablement.
                self.archive.conserver(&bloc);
                self.hauteur_max_vue = self.hauteur_max_vue.max(bloc.hauteur);
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
    ///
    /// # Le chaînage impossible déclenche désormais un RATTRAPAGE
    ///
    /// Ne pas sanctionner restait juste ; se taire ne l'était pas. Un nœud ayant
    /// manqué une hauteur refusait ensuite tous les blocs, pour toujours, en servant
    /// un historique plus court mais parfaitement COHÉRENT — indiscernable d'un nœud
    /// à jour pour quiconque s'y synchronise.
    ///
    /// Le déclencheur est `bloc.hauteur > notre_hauteur + 1` : « ce bloc est en
    /// avance, il me manque au moins la hauteur suivante ». On demande alors la
    /// PREMIÈRE hauteur manquante, jamais celle du bloc reçu — sans le trou
    /// intermédiaire, ce bloc-là ne s'enchaînerait pas davantage.
    ///
    /// ## Pourquoi cela ne boucle pas entre deux nœuds désaccordés
    ///
    /// Trois propriétés le garantissent, et il faut les trois :
    ///
    /// 1. **Une demande ne naît que d'un bloc REÇU.** Recevoir une demande n'en
    ///    produit jamais une autre ; le silence est une réponse terminale.
    /// 2. **Le déclencheur est une inégalité STRICTE.** Deux nœuds à la même hauteur
    ///    sur des chaînes divergentes se refusent mutuellement leurs blocs
    ///    (`hauteur == notre_hauteur + 1`) sans jamais rien se demander.
    /// 3. **Un rattrapage qui échoue s'arrête au premier pas.** Si le pair sert un
    ///    bloc issu d'une AUTRE chaîne, ce bloc arrive exactement à la hauteur
    ///    attendue : il est refusé, l'inégalité stricte est fausse, aucune nouvelle
    ///    demande ne part.
    ///
    /// Le rattrapage progresse donc d'un bloc par échange, et s'éteint dès qu'un
    /// échange ne fait plus avancer la hauteur.
    fn sur_bloc(&mut self, de: PeerId, bloc: Bloc) -> Vec<Action> {
        // Enregistré AVANT toute décision : même un bloc refusé nous apprend qu'une
        // chaîne plus longue existe, et c'est précisément le cas où on en a besoin.
        self.hauteur_max_vue = self.hauteur_max_vue.max(bloc.hauteur);

        match self.etat.appliquer_bloc(&bloc) {
            Ok(_) => {
                // Les transactions du bloc ne sont plus en attente ; celles qui sont
                // devenues inapplicables (double-dépense) partent avec la purge.
                for tx in &bloc.transactions {
                    self.mempool.retirer(&tx.tx_digest);
                }
                self.mempool.purger(&self.etat);
                self.archive.conserver(&bloc);

                let mut actions = Vec::new();
                match Bloc::from_bytes(&bloc.to_bytes()) {
                    Ok(copie) => actions.push(Action::Diffuser(Message::Bloc(Box::new(copie)))),
                    Err(_) => return actions,
                }
                // Toujours en retard après ce bloc : on enchaîne sur la hauteur
                // suivante, auprès du pair qui vient de nous prouver qu'il l'a. Sans
                // cet enchaînement, un nœud en retard de trois blocs n'en
                // récupérerait qu'un par bloc neuf diffusé sur le réseau.
                if let Some(demande) = self.demander_suivant(de) {
                    actions.push(demande);
                }
                actions
            }
            // Des fautes NON ÉQUIVOQUES, sanctionnées de la même façon :
            //
            // - une transaction invalide nous a fait vérifier tout un bloc pour rien ;
            // - une ÉMISSION (ou des AUTORITÉS) hors genèse est une tentative de
            //   réécrire les règles de la chaîne — aucune lecture innocente ;
            // - un SCELLEMENT manquant, hors tour ou étranger viole l'élection de
            //   producteur : le bloc est refusé À TOUTE hauteur par tout nœud de
            //   cette chaîne, ce n'est jamais le cas normal d'un retard. (Le refus
            //   de scellement tombe APRÈS le chaînage dans `appliquer_bloc` : un
            //   bloc d'une autre chaîne rend `ParentInattendu`, sans sanction.)
            Err(BlocRefus::Transaction { .. })
            | Err(BlocRefus::EmissionHorsGenese { .. })
            | Err(BlocRefus::AutoritesHorsGenese { .. })
            | Err(BlocRefus::ScellementManquant { .. })
            | Err(BlocRefus::ScellementInvalide { .. })
            | Err(BlocRefus::ScellementInattendu) => {
                self.pairs.ajuster_score(&de, PENALITE_BLOC_INVALIDE);
                Vec::new()
            }
            // Chaînage : ni faute ni relais. Ne pas sanctionner est la bonne réponse
            // (deux scellements simultanés, ou un simple retard), et relayer un bloc
            // qu'on n'a pas appliqué propagerait une chaîne qu'on ne suit pas.
            //
            // `HauteurInattendue` et `ParentInattendu` sont traités ensemble à
            // dessein : `appliquer_bloc` teste le parent EN PREMIER, si bien qu'un
            // bloc en avance rend `ParentInattendu` et non `HauteurInattendue`. Se
            // fier au seul variant d'erreur laisserait le cas le plus courant du
            // retard sans rattrapage. On tranche sur les hauteurs, qui sont la même
            // information dans les deux cas.
            Err(refus) => {
                self.blocs_desaccordes += 1;
                let recue = match refus {
                    BlocRefus::HauteurInattendue { recue, .. } => recue,
                    _ => bloc.hauteur,
                };
                if recue > self.etat.hauteur().saturating_add(1) {
                    if let Some(demande) = self.demander_suivant(de) {
                        return vec![demande];
                    }
                }
                Vec::new()
            }
        }
    }

    /// Demande à `de` la PREMIÈRE hauteur qui nous manque, si nous nous savons en
    /// retard. `None` sinon — ne rien demander est le cas normal.
    fn demander_suivant(&self, de: PeerId) -> Option<Action> {
        let suivante = self.etat.hauteur().saturating_add(1);
        if self.hauteur_max_vue < suivante {
            return None;
        }
        Some(Action::Envoyer(
            de,
            Message::DemandeBloc { hauteur: suivante },
        ))
    }

    /// Un pair demande un bloc : on le sert si on l'a ARCHIVÉ, silence sinon.
    ///
    /// Le silence, pas une erreur : exactement comme une demande de transaction
    /// purgée entre l'annonce et la demande (`sur_demande`). Une hauteur peut être
    /// hors de notre archive bornée, ou n'exister sur aucune chaîne — dans les deux
    /// cas, celui qui demande n'a commis aucune faute et ne doit pas être pénalisé.
    /// Pénaliser rendrait le rattrapage plus dangereux que l'immobilité.
    ///
    /// L'archive ne contient que des blocs que NOUS avons appliqués : servir depuis
    /// elle ne peut pas propager une chaîne que nous ne suivons pas.
    ///
    /// ⚠️ Servir un bloc de ~34 Kio à ~1 Mio pour une demande de 9 octets est une
    /// asymétrie d'AMPLIFICATION. Elle est ÉTRANGLÉE par le même seau à jetons,
    /// indexé sur `GroupeReseau`, que le service d'historique — voir le corps de la
    /// fonction et docs/THREAT_MODEL.md.
    fn sur_demande_bloc(&mut self, de: PeerId, hauteur: u64, maintenant_ms: u64) -> Vec<Action> {
        // MÊME étranglement que le service d'historique, même seau : une DemandeBloc
        // de 9 octets fait renvoyer jusqu'à ~1 Mio — c'était la seule amplification
        // non étranglée du chemin réseau. Fail-closed (sans adresse, pas de groupe,
        // donc silence), et le silence d'un crédit épuisé reste indistinguable des
        // autres silences — un refus distinct ferait du crédit une information.
        let Some(adresse) = self.adresses.get(&de).copied() else {
            return Vec::new();
        };
        if !self
            .etrangleur
            .autoriser(GroupeReseau::de(&adresse), maintenant_ms)
        {
            return Vec::new();
        }
        match self.archive.octets_a(hauteur) {
            // On re-décode plutôt que de garder un `Bloc` : les octets archivés sont
            // la source de vérité, et un décodage qui échouerait signalerait une
            // corruption chez nous — pas une faute du demandeur.
            Some(octets) => match Bloc::from_bytes(octets) {
                Ok(copie) => vec![Action::Envoyer(de, Message::Bloc(Box::new(copie)))],
                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        }
    }

    /// Un wallet demande les sorties d'une hauteur : on les sert, ou on se TAIT.
    ///
    /// # Aucune sanction, jamais
    ///
    /// Demander son historique est un comportement NORMAL — c'est même la seule façon
    /// pour un wallet de pouvoir recevoir de la monnaie. Pénaliser un demandeur
    /// rendrait la synchronisation plus risquée que l'immobilité, et comme le score
    /// gouverne la sélection sortante, cela reviendrait à dégrader notre propre
    /// anti-eclipse à chaque wallet qui se connecte.
    ///
    /// Toutes les issues négatives sont donc le SILENCE, indistinguables entre elles :
    /// pas d'archive, hauteur inconnue, hauteur absurde, crédit épuisé, adresse
    /// inconnue. Un refus qui se distinguerait ferait du crédit — et de la présence
    /// d'une hauteur — une information sondable.
    ///
    /// # L'étranglement s'indexe sur le GROUPE RÉSEAU
    ///
    /// Jamais sur le `PeerId` : il est gratuit, et le wallet en tire un neuf à chaque
    /// commande. Un seau par pair ne défendrait rien et grossirait sans fin. Le coût
    /// FIXE de la requête est débité AVANT de savoir s'il y a quelque chose à servir —
    /// une réponse vide n'est pas gratuite (allocation, cascade AEAD, écriture, flush).
    ///
    /// # Une demande, plusieurs messages
    ///
    /// Un bloc plein pèse ≈1,4 Mio, au-delà du cadre réseau. Le découpage est décidé
    /// ICI, par le serveur, et jamais demandé par le client (cf. [`crate::synchro`]).
    ///
    /// # ⚠️ Ce que servir l'historique révèle, et ne révèle pas
    ///
    /// Le nœud apprend l'IP du wallet, sa cadence et sa position de chaîne, et il peut
    /// **mentir par omission** : taire une sortie rend le paiement invisible, laisse la
    /// racine intacte, et rien ne l'attrape. Il ne peut en revanche ni fabriquer de
    /// crédit (les commitments sont liés au bloc, donc à `Bloc::id()`) ni apprendre
    /// quelles notes sont celles du demandeur — le balayage est LOCAL au wallet.
    fn sur_demande_historique(
        &mut self,
        de: PeerId,
        hauteur: u64,
        maintenant_ms: u64,
    ) -> Vec<Action> {
        // Fail-closed : sans adresse, aucun groupe réseau, donc aucun étranglement
        // possible. Servir quand même reviendrait à offrir un contournement à qui
        // saurait se faire oublier de la table.
        let Some(adresse) = self.adresses.get(&de).copied() else {
            return Vec::new();
        };
        let groupe = GroupeReseau::de(&adresse);
        if !self.etrangleur.autoriser(groupe, maintenant_ms) {
            return Vec::new();
        }

        // La hauteur vient du RÉSEAU : `tranche` et `sorties_du_bloc` la ramènent dans
        // le repère local par `checked_sub` + `usize::try_from` + `get(..)`, jamais par
        // indexation. `u64::MAX` y vaut `None`, comme n'importe quelle hauteur absente.
        let (morceaux, servies) = {
            let Some(h) = self.etat.historique() else {
                return Vec::new();
            };
            let (Some(tranche), Some(sorties)) = (h.tranche(hauteur), h.sorties_du_bloc(hauteur))
            else {
                return Vec::new();
            };
            // La tête ANNONCÉE est celle qu'on peut réellement servir, pas
            // `etat.hauteur()` : promettre une hauteur qu'on n'archive pas ferait
            // boucler le wallet sur une demande éternellement silencieuse.
            let tete = h.hauteur_max().unwrap_or(tranche.hauteur);
            match ReponseHistorique::decouper(tranche, sorties, tete) {
                Some(m) => (m, sorties.len() as u64),
                None => return Vec::new(),
            }
        };

        // Coût VARIABLE, en plus du coût fixe déjà débité.
        self.etrangleur.debiter(groupe, servies);
        morceaux
            .into_iter()
            .map(|r| Action::Envoyer(de, Message::Historique(Box::new(r))))
            .collect()
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
    fn sur_transaction(&mut self, de: PeerId, tx: ProvedTx, maintenant_ms: u64) -> Vec<Action> {
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
        noeud_avec_transaction_param(SigKeypair::generate(), Vec::new())
    }

    /// Idem, en choisissant l'IDENTITÉ du nœud et les AUTORITÉS de la genèse —
    /// c'est ce qui permet d'exercer l'élection de producteur avec un mempool
    /// réellement garni.
    #[cfg(test)]
    fn noeud_avec_transaction_param(
        identite: SigKeypair,
        autorites: Vec<crypto::sig::SigPublicKey>,
    ) -> (Noeud, ProvedTx) {
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
        let n0 = SpendNote {
            value: 1_000,
            owner,
            rho: d(20),
            r: d(30),
        };
        let n1 = SpendNote {
            value: 500,
            owner,
            rho: d(40),
            r: d(50),
        };
        let cm0 = rescue::note_commitment(n0.value, &n0.owner, &n0.rho, &n0.r);
        let cm1 = rescue::note_commitment(n1.value, &n1.owner, &n1.rho, &n1.r);

        // La monnaie n'existe QUE par la genèse — le nœud est amorcé dessus, il ne
        // peut plus rien créer ensuite.
        let genese = ledger::bloc::Bloc::genese_avec_autorites(
            vec![
                ledger::proved_wallet::emission_factice(&cm0),
                ledger::proved_wallet::emission_factice(&cm1),
            ],
            autorites,
        )
        .expect("genèse bornée");
        let noeud = Noeud::new(
            identite,
            ProvedLedgerState::depuis_genese_depth(&genese, 4).expect("amorçage"),
            [7u8; 32],
        );
        let mut arbre = merkle::ProvedMerkleTree::new(4);
        arbre.append(&cm0);
        arbre.append(&cm1);
        let (i0, i1) = (0u64, 1u64);

        let o0 = SpendNote {
            value: 900,
            owner: d(60),
            rho: d(61),
            r: d(62),
        };
        let o1 = SpendNote {
            value: 580,
            owner: d(70),
            rho: d(71),
            r: d(72),
        };
        let oc0 = rescue::note_commitment(o0.value, &o0.owner, &o0.rho, &o0.r);
        let oc1 = rescue::note_commitment(o1.value, &o1.owner, &o1.rho, &o1.r);
        let (r0, r1) = (
            crypto::kem::KemKeypair::generate(),
            crypto::kem::KemKeypair::generate(),
        );
        let enc = [
            encrypt_note(&r0.public, &oc0, &o0).unwrap(),
            encrypt_note(&r1.public, &oc1, &o1).unwrap(),
        ];
        let inputs = [
            ProvedInput {
                note: n0,
                path: arbre.path(i0).unwrap(),
                index: i0,
            },
            ProvedInput {
                note: n1,
                path: arbre.path(i1).unwrap(),
                index: i1,
            },
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

    /// INVARIANT DE DIFFUSION : un bloc que NOUS scellons doit tenir dans un cadre
    /// réseau, tel qu'il partira sur le fil — `Message::Bloc` (tag applicatif) PUIS
    /// chiffré (le cadre borne le CHIFFRÉ, cf. `crypto::aead::SURCOUT`). Sans le
    /// plafond d'octets, un mempool chargé produirait un bloc localement valide que
    /// personne ne pourrait recevoir — partition définitive. La première version de
    /// ce test mesurait le message EN CLAIR : à la borne, les 68 octets de la
    /// cascade suffisaient à rendre le bloc indiffusable sans qu'aucun test rougisse.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
    fn un_bloc_scelle_tient_toujours_dans_un_cadre_reseau() {
        let (mut n, tx) = noeud_avec_transaction();
        n.mempool.admettre(&n.etat, tx).expect("admission");
        let (bloc, _) = n.sceller().expect("un bloc à sceller");
        let sur_le_fil = crate::message::Message::Bloc(Box::new(bloc)).to_bytes();
        assert!(
            sur_le_fil.len() + crypto::aead::SURCOUT <= net::MAX_CADRE,
            "bloc de {} o chiffrés sur le fil : au-delà du cadre de {} o",
            sur_le_fil.len() + crypto::aead::SURCOUT,
            net::MAX_CADRE
        );
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
        assert!(
            n.etat.is_spent(&nf),
            "le nullifier est DÉFINITIVEMENT dépensé"
        );
        assert_eq!(n.mempool.len(), 0, "la transaction n'est plus en attente");
        assert!(matches!(
            actions.as_slice(),
            [Action::Diffuser(Message::Bloc(_))]
        ));
    }

    /// Un mempool vide ne produit pas de bloc : une chaîne au repos ne doit pas
    /// s'allonger de blocs vides que chaque nœud devrait ensuite propager.
    #[test]
    fn sceller_sans_rien_ne_produit_pas_de_bloc() {
        let mut n = noeud_de_test();
        assert!(n.sceller().is_none());
        assert_eq!(n.etat.hauteur(), 0);
    }

    /// ÉLECTION : sur une chaîne à autorités, un bloc mal scellé est une FAUTE non
    /// équivoque (contrairement au bloc non chaîné) — sanctionnée comme une
    /// transaction invalide.
    #[test]
    fn bloc_mal_scelle_penalise() {
        // Autorités [nous, autre] : la hauteur 1 revient à `nous`.
        let nous = SigKeypair::generate();
        let autre = SigKeypair::generate();
        let genese = ledger::bloc::Bloc::genese_avec_autorites(
            Vec::new(),
            vec![nous.public.clone(), autre.public.clone()],
        )
        .unwrap();
        let mut n = Noeud::new(
            nous,
            ProvedLedgerState::depuis_genese_depth(&genese, 4).unwrap(),
            [7u8; 32],
        );
        let (p, adr) = pair(1);
        n.pairs.ajouter(p, adr);

        // Sans scellement : refusé, sanctionné, jamais relayé.
        let nu = ledger::bloc::Bloc::sceller(&n.etat.tete(), 1, Vec::new()).unwrap();
        assert!(n.traiter(p, Message::Bloc(Box::new(nu)), 0).is_empty());
        assert_eq!(n.pairs.get(&p).unwrap().score, PENALITE_BLOC_INVALIDE);

        // HORS TOUR : signé par `autre` alors que la hauteur 1 revient à `nous`.
        let mut hors_tour = ledger::bloc::Bloc::sceller(&n.etat.tete(), 1, Vec::new()).unwrap();
        hors_tour.signer_scellement(&autre);
        assert!(n
            .traiter(p, Message::Bloc(Box::new(hors_tour)), 0)
            .is_empty());
        assert_eq!(n.pairs.get(&p).unwrap().score, 2 * PENALITE_BLOC_INVALIDE);
        assert_eq!(n.etat.hauteur(), 0, "aucun des deux blocs n'est passé");
    }

    /// Chaîne OUVERTE : un scellement n'y a aucun sens — refusé et sanctionné
    /// (deux encodages valides du même bloc casseraient la canonicité).
    #[test]
    fn scellement_sur_chaine_ouverte_penalise() {
        let mut n = noeud_de_test();
        let (p, adr) = pair(1);
        n.pairs.ajouter(p, adr);
        let mut signe = ledger::bloc::Bloc::sceller(&n.etat.tete(), 1, Vec::new()).unwrap();
        signe.signer_scellement(&SigKeypair::generate());
        assert!(n.traiter(p, Message::Bloc(Box::new(signe)), 0).is_empty());
        assert_eq!(n.pairs.get(&p).unwrap().score, PENALITE_BLOC_INVALIDE);
    }

    /// ÉLECTION : hors de son tour, `sceller` ne produit RIEN — pas même un octet
    /// diffusable — et le mempool reste intact pour le producteur légitime.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
    fn sceller_refuse_hors_de_son_tour() {
        let nous = SigKeypair::generate();
        let nous_pub = nous.public.clone();
        let autre_pub = SigKeypair::generate().public;
        // La hauteur 1 revient à `autre` : PAS notre tour.
        let (mut n, tx) = noeud_avec_transaction_param(nous, vec![autre_pub, nous_pub]);
        n.mempool.admettre(&n.etat, tx).expect("admission");
        assert!(n.sceller().is_none(), "hors tour : aucun bloc");
        assert_eq!(n.etat.hauteur(), 0);
        assert_eq!(n.mempool.len(), 1, "la transaction reste candidate");
    }

    /// ÉLECTION : à son tour, `sceller` SIGNE — et le bloc diffusé porte le
    /// scellement (il doit survivre au réencodage wire).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
    fn sceller_signe_a_son_tour() {
        let nous = SigKeypair::generate();
        let nous_pub = nous.public.clone();
        let autre_pub = SigKeypair::generate().public;
        // La hauteur 1 nous revient.
        let (mut n, tx) = noeud_avec_transaction_param(nous, vec![nous_pub.clone(), autre_pub]);
        n.mempool.admettre(&n.etat, tx).expect("admission");

        let (bloc, actions) = n.sceller().expect("notre tour : un bloc");
        assert!(bloc.verifier_scellement(&nous_pub), "scellé par nous");
        assert_eq!(n.etat.hauteur(), 1, "appliqué à notre propre état");
        match actions.as_slice() {
            [Action::Diffuser(Message::Bloc(b))] => {
                assert!(
                    b.verifier_scellement(&nous_pub),
                    "le scellement doit survivre au réencodage wire"
                );
            }
            autres => panic!("diffusion attendue, reçu {} actions", autres.len()),
        }
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

        let etranger = Bloc::sceller(&[9u8; 64], 1, Vec::new()).unwrap();
        let actions = n.traiter(p, Message::Bloc(Box::new(etranger)), 0);
        assert!(
            actions.is_empty(),
            "on ne relaie pas un bloc qu'on n'applique pas"
        );
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

        let bloc = Bloc::sceller(&n.etat.tete(), 1, vec![tx]).unwrap();
        n.traiter(p, Message::Bloc(Box::new(bloc)), 0);
        assert_eq!(n.pairs.get(&p).unwrap().score, PENALITE_BLOC_INVALIDE);
        assert_eq!(n.etat.hauteur(), 0, "aucune trace du bloc refusé");
    }

    /// UN BLOC QUI ÉMET DE LA MONNAIE EST REFUSÉ **ET** SANCTIONNÉ.
    ///
    /// La distinction avec le bloc non chaîné est tout l'enjeu : être en retard ou
    /// sceller en même temps qu'un autre n'est la faute de personne, alors qu'une
    /// émission hors genèse n'a aucune lecture innocente — aucun bloc valide n'en
    /// contient, à aucune hauteur. Ne pas sanctionner ici rendrait la tentative
    /// d'inflation gratuite et répétable à l'infini.
    #[test]
    fn bloc_avec_emission_refuse_et_penalise() {
        let mut n = noeud_de_test();
        let (p, adr) = pair(1);
        n.pairs.ajouter(p, adr);

        // Bien chaîné, bien numéroté — seule l'émission cloche.
        let mut inflation = Bloc::sceller(&n.etat.tete(), 1, Vec::new()).unwrap();
        inflation.emissions = vec![ledger::proved_wallet::emission_factice(
            &proved_hash::digest::Digest(core::array::from_fn(|i| {
                proved_hash::felt::Felt::from_canonical_u64(1_000 + i as u64).unwrap()
            })),
        )];

        let actions = n.traiter(p, Message::Bloc(Box::new(inflation)), 0);
        assert!(actions.is_empty(), "un bloc refusé n'est jamais relayé");
        assert_eq!(n.etat.hauteur(), 0, "aucune monnaie créée");
        assert_eq!(
            n.pairs.get(&p).unwrap().score,
            PENALITE_BLOC_INVALIDE,
            "émettre hors genèse doit coûter au pair : sinon l'essai est gratuit"
        );
        assert_eq!(
            n.blocs_desaccordes(),
            0,
            "ce n'est PAS un désaccord de chaîne : le compteur qui signale un nœud \
             figé ne doit pas être pollué par des blocs frauduleux"
        );
    }

    /// UN BLOC EN AVANCE DÉCLENCHE UNE DEMANDE DE RATTRAPAGE — et aucune sanction.
    ///
    /// C'est la réparation du défaut structurel : jusqu'ici un nœud ayant manqué une
    /// hauteur refusait tous les blocs suivants pour toujours, en servant un
    /// historique plus court mais parfaitement cohérent. La demande porte la PREMIÈRE
    /// hauteur manquante et non celle du bloc reçu : demander la seconde ne servirait
    /// à rien, elle ne s'enchaînerait pas davantage.
    #[test]
    fn bloc_en_avance_declenche_une_demande_de_rattrapage() {
        let mut n = noeud_de_test();
        let (p, adr) = pair(1);
        n.pairs.ajouter(p, adr);

        // Nous sommes à la hauteur 0 ; un pair diffuse un bloc de hauteur 4.
        let avance = Bloc::sceller(&[9u8; 64], 4, Vec::new()).unwrap();
        let actions = n.traiter(p, Message::Bloc(Box::new(avance)), 0);
        match actions.as_slice() {
            [Action::Envoyer(vers, Message::DemandeBloc { hauteur })] => {
                assert_eq!(*vers, p);
                assert_eq!(*hauteur, 1, "la PREMIÈRE hauteur manquante, pas la reçue");
            }
            _ => panic!("attendu une demande de bloc"),
        }
        assert_eq!(
            n.pairs.get(&p).unwrap().score,
            0,
            "être en retard n'est la faute de personne"
        );
        assert_eq!(n.blocs_desaccordes(), 1, "le désaccord reste visible");
        assert_eq!(n.hauteur_max_vue(), 4, "on se sait en retard de 4");
    }

    /// PAS DE BOUCLE entre deux nœuds désaccordés à la MÊME hauteur.
    ///
    /// C'est le cas normal de deux scellements simultanés. Le déclencheur est une
    /// inégalité STRICTE (`recue > attendue`) précisément pour cela : si un bloc
    /// concurrent déclenchait une demande, les deux nœuds se demanderaient
    /// mutuellement des blocs à chaque échange, sans que rien ne s'applique jamais —
    /// un amplificateur de trafic construit par nos propres soins.
    #[test]
    fn bloc_concurrent_a_la_meme_hauteur_ne_demande_rien() {
        let mut n = noeud_de_test();
        let (p, adr) = pair(1);
        n.pairs.ajouter(p, adr);

        // Hauteur 1 = exactement celle qu'on attend, mais chaîné ailleurs.
        let concurrent = Bloc::sceller(&[9u8; 64], 1, Vec::new()).unwrap();
        let actions = n.traiter(p, Message::Bloc(Box::new(concurrent)), 0);
        assert!(
            actions.is_empty(),
            "un bloc concurrent ne doit RIEN déclencher : ni relais, ni demande"
        );
        assert_eq!(n.pairs.get(&p).unwrap().score, 0);
    }

    /// UN RATTRAPAGE QUI ÉCHOUE S'ARRÊTE AU PREMIER PAS.
    ///
    /// Le pire cas de boucle : nous demandons la hauteur manquante, le pair sert un
    /// bloc issu d'une AUTRE chaîne. Ce bloc arrive à la hauteur attendue, l'inégalité
    /// stricte est fausse, et aucune nouvelle demande ne part. Le nœud reste figé —
    /// ce qui est honnête — mais il ne saigne pas de bande passante.
    #[test]
    fn un_rattrapage_infructueux_ne_relance_pas_de_demande() {
        let mut n = noeud_de_test();
        let (p, adr) = pair(1);
        n.pairs.ajouter(p, adr);

        // 1er échange : bloc en avance → une demande part.
        let avance = Bloc::sceller(&[9u8; 64], 5, Vec::new()).unwrap();
        assert_eq!(n.traiter(p, Message::Bloc(Box::new(avance)), 0).len(), 1);

        // 2e échange : le pair sert la hauteur 1… d'une chaîne qui n'est pas la
        // nôtre. Elle est refusée, et surtout elle ne relance rien.
        for _ in 0..5 {
            let reponse = Bloc::sceller(&[9u8; 64], 1, Vec::new()).unwrap();
            let actions = n.traiter(p, Message::Bloc(Box::new(reponse)), 0);
            assert!(actions.is_empty(), "aucune demande ne doit repartir");
        }
        assert_eq!(n.etat.hauteur(), 0, "toujours figé, mais silencieux");
        assert_eq!(n.pairs.get(&p).unwrap().score, 0);
    }

    /// Une demande pour une hauteur INCONNUE : ni réponse, ni sanction.
    ///
    /// Même règle que pour une transaction purgée. L'archive est bornée : une hauteur
    /// trop ancienne, ou d'une chaîne qu'on ne suit pas, est un cas légitime. La
    /// pénaliser rendrait le rattrapage plus risqué que l'immobilité, ce qui
    /// détruirait l'intérêt même de l'avoir écrit.
    #[test]
    fn demande_de_bloc_inconnue_ni_reponse_ni_sanction() {
        let mut n = noeud_de_test();
        let (p, adr) = pair(1);
        n.pairs.ajouter(p, adr);
        for h in [0u64, 1, 999, u64::MAX] {
            let actions = n.traiter(p, Message::DemandeBloc { hauteur: h }, 0);
            assert!(actions.is_empty(), "hauteur {h} : silence attendu");
        }
        assert_eq!(
            n.pairs.get(&p).unwrap().score,
            0,
            "demander une hauteur qu'on n'a pas n'est PAS une faute"
        );
    }

    /// Une demande N'ENGENDRE JAMAIS une demande — la propriété qui ferme la boucle.
    ///
    /// Le rattrapage n'a qu'une seule source : l'arrivée d'un BLOC. Si servir une
    /// demande pouvait en produire une autre, deux nœuds se renverraient des demandes
    /// indéfiniment. Ici on sert un vrai bloc archivé et on exige que la seule action
    /// produite soit l'envoi de ce bloc.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
    fn servir_une_demande_ne_produit_quun_bloc() {
        let (mut n, tx) = noeud_avec_transaction();
        let (p, adr) = pair(1);
        n.pairs.ajouter(p, adr);
        // Le service de blocs est désormais étranglé comme celui d'historique :
        // fail-closed, un pair sans adresse observée n'est pas servi.
        n.noter_adresse(p, adr);
        n.mempool.admettre(&n.etat, tx).expect("admission");
        let (bloc, _) = n.sceller().expect("bloc");

        let actions = n.traiter(p, Message::DemandeBloc { hauteur: 1 }, 0);
        match actions.as_slice() {
            [Action::Envoyer(vers, Message::Bloc(servi))] => {
                assert_eq!(*vers, p);
                assert_eq!(servi.id(), bloc.id(), "le bloc servi est bien le nôtre");
            }
            _ => panic!("attendu exactement l'envoi du bloc demandé"),
        }
    }

    /// Un bloc SCELLÉ localement entre à l'archive : c'est celui que personne d'autre
    /// n'a, donc le plus susceptible d'être redemandé. S'il n'y entrait pas, le nœud
    /// qui produit les blocs serait précisément celui incapable de les re-servir.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
    fn sceller_alimente_larchive() {
        let (mut n, tx) = noeud_avec_transaction();
        assert!(n.archive().is_empty());
        n.mempool.admettre(&n.etat, tx).expect("admission");
        let (bloc, _) = n.sceller().expect("bloc");
        assert_eq!(n.archive().len(), 1);
        let servi = Bloc::from_bytes(n.archive().octets_a(1).expect("hauteur 1")).unwrap();
        assert_eq!(servi.id(), bloc.id());
    }

    // ================================================================================
    // Service d'HISTORIQUE (synchronisation du wallet).
    // ================================================================================

    /// Nombre de sorties d'une genèse de test. Choisi assez grand pour que le coût
    /// variable domine le coût fixe (l'étranglement doit se voir en quelques dizaines
    /// de requêtes) et assez petit pour rester sous `MAX_SORTIES_PAR_REPONSE` : une
    /// genèse est plafonnée à `MAX_EMISSIONS_PAR_BLOC` (512), donc elle ne peut PAS
    /// produire un bloc à plusieurs morceaux. Le découpage est éprouvé à son niveau, sur
    /// le format de fil (`crate::synchro::le_decoupage_couvre_exactement_le_bloc`) —
    /// l'atteindre ici exigerait ≈370 preuves STARK.
    const SORTIES_DE_GENESE: usize = 64;

    /// Un nœud ARCHIVISTE, amorcé sur une genèse de [`SORTIES_DE_GENESE`] émissions.
    fn noeud_archiviste() -> Noeud {
        let cm = |n: u64| {
            proved_hash::digest::Digest(core::array::from_fn(|i| {
                proved_hash::felt::Felt::from_canonical_u64(1_000 + n * 64 + i as u64).unwrap()
            }))
        };
        let emissions = (0..SORTIES_DE_GENESE as u64)
            .map(|n| ledger::proved_wallet::emission_factice(&cm(n)))
            .collect();
        let genese = Bloc::genese_avec(emissions).expect("genèse bornée");
        Noeud::new(
            SigKeypair::generate(),
            ProvedLedgerState::depuis_genese_depth_archivant(&genese, 10).expect("amorçage"),
            [7u8; 32],
        )
    }

    /// Un pair connecté, dont l'adresse est notée comme le ferait le runtime.
    fn pair_connecte(n: &mut Noeud, a: u8, b: u8, c: u8, d: u8) -> PeerId {
        let id = PeerId::depuis_identite(&SigKeypair::generate().public);
        let adresse = SocketAddr::from((Ipv4Addr::new(a, b, c, d), 8333));
        n.pairs.ajouter(id, adresse);
        n.noter_adresse(id, adresse);
        id
    }

    /// ALLER-RETOUR COMPLET DU SERVICE : la réponse porte les feuilles du bloc, leur
    /// plage absolue, la racine de fin de bloc et la tête du serveur.
    ///
    /// Sans la plage absolue, le wallet ne saurait pas à quel INDEX ranger chaque
    /// feuille — et un index faux produit un chemin de Merkle faux, que rien ne signale :
    /// sa transaction est simplement refusée pour « ancre inconnue ». Sans
    /// `racine_apres`, il n'aurait aucune ancre de frontière de bloc à publier, et son
    /// `ProvedTx::anchor` — public — deviendrait sa position exacte de synchronisation,
    /// c'est-à-dire un pseudonyme.
    #[test]
    fn historique_servi_avec_plage_racine_et_tete() {
        let mut n = noeud_archiviste();
        let p = pair_connecte(&mut n, 203, 0, 113, 1);

        let actions = n.traiter(p, Message::DemandeHistorique { hauteur: 0 }, 0);
        match actions.as_slice() {
            [Action::Envoyer(vers, Message::Historique(r))] => {
                assert_eq!(*vers, p);
                assert_eq!(r.hauteur, 0);
                assert_eq!((r.debut, r.fin), (0, SORTIES_DE_GENESE as u64));
                assert_eq!(r.decalage, 0);
                assert_eq!((r.morceau, r.morceaux), (0, 1));
                assert_eq!(r.sorties.len(), SORTIES_DE_GENESE);
                assert_eq!(r.hauteur_tete, 0, "la tête réellement SERVABLE");
                // La racine annoncée est bien celle de l'état, pas une valeur inventée.
                let attendue = n
                    .etat
                    .historique()
                    .and_then(|h| h.tranche(0))
                    .map(|t| t.racine_apres)
                    .expect("tranche");
                assert_eq!(r.racine_apres.to_bytes(), attendue.to_bytes());
                // Et la réponse survit au fil, tag applicatif compris.
                let octets = Message::Historique(Box::new(
                    crate::synchro::ReponseHistorique::from_bytes(&r.to_bytes())
                        .expect("relecture"),
                ))
                .to_bytes();
                assert!(Message::from_bytes(&octets).is_ok());
            }
            _ => panic!("attendu exactement une réponse d'historique"),
        }
    }

    /// UN NŒUD QUI N'ARCHIVE PAS RÉPOND LE SILENCE — et reste valide.
    ///
    /// L'archivage est un rôle d'opérateur, séparé et optionnel : faire dépendre le
    /// service du consensus (ou l'inverse) ferait de la confidentialité un privilège
    /// d'opérateur. Le demandeur n'a rien fait de mal, il doit simplement s'adresser
    /// ailleurs.
    #[test]
    fn noeud_sans_archive_repond_le_silence_sans_sanction() {
        let mut n = noeud_de_test(); // pas d'historique
        let p = pair_connecte(&mut n, 203, 0, 113, 1);
        assert!(n.etat.historique().is_none());
        let actions = n.traiter(p, Message::DemandeHistorique { hauteur: 0 }, 0);
        assert!(actions.is_empty());
        assert_eq!(n.pairs.get(&p).unwrap().score, 0);
    }

    /// FAIL-CLOSED : un pair dont l'adresse est inconnue n'est pas servi.
    ///
    /// Sans adresse il n'y a pas de groupe réseau, donc pas d'étranglement possible.
    /// Servir quand même offrirait un contournement complet à qui saurait se faire
    /// oublier de la table — et l'étranglement ne protégerait plus que les honnêtes.
    #[test]
    fn pair_sans_adresse_connue_nest_pas_servi() {
        let mut n = noeud_archiviste();
        let inconnu = PeerId::depuis_identite(&SigKeypair::generate().public);
        assert!(n
            .traiter(inconnu, Message::DemandeHistorique { hauteur: 0 }, 0)
            .is_empty());
        // Et la même demande, une fois l'adresse notée, est bien servie : c'est
        // l'adresse qui manquait, pas autre chose.
        n.noter_adresse(
            inconnu,
            SocketAddr::from((Ipv4Addr::new(198, 51, 100, 4), 8333)),
        );
        assert_eq!(
            n.traiter(inconnu, Message::DemandeHistorique { hauteur: 0 }, 0)
                .len(),
            1
        );
    }

    /// HAUTEURS HOSTILES : `u64::MAX`, la hauteur suivante, une hauteur absurde.
    ///
    /// Elles viennent du réseau et traversent `tranche` / `sorties_du_bloc`, qui les
    /// ramènent dans le repère local par `checked_sub` + `usize::try_from` + `get(..)`.
    /// Une indexation directe donnerait ici une panique — ou pire, la tranche d'une
    /// AUTRE hauteur, donc des index faux servis en silence à un wallet qui les croirait.
    #[test]
    fn hauteurs_hostiles_rendent_le_silence_sans_paniquer() {
        let mut n = noeud_archiviste();
        let p = pair_connecte(&mut n, 203, 0, 113, 1);
        // hauteur == tête (servie), tête+1, tête+2, et les extrêmes du domaine.
        for h in [1u64, 2, 1_000_000, u64::MAX, u64::MAX - 1] {
            let actions = n.traiter(p, Message::DemandeHistorique { hauteur: h }, 0);
            assert!(actions.is_empty(), "hauteur {h} : silence attendu");
        }
        assert_eq!(
            n.pairs.get(&p).unwrap().score,
            0,
            "demander une hauteur qu'on n'a pas n'est PAS une faute"
        );
        // La hauteur valide reste servie : le silence n'était pas un blocage global.
        assert_eq!(
            n.traiter(p, Message::DemandeHistorique { hauteur: 0 }, 0)
                .len(),
            1
        );
    }

    /// L'ÉTRANGLEMENT RÉSISTE À LA ROTATION D'IDENTITÉ.
    ///
    /// C'est LA propriété de la brique. Un `PeerId` est un hachage de clé publique :
    /// gratuit, et le wallet en tire délibérément un neuf à chaque commande. Indexer le
    /// crédit dessus donnerait un service étranglé sur le papier et illimité en
    /// pratique — il suffirait de régénérer une clé entre deux requêtes.
    ///
    /// Ici 200 identités DISTINCTES depuis un seul `/16` se partagent un seul seau : le
    /// nombre de réponses reste celui d'un groupe. Et un pair d'un AUTRE groupe est
    /// toujours servi, sinon étrangler un attaquant reviendrait à couper le service pour
    /// tout le monde.
    #[test]
    fn etranglement_indexe_sur_le_groupe_resiste_a_la_rotation_didentite() {
        let mut n = noeud_archiviste();
        let mut servies = 0usize;
        for i in 0..200u16 {
            // Identité neuve à CHAQUE requête, adresses variées… dans le même /16.
            let p = pair_connecte(&mut n, 203, 0, (i % 256) as u8, (i / 256) as u8);
            if !n
                .traiter(p, Message::DemandeHistorique { hauteur: 0 }, 0)
                .is_empty()
            {
                servies += 1;
            }
        }
        // Coût d'une requête servie : COUT_REQUETE + SORTIES_DE_GENESE entrées.
        let plafond = (crate::etranglement::CAPACITE_SEAU
            / (crate::etranglement::COUT_REQUETE + SORTIES_DE_GENESE as u64))
            as usize
            + 1;
        assert!(
            servies >= 1,
            "un wallet honnête doit être servi au moins une fois"
        );
        assert!(
            servies <= plafond,
            "200 identités d'un même /16 ont obtenu {servies} réponses (plafond {plafond}) : \
             le crédit suit le PAIR et non le GROUPE"
        );

        // Un groupe réseau DIFFÉRENT est intact.
        let autre = pair_connecte(&mut n, 198, 51, 100, 1);
        assert_eq!(
            n.traiter(autre, Message::DemandeHistorique { hauteur: 0 }, 0)
                .len(),
            1,
            "étrangler un groupe ne doit pas couper le service pour les autres"
        );
    }

    /// À CRÉDIT ÉPUISÉ : LE SILENCE, ET AUCUNE SANCTION.
    ///
    /// Deux exigences distinctes qui tiennent ensemble. Une réponse « courte » de refus
    /// coûterait exactement ce qu'on cherche à éviter (allocation, cascade AEAD,
    /// écriture, flush) et ferait du crédit une information sondable. Et sanctionner
    /// serait pire encore : le score gouverne la sélection sortante, donc pénaliser les
    /// wallets qui se synchronisent dégraderait notre propre anti-eclipse — sur le
    /// comportement le plus normal qui soit.
    #[test]
    fn credit_epuise_donne_le_silence_et_aucune_sanction() {
        let mut n = noeud_archiviste();
        let p = pair_connecte(&mut n, 203, 0, 113, 1);
        let mut vues = 0usize;
        for _ in 0..500 {
            if n.traiter(p, Message::DemandeHistorique { hauteur: 0 }, 0)
                .is_empty()
            {
                vues += 1;
            }
        }
        assert!(vues > 0, "le crédit doit finir par s'épuiser");
        assert_eq!(
            n.pairs.get(&p).unwrap().score,
            0,
            "demander son historique n'est JAMAIS une faute, même à crédit épuisé"
        );
        assert!(!n.pairs.get(&p).unwrap().banni());

        // Et le crédit REMONTE avec le temps : l'étranglement freine, il ne bannit pas.
        assert!(
            !n.traiter(p, Message::DemandeHistorique { hauteur: 0 }, 60_000)
                .is_empty(),
            "une minute plus tard, le service doit être de nouveau rendu"
        );
    }

    /// UNE RÉPONSE D'HISTORIQUE REÇUE PAR UN NŒUD EST IGNORÉE, SANS SANCTION.
    ///
    /// Un nœud n'en demande jamais — c'est un message de wallet. En recevoir une n'a
    /// pourtant rien d'anormal : réponse tardive après renoncement, pair qui parle à la
    /// mauvaise adresse. Sanctionner ferait payer un décalage de calendrier, et la
    /// pénalité retomberait sur la diversité de pairs.
    #[test]
    fn reponse_dhistorique_non_sollicitee_ignoree_sans_sanction() {
        let mut n = noeud_archiviste();
        let p = pair_connecte(&mut n, 203, 0, 113, 1);
        let tranche = ledger::historique::TrancheBloc {
            hauteur: 0,
            debut: 0,
            fin: 0,
            racine_apres: proved_hash::digest::Digest(core::array::from_fn(|i| {
                proved_hash::felt::Felt::from_canonical_u64(9 + i as u64).unwrap()
            })),
        };
        let r = crate::synchro::ReponseHistorique::decouper(&tranche, &[], 0).expect("découpage");
        let actions = n.traiter(
            p,
            Message::Historique(Box::new(r.into_iter().next().unwrap())),
            0,
        );
        assert!(actions.is_empty());
        assert_eq!(n.pairs.get(&p).unwrap().score, 0);
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
