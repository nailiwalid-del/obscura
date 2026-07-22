//! Nœud Obscura : câblage des briques réseau et consensus (phase 5).
//!
//! Les phases 3 et 4 ont produit des briques testées ISOLÉMENT — circuit, ledger,
//! transport chiffré, pairs, mempool, Dandelion++. Aucune ne parle aux autres.
//! Ce crate est le câblage.
//!
//! | module | rôle |
//! |---|---|
//! | [`archive`] | les N derniers blocs, pour SERVIR un pair qui a manqué une hauteur |
//! | [`autorite`] | publier/relire une clé d'autorité de scellement — les deux bouts |
//! | [`message`] | protocole applicatif circulant DANS le canal chiffré |
//! | [`synchro`] | format de fil du service d'HISTORIQUE (synchronisation wallet) |
//! | [`etranglement`] | seaux à jetons du service d'historique, par GROUPE RÉSEAU |
//! | [`orchestration`] | ce qu'un nœud FAIT d'un message — fonction PURE, sans E/S |
//! | [`runtime`] | l'EXÉCUTION : sockets, threads de lecture, boucle d'événements |
//! | [`persistance`] | identité et état d'un nœud entre deux lancements |
//!
//! Il dépend de `net` (transport) ET du consensus (`circuit`, `ledger`) : c'est
//! précisément pour garder `net` PUR TRANSPORT — sans dépendance au consensus — que
//! le câblage vit ici plutôt que là-bas.

pub mod archive;
pub mod autorite;
pub mod client;
pub mod etranglement;
pub mod journal;
pub mod message;
pub mod orchestration;
pub mod persistance;
pub mod runtime;
pub mod synchro;

pub use archive::ArchiveBlocs;
pub use client::{synchroniser_avec_temoin, synchroniser_par_connexion, Arret, ResumeSynchro};
pub use etranglement::Etrangleur;
pub use message::{Message, MessageError};
pub use orchestration::{Action, Noeud};
pub use persistance::Donnees;
pub use runtime::Runtime;
pub use synchro::{ReponseHistorique, MAX_SORTIES_PAR_REPONSE};
