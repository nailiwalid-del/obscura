//! Nœud Obscura : câblage des briques réseau et consensus (phase 5).
//!
//! Les phases 3 et 4 ont produit des briques testées ISOLÉMENT — circuit, ledger,
//! transport chiffré, pairs, mempool, Dandelion++. Aucune ne parle aux autres.
//! Ce crate est le câblage.
//!
//! | module | rôle |
//! |---|---|
//! | [`message`] | protocole applicatif circulant DANS le canal chiffré |
//! | [`orchestration`] | ce qu'un nœud FAIT d'un message — fonction PURE, sans E/S |
//! | [`runtime`] | l'EXÉCUTION : sockets, threads de lecture, boucle d'événements |
//!
//! Il dépend de `net` (transport) ET du consensus (`circuit`, `ledger`) : c'est
//! précisément pour garder `net` PUR TRANSPORT — sans dépendance au consensus — que
//! le câblage vit ici plutôt que là-bas.

pub mod message;
pub mod orchestration;
pub mod runtime;

pub use message::{Message, MessageError};
pub use orchestration::{Action, Noeud};
pub use runtime::Runtime;
