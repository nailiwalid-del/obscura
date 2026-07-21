//! Nœud Obscura : câblage des briques réseau et consensus (phase 5).
//!
//! Les phases 3 et 4 ont produit des briques testées ISOLÉMENT — circuit, ledger,
//! transport chiffré, pairs, mempool, Dandelion++. Aucune ne parle aux autres.
//! Ce crate est le câblage.
//!
//! | module | rôle |
//! |---|---|
//! | [`message`] | protocole applicatif circulant DANS le canal chiffré |
//!
//! Il dépend de `net` (transport) ET du consensus (`circuit`, `ledger`) : c'est
//! précisément pour garder `net` PUR TRANSPORT — sans dépendance au consensus — que
//! le câblage vit ici plutôt que là-bas.

pub mod message;

pub use message::{Message, MessageError};
