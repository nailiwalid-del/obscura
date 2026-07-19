//! Layout monolithe du circuit de validité.
//!
//! ⚠️ **validity-only** : ce module décrit le plan de colonnes pour les preuves
//! STARK d'intégrité des transactions. Ces colonnes ne masquent pas le témoin ;
//! winterfell n'est pas zero-knowledge. Ne jamais présenter les preuves d'ici
//! comme `zk`/`private`/`shielded`.

pub(crate) mod layout;
