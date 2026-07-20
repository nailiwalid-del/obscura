//! Layout monolithe du circuit de validité.
//!
//! **Witness-hiding (HVZK en ROM) depuis 3z-b1** : les preuves de ce module
//! établissent l'intégrité (P1–P7) ET masquent le témoin par lignes de blinding
//! (région aléatoire `[used_rows, trace_len)`, gating global `blind_off`, aléa
//! OsRng frais par preuve). Argument et caveats — honnête-vérifieur, prototype
//! non audité, pas de « perfect ZK » — dans docs/STARK_STATEMENT.md, section
//! « Witness-hiding du monolithe — argument HVZK ».

pub(crate) mod air;
pub(crate) mod layout;
pub(crate) mod trace;
