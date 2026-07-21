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

// --- 3z-c1 : monolithe SEGMENTÉ, construit À CÔTÉ de l'existant ---
//
// La refonte séquentielle (segments empilés, largeur uniforme) est développée en
// parallèle du monolithe côte-à-côte plutôt qu'en remplacement en place : le crate
// compile et TOUS les tests tournent à chaque étape, et le côte-à-côte sert
// d'ORACLE DE PARITÉ vivant (mêmes publics pour le même témoin). La bascule de
// `tx.rs` vers le segmenté n'aura lieu qu'une fois la parité et la soundness
// établies ; l'ancien module sera alors supprimé.
//
// Première tentative (parquée en 333e4e4) : remplacement en place — le crate ne
// compilait plus dès T1 et rien n'était testable avant T3. À ne pas refaire.
// `allow(dead_code)` transitoire : la géométrie est posée (T1) mais ses consommateurs
// (`seg_trace` T2, `seg_air` T3) n'existent pas encore. À retirer dès T3.
#[allow(dead_code)]
pub(crate) mod seg_layout;
#[allow(dead_code)]
pub(crate) mod seg_trace;
#[allow(dead_code)]
pub(crate) mod seg_air;
