//! Layout monolithe du circuit de validité.
//!
//! **Witness-hiding (HVZK en ROM) depuis 3z-b1** : les preuves de ce module
//! établissent l'intégrité (P1–P7) ET masquent le témoin par lignes de blinding
//! (région aléatoire `[used_rows, trace_len)`, gating global `blind_off`, aléa
//! OsRng frais par preuve). Argument et caveats — honnête-vérifieur, prototype
//! non audité, pas de « perfect ZK » — dans docs/STARK_STATEMENT.md, section
//! « Witness-hiding du monolithe — argument HVZK ».

// --- Monolithe CÔTE-À-CÔTE (3z-b1) : conservé comme ORACLE DE PARITÉ ---
//
// Depuis la bascule 3z-c1 T6, `tx.rs` prouve avec le monolithe SEGMENTÉ. Le
// côte-à-côte n'est donc plus sur le chemin de production, d'où `allow(dead_code)`
// sur ses points d'entrée (`prove_monolith`, `MonolithAir`, …).
//
// Il n'est PAS supprimé pour autant : il fait tourner
// `seg_air::parite_publics_segmente_vs_cote_a_cote`, qui vérifie que les deux
// implémentations produisent les MÊMES publics pour le même témoin. C'est une
// protection de non-régression contre une implémentation indépendante et éprouvée
// — la plus forte disponible tant que le segmenté est jeune. Plusieurs de ses
// helpers (`key_rows`, `sponge_rows_for`, `push_preamble`, `MonolithPublicInputs`)
// restent d'ailleurs UTILISÉS par le segmenté : les deux partagent la même
// construction cryptographique, seule la disposition diffère.
//
// À supprimer quand la confiance dans le segmenté sera suffisante (au plus tard
// avec 3z-c2, qui rendra la forme 2-in/2-out du côte-à-côte caduque).
#[allow(dead_code)]
pub(crate) mod air;
#[allow(dead_code)]
pub(crate) mod layout;
#[allow(dead_code)]
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
pub(crate) mod seg_layout;
pub(crate) mod seg_trace;
pub(crate) mod seg_air;
