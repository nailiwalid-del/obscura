//! Layout monolithe du circuit de validité.
//!
//! **Witness-hiding (HVZK en ROM) depuis 3z-b1** : les preuves de ce module
//! établissent l'intégrité (P1–P7) ET masquent le témoin par lignes de blinding
//! (région aléatoire `[used_rows, trace_len)`, gating global `blind_off`, aléa
//! OsRng frais par preuve). Argument et caveats — honnête-vérifieur, prototype
//! non audité, pas de « perfect ZK » — dans docs/STARK_STATEMENT.md, section
//! « Witness-hiding du monolithe — argument HVZK ».
//!
//! # Histoire : le côte-à-côte a existé, et a été SUPPRIMÉ (C2-T8)
//!
//! Le monolithe historique « côte-à-côte » (3z-b1, largeur 201) a servi d'ORACLE
//! DE PARITÉ pendant toute la construction du segmenté (3z-c1) : mêmes publics
//! pour le même témoin, contre une implémentation indépendante et éprouvée. La
//! variabilité de forme (3z-c2) a rendu sa géométrie 2-in/2-out caduque, et il a
//! été supprimé une fois la parité, la soundness (C2-T4) et les benchs établis.
//! Ce que les deux implémentations PARTAGEAIENT — la construction cryptographique
//! (lignes d'éponge, bloc de clé, publics, préambules) — vit dans [`socle`].
//!
//! La géométrie 2/2 historique reste ÉPINGLÉE par des constantes de test dans
//! `seg_layout` : la forme 2/2 est du CONSENSUS (des preuves existantes s'y
//! vérifient), sa géométrie ne doit pas dériver en silence.
pub(crate) mod socle;

pub(crate) mod seg_air;
pub(crate) mod seg_layout;
pub(crate) mod seg_trace;
