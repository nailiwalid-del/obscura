//! Constantes de layout du monolithe : offsets de colonne et budget.
//!
//! Tous les offsets sont dérivés par addition des tailles de groupe précédentes,
//! sans littéraux magiques. Les groupes sont contigus et ne se chevauchent pas.

// Bloc groupé : ces constantes sont consommées par trace.rs/air.rs (tâches
// 3z-a2/a3) ; allow(dead_code) temporaire — à retirer quand ces modules les
// brancheront. (Hors tests, rien ne les consomme encore : sans ce bloc, la
// compilation de la lib les signalerait toutes.)
#[allow(dead_code)]
mod plan {
    // Offsets de groupes de colonnes (dérivés par addition).
    pub(crate) const KEY_OFF: usize = 0;
    pub(crate) const U0_OFF: usize = KEY_OFF + 24;
    pub(crate) const M0_OFF: usize = U0_OFF + 20;
    pub(crate) const U1_OFF: usize = M0_OFF + 29;
    pub(crate) const M1_OFF: usize = U1_OFF + 20;
    pub(crate) const O0_OFF: usize = M1_OFF + 29;
    pub(crate) const O1_OFF: usize = O0_OFF + 20;
    pub(crate) const BAL_OFF: usize = O1_OFF + 20;
    pub(crate) const CARRIER_OFF: usize = BAL_OFF + 3;
    pub(crate) const WIDTH: usize = CARRIER_OFF + 36;

    // Porteuses (colonnes constantes), ordre par entrée i : rho, cm, leaf,
    // puis vin/vout. Les tâches suivantes indexent par entrée → `[usize; 2]`.
    pub(crate) const OWNER_C: usize = CARRIER_OFF;
    pub(crate) const NK_C: usize = OWNER_C + 4;

    // Intermédiaires scalaires : deux tableaux const ne peuvent pas se
    // référencer mutuellement (cycle d'évaluation const), on chaîne donc ici.
    const RHO_C_0: usize = NK_C + 4;
    const CM_C_0: usize = RHO_C_0 + 4;
    const LEAF_C_0: usize = CM_C_0 + 4;
    const RHO_C_1: usize = LEAF_C_0 + 4;
    const CM_C_1: usize = RHO_C_1 + 4;
    const LEAF_C_1: usize = CM_C_1 + 4;
    const VIN_C_0: usize = LEAF_C_1 + 4;
    const VIN_C_1: usize = VIN_C_0 + 1;
    const VOUT_C_0: usize = VIN_C_1 + 1;
    const VOUT_C_1: usize = VOUT_C_0 + 1;

    pub(crate) const RHO_C: [usize; 2] = [RHO_C_0, RHO_C_1];
    pub(crate) const CM_C: [usize; 2] = [CM_C_0, CM_C_1];
    pub(crate) const LEAF_C: [usize; 2] = [LEAF_C_0, LEAF_C_1];
    pub(crate) const VIN_C: [usize; 2] = [VIN_C_0, VIN_C_1];
    pub(crate) const VOUT_C: [usize; 2] = [VOUT_C_0, VOUT_C_1];

    // Segments de lignes d'une éponge de dépense U_i.
    pub(crate) const CM_ROWS_START: usize = 0;
    pub(crate) const CM_ROWS_END: usize = 32;
    pub(crate) const LEAF_ROWS_START: usize = 32;
    pub(crate) const LEAF_ROWS_END: usize = 40;
    pub(crate) const NF_ROWS_START: usize = 40;
    pub(crate) const NF_ROWS_END: usize = 56;

    /// Longueur de trace pour une profondeur d'arbre donnée.
    ///
    /// Retourne `max(256, 16*depth)`, où 256 est le minimum absolu et
    /// 16*depth est le minimum basé sur la taille du chemin Merkle.
    pub(crate) fn trace_len(depth: usize) -> usize {
        std::cmp::max(256, 16 * depth)
    }
}
#[allow(unused_imports)] // même raison : consommés par les tâches 3z-a2/a3
pub(crate) use plan::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_colonnes_respecte() {
        assert!(WIDTH <= winterfell::TraceInfo::MAX_TRACE_WIDTH);
        assert_eq!(WIDTH, CARRIER_OFF + 36);
        // Groupes contigus, sans chevauchement.
        assert_eq!(U0_OFF, KEY_OFF + 24);
        assert_eq!(M0_OFF, U0_OFF + 20);
        assert_eq!(U1_OFF, M0_OFF + 29);
        assert_eq!(M1_OFF, U1_OFF + 20);
        assert_eq!(O0_OFF, M1_OFF + 29);
        assert_eq!(O1_OFF, O0_OFF + 20);
        assert_eq!(BAL_OFF, O1_OFF + 20);
        assert_eq!(CARRIER_OFF, BAL_OFF + 3);
    }

    #[test]
    fn porteuses_contigues() {
        // 36 colonnes porteuses contiguës, sans trou, jusqu'à WIDTH.
        assert_eq!(OWNER_C, CARRIER_OFF);
        assert_eq!(NK_C, OWNER_C + 4);
        assert_eq!(RHO_C[0], NK_C + 4);
        assert_eq!(CM_C[0], RHO_C[0] + 4);
        assert_eq!(LEAF_C[0], CM_C[0] + 4);
        assert_eq!(RHO_C[1], LEAF_C[0] + 4);
        assert_eq!(CM_C[1], RHO_C[1] + 4);
        assert_eq!(LEAF_C[1], CM_C[1] + 4);
        assert_eq!(VIN_C[0], LEAF_C[1] + 4);
        assert_eq!(VIN_C[1], VIN_C[0] + 1);
        assert_eq!(VOUT_C[0], VIN_C[1] + 1);
        assert_eq!(VOUT_C[1], VOUT_C[0] + 1);
        assert_eq!(VOUT_C[1] + 1, WIDTH);
    }

    #[test]
    fn longueur_de_trace() {
        assert_eq!(trace_len(32), 512); // consensus : le chemin domine
        assert_eq!(trace_len(4), 256); // dev : l'équilibre (4 blocs × 64) domine
    }
}
