//! Constantes de layout du monolithe : offsets de colonne et budget.
//!
//! Tous les offsets sont dérivés par addition des tailles de groupe précédentes,
//! sans littéraux magiques. Les groupes sont contigus et ne se chevauchent pas.

// Bloc groupé : ces constantes sont LUES par `trace.rs`/`air.rs`, atteignables
// depuis l'API publique du crate depuis 3z-a5 (`tx::prove_tx` → `prove_monolith` →
// `build_monolith_trace`) — plus d'`allow(dead_code)` nécessaire.
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

    /// Lignes de blinding (witness-hiding, 3z-b1). Dérivé : ≥ q(32) + OOD(2) + marge(6).
    /// `q` = nombre de requêtes de `proof_options_hi`. Assertion de cohérence dans air.rs.
    pub(crate) const BLIND_ROWS: usize = 40;

    /// Lignes utiles (contraintes + assertions) : l'ancienne longueur de trace.
    ///
    /// Retourne `max(256, 16*depth)`, où 256 est le minimum absolu (équilibre :
    /// 4 blocs × 64) et 16*depth le minimum basé sur la taille du chemin Merkle.
    pub(crate) fn used_rows(depth: usize) -> usize {
        core::cmp::max(256, 16 * depth)
    }

    /// Longueur de trace pour une profondeur d'arbre donnée : lignes utiles +
    /// lignes de blinding, arrondies à la puissance de 2 supérieure (winterfell).
    pub(crate) fn trace_len(depth: usize) -> usize {
        (used_rows(depth) + BLIND_ROWS).next_power_of_two()
    }
}
pub(crate) use plan::*;

#[cfg(test)]
mod tests {
    use super::*;

    // Budget de colonnes : garde-fou COMPILE-TIME (pas un test à exécuter — la
    // valeur est déjà connue à la compilation). `const _: () = assert!(...)` évite
    // le lint `assertions_on_constants` tout en PRÉSERVANT la vérification : si
    // WIDTH dépasse le budget winterfell, la compilation échoue.
    const _: () = assert!(WIDTH <= winterfell::TraceInfo::MAX_TRACE_WIDTH);

    // Marge de blinding : garde-fou COMPILE-TIME (même motif). 32 = nombre de
    // requêtes de `proof_options_hi`, +2 = évaluations OOD ; la liaison RUNTIME
    // aux options réelles est assertée dans `MonolithAir::new`.
    const _: () = assert!(BLIND_ROWS >= 32 + 2);

    #[test]
    fn budget_colonnes_respecte() {
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
    fn trace_len_avec_blinding() {
        assert_eq!(used_rows(32), 512); // consensus : le chemin domine
        assert_eq!(trace_len(32), 1024); // next_pow2(512+40)
        assert_eq!(used_rows(4), 256); // dev : l'équilibre (4 blocs × 64) domine
        assert_eq!(trace_len(4), 512); // next_pow2(256+40)
    }
}
