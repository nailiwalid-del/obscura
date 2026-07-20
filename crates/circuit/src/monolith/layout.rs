//! Géométrie de segment du monolithe empilé (3z-c1) : offsets de colonne,
//! schedule et budget.
//!
//! La trace utile est une **suite ordonnée de segments séquentiels de LARGEUR
//! uniforme et de LONGUEURS variables par type** :
//! `[KEY] → [IN0] → [IN1] → [OUT0] → [OUT1] → [blinding]`. Chaque segment occupe
//! `seg_len(kind, depth)` lignes contiguës (une longueur uniforme calée sur le
//! chemin de Merkle gaspillait ~480 lignes sur KEY/OUT et quadruplait la trace) ;
//! le schedule 2-in/2-out est FIGÉ mais construit à partir d'une liste de types
//! (`SegKind`) — c'est la **couture** que 3z-c2 fera varier (M-in/N-out).
//!
//! **Décision de géométrie (parallélisme intra-segment)** : dans un segment IN,
//! la pile d'éponge cm→feuille→nullifier (56 lignes) et le chemin de Merkle
//! (`16·depth` lignes, éponge active à CHAQUE ligne) tournent **en parallèle dès
//! la ligne 0** (liés par la porteuse `LEAF_C`, comme dans le côte-à-côte). Ils
//! ne peuvent donc PAS partager le même groupe d'éponge : le motif `merkle_path`
//! garde son éponge embarquée (29 colonnes complètes, disjointes des 20 de la
//! pile). C'est ce qui permet `in_len = max(64, 16·depth)` — le **max** des deux
//! longueurs, pas leur somme.
//!
//! Tous les offsets sont dérivés par addition des tailles de groupe précédentes,
//! sans littéraux magiques. Les groupes sont contigus et ne se chevauchent pas
//! (exception DOCUMENTÉE : le bloc KEY, 24 colonnes, déborde de 4 colonnes sur le
//! groupe Merkle — inactif sur un segment KEY, gaté par le sélecteur de type).

// Bloc groupé : ces constantes sont LUES par `trace.rs`/`air.rs` (Tâches 2-3 de
// 3z-c1), atteignables depuis l'API publique du crate (`tx::prove_tx` →
// `prove_monolith` → `build_monolith_trace`).
mod plan {
    use crate::rescue_round::STATE_WIDTH;
    use crate::sponge::TRACE_WIDTH as SPONGE_W;
    use proved_hash::digest::DIGEST_FELTS;

    // ============================================================================
    // Colonnes DANS un segment (mêmes offsets pour tous les segments ; les
    // familles de contraintes sont routées par le sélecteur de type — Tâche 3).
    // ============================================================================

    /// Éponge « principale » du segment (20 col) : pile cm→feuille→nullifier sur
    /// un segment IN, commitment de sortie sur un segment OUT.
    pub(crate) const SEG_SPONGE_OFF: usize = 0;
    pub(crate) const SEG_SPONGE_W: usize = SPONGE_W; // 20

    /// Motif `merkle_path` COMPLET (29 col = son éponge 20 + cur 4 + sib 4 + bit 1),
    /// actif uniquement sur les segments IN (voir la décision de géométrie en tête).
    pub(crate) const SEG_MERKLE_OFF: usize = SEG_SPONGE_OFF + SEG_SPONGE_W; // 20
    pub(crate) const SEG_MERKLE_W: usize = SPONGE_W + 2 * DIGEST_FELTS + 1; // 29

    /// Équilibre local au segment : `[bit, VACC]` (décomposition binaire du
    /// montant, poids remis à zéro par segment). L'accumulateur global `S` est
    /// une colonne PARTAGÉE (`S_COL`), chaînée à travers tous les segments.
    pub(crate) const SEG_BALBIT_OFF: usize = SEG_MERKLE_OFF + SEG_MERKLE_W; // 49
    pub(crate) const SEG_BAL_BIT: usize = 0; // relatif à SEG_BALBIT_OFF
    pub(crate) const SEG_BAL_VACC: usize = 1; // relatif à SEG_BALBIT_OFF
    pub(crate) const SEG_BALBIT_W: usize = 2;

    /// Largeur uniforme d'un segment.
    pub(crate) const SEG_WIDTH: usize = SEG_BALBIT_OFF + SEG_BALBIT_W; // 51

    /// Bloc KEY : 2 états Rescue de 12 col côte à côte (owner ‖ nk), 8 lignes.
    /// Il RÉUTILISE les colonnes du segment à partir de 0 : les 4 colonnes de
    /// débordement (20..24) tombent dans le groupe Merkle, inactif sur KEY.
    pub(crate) const SEG_KEY_OFF: usize = SEG_SPONGE_OFF;
    pub(crate) const SEG_KEY_W: usize = 2 * STATE_WIDTH; // 24

    // ============================================================================
    // Colonnes PARTAGÉES (constantes ou chaînées sur TOUTE la trace utile) :
    // porteuses + accumulateur d'équilibre S.
    // ============================================================================

    pub(crate) const SHARED_OFF: usize = SEG_WIDTH;

    // Porteuses (colonnes constantes), ordre : owner, nk, root, puis par entrée
    // i : rho, cm, leaf, puis vin/vout. Les tâches suivantes indexent par
    // entrée → `[usize; 2]`. `ROOT_C` est NOUVELLE (3z-c1) : chaque segment IN
    // asserte « racine calculée du chemin == ROOT_C », root public une seule fois.
    pub(crate) const OWNER_C: usize = SHARED_OFF;
    pub(crate) const NK_C: usize = OWNER_C + DIGEST_FELTS;
    pub(crate) const ROOT_C: usize = NK_C + DIGEST_FELTS;

    // Intermédiaires scalaires : deux tableaux const ne peuvent pas se
    // référencer mutuellement (cycle d'évaluation const), on chaîne donc ici.
    const RHO_C_0: usize = ROOT_C + DIGEST_FELTS;
    const CM_C_0: usize = RHO_C_0 + DIGEST_FELTS;
    const LEAF_C_0: usize = CM_C_0 + DIGEST_FELTS;
    const RHO_C_1: usize = LEAF_C_0 + DIGEST_FELTS;
    const CM_C_1: usize = RHO_C_1 + DIGEST_FELTS;
    const LEAF_C_1: usize = CM_C_1 + DIGEST_FELTS;
    const VIN_C_0: usize = LEAF_C_1 + DIGEST_FELTS;
    const VIN_C_1: usize = VIN_C_0 + 1;
    const VOUT_C_0: usize = VIN_C_1 + 1;
    const VOUT_C_1: usize = VOUT_C_0 + 1;

    pub(crate) const RHO_C: [usize; 2] = [RHO_C_0, RHO_C_1];
    pub(crate) const CM_C: [usize; 2] = [CM_C_0, CM_C_1];
    pub(crate) const LEAF_C: [usize; 2] = [LEAF_C_0, LEAF_C_1];
    pub(crate) const VIN_C: [usize; 2] = [VIN_C_0, VIN_C_1];
    pub(crate) const VOUT_C: [usize; 2] = [VOUT_C_0, VOUT_C_1];

    /// Accumulateur d'équilibre chaîné à travers TOUS les segments : démarre à 0
    /// (asserté), +value par segment IN, −value par segment OUT, == fee à la
    /// dernière ligne utile (asserté). Remplace la région BAL du côte-à-côte.
    pub(crate) const S_COL: usize = VOUT_C_1 + 1;

    /// Largeur totale de la trace : segment uniforme + colonnes partagées.
    pub(crate) const WIDTH: usize = S_COL + 1; // 92

    // ============================================================================
    // Lignes : sous-segments d'un segment, schedule et budget.
    // ============================================================================

    // Sous-segments de LIGNES de la pile d'éponge d'un segment IN, RELATIFS au
    // début du segment (`seg_start`).
    pub(crate) const CM_ROWS_START: usize = 0;
    pub(crate) const CM_ROWS_END: usize = 32;
    pub(crate) const LEAF_ROWS_START: usize = 32;
    pub(crate) const LEAF_ROWS_END: usize = 40;
    pub(crate) const NF_ROWS_START: usize = 40;
    pub(crate) const NF_ROWS_END: usize = 56;

    /// Lignes par niveau du chemin de Merkle (= `merkle_path::BLOCK`, bloc B=2).
    pub(crate) const MERKLE_LEVEL_ROWS: usize = 16;

    /// Longueur d'un segment KEY : 1 bloc de permutation Rescue (8 lignes) — les
    /// deux éponges owner/nk tournent CÔTE À CÔTE en colonnes (`SEG_KEY_W` = 24).
    pub(crate) const KEY_LEN: usize = crate::rescue_round::TRACE_LEN; // 8

    /// Plancher de longueur d'un segment IN. 64 car il faut couvrir la pile
    /// d'éponge d'une entrée (`NF_ROWS_END` = 56) et les 60 lignes de bits du
    /// range-check (`RANGE_BITS`), en restant un multiple de `MERKLE_LEVEL_ROWS`
    /// (pavage du chemin) et une puissance de 2 (arrondis de trace amicaux).
    pub(crate) const MIN_IN_LEN: usize = 64;

    /// Longueur d'un segment OUT : l'éponge de commitment (`CM_ROWS_END` = 32) et
    /// les 60 lignes de bits du range-check tournent en parallèle (groupes de
    /// colonnes disjoints) → max(32, 60) arrondi à 64 (puissance de 2).
    pub(crate) const OUT_LEN: usize = 64;

    /// Lignes de blinding (witness-hiding, 3z-b1). Dérivé : ≥ q(32) + OOD(2) + marge(6).
    /// `q` = nombre de requêtes de `proof_options_hi`. Assertion de cohérence dans air.rs.
    pub(crate) const BLIND_ROWS: usize = 40;

    /// Nombre de segments du schedule 2-in/2-out figé (1 KEY + 2 IN + 2 OUT).
    pub(crate) const N_SEGMENTS: usize = 5;

    /// Type d'un segment — la couture 3z-c2 : la généralisation M-in/N-out fera
    /// varier la LISTE de segments, pas la géométrie d'un segment.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(crate) enum SegKind {
        Key,
        Input,
        Output,
    }

    /// Schedule figé de la forme 2-in/2-out (3z-c1, parité avec le côte-à-côte).
    pub(crate) fn schedule_2in2out() -> [SegKind; N_SEGMENTS] {
        [
            SegKind::Key,
            SegKind::Input,
            SegKind::Input,
            SegKind::Output,
            SegKind::Output,
        ]
    }

    /// Lignes du segment selon son TYPE — longueurs VARIABLES par type (décision
    /// utilisateur, 3z-c1 révisé : une longueur uniforme calée sur le chemin de
    /// Merkle gaspillait ~480 lignes sur KEY/OUT et quadruplait la trace).
    pub(crate) fn seg_len(kind: SegKind, depth: usize) -> usize {
        match kind {
            SegKind::Key => KEY_LEN,
            SegKind::Input => in_len(depth),
            SegKind::Output => OUT_LEN,
        }
    }

    /// Longueur d'un segment IN : `max(MIN_IN_LEN, 16·depth)` — le chemin de
    /// Merkle domine dès `depth ≥ 4` (512 au consensus, 64 en dev).
    pub(crate) fn in_len(depth: usize) -> usize {
        core::cmp::max(MIN_IN_LEN, MERKLE_LEVEL_ROWS * depth)
    }

    /// Ligne de début du segment `i` du schedule : somme CUMULÉE des longueurs
    /// des segments précédents (frontières irrégulières — au consensus :
    /// 0, 8, 520, 1032, 1096). Pavage contigu, sans trou ni chevauchement.
    pub(crate) fn seg_start(i: usize, depth: usize) -> usize {
        schedule_2in2out()[..i]
            .iter()
            .map(|k| seg_len(*k, depth))
            .sum()
    }

    /// Lignes utiles (contraintes + assertions) : somme des longueurs des
    /// segments du schedule (au consensus : 8 + 2·512 + 2·64 = 1160).
    pub(crate) fn used_rows(depth: usize) -> usize {
        schedule_2in2out()
            .iter()
            .map(|k| seg_len(*k, depth))
            .sum()
    }

    /// Longueur de trace pour une profondeur d'arbre donnée : lignes utiles +
    /// lignes de blinding, arrondies à la puissance de 2 supérieure (winterfell).
    pub(crate) fn trace_len(depth: usize) -> usize {
        (used_rows(depth) + BLIND_ROWS).next_power_of_two()
    }

    // Garde-fous COMPILE-TIME de la géométrie (voir aussi ceux du mod tests) :
    // le plancher IN couvre la pile d'éponge, les bits du range-check, et pave
    // en blocs de Merkle entiers ; OUT couvre l'éponge de commitment et les bits.
    const _: () = assert!(MIN_IN_LEN >= NF_ROWS_END);
    const _: () = assert!(MIN_IN_LEN >= crate::range_check::RANGE_BITS);
    const _: () = assert!(MIN_IN_LEN % MERKLE_LEVEL_ROWS == 0);
    const _: () = assert!(MIN_IN_LEN.is_power_of_two());
    const _: () = assert!(OUT_LEN >= CM_ROWS_END);
    const _: () = assert!(OUT_LEN >= crate::range_check::RANGE_BITS);
    // Le bloc KEY tient dans la largeur d'un segment.
    const _: () = assert!(SEG_KEY_OFF + SEG_KEY_W <= SEG_WIDTH);
}
pub(crate) use plan::*;

#[cfg(test)]
mod tests {
    use super::*;
    use proved_hash::digest::DIGEST_FELTS;

    // Budget de colonnes : garde-fou COMPILE-TIME (pas un test à exécuter — la
    // valeur est déjà connue à la compilation). `const _: () = assert!(...)` évite
    // le lint `assertions_on_constants` tout en PRÉSERVANT la vérification : si
    // WIDTH dépasse le budget winterfell, la compilation échoue.
    const _: () = assert!(WIDTH <= winterfell::TraceInfo::MAX_TRACE_WIDTH);

    // Marge de blinding : garde-fou COMPILE-TIME (même motif). 32 = nombre de
    // requêtes de `proof_options_hi`, +4 = 2 évaluations OOD × 2 composantes base-field
    // (extension quadratique) ; la liaison RUNTIME aux options réelles est assertée
    // dans `MonolithAir::new`.
    const _: () = assert!(BLIND_ROWS >= 32 + 4);

    #[test]
    fn groupes_de_segment_contigus() {
        // Groupes de colonnes DANS un segment : contigus, sans trou, dérivés des
        // largeurs des gadgets (éponge 20, motif merkle 29, équilibre local 2).
        assert_eq!(SEG_SPONGE_OFF, 0);
        assert_eq!(SEG_SPONGE_W, crate::sponge::TRACE_WIDTH);
        assert_eq!(SEG_MERKLE_OFF, SEG_SPONGE_OFF + SEG_SPONGE_W);
        assert_eq!(SEG_MERKLE_W, SEG_SPONGE_W + 2 * DIGEST_FELTS + 1);
        assert_eq!(SEG_BALBIT_OFF, SEG_MERKLE_OFF + SEG_MERKLE_W);
        assert_eq!(SEG_WIDTH, SEG_BALBIT_OFF + SEG_BALBIT_W);
        // Le bloc KEY (2 états de 12) tient dans le segment : son débordement de
        // 4 colonnes sur le groupe Merkle (inactif sur un segment KEY) est couvert.
        assert_eq!(SEG_KEY_W, 2 * crate::rescue_round::STATE_WIDTH);
        assert!(SEG_KEY_OFF + SEG_KEY_W <= SEG_WIDTH);
        // Sous-indices d'équilibre local dans le groupe.
        assert!(SEG_BAL_BIT < SEG_BALBIT_W && SEG_BAL_VACC < SEG_BALBIT_W);
        // Sous-segments de lignes de la pile : contigus.
        assert_eq!(CM_ROWS_START, 0);
        assert_eq!(LEAF_ROWS_START, CM_ROWS_END);
        assert_eq!(NF_ROWS_START, LEAF_ROWS_END);
    }

    #[test]
    fn colonnes_partagees_contigues() {
        // Colonnes partagées (porteuses + accumulateur S) : contiguës, sans trou,
        // du bord du segment jusqu'à WIDTH.
        assert_eq!(SHARED_OFF, SEG_WIDTH);
        assert_eq!(OWNER_C, SHARED_OFF);
        assert_eq!(NK_C, OWNER_C + DIGEST_FELTS);
        assert_eq!(ROOT_C, NK_C + DIGEST_FELTS);
        assert_eq!(RHO_C[0], ROOT_C + DIGEST_FELTS);
        assert_eq!(CM_C[0], RHO_C[0] + DIGEST_FELTS);
        assert_eq!(LEAF_C[0], CM_C[0] + DIGEST_FELTS);
        assert_eq!(RHO_C[1], LEAF_C[0] + DIGEST_FELTS);
        assert_eq!(CM_C[1], RHO_C[1] + DIGEST_FELTS);
        assert_eq!(LEAF_C[1], CM_C[1] + DIGEST_FELTS);
        assert_eq!(VIN_C[0], LEAF_C[1] + DIGEST_FELTS);
        assert_eq!(VIN_C[1], VIN_C[0] + 1);
        assert_eq!(VOUT_C[0], VIN_C[1] + 1);
        assert_eq!(VOUT_C[1], VOUT_C[0] + 1);
        assert_eq!(S_COL, VOUT_C[1] + 1);
        assert_eq!(S_COL + 1, WIDTH);
        // Budget winterfell (doublé par l'assert compile-time ci-dessus).
        assert!(WIDTH <= winterfell::TraceInfo::MAX_TRACE_WIDTH);
    }

    #[test]
    fn longueurs_par_type_couvrent_leurs_gadgets() {
        // KEY : 1 bloc de permutation (owner/nk côte à côte en colonnes).
        assert_eq!(KEY_LEN, crate::rescue_round::TRACE_LEN); // 8
        // IN : la pile d'éponge (cm 32 + leaf 8 + nf 16 = 56 lignes) ET le chemin
        // de Merkle (16·depth) tournent en PARALLÈLE (groupes de colonnes
        // disjoints). in_len = max des deux, jamais la somme.
        assert_eq!(NF_ROWS_END, 56);
        assert_eq!(in_len(32), MERKLE_LEVEL_ROWS * 32); // consensus : le chemin domine
        assert_eq!(in_len(2), MIN_IN_LEN); // dev : 16·2 = 32 < 56 → plancher 64
        assert_eq!(in_len(4), MIN_IN_LEN); // 16·4 = 64 = plancher
        for depth in [2, 4, 16, 32] {
            assert!(in_len(depth) >= NF_ROWS_END, "pile d'éponge couverte");
            assert!(in_len(depth) >= MERKLE_LEVEL_ROWS * depth, "chemin couvert");
            assert!(
                in_len(depth) >= crate::range_check::RANGE_BITS,
                "60 lignes de bits du range-check couvertes"
            );
            assert_eq!(in_len(depth) % MERKLE_LEVEL_ROWS, 0, "pavage en blocs de 16");
        }
        // OUT : éponge de commitment (32) et bits de range (60) en parallèle.
        assert!(OUT_LEN >= CM_ROWS_END, "éponge de commitment couverte");
        assert!(OUT_LEN >= crate::range_check::RANGE_BITS, "bits de range couverts");
        // seg_len route la bonne longueur selon le type.
        for depth in [2, 32] {
            assert_eq!(seg_len(SegKind::Key, depth), KEY_LEN);
            assert_eq!(seg_len(SegKind::Input, depth), in_len(depth));
            assert_eq!(seg_len(SegKind::Output, depth), OUT_LEN);
        }
    }

    #[test]
    fn schedule_2in2out_correct() {
        let sched = schedule_2in2out();
        assert_eq!(
            sched,
            [
                SegKind::Key,
                SegKind::Input,
                SegKind::Input,
                SegKind::Output,
                SegKind::Output
            ]
        );
        assert_eq!(sched.len(), N_SEGMENTS);
        // Forme 2-in/2-out figée (3z-c1) — dérivée du schedule, pas de littéral à part.
        assert_eq!(sched.iter().filter(|k| **k == SegKind::Key).count(), 1);
        assert_eq!(sched.iter().filter(|k| **k == SegKind::Input).count(), 2);
        assert_eq!(sched.iter().filter(|k| **k == SegKind::Output).count(), 2);
    }

    #[test]
    fn segments_pavent_sans_trou() {
        for depth in [2, 4, 32] {
            // seg_start = somme cumulée des longueurs du schedule : strictement
            // croissant, segments contigus (pas de trou, pas de chevauchement),
            // et la fin du dernier segment == used_rows.
            let sched = schedule_2in2out();
            let mut attendu = 0;
            for (i, kind) in sched.iter().enumerate() {
                assert_eq!(seg_start(i, depth), attendu, "depth={depth} i={i}");
                attendu += seg_len(*kind, depth);
            }
            assert_eq!(used_rows(depth), attendu);
        }
        // Frontières concrètes au consensus (profondeur 32) : KEY 8, IN 512.
        assert_eq!(seg_start(0, 32), 0);
        assert_eq!(seg_start(1, 32), 8);
        assert_eq!(seg_start(2, 32), 520);
        assert_eq!(seg_start(3, 32), 1032);
        assert_eq!(seg_start(4, 32), 1096);
    }

    #[test]
    fn trace_len_avec_blinding() {
        // Consensus (profondeur 32) : 8 + 2·512 + 2·64 = 1160 lignes utiles.
        assert_eq!(used_rows(32), KEY_LEN + 2 * in_len(32) + 2 * OUT_LEN);
        assert_eq!(used_rows(32), 1160);
        assert_eq!(trace_len(32), (used_rows(32) + BLIND_ROWS).next_power_of_two());
        assert_eq!(trace_len(32), 2048);
        assert!(trace_len(32).is_power_of_two());
        assert!(trace_len(32) >= used_rows(32) + BLIND_ROWS);
        // Dev (profondeur 2) : 8 + 2·64 + 2·64 = 264 lignes utiles.
        assert_eq!(used_rows(2), KEY_LEN + 2 * MIN_IN_LEN + 2 * OUT_LEN);
        assert_eq!(trace_len(2), (used_rows(2) + BLIND_ROWS).next_power_of_two());
        assert_eq!(trace_len(2), 512);
    }
}
