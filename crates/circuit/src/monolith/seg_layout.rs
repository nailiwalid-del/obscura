//! Géométrie de segment du monolithe empilé (3z-c1) : offsets de colonne,
//! schedule et budget.
//!
//! La trace utile est une **suite ordonnée de segments séquentiels de LARGEUR
//! uniforme et de LONGUEURS variables par type** :
//! `[KEY] → [IN0] → [IN1] → [OUT0] → [OUT1] → [blinding]`. Chaque segment occupe
//! `seg_len(kind, depth)` lignes contiguës (une longueur uniforme calée sur le
//! chemin de Merkle gaspillait ~480 lignes sur KEY/OUT et quadruplait la trace) ;
//! le schedule est construit à partir d'une liste de types (`SegKind`) et VARIE
//! avec la forme depuis 3z-c2 (M-in/N-out, `Forme`).
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

// Bloc groupé : ces constantes sont LUES par `seg_trace.rs`/`seg_air.rs`,
// atteignables depuis l'API publique du crate (`tx::prove_tx` → `prove_seg_forme`).
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

    // Porteuses 2/2 ÉPINGLÉES, test-only (C2-T8) — depuis C2-T3, l'AIR indexe par
    // `Forme::{rho_c,…}`. Ces valeurs restent pour VERROUILLER la géométrie 2/2
    // (`forme_2_2_identique_aux_constantes`) : la forme 2/2 est du CONSENSUS, sa
    // disposition ne doit pas dériver en silence sous un refactor de `Forme`.
    #[cfg(test)]
    pub(crate) const RHO_C: [usize; 2] = [RHO_C_0, RHO_C_1];
    #[cfg(test)]
    pub(crate) const CM_C: [usize; 2] = [CM_C_0, CM_C_1];
    #[cfg(test)]
    pub(crate) const LEAF_C: [usize; 2] = [LEAF_C_0, LEAF_C_1];
    #[cfg(test)]
    pub(crate) const VIN_C: [usize; 2] = [VIN_C_0, VIN_C_1];
    #[cfg(test)]
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

    /// Longueur d'un segment KEY : **16** lignes, alors que le calcul lui-même n'en
    /// occupe que 8 (1 bloc de permutation Rescue ; les deux éponges owner/nk
    /// tournent CÔTE À CÔTE en colonnes, `SEG_KEY_W` = 24). Les 8 lignes restantes
    /// sont inactives (éteintes par le sélecteur de type dans l'AIR).
    ///
    /// ⚠️ **Pourquoi 16 et pas 8** (corrigé en T3) : les colonnes périodiques du
    /// chemin de Merkle sont CYCLIQUES de période `MERKLE_LEVEL_ROWS` = 16
    /// (`round_flag` à p ∈ {7,15}, `init0`/`init7`/`chain`) et s'alignent sur
    /// `row % 16`. Avec `KEY_LEN = 8`, TOUS les segments suivants démarraient à
    /// ≡ 8 (mod 16) — le cycle de Merkle aurait été désaligné dans chaque segment
    /// d'entrée. Toutes les longueurs de segment étant des multiples de 16, chaque
    /// `seg_start` l'est aussi (garde compile-time plus bas). Coût réel : NUL —
    /// `trace_len` reste 512 (depth 2) et 2048 (depth 32).
    pub(crate) const KEY_LEN: usize = MERKLE_LEVEL_ROWS; // 16 (dont 8 utiles)

    /// Lignes effectivement calculées dans un segment KEY (le reste est inactif).
    pub(crate) const KEY_USED_ROWS: usize = crate::rescue_round::TRACE_LEN; // 8

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
    /// Test-only depuis C2-T8, comme le reste de la forme 2/2 épinglée
    /// (production : `Forme::n_segments`).
    #[cfg(test)]
    pub(crate) const N_SEGMENTS: usize = 5;

    /// Type d'un segment — la couture 3z-c2 : la généralisation M-in/N-out fera
    /// varier la LISTE de segments, pas la géométrie d'un segment.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(crate) enum SegKind {
        Key,
        Input,
        Output,
    }

    /// Schedule figé de la forme 2-in/2-out (3z-c1). Test-only depuis C2-T8 :
    /// le schedule de production sort de `Forme::seg_kind` ; celui-ci reste la
    /// référence ÉPINGLÉE de la forme historique.
    #[cfg(test)]
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

    /// Ligne de début du segment `i` du schedule 2/2 : somme CUMULÉE des longueurs
    /// des segments précédents. Test-only depuis C2-T8 (production :
    /// `Forme::seg_start`) — référence épinglée de la forme historique.
    #[cfg(test)]
    pub(crate) fn seg_start(i: usize, depth: usize) -> usize {
        schedule_2in2out()[..i]
            .iter()
            .map(|k| seg_len(*k, depth))
            .sum()
    }

    /// Lignes utiles 2/2 (au consensus : 16 + 2·512 + 2·64 = 1168). Test-only
    /// depuis C2-T8 (production : `Forme::used_rows`).
    #[cfg(test)]
    pub(crate) fn used_rows(depth: usize) -> usize {
        schedule_2in2out()
            .iter()
            .map(|k| seg_len(*k, depth))
            .sum()
    }

    /// Longueur de trace 2/2 : lignes utiles + blinding, puissance de 2
    /// supérieure (winterfell). Test-only depuis C2-T8 (production :
    /// `Forme::trace_len`) — référence épinglée de la forme historique.
    #[cfg(test)]
    pub(crate) fn trace_len(depth: usize) -> usize {
        (used_rows(depth) + BLIND_ROWS).next_power_of_two()
    }

    // ============================================================================
    // FORME VARIABLE (3z-c2) : M entrées / N sorties, bornées.
    //
    // La forme GÉNÉRALISE la géométrie 2/2 historique : `Forme::F22` doit
    // produire exactement les valeurs épinglées ci-dessus — c'est ce que le test
    // `forme_2_2_identique_aux_constantes` garantit. La 2/2 étant la forme de
    // CONSENSUS la plus peuplée, sa géométrie ne doit jamais dériver en silence.
    // ============================================================================

    /// Bornes de forme — constantes de CONSENSUS (les changer = nouvelle version
    /// de format, pas un patch). La soundness de l'équilibre en permettrait 8 par
    /// côté (`8·2^60 = 2^63 < p`, cf. 3b3a) : 4 est un choix de COÛT — chaque
    /// entrée ajoute 13 colonnes de porteuses, chaque sortie 1.
    pub const MAX_IN: usize = 4;
    pub const MAX_OUT: usize = 4;

    /// Colonnes de porteuses par entrée : rho + cm + leaf (3 digests).
    const PORTEUSES_PAR_ENTREE: usize = 3 * DIGEST_FELTS;

    /// Forme d'une transaction : `m` entrées, `n` sorties. Construite VALIDÉE —
    /// les bornes vivent dans le constructeur, pas dans les commentaires (règle du
    /// dépôt : toute borne d'un décodeur existe aussi dans le constructeur).
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(crate) struct Forme {
        m: usize,
        n: usize,
    }

    /// Refus d'une forme hors bornes. `m = 0` : une transaction sans entrée n'a
    /// pas d'autorité de dépense ; `n = 0` : sans sortie, pas de destinataire
    /// (les « frais purs » passent par une sortie de valeur 0 vers soi).
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(crate) struct FormeInvalide {
        pub m: usize,
        pub n: usize,
    }

    // L'allow couvre les méthodes de commodité consommées seulement par les tests
    // et les gardes const (F22, …) — le gros de l'impl est sur le chemin de prod.
    #[allow(dead_code)]
    impl Forme {
        /// La forme historique 2-in/2-out — celle des constantes ci-dessus, et la
        /// forme par DÉFAUT du wallet (le seau d'anonymat le plus peuplé, cf. spec
        /// 3z-c2 D3).
        pub(crate) const F22: Forme = Forme { m: 2, n: 2 };

        pub(crate) const fn new(m: usize, n: usize) -> Result<Forme, FormeInvalide> {
            if m == 0 || m > MAX_IN || n == 0 || n > MAX_OUT {
                return Err(FormeInvalide { m, n });
            }
            Ok(Forme { m, n })
        }

        pub(crate) const fn m(self) -> usize {
            self.m
        }

        pub(crate) const fn n(self) -> usize {
            self.n
        }

        /// Nombre de segments : 1 KEY + m IN + n OUT.
        pub(crate) const fn n_segments(self) -> usize {
            1 + self.m + self.n
        }

        /// Type du segment `i` du schedule `[KEY][IN×m][OUT×n]`.
        ///
        /// L'ORDRE est normatif : les publics sont liés position par position aux
        /// segments (le j-ième commitment de sortie au j-ième segment OUT — cf.
        /// spec D7.3), donc le schedule ne peut pas être réordonné sans casser la
        /// preuve. C'est voulu.
        pub(crate) const fn seg_kind(self, i: usize) -> SegKind {
            if i == 0 {
                SegKind::Key
            } else if i <= self.m {
                SegKind::Input
            } else {
                SegKind::Output
            }
        }

        /// Ligne de début du segment `i` : somme cumulée des longueurs. Toutes les
        /// longueurs étant des multiples de `MERKLE_LEVEL_ROWS`, chaque frontière
        /// l'est aussi — l'invariant d'alignement de 3z-c1 tient pour TOUTE forme
        /// (c'est précisément ce que sa garde compile-time promettait).
        pub(crate) fn seg_start(self, i: usize, depth: usize) -> usize {
            (0..i).map(|k| seg_len(self.seg_kind(k), depth)).sum()
        }

        /// Lignes utiles : 16 + m·in_len + n·64.
        pub(crate) fn used_rows(self, depth: usize) -> usize {
            KEY_LEN + self.m * in_len(depth) + self.n * OUT_LEN
        }

        /// Longueur de trace : utiles + blinding, puissance de 2 supérieure.
        pub(crate) fn trace_len(self, depth: usize) -> usize {
            (self.used_rows(depth) + BLIND_ROWS).next_power_of_two()
        }

        // ----------------------------------------------------------------- colonnes

        /// Porteuse rho de l'entrée `i` (`i < m`).
        ///
        /// Disposition, identique au 2/2 pour F22 : après `ROOT_C`, un bloc de
        /// 3 digests (rho, cm, leaf) PAR ENTRÉE, puis les scalaires vin×m, vout×n,
        /// puis `S`. La largeur est DIMENSIONNÉE À LA FORME (spec D2) : une
        /// transaction 1-in/2-out ne paie pas les colonnes d'une 4-in/4-out.
        pub(crate) const fn rho_c(self, i: usize) -> usize {
            debug_assert!(i < self.m);
            ROOT_C + DIGEST_FELTS + i * PORTEUSES_PAR_ENTREE
        }

        pub(crate) const fn cm_c(self, i: usize) -> usize {
            self.rho_c(i) + DIGEST_FELTS
        }

        pub(crate) const fn leaf_c(self, i: usize) -> usize {
            self.cm_c(i) + DIGEST_FELTS
        }

        /// Scalaire vin de l'entrée `i` — après TOUS les blocs de digests.
        pub(crate) const fn vin_c(self, i: usize) -> usize {
            debug_assert!(i < self.m);
            ROOT_C + DIGEST_FELTS + self.m * PORTEUSES_PAR_ENTREE + i
        }

        /// Scalaire vout de la sortie `j`.
        pub(crate) const fn vout_c(self, j: usize) -> usize {
            debug_assert!(j < self.n);
            ROOT_C + DIGEST_FELTS + self.m * PORTEUSES_PAR_ENTREE + self.m + j
        }

        /// Accumulateur d'équilibre chaîné.
        pub(crate) const fn s_col(self) -> usize {
            ROOT_C + DIGEST_FELTS + self.m * PORTEUSES_PAR_ENTREE + self.m + self.n
        }

        /// Largeur totale de la trace pour cette forme.
        pub(crate) const fn width(self) -> usize {
            self.s_col() + 1
        }
    }

    /// Retrouve la forme à partir de la LARGEUR de trace. La correspondance
    /// `largeur → (m, n)` est BIJECTIVE sur `1..=MAX × 1..=MAX` (chaque entrée pèse
    /// 13 colonnes, chaque sortie 1 : `13·(m−2) + (n−2)` ne collisionne pas pour
    /// `|Δn| < 13`), garde `bijection_largeur_forme`.
    ///
    /// C'est ce qui permet à l'AIR de structurer ses contraintes sur la largeur
    /// RÉELLEMENT COMMISE (jamais un indice hors du cadre), la liaison de la FORME
    /// aux publics restant assurée par Fiat-Shamir (`to_elements` préfixe m, n).
    pub(crate) fn forme_depuis_largeur(largeur: usize) -> Option<Forme> {
        (1..=MAX_IN)
            .flat_map(|m| (1..=MAX_OUT).map(move |n| (m, n)))
            .find_map(|(m, n)| {
                Forme::new(m, n)
                    .ok()
                    .filter(|f| f.width() == largeur)
            })
    }

    // La forme MAXIMALE tient dans le budget winterfell — garde compile-time :
    // si un futur MAX la fait déborder, la compilation échoue, pas la production.
    const FORME_MAX: Forme = match Forme::new(MAX_IN, MAX_OUT) {
        Ok(f) => f,
        Err(_) => panic!("bornes MAX invalides"),
    };
    const _: () = assert!(FORME_MAX.width() <= winterfell::TraceInfo::MAX_TRACE_WIDTH);

    /// Largeur du TAMPON de construction de trace : celle de la forme MAXIMALE.
    /// Le tampon est transient (mémoire de travail du prouveur) ; la trace ÉMISE
    /// garde la largeur de la FORME (spec D2) — les colonnes du tampon au-delà de
    /// `forme.width()` ne sont jamais copiées dans la TraceTable.
    pub(crate) const WIDTH_MAX: usize = FORME_MAX.width();
    // Et F22 reproduit exactement la géométrie des constantes historiques.
    const _: () = assert!(Forme::F22.width() == WIDTH);
    const _: () = assert!(Forme::F22.s_col() == S_COL);

    // Garde-fous COMPILE-TIME de la géométrie (voir aussi ceux du mod tests) :
    // le plancher IN couvre la pile d'éponge, les bits du range-check, et pave
    // en blocs de Merkle entiers ; OUT couvre l'éponge de commitment et les bits.
    const _: () = assert!(MIN_IN_LEN >= NF_ROWS_END);
    const _: () = assert!(MIN_IN_LEN >= crate::range_check::RANGE_BITS);
    const _: () = assert!(MIN_IN_LEN.is_multiple_of(MERKLE_LEVEL_ROWS));
    const _: () = assert!(MIN_IN_LEN.is_power_of_two());
    const _: () = assert!(OUT_LEN >= CM_ROWS_END);
    const _: () = assert!(OUT_LEN >= crate::range_check::RANGE_BITS);
    // Le bloc KEY tient dans la largeur d'un segment, et son calcul tient dans sa longueur.
    const _: () = assert!(SEG_KEY_OFF + SEG_KEY_W <= SEG_WIDTH);
    const _: () = assert!(KEY_USED_ROWS <= KEY_LEN);

    // ALIGNEMENT SUR LE CYCLE DE MERKLE — invariant STRUCTUREL, pas accidentel.
    // Les colonnes périodiques du chemin de Merkle sont cycliques de période
    // MERKLE_LEVEL_ROWS et s'alignent sur `row % MERKLE_LEVEL_ROWS`. Si CHAQUE
    // longueur de segment est un multiple de 16, alors chaque `seg_start` (somme
    // cumulée de longueurs) l'est aussi, quel que soit le schedule — y compris les
    // schedules variables de 3z-c2. C'est la garde qui rend la généralisation sûre.
    const _: () = assert!(KEY_LEN.is_multiple_of(MERKLE_LEVEL_ROWS));
    const _: () = assert!(OUT_LEN.is_multiple_of(MERKLE_LEVEL_ROWS));
    // (in_len = max(MIN_IN_LEN, 16·depth) : MIN_IN_LEN multiple de 16 — asserté
    // ci-dessus — et 16·depth trivialement, donc in_len l'est pour tout depth.)
}
// Ré-export transitoirement non consommé : `seg_trace` (T2) et `seg_air` (T3)
// l'utiliseront. À dé-annoter dès T2.
#[allow(unused_imports)]
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
        const { assert!(SEG_KEY_OFF + SEG_KEY_W <= SEG_WIDTH) };
        // Sous-indices d'équilibre local dans le groupe.
        const { assert!(SEG_BAL_BIT < SEG_BALBIT_W && SEG_BAL_VACC < SEG_BALBIT_W) };
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
        const { assert!(WIDTH <= winterfell::TraceInfo::MAX_TRACE_WIDTH) };
    }

    #[test]
    fn longueurs_par_type_couvrent_leurs_gadgets() {
        // KEY : le CALCUL fait 1 bloc de permutation (owner/nk côte à côte en
        // colonnes) = 8 lignes, mais le SEGMENT en réserve 16 pour rester aligné sur
        // le cycle de Merkle (cf. doc de KEY_LEN). Les 8 lignes restantes sont
        // inactives.
        assert_eq!(KEY_USED_ROWS, crate::rescue_round::TRACE_LEN); // 8
        assert_eq!(KEY_LEN, MERKLE_LEVEL_ROWS); // 16
        const { assert!(KEY_USED_ROWS <= KEY_LEN) };
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
        const { assert!(OUT_LEN >= CM_ROWS_END, "éponge de commitment couverte") };
        const {
            assert!(
                OUT_LEN >= crate::range_check::RANGE_BITS,
                "bits de range couverts"
            )
        };
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
        // Frontières concrètes au consensus (profondeur 32) : KEY 16, IN 512.
        assert_eq!(seg_start(0, 32), 0);
        assert_eq!(seg_start(1, 32), 16);
        assert_eq!(seg_start(2, 32), 528);
        assert_eq!(seg_start(3, 32), 1040);
        assert_eq!(seg_start(4, 32), 1104);
        // INVARIANT D'ALIGNEMENT : chaque frontière de segment est un multiple de
        // MERKLE_LEVEL_ROWS, sans quoi les colonnes périodiques cycliques du chemin
        // de Merkle seraient déphasées dans les segments d'entrée (bug corrigé en T3).
        for depth in [2, 4, 16, 32] {
            for i in 0..N_SEGMENTS {
                assert_eq!(
                    seg_start(i, depth) % MERKLE_LEVEL_ROWS,
                    0,
                    "frontière du segment {i} @ depth {depth} désalignée du cycle Merkle"
                );
            }
        }
    }

    /// LA FORME 2/2 EST BIT-IDENTIQUE AUX CONSTANTES HISTORIQUES ÉPINGLÉES.
    ///
    /// Né pour rendre la bascule C2-T2/T3 sans risque, conservé après C2-T8 comme
    /// ÉPINGLE DE CONSENSUS : la 2/2 est la forme par défaut du wallet, des preuves
    /// existantes s'y vérifient — un refactor de `Forme` qui déplacerait un offset
    /// changerait l'AIR 2/2 en silence. Tant que ce test est vert, c'est impossible.
    #[test]
    fn forme_2_2_identique_aux_constantes() {
        let f = Forme::F22;
        assert_eq!(f.width(), WIDTH);
        assert_eq!(f.s_col(), S_COL);
        assert_eq!(f.n_segments(), N_SEGMENTS);
        for i in 0..2 {
            assert_eq!(f.rho_c(i), RHO_C[i], "rho[{i}]");
            assert_eq!(f.cm_c(i), CM_C[i], "cm[{i}]");
            assert_eq!(f.leaf_c(i), LEAF_C[i], "leaf[{i}]");
            assert_eq!(f.vin_c(i), VIN_C[i], "vin[{i}]");
            assert_eq!(f.vout_c(i), VOUT_C[i], "vout[{i}]");
        }
        let sched = schedule_2in2out();
        for (i, attendu) in sched.iter().enumerate() {
            assert_eq!(f.seg_kind(i), *attendu, "segment {i}");
        }
        for depth in [2, 4, 32] {
            assert_eq!(f.used_rows(depth), used_rows(depth));
            assert_eq!(f.trace_len(depth), trace_len(depth));
            for i in 0..N_SEGMENTS {
                assert_eq!(f.seg_start(i, depth), seg_start(i, depth));
            }
        }
    }

    /// Les BORNES vivent dans le constructeur : m/n nuls ou au-delà de MAX sont
    /// REFUSÉS. Une forme sans entrée n'a pas d'autorité de dépense ; sans sortie,
    /// pas de destinataire.
    /// `forme_depuis_largeur` est l'inverse EXACT de `Forme::width` sur les 16
    /// formes, et rend `None` pour une largeur qui n'est celle d'aucune forme. C'est
    /// ce qui autorise l'AIR à structurer ses contraintes sur la largeur commise sans
    /// jamais indexer hors du cadre.
    #[test]
    fn bijection_largeur_forme() {
        let mut vues = std::collections::HashSet::new();
        for m in 1..=MAX_IN {
            for n in 1..=MAX_OUT {
                let f = Forme::new(m, n).unwrap();
                assert!(vues.insert(f.width()), "largeur {} en collision", f.width());
                let retrouvee = forme_depuis_largeur(f.width()).expect("forme retrouvée");
                assert_eq!((retrouvee.m(), retrouvee.n()), (m, n));
            }
        }
        // Une largeur DANS UN TROU entre deux amas de formes. Chaque entrée pèse 13
        // colonnes, chaque sortie 1 (|Δsorties| ≤ 3) : il existe donc des largeurs
        // qu'aucune forme n'atteint — p.ex. `width(2,4) + 5` tombe avant le premier
        // `width(3, ·)`. C'est ce trou qui garantit qu'une largeur commise
        // correspond à AU PLUS une forme.
        let entre_amas = Forme::new(2, MAX_OUT).unwrap().width() + 5;
        assert!(forme_depuis_largeur(entre_amas).is_none(), "largeur {entre_amas}");
        assert!(forme_depuis_largeur(0).is_none());
    }

    #[test]
    fn formes_hors_bornes_refusees() {
        assert!(Forme::new(0, 1).is_err(), "m = 0 : aucune autorité");
        assert!(Forme::new(1, 0).is_err(), "n = 0 : aucun destinataire");
        assert!(Forme::new(MAX_IN + 1, 1).is_err());
        assert!(Forme::new(1, MAX_OUT + 1).is_err());
        assert!(Forme::new(1, 1).is_ok());
        assert!(Forme::new(MAX_IN, MAX_OUT).is_ok());
    }

    /// GÉOMÉTRIE PARAMÉTRIQUE : pour LES 16 FORMES, colonnes contiguës sans trou
    /// ni chevauchement, frontières de segments alignées sur le cycle de Merkle,
    /// pavage exact des lignes utiles.
    ///
    /// C'est la généralisation des tests 2/2 ci-dessus — un trou dans une forme
    /// rare (4/1…) ne se verrait dans aucun test à forme fixe, et une colonne
    /// chevauchée ferait s'écraser deux porteuses en silence : la preuve resterait
    /// VALIDE, sur un statement qui ne serait plus le bon.
    #[test]
    fn geometrie_parametrique_16_formes() {
        for m in 1..=MAX_IN {
            for n in 1..=MAX_OUT {
                let f = Forme::new(m, n).unwrap();
                let etiquette = format!("forme {m}/{n}");

                // Colonnes : blocs par entrée contigus, puis scalaires, puis S.
                let mut attendu = ROOT_C + DIGEST_FELTS;
                for i in 0..m {
                    assert_eq!(f.rho_c(i), attendu, "{etiquette} rho[{i}]");
                    assert_eq!(f.cm_c(i), f.rho_c(i) + DIGEST_FELTS, "{etiquette}");
                    assert_eq!(f.leaf_c(i), f.cm_c(i) + DIGEST_FELTS, "{etiquette}");
                    attendu = f.leaf_c(i) + DIGEST_FELTS;
                }
                for i in 0..m {
                    assert_eq!(f.vin_c(i), attendu, "{etiquette} vin[{i}]");
                    attendu += 1;
                }
                for j in 0..n {
                    assert_eq!(f.vout_c(j), attendu, "{etiquette} vout[{j}]");
                    attendu += 1;
                }
                assert_eq!(f.s_col(), attendu, "{etiquette} S");
                assert_eq!(f.width(), attendu + 1, "{etiquette} width");
                assert!(
                    f.width() <= winterfell::TraceInfo::MAX_TRACE_WIDTH,
                    "{etiquette} déborde winterfell"
                );

                // Schedule : 1 KEY puis m IN puis n OUT, rien d'autre.
                assert_eq!(f.seg_kind(0), SegKind::Key, "{etiquette}");
                for i in 1..=m {
                    assert_eq!(f.seg_kind(i), SegKind::Input, "{etiquette} seg {i}");
                }
                for i in (m + 1)..f.n_segments() {
                    assert_eq!(f.seg_kind(i), SegKind::Output, "{etiquette} seg {i}");
                }

                // Lignes : pavage contigu, frontières alignées cycle Merkle.
                for depth in [2, 4, 32] {
                    let mut cumul = 0;
                    for i in 0..f.n_segments() {
                        assert_eq!(
                            f.seg_start(i, depth),
                            cumul,
                            "{etiquette} depth {depth} seg {i}"
                        );
                        assert_eq!(
                            cumul % MERKLE_LEVEL_ROWS,
                            0,
                            "{etiquette} frontière désalignée du cycle Merkle"
                        );
                        cumul += seg_len(f.seg_kind(i), depth);
                    }
                    assert_eq!(f.used_rows(depth), cumul, "{etiquette} pavage exact");
                    let t = f.trace_len(depth);
                    assert!(t.is_power_of_two() && t >= cumul + BLIND_ROWS);
                }
            }
        }
        // Points de repère chiffrés de la spec (D1) : pire cas au consensus.
        let max = Forme::new(MAX_IN, MAX_OUT).unwrap();
        assert_eq!(max.width(), 120, "spec D1 : 92 + 2·13 + 2·1");
        assert_eq!(max.used_rows(32), 16 + 4 * 512 + 4 * 64);
        assert_eq!(max.trace_len(32), 4096);
        // Et la petite forme est bien MOINS large que la 2/2 : la largeur suit la
        // forme (spec D2), elle n'est pas payée au MAX.
        let petite = Forme::new(1, 2).unwrap();
        assert!(petite.width() < Forme::F22.width());
    }

    #[test]
    fn trace_len_avec_blinding() {
        // Consensus (profondeur 32) : 16 + 2·512 + 2·64 = 1168 lignes utiles.
        assert_eq!(used_rows(32), KEY_LEN + 2 * in_len(32) + 2 * OUT_LEN);
        assert_eq!(used_rows(32), 1168);
        assert_eq!(trace_len(32), (used_rows(32) + BLIND_ROWS).next_power_of_two());
        assert_eq!(trace_len(32), 2048);
        assert!(trace_len(32).is_power_of_two());
        assert!(trace_len(32) >= used_rows(32) + BLIND_ROWS);
        // Dev (profondeur 2) : 16 + 2·64 + 2·64 = 272 lignes utiles.
        assert_eq!(used_rows(2), KEY_LEN + 2 * MIN_IN_LEN + 2 * OUT_LEN);
        assert_eq!(trace_len(2), (used_rows(2) + BLIND_ROWS).next_power_of_two());
        assert_eq!(trace_len(2), 512);
    }
}
