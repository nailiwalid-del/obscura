//! AIR du monolithe SEGMENTÉ (3z-c1, tâche T3) — **sélecteurs et inventaire
//! périodique** (étapes 1 et 2a).
//!
//! Ce module porte les colonnes périodiques de la disposition segmentée, écrites
//! comme des FONCTIONS PURES et testables sans faire tourner le moindre prouveur :
//! une erreur de sélecteur se traduirait sinon par un échec de preuve illisible en
//! `--release`, le pire mode de débogage sur un circuit.
//!
//! Il expose ensuite `build_periodic`, qui construit TOUTES les colonnes **et leurs
//! index nommés en un seul passage** (`PeriodicIdx`). L'implémentation du trait
//! `winterfell::Air` (transitions, assertions, degrés) est l'étape 2b et lira ces
//! champs nommés — jamais des indices en dur.
//!
//! # Le renversement par rapport au côte-à-côte
//!
//! Dans `super::air`, les quatre éponges (2 entrées + 2 sorties) vivent sur des
//! COLONNES distinctes et partagent le même sélecteur de LIGNE (`sel_u`, `sel_o`).
//! Ici, elles partagent la même colonne et sont distinguées par leur SEGMENT de
//! lignes. Donc :
//!
//! - les familles de contraintes sont **mutualisées** (une seule famille d'éponge
//!   au lieu de quatre, un seul chemin de Merkle au lieu de deux) ;
//! - mais chaque liaison ancrée à une ligne précise a besoin de SON sélecteur
//!   mono-ligne, ancré à `seg_start(i) + ancre_locale` (cf. `at_abs`).
//!
//! # Alignement
//!
//! Les colonnes périodiques CYCLIQUES (éponge cycle 8, Merkle cycle 16) ne sont pas
//! reconstruites ici : elles restent valides telles quelles parce que chaque
//! `seg_start` est un multiple de `MERKLE_LEVEL_ROWS` (garde compile-time de
//! `seg_layout`). C'est précisément ce que le passage `KEY_LEN` 8 → 16 a assuré.

use super::air::{push_preamble, MonolithPublicInputs};
use super::seg_layout::*;
use super::seg_trace::build_seg_trace;
use super::trace::MonolithWitness;
use crate::merkle_path::enforce_merkle_transition;
use crate::rescue_round::{enforce_round_block, STATE_WIDTH};
use crate::sponge::{enforce_sponge_transition, RATE_START};
use crate::ValidityProof;
use proved_hash::digest::DIGEST_FELTS;
use proved_hash::domain::Domain;
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;
use winterfell::crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree};
use winterfell::matrix::ColMatrix;
use winterfell::{
    AirContext, Assertion, AuxRandElements, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, EvaluationFrame, PartitionOptions, ProofOptions, Prover, StarkDomain,
    TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

type Blake3 = Blake3_256<BaseElement>;

/// Construit une colonne pleine longueur `l` en évaluant `f(kind, i, local)` sur
/// chaque ligne appartenant à un segment, et `ZERO` hors des segments (traîne
/// idle et région de blinding).
///
/// `kind` = type du segment, `i` = son index dans le schedule, `local` = ligne
/// relative au début du segment. C'est LE point de passage unique du layout
/// segmenté vers les sélecteurs : toute colonne pleine longueur se bâtit ainsi,
/// ce qui garantit qu'aucune n'oublie un segment ni ne déborde du sien.
pub(crate) fn par_segment(
    depth: usize,
    l: usize,
    f: impl Fn(SegKind, usize, usize) -> BaseElement,
) -> Vec<BaseElement> {
    let mut col = vec![BaseElement::ZERO; l];
    for (i, kind) in schedule_2in2out().iter().enumerate() {
        let start = seg_start(i, depth);
        let n = seg_len(*kind, depth);
        for local in 0..n {
            let row = start + local;
            if row < l {
                col[row] = f(*kind, i, local);
            }
        }
    }
    col
}

/// Sélecteur mono-ligne à la ligne ABSOLUE `r0` (motif `at` du côte-à-côte, mais
/// l'ancre est calculée `seg_start(i) + ancre_locale` par l'appelant).
///
/// ⚠️ Ne jamais ancrer en `l − 1` : la transition de la dernière ligne est exclue
/// du domaine d'enforcement de winterfell, une liaison y serait inopérante.
pub(crate) fn at_abs(l: usize, r0: usize) -> Vec<BaseElement> {
    let mut col = vec![BaseElement::ZERO; l];
    if r0 < l {
        col[r0] = BaseElement::ONE;
    }
    col
}

const fn est_unite(kind: SegKind) -> bool {
    matches!(kind, SegKind::Input | SegKind::Output)
}

/// `sel_key` : rondes de clé. Actif sur les transitions `local < KEY_USED_ROWS − 1`
/// des segments `Key`.
///
/// ⚠️ `KEY_USED_ROWS` (8), PAS `KEY_LEN` (16) : le segment réserve 16 lignes pour
/// l'alignement sur le cycle de Merkle, mais le calcul de clé n'en occupe que 8 —
/// les 8 dernières doivent rester INACTIVES.
pub(crate) fn sel_key(depth: usize, l: usize) -> Vec<BaseElement> {
    par_segment(depth, l, |kind, _, local| {
        if kind == SegKind::Key && local + 1 < KEY_USED_ROWS {
            BaseElement::ONE
        } else {
            BaseElement::ZERO
        }
    })
}

/// `sel_sponge` : famille d'éponge MUTUALISÉE (là où le côte-à-côte avait `sel_u`
/// et `sel_o` séparés, sur des colonnes distinctes).
///
/// - segment `Input` : pile cm→feuille→nullifier, active sur `local < NF_ROWS_END`
///   SAUF les frontières de bloc 31/39/55 (absorption, pas de ronde) ;
/// - segment `Output` : commitment seul, actif sur `local < CM_ROWS_END − 1`.
pub(crate) fn sel_sponge(depth: usize, l: usize) -> Vec<BaseElement> {
    par_segment(depth, l, |kind, _, local| {
        let actif = match kind {
            SegKind::Input => {
                local < NF_ROWS_END
                    && local != CM_ROWS_END - 1
                    && local != LEAF_ROWS_END - 1
                    && local != NF_ROWS_END - 1
            }
            SegKind::Output => local + 1 < CM_ROWS_END,
            SegKind::Key => false,
        };
        if actif {
            BaseElement::ONE
        } else {
            BaseElement::ZERO
        }
    })
}

/// `sel_m` : chemin de Merkle, actif sur les segments `Input` uniquement, sur
/// `local < MERKLE_LEVEL_ROWS·depth − 1` (au-delà, le segment est idle : `in_len`
/// vaut `max(64, 16·depth)`, donc à faible profondeur il reste des lignes libres).
pub(crate) fn sel_m(depth: usize, l: usize) -> Vec<BaseElement> {
    let last = MERKLE_LEVEL_ROWS * depth - 1;
    par_segment(depth, l, |kind, _, local| {
        if kind == SegKind::Input && local < last {
            BaseElement::ONE
        } else {
            BaseElement::ZERO
        }
    })
}

/// `sel_bal` : équilibre actif sur tout segment `Input`/`Output`.
pub(crate) fn sel_bal(depth: usize, l: usize) -> Vec<BaseElement> {
    par_segment(depth, l, |kind, _, _| {
        if est_unite(kind) {
            BaseElement::ONE
        } else {
            BaseElement::ZERO
        }
    })
}

/// `signe` : **+1** sur `Input`, **−1** sur `Output`, **0** sur `Key` et hors
/// segments.
///
/// C'est ce zéro qui tient `S` CONSTANT là où il ne doit pas bouger (segment de
/// clé, traîne idle) sans gating supplémentaire — même astuce qu'en côte-à-côte.
pub(crate) fn signe(depth: usize, l: usize) -> Vec<BaseElement> {
    par_segment(depth, l, |kind, _, _| match kind {
        SegKind::Input => BaseElement::ONE,
        SegKind::Output => -BaseElement::ONE,
        SegKind::Key => BaseElement::ZERO,
    })
}

/// `pow` : poids `2^local` du bit de rang `local`, sur les segments `Input`/
/// `Output`, nul dès `local >= RANGE_BITS`.
///
/// ⚠️ Le poids est RELATIF au segment. Un poids global (`2^row`) permettrait de
/// décomposer un montant avec les poids d'un autre segment — c'est l'une des cinq
/// vérifications de soundness de l'équilibre chaîné.
pub(crate) fn pow(depth: usize, l: usize) -> Vec<BaseElement> {
    par_segment(depth, l, |kind, _, local| {
        if est_unite(kind) && local < crate::range_check::RANGE_BITS {
            BaseElement::new(1u64 << local)
        } else {
            BaseElement::ZERO
        }
    })
}

/// `endblk` : 1 sur la DERNIÈRE ligne de chaque segment `Input`/`Output` — c'est
/// elle qui remet `VACC` à zéro pour le segment suivant.
pub(crate) fn endblk(depth: usize, l: usize) -> Vec<BaseElement> {
    par_segment(depth, l, |kind, i, local| {
        if est_unite(kind) && local + 1 == seg_len(schedule_2in2out()[i], depth) {
            BaseElement::ONE
        } else {
            BaseElement::ZERO
        }
    })
}

/// `blind_off` (witness-hiding 3z-b1) : 1 ssi la transition `r → r+1` reste DANS la
/// région utile. Éteint toutes les familles sur le saut vers l'aléa et sur la
/// région de blinding. Identique au côte-à-côte.
pub(crate) fn blind_off(depth: usize, l: usize) -> Vec<BaseElement> {
    let used = used_rows(depth);
    (0..l)
        .map(|r| {
            if r + 1 < used {
                BaseElement::ONE
            } else {
                BaseElement::ZERO
            }
        })
        .collect()
}

// ================================================================================================
// INVENTAIRE NOMMÉ DES COLONNES PÉRIODIQUES
// ================================================================================================
//
// Le côte-à-côte indexe ses 49 colonnes périodiques EN DUR (`pv[37]`, `pv[38]`, …
// `pv[48]`). La disposition segmentée en compte ~59 — parce que chaque liaison a
// besoin de son propre sélecteur mono-ligne ancré à SON segment (là où le
// côte-à-côte partageait un sélecteur de ligne et distinguait par la colonne).
//
// À cette échelle, l'indexation brute est un piège : une contrainte lisant le
// mauvais `pv[..]` produit une AIR silencieusement fausse — pas une erreur de
// compilation, pas un test rouge, juste une soundness perdue. On construit donc
// les colonnes ET leurs index dans le MÊME passage, et `evaluate_transition`
// (étape 2b) lira des champs nommés.

/// Ancres LOCALES d'un segment d'entrée (lignes relatives au début du segment),
/// dans l'ordre de `PeriodicIdx::anc_in`. Identiques au côte-à-côte : ce sont des
/// positions DANS la pile d'éponge, que la segmentation ne déplace pas — seule
/// leur adresse absolue change (`seg_start(i) + ancre`).
pub(crate) const ANCRES_IN: [usize; 7] = [0, 7, 31, 32, 39, 40, 47];

// Index symboliques dans `ANCRES_IN` / `anc_in[i]`.
pub(crate) const A_S0: usize = 0; // owner conso, feuille conso (chemin), vin prod
pub(crate) const A_S7: usize = 1; // rho conso (préambule commitment)
pub(crate) const A_S31: usize = 2; // cm prod (digest commitment)
pub(crate) const A_S32: usize = 3; // cm conso (préambule feuille)
pub(crate) const A_S39: usize = 4; // feuille prod (digest feuille)
pub(crate) const A_S40: usize = 5; // nk + rho0 conso (préambule nullifier)
pub(crate) const A_S47: usize = 6; // rho1..3 + cm conso (nullifier)

/// Index (dans le vecteur rendu par `build_periodic`) de chaque colonne périodique.
/// Remplace les `pv[37]` magiques du côte-à-côte.
#[derive(Debug, Clone)]
pub(crate) struct PeriodicIdx {
    // --- cycliques (inchangées : l'alignement 16 des seg_start les rend valides) ---
    pub round_flag_s: usize,
    /// Début des 12 colonnes ARK1 (les 12 suivantes sont ARK2).
    pub ark1: usize,
    pub ark2: usize,
    pub round_flag_m: usize,
    pub init0: usize,
    pub init7: usize,
    pub chain: usize,
    // --- pleine longueur, bâties par segment ---
    pub sel_key: usize,
    pub sel_sponge: usize,
    pub sel_m: usize,
    pub sel_bal: usize,
    pub signe: usize,
    pub pow: usize,
    pub endblk: usize,
    pub blind_off: usize,
    // --- ancres de liaison, une par (segment, ancre) ---
    /// Ligne 0 du segment KEY : liaison secret owner↔nk.
    pub s0_key: usize,
    /// Ligne 7 du segment KEY : production owner et nk.
    pub s7_key: usize,
    /// `anc_in[i][A_*]` : ancre `ANCRES_IN[A_*]` du i-ème segment d'ENTRÉE.
    pub anc_in: [[usize; ANCRES_IN.len()]; 2],
    /// Ligne `RANGE_BITS` du i-ème segment d'entrée : consommation VACC (montant plein).
    pub vacc_in: [usize; 2],
    /// Dernière ligne du chemin de Merkle du i-ème segment d'entrée
    /// (`16·depth − 1`) : liaison « racine repliée == porteuse `ROOT_C` ».
    ///
    /// NOUVEAU en segmenté : le côte-à-côte assertait `root` publiquement sur
    /// CHAQUE `M_i` ; ici `root` est assertée une seule fois sur la porteuse, et
    /// chaque entrée s'y raccroche par cette liaison.
    pub root_in: [usize; 2],
    /// Ligne 0 du j-ème segment de SORTIE : production vout.
    pub s0_out: [usize; 2],
    /// Ligne `RANGE_BITS` du j-ème segment de sortie : consommation VACC.
    pub vacc_out: [usize; 2],
    /// Nombre total de colonnes périodiques.
    pub total: usize,
}

/// Construit TOUTES les colonnes périodiques et leurs index, en un seul passage.
///
/// L'unicité du passage est ce qui garantit la cohérence : un index ne peut pas
/// désigner une autre colonne que celle qui vient d'être poussée.
pub(crate) fn build_periodic(depth: usize, l: usize) -> (PeriodicIdx, Vec<Vec<BaseElement>>) {
    let mut cols: Vec<Vec<BaseElement>> = Vec::new();
    let z = BaseElement::ZERO;
    let o = BaseElement::ONE;

    let push = |cols: &mut Vec<Vec<BaseElement>>, c: Vec<BaseElement>| -> usize {
        cols.push(c);
        cols.len() - 1
    };

    // --- Cycliques (identiques au côte-à-côte). ---
    let mut rf_s = vec![o; 8];
    rf_s[7] = z;
    let round_flag_s = push(&mut cols, rf_s);

    let ark = crate::rescue_round::periodic_ark_columns();
    let ark1 = cols.len();
    for c in ark {
        cols.push(c);
    }
    let ark2 = ark1 + crate::rescue_round::STATE_WIDTH;

    let round_flag_m = push(
        &mut cols,
        (0..MERKLE_LEVEL_ROWS)
            .map(|p| if p == 7 || p == 15 { z } else { o })
            .collect(),
    );
    let init0 = push(
        &mut cols,
        (0..MERKLE_LEVEL_ROWS).map(|p| if p == 0 { o } else { z }).collect(),
    );
    let init7 = push(
        &mut cols,
        (0..MERKLE_LEVEL_ROWS).map(|p| if p == 7 { o } else { z }).collect(),
    );
    let chain = push(
        &mut cols,
        (0..MERKLE_LEVEL_ROWS).map(|p| if p == 15 { o } else { z }).collect(),
    );

    // --- Pleine longueur (étape 1). ---
    let sel_key = push(&mut cols, self::sel_key(depth, l));
    let sel_sponge = push(&mut cols, self::sel_sponge(depth, l));
    let sel_m = push(&mut cols, self::sel_m(depth, l));
    let sel_bal = push(&mut cols, self::sel_bal(depth, l));
    let signe = push(&mut cols, self::signe(depth, l));
    let pow = push(&mut cols, self::pow(depth, l));
    let endblk = push(&mut cols, self::endblk(depth, l));
    let blind_off = push(&mut cols, self::blind_off(depth, l));

    // --- Ancres de liaison, adressées `seg_start(i) + ancre_locale`. ---
    let schedule = schedule_2in2out();
    let idx_de = |voulu: SegKind| -> Vec<usize> {
        schedule
            .iter()
            .enumerate()
            .filter(|(_, k)| **k == voulu)
            .map(|(i, _)| i)
            .collect()
    };
    let ins = idx_de(SegKind::Input);
    let outs = idx_de(SegKind::Output);
    debug_assert_eq!((ins.len(), outs.len()), (2, 2));

    let key_start = seg_start(0, depth);
    let s0_key = push(&mut cols, at_abs(l, key_start));
    let s7_key = push(&mut cols, at_abs(l, key_start + 7));

    let mut anc_in = [[0usize; ANCRES_IN.len()]; 2];
    let mut vacc_in = [0usize; 2];
    let mut root_in = [0usize; 2];
    for (n, &i) in ins.iter().enumerate() {
        let s = seg_start(i, depth);
        for (a, &ancre) in ANCRES_IN.iter().enumerate() {
            anc_in[n][a] = push(&mut cols, at_abs(l, s + ancre));
        }
        vacc_in[n] = push(&mut cols, at_abs(l, s + crate::range_check::RANGE_BITS));
        // Dernière ligne du chemin : racine repliée == porteuse ROOT_C.
        root_in[n] = push(&mut cols, at_abs(l, s + MERKLE_LEVEL_ROWS * depth - 1));
    }

    let mut s0_out = [0usize; 2];
    let mut vacc_out = [0usize; 2];
    for (n, &j) in outs.iter().enumerate() {
        let s = seg_start(j, depth);
        s0_out[n] = push(&mut cols, at_abs(l, s));
        vacc_out[n] = push(&mut cols, at_abs(l, s + crate::range_check::RANGE_BITS));
    }

    let total = cols.len();
    (
        PeriodicIdx {
            round_flag_s,
            ark1,
            ark2,
            round_flag_m,
            init0,
            init7,
            chain,
            sel_key,
            sel_sponge,
            sel_m,
            sel_bal,
            signe,
            pow,
            endblk,
            blind_off,
            s0_key,
            s7_key,
            anc_in,
            vacc_in,
            root_in,
            s0_out,
            vacc_out,
            total,
        },
        cols,
    )
}

// ================================================================================================
// FAMILLES DE CONTRAINTES (ordre figé pour `result` / `degrees`)
// ================================================================================================
//
// Recomptées pour la disposition segmentée — surtout PAS recopiées du côte-à-côte.
// La mutualisation fait fondre les familles répétées (4 éponges → 1, 2 chemins → 1)
// tandis que la porteuse `ROOT_C` et ses liaisons en ajoutent.

const N_KEY: usize = 2 * STATE_WIDTH; // 24 : rondes owner + nk
const N_SPONGE: usize = STATE_WIDTH; // 12 : UNE famille (était 4×12 = 48)
const N_MERKLE: usize = 30; // UNE famille (était 2×30 = 60)
const N_BAL: usize = 3; // bit booléen, S chaîné, VACC
/// Porteuses = toutes les colonnes partagées SAUF `S_COL` (qui n'est pas constante :
/// elle est chaînée). Bloc contigu `SHARED_OFF..S_COL`.
const N_CARRIER: usize = S_COL - SHARED_OFF; // 40 (36 + ROOT_C)
const N_BASE: usize = N_KEY + N_SPONGE + N_MERKLE + N_BAL + N_CARRIER; // 109

const N_SECRET: usize = DIGEST_FELTS; // liaison secret owner↔nk
const N_OWNER: usize = 3 * DIGEST_FELTS; // prod (clé) + 2 conso (commitments)
const N_NK: usize = 3 * DIGEST_FELTS; // prod (clé) + 2 conso (nullifiers)
const N_RHO: usize = 2 * (2 * DIGEST_FELTS); // par entrée : @7(4) + @40(1) + @47(3)
const N_CM: usize = 2 * (3 * DIGEST_FELTS); // par entrée : @31 + @32 + @47
const N_LEAF: usize = 2 * (2 * DIGEST_FELTS); // par entrée : prod @39 + conso @0 (chemin)
/// NOUVEAU en segmenté : la racine repliée de CHAQUE entrée == porteuse `ROOT_C`.
/// Le côte-à-côte assertait `root` publiquement sur chaque `M_i` ; ici elle est
/// assertée une seule fois sur la porteuse, et sans cette liaison les deux entrées
/// pourraient se replier vers des racines DIFFÉRENTES.
const N_ROOT: usize = 2 * DIGEST_FELTS;
const N_VIN: usize = 4; // 2 × (prod @0 + conso VACC)
const N_VOUT: usize = 4; // 2 × (prod @0 + conso VACC)
const N_LIAISON: usize =
    N_SECRET + N_OWNER + N_NK + N_RHO + N_CM + N_LEAF + N_ROOT + N_VIN + N_VOUT; // 100
const N_CONSTRAINTS: usize = N_BASE + N_LIAISON; // 209 (vs 263 côte-à-côte)

/// Nombre d'assertions publiques.
///
/// KEY(16) + 2·IN(43) + 2·chemin(12·depth) + root(4) + 2·OUT(27) + BAL(3).
/// Écart avec le côte-à-côte (`167 + 24·depth`) : **−4**, parce que `root` est
/// assertée UNE fois sur la porteuse au lieu d'une fois par chemin.
fn num_assertions(depth: usize) -> usize {
    16 + 2 * 43 + 2 * (12 * depth) + 4 + 2 * 27 + 3
}

// ================================================================================================
// AIR
// ================================================================================================

pub(crate) struct SegMonolithAir {
    context: AirContext<BaseElement>,
    pi: MonolithPublicInputs,
    l: usize,
    depth: usize,
    /// Index NOMMÉS des colonnes périodiques, calculés une fois à la construction.
    /// `evaluate_transition` les lit par nom — jamais d'indice en dur.
    ix: PeriodicIdx,
}

impl winterfell::Air for SegMonolithAir {
    type BaseField = BaseElement;
    type PublicInputs = MonolithPublicInputs;

    fn new(trace_info: TraceInfo, pi: MonolithPublicInputs, options: ProofOptions) -> Self {
        // Witness-hiding : mêmes exigences qu'en côte-à-côte (cf. super::air::new).
        assert!(
            BLIND_ROWS >= options.num_queries() + 4,
            "BLIND_ROWS ({}) doit couvrir num_queries + 4 ({})",
            BLIND_ROWS,
            options.num_queries() + 4
        );
        let l = trace_info.length();
        let depth = pi.depth;
        let (ix, _) = build_periodic(depth, l);
        let context = AirContext::new(trace_info, degrees(l), num_assertions(depth), options);
        SegMonolithAir { context, pi, l, depth, ix }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        pv: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let next = frame.next();
        let one = E::ONE;
        let ix = &self.ix;

        // --- Colonnes périodiques, lues par NOM (jamais par index en dur). ---
        let round_flag_s = pv[ix.round_flag_s];
        let ark1 = &pv[ix.ark1..ix.ark1 + STATE_WIDTH];
        let ark2 = &pv[ix.ark2..ix.ark2 + STATE_WIDTH];
        let round_flag_m = pv[ix.round_flag_m];
        let init0 = pv[ix.init0];
        let init7 = pv[ix.init7];
        let chain = pv[ix.chain];
        let sel_key = pv[ix.sel_key];
        let sel_sponge = pv[ix.sel_sponge];
        let sel_m = pv[ix.sel_m];
        let sel_bal = pv[ix.sel_bal];
        let signe = pv[ix.signe];
        let pow = pv[ix.pow];
        let endblk = pv[ix.endblk];
        let blind_off = pv[ix.blind_off];
        let rate = RATE_START;

        let mut idx = 0;

        // --- KEY : 2 blocs de rondes (owner ‖ nk), gatés sel_key. ---
        {
            let mut tmp = [E::ZERO; N_KEY];
            let k = &cur[SEG_KEY_OFF..SEG_KEY_OFF + N_KEY];
            let kn = &next[SEG_KEY_OFF..SEG_KEY_OFF + N_KEY];
            enforce_round_block(k, kn, 0, ark1, ark2, &mut tmp);
            enforce_round_block(k, kn, STATE_WIDTH, ark1, ark2, &mut tmp);
            for (r, t) in tmp.iter().enumerate() {
                result[idx + r] = sel_key * *t;
            }
            idx += N_KEY;
        }

        // --- ÉPONGE MUTUALISÉE : la même colonne sert la pile des entrées ET le
        //     commitment des sorties ; c'est le SEGMENT (donc sel_sponge) qui dit
        //     lequel. Là où le côte-à-côte écrivait quatre fois cette famille. ---
        {
            let mut tmp = [E::ZERO; N_SPONGE];
            enforce_sponge_transition(
                &cur[SEG_SPONGE_OFF..SEG_SPONGE_OFF + SEG_SPONGE_W],
                &next[SEG_SPONGE_OFF..SEG_SPONGE_OFF + SEG_SPONGE_W],
                round_flag_s,
                ark1,
                ark2,
                &mut tmp,
            );
            for (r, t) in tmp.iter().enumerate() {
                result[idx + r] = sel_sponge * *t;
            }
            idx += N_SPONGE;
        }

        // --- CHEMIN DE MERKLE : une seule famille, gatée sel_m (segments IN). ---
        {
            let mut tmp = [E::ZERO; N_MERKLE];
            enforce_merkle_transition(
                &cur[SEG_MERKLE_OFF..SEG_MERKLE_OFF + SEG_MERKLE_W],
                &next[SEG_MERKLE_OFF..SEG_MERKLE_OFF + SEG_MERKLE_W],
                round_flag_m,
                ark1,
                ark2,
                init0,
                init7,
                chain,
                &mut tmp,
            );
            for (r, t) in tmp.iter().enumerate() {
                result[idx + r] = sel_m * *t;
            }
            idx += N_MERKLE;
        }

        // --- ÉQUILIBRE CHAÎNÉ. `signe` vaut 0 sur KEY et hors segments : S y reste
        //     constant SANS gating supplémentaire. `pow` est relatif au segment. ---
        {
            let bit = cur[SEG_BALBIT_OFF + SEG_BAL_BIT];
            let s = cur[S_COL];
            let s_next = next[S_COL];
            let vacc = cur[SEG_BALBIT_OFF + SEG_BAL_VACC];
            let vacc_next = next[SEG_BALBIT_OFF + SEG_BAL_VACC];
            result[idx] = sel_bal * bit * (bit - one);
            result[idx + 1] = s_next - s - signe * bit * pow;
            result[idx + 2] = sel_bal * (vacc_next - (one - endblk) * (vacc + bit * pow));
            idx += N_BAL;
        }

        // --- PORTEUSES : constantes sur la région utile (bloc contigu, S_COL exclue).
        //     Le gating blind_off est appliqué par la boucle globale en fin. ---
        for c in 0..N_CARRIER {
            result[idx + c] = next[SHARED_OFF + c] - cur[SHARED_OFF + c];
        }
        idx += N_CARRIER;
        debug_assert_eq!(idx, N_BASE);

        // ============================================================================
        // LIAISONS — motif `sel_ancre · (cur[porteuse] − cur[cellule])`.
        //
        // Différence CLÉ avec le côte-à-côte : là-bas l'entrée était distinguée par
        // l'offset de COLONNE (`u_off`) avec un sélecteur de ligne partagé. Ici la
        // colonne est la même pour les deux entrées et c'est le SÉLECTEUR qui porte
        // le segment (`ix.anc_in[n][..]`). Une ancre qui désignerait le mauvais
        // segment lierait la porteuse d'une entrée aux cellules de l'autre.
        // ============================================================================
        let sp = SEG_SPONGE_OFF;

        // SECRET : le secret du bloc owner == celui du bloc nk (anti-double-dépense).
        {
            let s0k = pv[ix.s0_key];
            for k in 0..DIGEST_FELTS {
                result[idx + k] =
                    s0k * (cur[SEG_KEY_OFF + 7 + k] - cur[SEG_KEY_OFF + STATE_WIDTH + 7 + k]);
            }
            idx += N_SECRET;
        }

        // OWNER : production @7 du segment KEY, consommation @0 de chaque entrée.
        {
            let s7k = pv[ix.s7_key];
            for k in 0..DIGEST_FELTS {
                result[idx + k] = s7k * (cur[OWNER_C + k] - cur[SEG_KEY_OFF + rate + k]);
            }
            idx += DIGEST_FELTS;
            for n in 0..2 {
                let s0 = pv[ix.anc_in[n][A_S0]];
                for k in 0..DIGEST_FELTS {
                    result[idx + k] = s0 * (cur[OWNER_C + k] - cur[sp + 8 + k]);
                }
                idx += DIGEST_FELTS;
            }
        }

        // NK : production @7 (bloc nk de la clé), consommation @40 de chaque entrée.
        {
            let s7k = pv[ix.s7_key];
            for k in 0..DIGEST_FELTS {
                result[idx + k] =
                    s7k * (cur[NK_C + k] - cur[SEG_KEY_OFF + STATE_WIDTH + rate + k]);
            }
            idx += DIGEST_FELTS;
            for n in 0..2 {
                let s40 = pv[ix.anc_in[n][A_S40]];
                for k in 0..DIGEST_FELTS {
                    result[idx + k] = s40 * (cur[NK_C + k] - cur[sp + 7 + k]);
                }
                idx += DIGEST_FELTS;
            }
        }

        // RHO : le rho du nullifier == celui du commitment (v0.2, nf lié au cm).
        for n in 0..2 {
            let s7 = pv[ix.anc_in[n][A_S7]];
            let s40 = pv[ix.anc_in[n][A_S40]];
            let s47 = pv[ix.anc_in[n][A_S47]];
            for k in 0..DIGEST_FELTS {
                result[idx + k] = s7 * (cur[RHO_C[n] + k] - cur[sp + 12 + k]);
            }
            idx += DIGEST_FELTS;
            result[idx] = s40 * (cur[RHO_C[n]] - cur[sp + 11]);
            idx += 1;
            for j in 0..DIGEST_FELTS - 1 {
                result[idx + j] = s47 * (cur[RHO_C[n] + 1 + j] - cur[sp + 12 + j]);
            }
            idx += DIGEST_FELTS - 1;
        }

        // CM : le commitment produit gouverne la feuille ET le nullifier (P1).
        for n in 0..2 {
            let s31 = pv[ix.anc_in[n][A_S31]];
            let s32 = pv[ix.anc_in[n][A_S32]];
            let s47 = pv[ix.anc_in[n][A_S47]];
            for k in 0..DIGEST_FELTS {
                result[idx + k] = s31 * (cur[CM_C[n] + k] - cur[sp + rate + k]);
            }
            idx += DIGEST_FELTS;
            for k in 0..DIGEST_FELTS {
                result[idx + k] = s32 * (cur[CM_C[n] + k] - cur[sp + 7 + k]);
            }
            idx += DIGEST_FELTS;
            for k in 0..DIGEST_FELTS {
                result[idx + k] = s47 * (cur[CM_C[n] + k] - cur[sp + 15 + k]);
            }
            idx += DIGEST_FELTS;
        }

        // FEUILLE↔CHEMIN : la feuille produite == celle injectée dans le chemin.
        for n in 0..2 {
            let s39 = pv[ix.anc_in[n][A_S39]];
            let s0 = pv[ix.anc_in[n][A_S0]];
            for k in 0..DIGEST_FELTS {
                result[idx + k] = s39 * (cur[LEAF_C[n] + k] - cur[sp + rate + k]);
            }
            idx += DIGEST_FELTS;
            for k in 0..DIGEST_FELTS {
                result[idx + k] = s0 * (cur[LEAF_C[n] + k] - cur[SEG_MERKLE_OFF + 20 + k]);
            }
            idx += DIGEST_FELTS;
        }

        // RACINE (nouveau) : la racine repliée de chaque entrée == porteuse ROOT_C.
        // Sans elle, les deux entrées pourraient prouver contre des racines
        // DIFFÉRENTES (chacune valide isolément) — trou créé par la mutualisation.
        for n in 0..2 {
            let sr = pv[ix.root_in[n]];
            for k in 0..DIGEST_FELTS {
                result[idx + k] = sr * (cur[ROOT_C + k] - cur[SEG_MERKLE_OFF + rate + k]);
            }
            idx += DIGEST_FELTS;
        }

        // MONTANTS (P5) : la value de chaque commitment == le VACC de son segment.
        let vacc_col = SEG_BALBIT_OFF + SEG_BAL_VACC;
        for n in 0..2 {
            let s0 = pv[ix.anc_in[n][A_S0]];
            let vg = pv[ix.vacc_in[n]];
            result[idx] = s0 * (cur[VIN_C[n] ] - cur[sp + 7]);
            result[idx + 1] = vg * (cur[VIN_C[n]] - cur[vacc_col]);
            idx += 2;
        }
        for n in 0..2 {
            let s0 = pv[ix.s0_out[n]];
            let vg = pv[ix.vacc_out[n]];
            result[idx] = s0 * (cur[VOUT_C[n]] - cur[sp + 7]);
            result[idx + 1] = vg * (cur[VOUT_C[n]] - cur[vacc_col]);
            idx += 2;
        }

        debug_assert_eq!(idx, N_CONSTRAINTS);

        // --- Gating global witness-hiding (motif 3z-b1b conservé). ---
        for r in result.iter_mut() {
            *r *= blind_off;
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let d = self.depth;
        let mut a = Vec::with_capacity(num_assertions(d));
        let sp = SEG_SPONGE_OFF;
        let schedule = schedule_2in2out();
        let ins: Vec<usize> = schedule
            .iter()
            .enumerate()
            .filter(|(_, k)| **k == SegKind::Input)
            .map(|(i, _)| i)
            .collect();
        let outs: Vec<usize> = schedule
            .iter()
            .enumerate()
            .filter(|(_, k)| **k == SegKind::Output)
            .map(|(i, _)| i)
            .collect();

        // Segment KEY : éponges owner et nk.
        let ks = seg_start(0, d);
        push_preamble(&mut a, ks, SEG_KEY_OFF, 8, Domain::Owner.tag() as u64, DIGEST_FELTS);
        push_preamble(
            &mut a,
            ks,
            SEG_KEY_OFF + STATE_WIDTH,
            8,
            Domain::Nk.tag() as u64,
            DIGEST_FELTS,
        );

        // Segments d'ENTRÉE : préambules de la pile + nullifier public + préambules
        // de chaque merge du chemin. Toutes les lignes sont décalées de seg_start.
        for (n, &i) in ins.iter().enumerate() {
            let s = seg_start(i, d);
            push_preamble(&mut a, s + CM_ROWS_START, sp, 32, Domain::NoteCommitment.tag() as u64, 13);
            push_preamble(&mut a, s + LEAF_ROWS_START, sp, 8, Domain::MerkleLeaf.tag() as u64, 4);
            push_preamble(&mut a, s + NF_ROWS_START, sp, 16, Domain::Nullifier.tag() as u64, 12);
            for k in 0..DIGEST_FELTS {
                a.push(Assertion::single(
                    sp + RATE_START + k,
                    s + NF_ROWS_END - 1,
                    self.pi.nullifiers[n][k],
                ));
            }
            for b in 0..d {
                push_preamble(
                    &mut a,
                    s + b * MERKLE_LEVEL_ROWS,
                    SEG_MERKLE_OFF,
                    12,
                    Domain::MerkleNode.tag() as u64,
                    8,
                );
            }
        }

        // RACINE : assertée UNE SEULE FOIS sur la porteuse (les entrées s'y
        // raccrochent par la liaison `root_in`). Le côte-à-côte l'assertait sur
        // chaque chemin — d'où les 4 assertions économisées.
        for k in 0..DIGEST_FELTS {
            a.push(Assertion::single(ROOT_C + k, 0, self.pi.root[k]));
        }

        // Segments de SORTIE : préambule de commitment + commitment public.
        for (n, &j) in outs.iter().enumerate() {
            let s = seg_start(j, d);
            push_preamble(&mut a, s, sp, 32, Domain::NoteCommitment.tag() as u64, 13);
            for k in 0..DIGEST_FELTS {
                a.push(Assertion::single(
                    sp + RATE_START + k,
                    s + CM_ROWS_END - 1,
                    self.pi.output_commitments[n][k],
                ));
            }
        }

        // Équilibre : S part de 0, vaut fee à la dernière ligne utile.
        a.push(Assertion::single(S_COL, 0, BaseElement::ZERO));
        a.push(Assertion::single(
            S_COL,
            used_rows(d) - 1,
            BaseElement::new(self.pi.fee),
        ));
        // VACC du PREMIER segment d'unité : sinon témoin libre (aucun `endblk` ne le
        // précède — le segment KEY n'en produit pas). Même trou d'inflation qu'en
        // côte-à-côte, mais l'ancrage se déplace en `seg_start(premier IN)`.
        a.push(Assertion::single(
            SEG_BALBIT_OFF + SEG_BAL_VACC,
            seg_start(ins[0], d),
            BaseElement::ZERO,
        ));

        a
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        build_periodic(self.depth, self.l).1
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

/// Degrés (bornes SUPÉRIEURES) — même calibration qu'en côte-à-côte pour les
/// familles conservées ; les familles mutualisées gardent leur degré, seul leur
/// NOMBRE change.
fn degrees(n: usize) -> Vec<TransitionConstraintDegree> {
    let wc = TransitionConstraintDegree::with_cycles;
    let mut d = Vec::with_capacity(N_CONSTRAINTS);

    for _ in 0..N_KEY {
        d.push(wc(7, vec![n, n]));
    }
    for _ in 0..N_SPONGE {
        d.push(wc(7, vec![8, n, n]));
    }
    // Chemin : 12 sponge, 10 booléen/copies (deg 2), 8 swap (deg 3).
    for _ in 0..12 {
        d.push(wc(8, vec![8, MERKLE_LEVEL_ROWS, n, n]));
    }
    for _ in 0..10 {
        d.push(wc(2, vec![n, n]));
    }
    for _ in 0..8 {
        d.push(wc(3, vec![n, n]));
    }
    d.push(wc(2, vec![n, n])); // bit booléen
    d.push(wc(2, vec![n, n, n])); // S chaîné
    d.push(wc(2, vec![n, n, n, n])); // VACC
    for _ in 0..N_CARRIER {
        d.push(wc(1, vec![n]));
    }
    for _ in 0..N_LIAISON {
        d.push(wc(1, vec![n, n]));
    }

    debug_assert_eq!(d.len(), N_CONSTRAINTS);
    d
}

// ================================================================================================
// PROUVEUR + API INTERNE
// ================================================================================================

struct SegMonolithProver {
    options: ProofOptions,
    pi: MonolithPublicInputs,
}

impl Prover for SegMonolithProver {
    type BaseField = BaseElement;
    type Air = SegMonolithAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3;
    type VC = MerkleTree<Blake3>;
    type RandomCoin = DefaultRandomCoin<Blake3>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> MonolithPublicInputs {
        self.pi.clone()
    }
    fn options(&self) -> &ProofOptions {
        &self.options
    }
    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_options)
    }
    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }
}

fn read4(trace: &TraceTable<BaseElement>, col: usize, row: usize) -> [BaseElement; DIGEST_FELTS] {
    core::array::from_fn(|k| trace.get(col + k, row))
}

/// Prouve le monolithe SEGMENTÉ. À générer en `--release`.
///
/// Les publics sont extraits de la trace aux positions du SCHEDULE (et non à des
/// lignes littérales) : la racine sur la porteuse, les nullifiers et commitments à
/// la fin de la pile de leur segment respectif.
pub(crate) fn prove_seg_monolith(w: &MonolithWitness) -> (MonolithPublicInputs, ValidityProof) {
    let depth = w.inputs[0].path.len();
    let trace = build_seg_trace(w);
    debug_assert_eq!(trace.width(), WIDTH);

    let schedule = schedule_2in2out();
    let seg_de = |voulu: SegKind| -> Vec<usize> {
        schedule
            .iter()
            .enumerate()
            .filter(|(_, k)| **k == voulu)
            .map(|(i, _)| i)
            .collect()
    };
    let ins = seg_de(SegKind::Input);
    let outs = seg_de(SegKind::Output);
    let nf = |n: usize| {
        read4(
            &trace,
            SEG_SPONGE_OFF + RATE_START,
            seg_start(ins[n], depth) + NF_ROWS_END - 1,
        )
    };
    let oc = |n: usize| {
        read4(
            &trace,
            SEG_SPONGE_OFF + RATE_START,
            seg_start(outs[n], depth) + CM_ROWS_END - 1,
        )
    };

    let pi = MonolithPublicInputs {
        // La racine est lue sur la PORTEUSE (constante) — les liaisons `root_in`
        // garantissent qu'elle égale la racine repliée de chaque entrée.
        root: read4(&trace, ROOT_C, 0),
        nullifiers: [nf(0), nf(1)],
        output_commitments: [oc(0), oc(1)],
        fee: w.fee,
        depth,
    };

    let prover = SegMonolithProver {
        options: crate::proof_options_hi(),
        pi: pi.clone(),
    };
    let proof = prover.prove(trace).expect("génération de preuve");
    (pi, ValidityProof(proof))
}

/// Vérifie une preuve du monolithe segmenté.
pub(crate) fn verify_seg_monolith(
    pi: &MonolithPublicInputs,
    depth: usize,
    proof: &ValidityProof,
) -> bool {
    let mut pv = pi.clone();
    pv.depth = depth;
    let acceptable = winterfell::AcceptableOptions::MinConjecturedSecurity(95);
    winterfell::verify::<SegMonolithAir, Blake3, DefaultRandomCoin<Blake3>, MerkleTree<Blake3>>(
        proof.0.clone(),
        pv,
        &acceptable,
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monolith::trace::witness_de_test;

    const DEPTHS: [usize; 2] = [2, 32];

    /// Décompte des contraintes : recompté pour le segmenté, PAS recopié. La
    /// mutualisation fait fondre les familles répétées.
    #[test]
    fn decompte_des_contraintes() {
        assert_eq!(N_BASE, N_KEY + N_SPONGE + N_MERKLE + N_BAL + N_CARRIER);
        assert_eq!(N_CONSTRAINTS, N_BASE + N_LIAISON);
        // Les porteuses forment le bloc contigu SHARED_OFF..S_COL (S_COL exclue :
        // elle est chaînée, pas constante).
        assert_eq!(N_CARRIER, S_COL - SHARED_OFF);
        // `degrees` doit produire exactement N_CONSTRAINTS entrées.
        assert_eq!(degrees(trace_len(2)).len(), N_CONSTRAINTS);
        // Moins de slots que le côte-à-côte (263) : éponges 48→12, Merkle 60→30.
        const { assert!(N_CONSTRAINTS < 263, "la mutualisation doit réduire les slots") };
    }

    /// Roundtrip : une preuve segmentée d'un témoin honnête est acceptée, et chaque
    /// public falsifié est rejeté.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn roundtrip_segmente() {
        let (w, _root) = witness_de_test();
        let (pi, proof) = prove_seg_monolith(&w);
        assert!(verify_seg_monolith(&pi, pi.depth, &proof), "témoin honnête accepté");

        let falsifie = |f: &dyn Fn(&mut MonolithPublicInputs)| {
            let mut p = pi.clone();
            f(&mut p);
            assert!(
                !verify_seg_monolith(&p, pi.depth, &proof),
                "public falsifié doit être rejeté"
            );
        };
        falsifie(&|p| p.root[0] += BaseElement::ONE);
        falsifie(&|p| p.nullifiers[0][0] += BaseElement::ONE);
        falsifie(&|p| p.nullifiers[1][0] += BaseElement::ONE);
        falsifie(&|p| p.output_commitments[0][0] += BaseElement::ONE);
        falsifie(&|p| p.output_commitments[1][0] += BaseElement::ONE);
        falsifie(&|p| p.fee += 1);
    }

    /// FORGE SPÉCIFIQUE AU SEGMENTÉ (RED) : les deux entrées prouvent leur
    /// appartenance contre des racines DIFFÉRENTES.
    ///
    /// En côte-à-côte cette forge n'avait pas de sens : `root` était assertée
    /// PUBLIQUEMENT sur chaque chemin `M_i`, donc deux racines distinctes étaient
    /// structurellement impossibles. La mutualisation change cela — `root` devient
    /// une porteuse assertée UNE SEULE FOIS — et c'est la liaison `root_in[i]`
    /// (ajoutée en T3) qui doit mordre.
    ///
    /// Sans elle, un prouveur dépenserait une note appartenant à un arbre et une
    /// note appartenant à un AUTRE arbre dans la même transaction, chaque chemin
    /// étant valide isolément. C'est un trou d'inflation créé par la refonte
    /// elle-même : ce test est donc la contrepartie obligatoire du gain de slots.
    ///
    /// La forge est faite au niveau du TÉMOIN (chemin de l'entrée 1 pris dans un
    /// second arbre), sans constructeur de trace dédié.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn racines_differentes_rejetees() {
        use crate::spend::SpendNote;
        use crate::tx::ProvedInput;
        use proved_hash::digest::{Digest, ShieldedSecret};
        use proved_hash::felt::Felt;
        use proved_hash::{merkle, rescue};

        let dg = |seed: u64| {
            Digest(core::array::from_fn(|i| {
                Felt::from_canonical_u64(seed + i as u64).unwrap()
            }))
        };
        let secret = ShieldedSecret::from_felts(core::array::from_fn(|i| {
            Felt::from_canonical_u64(700 + i as u64).unwrap()
        }));
        let owner = rescue::hash(Domain::Owner, secret.as_felts());

        let n0 = SpendNote { value: 1_000, owner, rho: dg(20), r: dg(30) };
        let n1 = SpendNote { value: 500, owner, rho: dg(40), r: dg(50) };
        let cm0 = rescue::note_commitment(n0.value, &n0.owner, &n0.rho, &n0.r);
        let cm1 = rescue::note_commitment(n1.value, &n1.owner, &n1.rho, &n1.r);

        // Arbre A (profondeur 2) : contient cm0 en index 0.
        let l0 = merkle::leaf(&cm0);
        let a1 = merkle::leaf(&dg(9001));
        let a_gauche = merkle::node(&l0, &a1);
        let a_droite = merkle::node(&merkle::leaf(&dg(9002)), &merkle::leaf(&dg(9003)));
        let path0 = vec![a1, a_droite];

        // Arbre B, DIFFÉRENT (feuilles muettes distinctes) : contient cm1 en index 3.
        let l1 = merkle::leaf(&cm1);
        let b2 = merkle::leaf(&dg(7002));
        let b_gauche = merkle::node(&merkle::leaf(&dg(7000)), &merkle::leaf(&dg(7001)));
        let path1 = vec![b2, b_gauche];

        // Les deux chemins sont individuellement COHÉRENTS, mais avec des racines
        // distinctes — c'est exactement ce que la liaison de racine doit interdire.
        let root_a = merkle::node(&a_gauche, &a_droite);
        let root_b = merkle::node(&b_gauche, &merkle::node(&b2, &l1));
        assert_ne!(root_a, root_b, "les deux arbres doivent différer");

        let w = MonolithWitness {
            secret,
            inputs: [
                ProvedInput { note: n0, path: path0, index: 0 },
                ProvedInput { note: n1, path: path1, index: 3 },
            ],
            outputs: [
                SpendNote { value: 900, owner: dg(60), rho: dg(61), r: dg(62) },
                SpendNote { value: 580, owner: dg(70), rho: dg(71), r: dg(72) },
            ],
            fee: 20,
        };

        let (pi, proof) = prove_seg_monolith(&w);
        assert!(
            !verify_seg_monolith(&pi, pi.depth, &proof),
            "deux entrées contre des racines DIFFÉRENTES doivent être rejetées \
             (liaison root_in) — sinon inflation inter-arbres"
        );
    }

    /// FORGE (RED) : ancrage `VACC` du PREMIER segment d'unité.
    ///
    /// Le segment KEY ne produit pas d'`endblk`, donc le `VACC` de la première ligne
    /// du premier segment d'ENTRÉE n'est remis à zéro par aucune transition — c'est
    /// un témoin LIBRE. Un prouveur y met `−k` et décompose `valeur₀ + k` : `VACC` à
    /// la ligne d'ancrage vaut toujours `valeur₀` (donc la liaison VIN reste
    /// honnête), mais `S` a encaissé `valeur₀ + k` → `k` unités créées.
    ///
    /// L'assertion `VACC[seg_start(premier IN)] = 0` ferme le trou. Même mécanisme
    /// qu'en côte-à-côte, mais l'ancrage a CHANGÉ D'ADRESSE avec la segmentation —
    /// d'où ce test dédié : il vérifie que la NOUVELLE adresse est bien contrainte.
    ///
    /// ⚠️ Portée exacte : c'est une forge GROSSIÈRE (écrasement direct de la cellule),
    /// donc elle mord à la fois par l'assertion d'ancrage ET par la contrainte de
    /// transition `VACC`. Elle établit que la ligne d'ancrage est contrainte, PAS que
    /// l'assertion seule suffirait. La forge fine — bits recomposés en cascade
    /// cohérente pour n'exercer QUE l'ancrage, miroir de `Forge::VaccInitial` du
    /// côte-à-côte — reste à porter avec le reste de la suite de forges.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn vacc_initial_non_nul_rejete() {
        let (w, _root) = witness_de_test();
        let depth = w.inputs[0].path.len();
        let premier_in = schedule_2in2out()
            .iter()
            .position(|k| *k == SegKind::Input)
            .expect("un segment d'entrée");
        let ligne = seg_start(premier_in, depth);

        // Trace honnête, puis VACC de la ligne d'ancrage forcé à une valeur ≠ 0.
        let mut trace = build_seg_trace(&w);
        let vacc_col = SEG_BALBIT_OFF + SEG_BAL_VACC;
        let mut ligne_forgee: Vec<BaseElement> = (0..WIDTH).map(|c| trace.get(c, ligne)).collect();
        ligne_forgee[vacc_col] = BaseElement::new(7);
        trace.update_row(ligne, &ligne_forgee);

        // Publics relus de la trace forgée (self-consistants).
        let pi = MonolithPublicInputs {
            root: read4(&trace, ROOT_C, 0),
            nullifiers: [
                read4(&trace, SEG_SPONGE_OFF + RATE_START, seg_start(1, depth) + NF_ROWS_END - 1),
                read4(&trace, SEG_SPONGE_OFF + RATE_START, seg_start(2, depth) + NF_ROWS_END - 1),
            ],
            output_commitments: [
                read4(&trace, SEG_SPONGE_OFF + RATE_START, seg_start(3, depth) + CM_ROWS_END - 1),
                read4(&trace, SEG_SPONGE_OFF + RATE_START, seg_start(4, depth) + CM_ROWS_END - 1),
            ],
            fee: w.fee,
            depth,
        };
        let prover = SegMonolithProver {
            options: crate::proof_options_hi(),
            pi: pi.clone(),
        };
        let proof = ValidityProof(prover.prove(trace).expect("génération"));
        assert!(
            !verify_seg_monolith(&pi, depth, &proof),
            "VACC initial non nul doit être rejeté (ancrage anti-inflation)"
        );
    }

    /// MESURE DÉCISIVE (T6 anticipé) : segmenté vs côte-à-côte à la profondeur
    /// CONSENSUS (32), sur le même témoin.
    ///
    /// Le design 3z-c1 laissait la question ouverte — « l'effet net sur la taille de
    /// preuve reste à mesurer : la largeur ÷2,2 peut compenser, voire battre, la
    /// longueur ×2 ; le bench tranche ». Ce test EST ce bench. Il conditionne
    /// l'intérêt d'investir dans le reste de la refonte (et dans 3z-c2).
    ///
    /// Ignoré par défaut (coûteux) : `cargo test -p circuit --release --lib
    /// mesure_segmente_vs_cote_a_cote -- --ignored --nocapture`.
    #[test]
    #[ignore = "bench : lancer explicitement avec --ignored --nocapture"]
    fn mesure_segmente_vs_cote_a_cote() {
        use crate::monolith::trace::witness_de_test_profondeur_consensus;
        use std::time::Instant;

        let (w, _root) = witness_de_test_profondeur_consensus();
        let depth = w.inputs[0].path.len();
        assert_eq!(depth, 32, "profondeur consensus");

        // --- Segmenté ---
        let t0 = Instant::now();
        let (pi_seg, proof_seg) = prove_seg_monolith(&w);
        let gen_seg = t0.elapsed();
        let t1 = Instant::now();
        assert!(verify_seg_monolith(&pi_seg, depth, &proof_seg));
        let ver_seg = t1.elapsed();
        let taille_seg = proof_seg.0.to_bytes().len();

        // --- Côte-à-côte (référence 3z-b1) ---
        let (w2, _) = witness_de_test_profondeur_consensus();
        let t2 = Instant::now();
        let (pi_ref, proof_ref) = super::super::air::prove_monolith(&w2);
        let gen_ref = t2.elapsed();
        let t3 = Instant::now();
        assert!(super::super::air::verify_monolith(&pi_ref, depth, &proof_ref));
        let ver_ref = t3.elapsed();
        let taille_ref = proof_ref.0.to_bytes().len();

        // Parité des publics à la profondeur consensus, tant qu'on y est.
        assert_eq!(pi_seg.root, pi_ref.root);
        assert_eq!(pi_seg.nullifiers, pi_ref.nullifiers);
        assert_eq!(pi_seg.output_commitments, pi_ref.output_commitments);

        println!("\n=== profondeur 32 (consensus) ===");
        println!(
            "côte-à-côte : largeur {:3}, trace {:5} | gen {:7.1} ms | ver {:5.1} ms | {:6.1} Kio",
            super::super::layout::WIDTH,
            super::super::layout::trace_len(depth),
            gen_ref.as_secs_f64() * 1e3,
            ver_ref.as_secs_f64() * 1e3,
            taille_ref as f64 / 1024.0
        );
        println!(
            "segmenté    : largeur {:3}, trace {:5} | gen {:7.1} ms | ver {:5.1} ms | {:6.1} Kio",
            WIDTH,
            trace_len(depth),
            gen_seg.as_secs_f64() * 1e3,
            ver_seg.as_secs_f64() * 1e3,
            taille_seg as f64 / 1024.0
        );
        println!(
            "ratio taille segmenté/côte-à-côte : {:.3}  (< 1 = le segmenté gagne)",
            taille_seg as f64 / taille_ref as f64
        );
        println!(
            "ratio gen : {:.2}×   ratio ver : {:.2}×\n",
            gen_seg.as_secs_f64() / gen_ref.as_secs_f64(),
            ver_seg.as_secs_f64() / ver_ref.as_secs_f64()
        );
    }

    /// ORACLE DE PARITÉ — le test que la construction côte à côte rend possible :
    /// le MÊME témoin doit produire les MÊMES publics par les deux monolithes.
    ///
    /// C'est la non-régression la plus forte disponible : elle compare le segmenté
    /// à une implémentation indépendante et déjà éprouvée, plutôt qu'à ses propres
    /// attentes.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithes gatés : --release")]
    fn parite_publics_segmente_vs_cote_a_cote() {
        let (w, _root) = witness_de_test();
        let (pi_seg, _) = prove_seg_monolith(&w);
        let (pi_ref, _) = super::super::air::prove_monolith(&w);

        assert_eq!(pi_seg.root, pi_ref.root, "racine");
        assert_eq!(pi_seg.nullifiers, pi_ref.nullifiers, "nullifiers");
        assert_eq!(
            pi_seg.output_commitments, pi_ref.output_commitments,
            "commitments de sortie"
        );
        assert_eq!(pi_seg.fee, pi_ref.fee, "fee");
        assert_eq!(pi_seg.depth, pi_ref.depth, "profondeur");
    }

    fn indices_non_nuls(col: &[BaseElement]) -> Vec<usize> {
        col.iter()
            .enumerate()
            .filter(|(_, v)| **v != BaseElement::ZERO)
            .map(|(i, _)| i)
            .collect()
    }

    /// Index des segments du schedule ayant un type donné.
    fn segments_de(kind_voulu: SegKind) -> Vec<usize> {
        schedule_2in2out()
            .iter()
            .enumerate()
            .filter(|(_, k)| **k == kind_voulu)
            .map(|(i, _)| i)
            .collect()
    }

    /// `par_segment` ne déborde jamais d'un segment et couvre exactement la région
    /// utile — la garantie dont dépendent TOUS les sélecteurs.
    #[test]
    fn par_segment_couvre_exactement_les_segments() {
        for depth in DEPTHS {
            let l = trace_len(depth);
            let col = par_segment(depth, l, |_, _, _| BaseElement::ONE);
            let allumes = indices_non_nuls(&col);
            let used = used_rows(depth);
            assert_eq!(
                allumes,
                (0..used).collect::<Vec<_>>(),
                "les segments doivent paver [0, used) sans trou ni débordement @ depth {depth}"
            );
        }
    }

    /// `sel_key` : allumé exactement sur les 7 transitions du calcul de clé — et
    /// SURTOUT pas sur les 8 lignes de bourrage du segment KEY (piège introduit par
    /// l'alignement KEY_LEN=16).
    #[test]
    fn sel_key_ignore_le_bourrage_du_segment() {
        for depth in DEPTHS {
            let l = trace_len(depth);
            let allumes = indices_non_nuls(&sel_key(depth, l));
            let start = seg_start(0, depth);
            assert_eq!(
                allumes,
                (start..start + KEY_USED_ROWS - 1).collect::<Vec<_>>(),
                "sel_key doit couvrir 7 transitions, pas les 15 du segment @ depth {depth}"
            );
            // Garde explicite : rien d'allumé au-delà du calcul réel.
            assert!(allumes.iter().all(|r| *r < start + KEY_USED_ROWS));
        }
    }

    /// `sel_sponge` : mutualisé. Sur chaque segment IN il couvre la pile 0..56 en
    /// excluant les 3 frontières d'absorption ; sur chaque segment OUT, 0..31.
    #[test]
    fn sel_sponge_mutualise_in_et_out() {
        for depth in DEPTHS {
            let l = trace_len(depth);
            let col = sel_sponge(depth, l);
            for i in segments_de(SegKind::Input) {
                let s = seg_start(i, depth);
                for frontiere in [CM_ROWS_END - 1, LEAF_ROWS_END - 1, NF_ROWS_END - 1] {
                    assert_eq!(
                        col[s + frontiere],
                        BaseElement::ZERO,
                        "frontière d'absorption locale {frontiere} doit être éteinte (segment {i})"
                    );
                }
                assert_eq!(col[s], BaseElement::ONE, "1re ligne de la pile allumée");
                assert_eq!(
                    col[s + NF_ROWS_END],
                    BaseElement::ZERO,
                    "au-delà de la pile : éteint"
                );
            }
            for j in segments_de(SegKind::Output) {
                let s = seg_start(j, depth);
                assert_eq!(col[s], BaseElement::ONE);
                assert_eq!(
                    col[s + CM_ROWS_END - 1],
                    BaseElement::ZERO,
                    "frontière du commitment de sortie éteinte"
                );
            }
            // Aucun segment KEY allumé.
            let sk = seg_start(0, depth);
            assert!((0..KEY_LEN).all(|r| col[sk + r] == BaseElement::ZERO));
        }
    }

    /// `sel_m` : uniquement sur les segments IN, et borné par la longueur réelle du
    /// chemin (16·depth), pas par la longueur du segment.
    #[test]
    fn sel_m_seulement_sur_les_entrees() {
        for depth in DEPTHS {
            let l = trace_len(depth);
            let col = sel_m(depth, l);
            let attendus: Vec<usize> = segments_de(SegKind::Input)
                .into_iter()
                .flat_map(|i| {
                    let s = seg_start(i, depth);
                    (0..MERKLE_LEVEL_ROWS * depth - 1).map(move |r| s + r)
                })
                .collect();
            assert_eq!(indices_non_nuls(&col), attendus, "@ depth {depth}");
        }
    }

    /// `signe` : +1 sur IN, −1 sur OUT, 0 sur KEY et hors segments. C'est le zéro
    /// sur KEY qui garde `S` constant pendant le segment de clé.
    #[test]
    fn signe_plus_un_moins_un_zero() {
        for depth in DEPTHS {
            let l = trace_len(depth);
            let col = signe(depth, l);
            for i in segments_de(SegKind::Input) {
                let s = seg_start(i, depth);
                assert_eq!(col[s], BaseElement::ONE);
                assert_eq!(col[s + seg_len(SegKind::Input, depth) - 1], BaseElement::ONE);
            }
            for j in segments_de(SegKind::Output) {
                let s = seg_start(j, depth);
                assert_eq!(col[s], -BaseElement::ONE);
            }
            // Segment KEY : signe nul sur TOUTES ses lignes → S constant.
            let sk = seg_start(0, depth);
            assert!(
                (0..KEY_LEN).all(|r| col[sk + r] == BaseElement::ZERO),
                "signe doit être nul sur tout le segment KEY"
            );
            // Hors région utile : nul.
            assert!((used_rows(depth)..l).all(|r| col[r] == BaseElement::ZERO));
        }
    }

    /// `pow` : poids RELATIF au segment (`2^local`), nul dès `RANGE_BITS`. Un poids
    /// global permettrait de décomposer un montant avec les poids d'un autre
    /// segment — vérification de soundness n°4 du plan T3.
    #[test]
    fn pow_est_relatif_au_segment() {
        for depth in DEPTHS {
            let l = trace_len(depth);
            let col = pow(depth, l);
            for i in segments_de(SegKind::Input)
                .into_iter()
                .chain(segments_de(SegKind::Output))
            {
                let s = seg_start(i, depth);
                assert_eq!(col[s], BaseElement::ONE, "2^0 en début de segment {i}");
                assert_eq!(col[s + 1], BaseElement::new(2));
                assert_eq!(
                    col[s + crate::range_check::RANGE_BITS - 1],
                    BaseElement::new(1u64 << (crate::range_check::RANGE_BITS - 1))
                );
                assert_eq!(
                    col[s + crate::range_check::RANGE_BITS],
                    BaseElement::ZERO,
                    "bits au-delà de RANGE_BITS : poids nul (borne du montant)"
                );
            }
        }
    }

    /// `endblk` : exactement une ligne par segment IN/OUT, la dernière.
    #[test]
    fn endblk_une_fois_en_fin_de_chaque_unite() {
        for depth in DEPTHS {
            let l = trace_len(depth);
            let attendus: Vec<usize> = schedule_2in2out()
                .iter()
                .enumerate()
                .filter(|(_, k)| matches!(k, SegKind::Input | SegKind::Output))
                .map(|(i, k)| seg_start(i, depth) + seg_len(*k, depth) - 1)
                .collect();
            assert_eq!(indices_non_nuls(&endblk(depth, l)), attendus, "@ depth {depth}");
        }
    }

    /// `blind_off` : éteint dès la transition `used−1 → used`, donc sur toute la
    /// région de blinding (witness-hiding préservé).
    #[test]
    fn blind_off_eteint_la_region_de_blinding() {
        for depth in DEPTHS {
            let l = trace_len(depth);
            let col = blind_off(depth, l);
            let used = used_rows(depth);
            assert_eq!(col[used - 2], BaseElement::ONE);
            assert_eq!(
                col[used - 1],
                BaseElement::ZERO,
                "la transition vers l'aléa doit être éteinte"
            );
            assert!((used..l).all(|r| col[r] == BaseElement::ZERO));
        }
    }

    /// `at_abs` : un seul 1, et jamais d'ancrage en `l − 1` (transition hors domaine
    /// d'enforcement).
    #[test]
    fn at_abs_est_mono_ligne() {
        let l = trace_len(2);
        let col = at_abs(l, 42);
        assert_eq!(indices_non_nuls(&col), vec![42]);
        // Hors bornes : colonne nulle (pas de panique).
        assert!(indices_non_nuls(&at_abs(l, l + 10)).is_empty());
    }

    // ---- Inventaire des colonnes périodiques ----

    /// Chaque index nommé désigne bien la colonne attendue : on vérifie le CONTENU
    /// pointé, pas seulement la cohérence des nombres. C'est la garantie qui
    /// remplace les `pv[37]` en dur du côte-à-côte.
    #[test]
    fn inventaire_periodique_index_pointent_les_bonnes_colonnes() {
        for depth in DEPTHS {
            let l = trace_len(depth);
            let (ix, cols) = build_periodic(depth, l);

            assert_eq!(cols.len(), ix.total);
            assert!(ix.total > 0);

            // Cycliques : longueurs de cycle attendues.
            assert_eq!(cols[ix.round_flag_s].len(), 8, "éponge : cycle 8");
            assert_eq!(cols[ix.round_flag_m].len(), MERKLE_LEVEL_ROWS, "Merkle : cycle 16");
            assert_eq!(cols[ix.init0].len(), MERKLE_LEVEL_ROWS);
            assert_eq!(indices_non_nuls(&cols[ix.init0]), vec![0]);
            assert_eq!(indices_non_nuls(&cols[ix.init7]), vec![7]);
            assert_eq!(indices_non_nuls(&cols[ix.chain]), vec![15]);
            // ARK : 2 × STATE_WIDTH colonnes contiguës, ark2 juste après ark1.
            let sw = crate::rescue_round::STATE_WIDTH;
            assert_eq!(ix.ark2, ix.ark1 + sw);
            assert!(ix.ark2 + sw <= ix.total);

            // Pleine longueur : le contenu doit coïncider avec les fonctions de l'étape 1.
            assert_eq!(cols[ix.sel_key], sel_key(depth, l));
            assert_eq!(cols[ix.sel_sponge], sel_sponge(depth, l));
            assert_eq!(cols[ix.sel_m], sel_m(depth, l));
            assert_eq!(cols[ix.sel_bal], sel_bal(depth, l));
            assert_eq!(cols[ix.signe], signe(depth, l));
            assert_eq!(cols[ix.pow], pow(depth, l));
            assert_eq!(cols[ix.endblk], endblk(depth, l));
            assert_eq!(cols[ix.blind_off], blind_off(depth, l));
        }
    }

    /// Les ancres pointent la BONNE ligne absolue : `seg_start(segment) + ancre
    /// locale`. C'est ici que se joue le renversement colonne→ligne : une ancre qui
    /// désignerait le segment voisin lierait la porteuse de l'entrée 0 aux cellules
    /// de l'entrée 1 — soundness perdue, silencieusement.
    #[test]
    fn ancres_pointent_la_ligne_absolue_de_leur_segment() {
        for depth in DEPTHS {
            let l = trace_len(depth);
            let (ix, cols) = build_periodic(depth, l);
            let schedule = schedule_2in2out();

            // Segment KEY.
            let ks = seg_start(0, depth);
            assert_eq!(indices_non_nuls(&cols[ix.s0_key]), vec![ks]);
            assert_eq!(indices_non_nuls(&cols[ix.s7_key]), vec![ks + 7]);

            // Segments d'ENTRÉE : chaque ancre à sa ligne, dans SON segment.
            let ins: Vec<usize> = segments_de(SegKind::Input);
            for (n, &i) in ins.iter().enumerate() {
                let s = seg_start(i, depth);
                for (a, &ancre) in ANCRES_IN.iter().enumerate() {
                    assert_eq!(
                        indices_non_nuls(&cols[ix.anc_in[n][a]]),
                        vec![s + ancre],
                        "ancre {ancre} de l'entrée {n} (segment {i}) @ depth {depth}"
                    );
                }
                assert_eq!(
                    indices_non_nuls(&cols[ix.vacc_in[n]]),
                    vec![s + crate::range_check::RANGE_BITS]
                );
                // Ancre de racine : dernière ligne du chemin de Merkle du segment.
                assert_eq!(
                    indices_non_nuls(&cols[ix.root_in[n]]),
                    vec![s + MERKLE_LEVEL_ROWS * depth - 1],
                    "ancre de racine de l'entrée {n} @ depth {depth}"
                );
            }

            // Segments de SORTIE.
            let outs: Vec<usize> = segments_de(SegKind::Output);
            for (n, &j) in outs.iter().enumerate() {
                let s = seg_start(j, depth);
                assert_eq!(indices_non_nuls(&cols[ix.s0_out[n]]), vec![s]);
                assert_eq!(
                    indices_non_nuls(&cols[ix.vacc_out[n]]),
                    vec![s + crate::range_check::RANGE_BITS]
                );
            }

            // Les ancres des DEUX entrées sont distinctes deux à deux : c'est
            // exactement ce qui remplace la distinction par colonne du côte-à-côte.
            for a in 0..ANCRES_IN.len() {
                let r0 = indices_non_nuls(&cols[ix.anc_in[0][a]]);
                let r1 = indices_non_nuls(&cols[ix.anc_in[1][a]]);
                assert_ne!(r0, r1, "les ancres {a} des 2 entrées doivent différer");
            }
            let _ = schedule;
        }
    }

    /// Aucun index nommé ne doit désigner deux fois la même colonne (hors ARK, qui
    /// est une plage), ni sortir du vecteur.
    #[test]
    fn inventaire_periodique_sans_collision() {
        for depth in DEPTHS {
            let l = trace_len(depth);
            let (ix, cols) = build_periodic(depth, l);
            let mut vus = vec![
                ix.round_flag_s,
                ix.round_flag_m,
                ix.init0,
                ix.init7,
                ix.chain,
                ix.sel_key,
                ix.sel_sponge,
                ix.sel_m,
                ix.sel_bal,
                ix.signe,
                ix.pow,
                ix.endblk,
                ix.blind_off,
                ix.s0_key,
                ix.s7_key,
            ];
            for n in 0..2 {
                vus.extend_from_slice(&ix.anc_in[n]);
                vus.push(ix.vacc_in[n]);
                vus.push(ix.root_in[n]);
                vus.push(ix.s0_out[n]);
                vus.push(ix.vacc_out[n]);
            }
            assert!(vus.iter().all(|i| *i < cols.len()), "index hors bornes");
            let avant = vus.len();
            vus.sort_unstable();
            vus.dedup();
            assert_eq!(avant, vus.len(), "deux index nommés désignent la même colonne");
        }
    }

    /// Les ancres de liaison, une fois décalées par segment, tombent bien DANS leur
    /// segment et jamais en `l − 1`.
    #[test]
    fn ancres_de_liaison_restent_dans_leur_segment() {
        for depth in DEPTHS {
            let l = trace_len(depth);
            let used = used_rows(depth);
            // Ancres locales de la pile d'éponge d'une entrée (cf. côte-à-côte).
            for i in segments_de(SegKind::Input) {
                let s = seg_start(i, depth);
                let n = seg_len(SegKind::Input, depth);
                for ancre in [0, 7, 31, 32, 39, 40, 47, crate::range_check::RANGE_BITS] {
                    let abs = s + ancre;
                    assert!(ancre < n, "ancre {ancre} hors du segment {i}");
                    assert!(abs < used, "ancre absolue {abs} hors région utile");
                    assert_ne!(abs, l - 1, "ancrage interdit en l−1");
                }
            }
        }
    }
}
