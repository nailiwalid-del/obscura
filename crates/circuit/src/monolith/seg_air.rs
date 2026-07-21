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
#[cfg(test)]
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
    forme: Forme,
    depth: usize,
    l: usize,
    f: impl Fn(SegKind, usize, usize) -> BaseElement,
) -> Vec<BaseElement> {
    let mut col = vec![BaseElement::ZERO; l];
    for i in 0..forme.n_segments() {
        let kind = forme.seg_kind(i);
        let start = forme.seg_start(i, depth);
        let n = seg_len(kind, depth);
        for local in 0..n {
            let row = start + local;
            if row < l {
                col[row] = f(kind, i, local);
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
pub(crate) fn sel_key(forme: Forme, depth: usize, l: usize) -> Vec<BaseElement> {
    par_segment(forme, depth, l, |kind, _, local| {
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
pub(crate) fn sel_sponge(forme: Forme, depth: usize, l: usize) -> Vec<BaseElement> {
    par_segment(forme, depth, l, |kind, _, local| {
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
pub(crate) fn sel_m(forme: Forme, depth: usize, l: usize) -> Vec<BaseElement> {
    let last = MERKLE_LEVEL_ROWS * depth - 1;
    par_segment(forme, depth, l, |kind, _, local| {
        if kind == SegKind::Input && local < last {
            BaseElement::ONE
        } else {
            BaseElement::ZERO
        }
    })
}

/// `sel_bal` : équilibre actif sur tout segment `Input`/`Output`.
pub(crate) fn sel_bal(forme: Forme, depth: usize, l: usize) -> Vec<BaseElement> {
    par_segment(forme, depth, l, |kind, _, _| {
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
pub(crate) fn signe(forme: Forme, depth: usize, l: usize) -> Vec<BaseElement> {
    par_segment(forme, depth, l, |kind, _, _| match kind {
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
pub(crate) fn pow(forme: Forme, depth: usize, l: usize) -> Vec<BaseElement> {
    par_segment(forme, depth, l, |kind, _, local| {
        if est_unite(kind) && local < crate::range_check::RANGE_BITS {
            BaseElement::new(1u64 << local)
        } else {
            BaseElement::ZERO
        }
    })
}

/// `endblk` : 1 sur la DERNIÈRE ligne de chaque segment `Input`/`Output` — c'est
/// elle qui remet `VACC` à zéro pour le segment suivant.
pub(crate) fn endblk(forme: Forme, depth: usize, l: usize) -> Vec<BaseElement> {
    par_segment(forme, depth, l, |kind, _, local| {
        if est_unite(kind) && local + 1 == seg_len(kind, depth) {
            BaseElement::ONE
        } else {
            BaseElement::ZERO
        }
    })
}

/// `blind_off` (witness-hiding 3z-b1) : 1 ssi la transition `r → r+1` reste DANS la
/// région utile. Éteint toutes les familles sur le saut vers l'aléa et sur la
/// région de blinding. Identique au côte-à-côte.
pub(crate) fn blind_off(forme: Forme, depth: usize, l: usize) -> Vec<BaseElement> {
    let used = forme.used_rows(depth);
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
    pub anc_in: Vec<[usize; ANCRES_IN.len()]>,
    /// Ligne `RANGE_BITS` du i-ème segment d'entrée : consommation VACC (montant plein).
    pub vacc_in: Vec<usize>,
    /// Dernière ligne du chemin de Merkle du i-ème segment d'entrée
    /// (`16·depth − 1`) : liaison « racine repliée == porteuse `ROOT_C` ».
    ///
    /// NOUVEAU en segmenté : le côte-à-côte assertait `root` publiquement sur
    /// CHAQUE `M_i` ; ici `root` est assertée une seule fois sur la porteuse, et
    /// chaque entrée s'y raccroche par cette liaison.
    pub root_in: Vec<usize>,
    /// Ligne 0 du j-ème segment de SORTIE : production vout.
    pub s0_out: Vec<usize>,
    /// Ligne `RANGE_BITS` du j-ème segment de sortie : consommation VACC.
    pub vacc_out: Vec<usize>,
    /// Nombre total de colonnes périodiques (vérifié par les tests d'inventaire).
    #[cfg_attr(not(test), allow(dead_code))]
    pub total: usize,
}

/// Construit TOUTES les colonnes périodiques et leurs index, en un seul passage.
///
/// L'unicité du passage est ce qui garantit la cohérence : un index ne peut pas
/// désigner une autre colonne que celle qui vient d'être poussée.
pub(crate) fn build_periodic(
    forme: Forme,
    depth: usize,
    l: usize,
) -> (PeriodicIdx, Vec<Vec<BaseElement>>) {
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
    let sel_key = push(&mut cols, self::sel_key(forme, depth, l));
    let sel_sponge = push(&mut cols, self::sel_sponge(forme, depth, l));
    let sel_m = push(&mut cols, self::sel_m(forme, depth, l));
    let sel_bal = push(&mut cols, self::sel_bal(forme, depth, l));
    let signe = push(&mut cols, self::signe(forme, depth, l));
    let pow = push(&mut cols, self::pow(forme, depth, l));
    let endblk = push(&mut cols, self::endblk(forme, depth, l));
    let blind_off = push(&mut cols, self::blind_off(forme, depth, l));

    // --- Ancres de liaison, adressées `forme.seg_start(i) + ancre_locale`. ---
    // L'ORDRE du schedule est normatif ([KEY][IN×m][OUT×n], cf. Forme::seg_kind) :
    // le i-ème segment d'entrée est le segment 1+i, le j-ième de sortie le
    // segment 1+m+j. C'est ce qui lie chaque nullifier public à SON segment,
    // position par position (spec D7.3).
    let key_start = forme.seg_start(0, depth);
    let s0_key = push(&mut cols, at_abs(l, key_start));
    let s7_key = push(&mut cols, at_abs(l, key_start + 7));

    let mut anc_in = Vec::with_capacity(forme.m());
    let mut vacc_in = Vec::with_capacity(forme.m());
    let mut root_in = Vec::with_capacity(forme.m());
    for n in 0..forme.m() {
        let s = forme.seg_start(1 + n, depth);
        debug_assert_eq!(forme.seg_kind(1 + n), SegKind::Input);
        let mut ancres = [0usize; ANCRES_IN.len()];
        for (a, &ancre) in ANCRES_IN.iter().enumerate() {
            ancres[a] = push(&mut cols, at_abs(l, s + ancre));
        }
        anc_in.push(ancres);
        vacc_in.push(push(&mut cols, at_abs(l, s + crate::range_check::RANGE_BITS)));
        // Dernière ligne du chemin : racine repliée == porteuse ROOT_C.
        root_in.push(push(&mut cols, at_abs(l, s + MERKLE_LEVEL_ROWS * depth - 1)));
    }

    let mut s0_out = Vec::with_capacity(forme.n());
    let mut vacc_out = Vec::with_capacity(forme.n());
    for n in 0..forme.n() {
        let s = forme.seg_start(1 + forme.m() + n, depth);
        debug_assert_eq!(forme.seg_kind(1 + forme.m() + n), SegKind::Output);
        s0_out.push(push(&mut cols, at_abs(l, s)));
        vacc_out.push(push(&mut cols, at_abs(l, s + crate::range_check::RANGE_BITS)));
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

// --- Familles FIXES (indépendantes de la forme) : gadgets mutualisés. ---
const N_KEY: usize = 2 * STATE_WIDTH; // 24 : rondes owner + nk
const N_SPONGE: usize = STATE_WIDTH; // 12 : UNE famille (était 4×12 = 48)
const N_MERKLE: usize = 30; // UNE famille (était 2×30 = 60)
const N_BAL: usize = 3; // bit booléen, S chaîné, VACC
const N_FIXE: usize = N_KEY + N_SPONGE + N_MERKLE + N_BAL; // 69
const N_SECRET: usize = DIGEST_FELTS; // liaison secret owner↔nk : une seule

// --- Familles PAR FORME : leur NOMBRE change avec (m, n), pas leur degré (3z-c2).
//     Le nombre de contraintes est propre à CHAQUE preuve — prouveur et vérifieur
//     construisent l'AIR à partir des MÊMES publics, donc s'accordent dessus. ---

/// Porteuses constantes : tout le bloc partagé SAUF `S_COL` (chaînée). Sa largeur
/// suit la forme (plus d'entrées = plus de porteuses rho/cm/leaf/vin).
fn n_carrier(f: Forme) -> usize {
    f.s_col() - SHARED_OFF
}

/// Liaisons dépendant de la forme (owner conso, nk conso, rho, cm, leaf, root, vin
/// par ENTRÉE ; vout par SORTIE). Les productions owner/nk @clé sont fixes (une
/// chacune) et comptées dans `N_LIAISON_FIXE`.
fn n_liaison(f: Forme) -> usize {
    let (m, n) = (f.m(), f.n());
    let owner_conso = m * DIGEST_FELTS;
    let nk_conso = m * DIGEST_FELTS;
    let rho = m * (2 * DIGEST_FELTS);
    let cm = m * (3 * DIGEST_FELTS);
    let leaf = m * (2 * DIGEST_FELTS);
    let root = m * DIGEST_FELTS; // racine repliée de chaque entrée == ROOT_C
    let vin = m * 2;
    let vout = n * 2;
    owner_conso + nk_conso + rho + cm + leaf + root + vin + vout
}

/// Liaisons FIXES : secret owner↔nk (4) + production owner @clé (4) + production nk
/// @clé (4).
const N_LIAISON_FIXE: usize = N_SECRET + DIGEST_FELTS + DIGEST_FELTS;

/// Nombre TOTAL de contraintes de transition pour cette forme.
fn n_constraints(f: Forme) -> usize {
    N_FIXE + n_carrier(f) + N_LIAISON_FIXE + n_liaison(f)
}

/// Nombre d'assertions publiques : `KEY(16) + m·IN(43) + m·chemin(12·depth) +
/// root(4) + n·OUT(27) + BAL(3)`. Écart au côte-à-côte : `root` assertée UNE fois
/// sur la porteuse au lieu d'une fois par chemin.
fn num_assertions(f: Forme, depth: usize) -> usize {
    16 + f.m() * 43 + f.m() * (12 * depth) + 4 + f.n() * 27 + 3
}

// ================================================================================================
// AIR
// ================================================================================================

pub(crate) struct SegMonolithAir {
    context: AirContext<BaseElement>,
    pi: MonolithPublicInputs,
    l: usize,
    depth: usize,
    /// Forme (m, n) DÉRIVÉE des publics — les longueurs des Vec. C'est elle qui
    /// pilote schedule, sélecteurs, ancres et assertions : une trace dont le
    /// nombre de segments ne correspond pas aux publics déclarés est contrainte
    /// contre le MAUVAIS schedule et échoue (cf. spec D7.1).
    forme: Forme,
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
        // Forme dérivée de la LARGEUR de trace commise (bijective), et NON des
        // publics : c'est ce qui structure les contraintes sur des colonnes qui
        // existent RÉELLEMENT — un attaquant qui déclare une forme (m, n)
        // différente de sa trace ne provoque pas d'accès hors cadre, il est rejeté
        // par Fiat-Shamir (les comptes m, n sont préfixés dans `to_elements`). Une
        // largeur qui ne correspond à AUCUNE forme valide retombe sur 2/2 : la
        // vérification échouera de toute façon (graine de challenge incohérente).
        let forme = forme_depuis_largeur(trace_info.main_trace_width())
            .unwrap_or(Forme::F22);
        let (ix, _) = build_periodic(forme, depth, l);
        let context = AirContext::new(
            trace_info,
            degrees(forme, l),
            num_assertions(forme, depth),
            options,
        );
        SegMonolithAir { context, pi, l, depth, forme, ix }
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
        let f = self.forme;
        let s_col = f.s_col();

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
            let s = cur[s_col];
            let s_next = next[s_col];
            let vacc = cur[SEG_BALBIT_OFF + SEG_BAL_VACC];
            let vacc_next = next[SEG_BALBIT_OFF + SEG_BAL_VACC];
            result[idx] = sel_bal * bit * (bit - one);
            result[idx + 1] = s_next - s - signe * bit * pow;
            result[idx + 2] = sel_bal * (vacc_next - (one - endblk) * (vacc + bit * pow));
            idx += N_BAL;
        }

        // --- PORTEUSES : constantes sur la région utile (bloc contigu, S_COL exclue).
        //     Le gating blind_off est appliqué par la boucle globale en fin. ---
        let nc = n_carrier(f);
        for c in 0..nc {
            result[idx + c] = next[SHARED_OFF + c] - cur[SHARED_OFF + c];
        }
        idx += nc;
        debug_assert_eq!(idx, N_FIXE + nc);

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
            for n in 0..f.m() {
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
            for n in 0..f.m() {
                let s40 = pv[ix.anc_in[n][A_S40]];
                for k in 0..DIGEST_FELTS {
                    result[idx + k] = s40 * (cur[NK_C + k] - cur[sp + 7 + k]);
                }
                idx += DIGEST_FELTS;
            }
        }

        // RHO : le rho du nullifier == celui du commitment (v0.2, nf lié au cm).
        for n in 0..f.m() {
            let rho_c = f.rho_c(n);
            let s7 = pv[ix.anc_in[n][A_S7]];
            let s40 = pv[ix.anc_in[n][A_S40]];
            let s47 = pv[ix.anc_in[n][A_S47]];
            for k in 0..DIGEST_FELTS {
                result[idx + k] = s7 * (cur[rho_c + k] - cur[sp + 12 + k]);
            }
            idx += DIGEST_FELTS;
            result[idx] = s40 * (cur[rho_c] - cur[sp + 11]);
            idx += 1;
            for j in 0..DIGEST_FELTS - 1 {
                result[idx + j] = s47 * (cur[rho_c + 1 + j] - cur[sp + 12 + j]);
            }
            idx += DIGEST_FELTS - 1;
        }

        // CM : le commitment produit gouverne la feuille ET le nullifier (P1).
        for n in 0..f.m() {
            let cm_c = f.cm_c(n);
            let s31 = pv[ix.anc_in[n][A_S31]];
            let s32 = pv[ix.anc_in[n][A_S32]];
            let s47 = pv[ix.anc_in[n][A_S47]];
            for k in 0..DIGEST_FELTS {
                result[idx + k] = s31 * (cur[cm_c + k] - cur[sp + rate + k]);
            }
            idx += DIGEST_FELTS;
            for k in 0..DIGEST_FELTS {
                result[idx + k] = s32 * (cur[cm_c + k] - cur[sp + 7 + k]);
            }
            idx += DIGEST_FELTS;
            for k in 0..DIGEST_FELTS {
                result[idx + k] = s47 * (cur[cm_c + k] - cur[sp + 15 + k]);
            }
            idx += DIGEST_FELTS;
        }

        // FEUILLE↔CHEMIN : la feuille produite == celle injectée dans le chemin.
        for n in 0..f.m() {
            let leaf_c = f.leaf_c(n);
            let s39 = pv[ix.anc_in[n][A_S39]];
            let s0 = pv[ix.anc_in[n][A_S0]];
            for k in 0..DIGEST_FELTS {
                result[idx + k] = s39 * (cur[leaf_c + k] - cur[sp + rate + k]);
            }
            idx += DIGEST_FELTS;
            for k in 0..DIGEST_FELTS {
                result[idx + k] = s0 * (cur[leaf_c + k] - cur[SEG_MERKLE_OFF + 20 + k]);
            }
            idx += DIGEST_FELTS;
        }

        // RACINE (nouveau) : la racine repliée de chaque entrée == porteuse ROOT_C.
        // Sans elle, les deux entrées pourraient prouver contre des racines
        // DIFFÉRENTES (chacune valide isolément) — trou créé par la mutualisation.
        for n in 0..f.m() {
            let sr = pv[ix.root_in[n]];
            for k in 0..DIGEST_FELTS {
                result[idx + k] = sr * (cur[ROOT_C + k] - cur[SEG_MERKLE_OFF + rate + k]);
            }
            idx += DIGEST_FELTS;
        }

        // MONTANTS (P5) : la value de chaque commitment == le VACC de son segment.
        let vacc_col = SEG_BALBIT_OFF + SEG_BAL_VACC;
        for n in 0..f.m() {
            let vin_c = f.vin_c(n);
            let s0 = pv[ix.anc_in[n][A_S0]];
            let vg = pv[ix.vacc_in[n]];
            result[idx] = s0 * (cur[vin_c] - cur[sp + 7]);
            result[idx + 1] = vg * (cur[vin_c] - cur[vacc_col]);
            idx += 2;
        }
        for n in 0..f.n() {
            let vout_c = f.vout_c(n);
            let s0 = pv[ix.s0_out[n]];
            let vg = pv[ix.vacc_out[n]];
            result[idx] = s0 * (cur[vout_c] - cur[sp + 7]);
            result[idx + 1] = vg * (cur[vout_c] - cur[vacc_col]);
            idx += 2;
        }

        debug_assert_eq!(idx, n_constraints(f));

        // --- Gating global witness-hiding (motif 3z-b1b conservé). ---
        for r in result.iter_mut() {
            *r *= blind_off;
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let d = self.depth;
        let f = self.forme;
        let mut a = Vec::with_capacity(num_assertions(f, d));
        let sp = SEG_SPONGE_OFF;

        // Segment KEY : éponges owner et nk.
        let ks = f.seg_start(0, d);
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
        // de chaque merge du chemin. Le n-ième segment IN est le segment 1+n
        // (ordre normatif [KEY][IN×m][OUT×n]).
        for n in 0..f.m() {
            let s = f.seg_start(1 + n, d);
            push_preamble(&mut a, s + CM_ROWS_START, sp, 32, Domain::NoteCommitment.tag() as u64, 13);
            push_preamble(&mut a, s + LEAF_ROWS_START, sp, 8, Domain::MerkleLeaf.tag() as u64, 4);
            push_preamble(&mut a, s + NF_ROWS_START, sp, 16, Domain::Nullifier.tag() as u64, 12);
            // Lecture DÉFENSIVE : si les publics déclarent moins d'entrées que la
            // trace (forme mentie), l'absence vaut ZÉRO → assertion fausse contre le
            // vrai nullifier → rejet propre, jamais de panique d'indexation.
            let nf_n = self.pi.nullifiers.get(n).copied().unwrap_or([BaseElement::ZERO; DIGEST_FELTS]);
            for (k, nf_k) in nf_n.iter().enumerate() {
                a.push(Assertion::single(sp + RATE_START + k, s + NF_ROWS_END - 1, *nf_k));
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
        for n in 0..f.n() {
            let s = f.seg_start(1 + f.m() + n, d);
            push_preamble(&mut a, s, sp, 32, Domain::NoteCommitment.tag() as u64, 13);
            let oc_n = self.pi.output_commitments.get(n).copied().unwrap_or([BaseElement::ZERO; DIGEST_FELTS]);
            for (k, oc_k) in oc_n.iter().enumerate() {
                a.push(Assertion::single(sp + RATE_START + k, s + CM_ROWS_END - 1, *oc_k));
            }
        }

        // Équilibre : S part de 0 (sa colonne suit la forme), vaut fee à la dernière
        // ligne utile.
        let s_col = f.s_col();
        a.push(Assertion::single(s_col, 0, BaseElement::ZERO));
        a.push(Assertion::single(
            s_col,
            f.used_rows(d) - 1,
            BaseElement::new(self.pi.fee),
        ));
        // VACC du PREMIER segment d'unité (segment 1 = premier IN) : sinon témoin
        // libre (aucun `endblk` ne le précède — le segment KEY n'en produit pas).
        a.push(Assertion::single(
            SEG_BALBIT_OFF + SEG_BAL_VACC,
            f.seg_start(1, d),
            BaseElement::ZERO,
        ));

        a
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        build_periodic(self.forme, self.depth, self.l).1
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

/// Degrés (bornes SUPÉRIEURES) — même calibration qu'en côte-à-côte pour les
/// familles conservées ; les familles mutualisées gardent leur degré, seul leur
/// NOMBRE change.
fn degrees(forme: Forme, n: usize) -> Vec<TransitionConstraintDegree> {
    let wc = TransitionConstraintDegree::with_cycles;
    let mut d = Vec::with_capacity(n_constraints(forme));

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
    for _ in 0..n_carrier(forme) {
        d.push(wc(1, vec![n]));
    }
    for _ in 0..(N_LIAISON_FIXE + n_liaison(forme)) {
        d.push(wc(1, vec![n, n]));
    }

    debug_assert_eq!(d.len(), n_constraints(forme));
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
    prove_seg_forme(&super::seg_trace::SegWitness::depuis_2in2out(w))
}

/// Prouve le monolithe segmenté à FORME VARIABLE (3z-c2). Extrait les publics de la
/// trace aux positions du SCHEDULE de la forme (racine sur la porteuse, nullifiers et
/// commitments à la fin de la pile de LEUR segment respectif — jamais à des lignes
/// littérales). À générer en `--release`.
pub(crate) fn prove_seg_forme(
    w: &super::seg_trace::SegWitness,
) -> (MonolithPublicInputs, ValidityProof) {
    let f = w.forme();
    let depth = w.inputs[0].path.len();
    let trace = super::seg_trace::build_seg_trace_forme_seeded(w, &mut rand::rngs::OsRng);
    debug_assert_eq!(trace.width(), f.width());

    // Le n-ième segment IN est le segment 1+n, le n-ième OUT le segment 1+m+n
    // (ordre normatif). Publics lus au MÊME endroit que l'AIR les asserte.
    let nf = |n: usize| {
        read4(
            &trace,
            SEG_SPONGE_OFF + RATE_START,
            f.seg_start(1 + n, depth) + NF_ROWS_END - 1,
        )
    };
    let oc = |n: usize| {
        read4(
            &trace,
            SEG_SPONGE_OFF + RATE_START,
            f.seg_start(1 + f.m() + n, depth) + CM_ROWS_END - 1,
        )
    };

    let pi = MonolithPublicInputs {
        // La racine est lue sur la PORTEUSE (constante) — les liaisons `root_in`
        // garantissent qu'elle égale la racine repliée de chaque entrée.
        root: read4(&trace, ROOT_C, 0),
        nullifiers: (0..f.m()).map(nf).collect(),
        output_commitments: (0..f.n()).map(oc).collect(),
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
        // 2/2 : le décompte doit COÏNCIDER avec l'ancien monolithe segmenté (209).
        // C'est la non-régression : la paramétrisation ne change pas la forme 2/2.
        let f22 = Forme::F22;
        assert_eq!(n_constraints(f22), 209, "2/2 inchangé (mutualisation : 48→12, 60→30)");
        assert!(n_constraints(f22) < 263, "moins de slots que le côte-à-côte");
        // Porteuses = bloc contigu SHARED_OFF..s_col (chaînée exclue).
        assert_eq!(n_carrier(f22), Forme::F22.s_col() - SHARED_OFF);
        // `degrees` produit exactement `n_constraints` entrées, POUR CHAQUE forme.
        for m in 1..=MAX_IN {
            for n in 1..=MAX_OUT {
                let f = Forme::new(m, n).unwrap();
                assert_eq!(degrees(f, trace_len(2)).len(), n_constraints(f), "forme {m}/{n}");
            }
        }
        // Le compte CROÎT avec la forme : plus d'entrées = plus de liaisons.
        assert!(n_constraints(Forme::new(4, 4).unwrap()) > n_constraints(f22));
        assert!(n_constraints(Forme::new(1, 1).unwrap()) < n_constraints(f22));
    }

    /// PREUVE + VÉRIFICATION à FORME VARIABLE : le critère de sortie de C2-T3.
    ///
    /// Une trace 1/1 et une trace 4/4 doivent produire une preuve acceptée, et un
    /// public falsifié (un nullifier, un commitment) doit être rejeté — sur des
    /// formes qu'aucun chemin figé n'exerçait. C'est ce qui prouve que sélecteurs,
    /// ancres, assertions et degrés dérivent RÉELLEMENT de la forme, pas d'un 2/2
    /// déguisé.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn preuve_forme_variable_1_1_et_4_4() {
        use crate::monolith::seg_trace::tests::witness_forme;
        for (m, n) in [(1usize, 1usize), (4, 4)] {
            let w = witness_forme(m, n);
            let (pi, proof) = prove_seg_forme(&w);
            assert_eq!(pi.m(), m, "forme {m}/{n} : m public");
            assert_eq!(pi.n(), n, "forme {m}/{n} : n public");
            assert!(
                verify_seg_monolith(&pi, pi.depth, &proof),
                "forme {m}/{n} : témoin honnête accepté"
            );

            // Un nullifier falsifié est rejeté.
            let mut faux = pi.clone();
            faux.nullifiers[0][0] += BaseElement::ONE;
            assert!(
                !verify_seg_monolith(&faux, faux.depth, &proof),
                "forme {m}/{n} : nullifier falsifié rejeté"
            );
            // Un commitment de sortie falsifié est rejeté.
            let mut faux = pi.clone();
            faux.output_commitments[n - 1][0] += BaseElement::ONE;
            assert!(
                !verify_seg_monolith(&faux, faux.depth, &proof),
                "forme {m}/{n} : commitment falsifié rejeté"
            );
        }
    }

    /// Extrait les publics d'une trace de forme `f` (positions du SCHEDULE de la
    /// forme, jamais des lignes littérales) — le pendant de `prove_seg_forme` pour
    /// une trace FORGÉE, dont les publics sont relus tels quels (self-consistants).
    fn publics_de_forme(
        f: Forme,
        trace: &TraceTable<BaseElement>,
        fee: u64,
        depth: usize,
    ) -> MonolithPublicInputs {
        let nf = |n: usize| {
            read4(
                trace,
                SEG_SPONGE_OFF + RATE_START,
                f.seg_start(1 + n, depth) + NF_ROWS_END - 1,
            )
        };
        let oc = |n: usize| {
            read4(
                trace,
                SEG_SPONGE_OFF + RATE_START,
                f.seg_start(1 + f.m() + n, depth) + CM_ROWS_END - 1,
            )
        };
        MonolithPublicInputs {
            root: read4(trace, ROOT_C, 0),
            nullifiers: (0..f.m()).map(nf).collect(),
            output_commitments: (0..f.n()).map(oc).collect(),
            fee,
            depth,
        }
    }

    /// Prouve une trace DÉJÀ construite (éventuellement forgée) avec les publics
    /// donnés — le prouveur ne re-dérive rien, on éprouve la VÉRIFICATION.
    fn prouver_trace(
        trace: TraceTable<BaseElement>,
        pi: &MonolithPublicInputs,
    ) -> ValidityProof {
        let prover = SegMonolithProver {
            options: crate::proof_options_hi(),
            pi: pi.clone(),
        };
        ValidityProof(prover.prove(trace).expect("génération"))
    }

    // ================================================================================
    // C2-T4 — SOUNDNESS SOUS FORME VARIABLE. Les trois forges D7 de la spec : chacune
    // vise une garantie que la VARIABILITÉ pourrait avoir supprimée, là où la forme
    // 2/2 figée la rendait structurelle. RED vérifié sur chacune.
    // ================================================================================

    /// D7.1 — LA FORME EST LIÉE. Une preuve honnête d'une forme ne se vérifie contre
    /// AUCUNE autre déclaration de (m, n).
    ///
    /// Sans le préfixage des comptes dans Fiat-Shamir (C2-T3), un prouveur pourrait
    /// présenter une transaction 2-in/2-out et la faire accepter déclarée 1-in/3-out
    /// (mêmes 4 digests, découpés autrement) : une dépense non déclarée, ou une
    /// sortie fantôme. Ici on prend une preuve 2/2 honnête et on la re-présente sous
    /// chaque autre forme de même nombre total de digests — toutes doivent être
    /// REJETÉES.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn d7_1_forme_liee_aux_publics() {
        use crate::monolith::seg_trace::tests::witness_forme;
        let w = witness_forme(2, 2);
        let (pi, proof) = prove_seg_forme(&w);
        assert!(verify_seg_monolith(&pi, pi.depth, &proof), "2/2 honnête accepté");

        // Re-découpage des MÊMES digests en 1/3 et 3/1 : la forme déclarée change,
        // la graine de challenge change, la vérification échoue.
        let tous_nf = pi.nullifiers.clone();
        let tous_oc = pi.output_commitments.clone();
        let digests: Vec<[BaseElement; DIGEST_FELTS]> =
            tous_nf.iter().chain(tous_oc.iter()).copied().collect();

        for (m, n) in [(1usize, 3usize), (3, 1)] {
            let mut faux = pi.clone();
            faux.nullifiers = digests[..m].to_vec();
            faux.output_commitments = digests[m..m + n].to_vec();
            assert_eq!(faux.m(), m);
            assert_eq!(faux.n(), n);
            assert!(
                !verify_seg_monolith(&faux, faux.depth, &proof),
                "forme 2/2 re-présentée en {m}/{n} doit être REJETÉE (forme liée)"
            );
        }
    }

    /// D7.3 — L'ORDRE PUBLICS↔SEGMENTS EST LIÉ. Permuter deux nullifiers (ou deux
    /// commitments de sortie) entre eux fait échouer la vérification : chaque public
    /// est asserté à la ligne de SON segment, pas d'« un » segment.
    ///
    /// La mutualisation des colonnes fait porter la distinction par le SÉLECTEUR de
    /// segment ; si l'AIR liait `output_commitments[j]` à un segment OUT quelconque
    /// au lieu du j-ième, un prouveur pourrait réordonner ses sorties sans invalider
    /// la preuve — sans conséquence ici, mais le gabarit se propagerait.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn d7_3_ordre_publics_segments_lie() {
        use crate::monolith::seg_trace::tests::witness_forme;
        // 4/4 : quatre segments de chaque, donc de vraies permutations à tester.
        let w = witness_forme(4, 4);
        let (pi, proof) = prove_seg_forme(&w);
        assert!(verify_seg_monolith(&pi, pi.depth, &proof), "4/4 honnête accepté");

        // Permuter deux nullifiers.
        let mut faux = pi.clone();
        faux.nullifiers.swap(0, 2);
        assert!(
            !verify_seg_monolith(&faux, faux.depth, &proof),
            "nullifiers permutés : chaque nf est lié à SON segment"
        );

        // Permuter deux commitments de sortie.
        let mut faux = pi.clone();
        faux.output_commitments.swap(1, 3);
        assert!(
            !verify_seg_monolith(&faux, faux.depth, &proof),
            "commitments permutés : chaque oc est lié à SON segment"
        );
    }

    /// D7.2 — L'ÉQUILIBRE EST SCELLÉ À LA FIN VARIABLE. `fee` n'entre dans l'AIR QUE
    /// par l'assertion `S = fee`, ancrée à `used_rows(m, n) − 1` — une ligne qui
    /// DÉPEND de la forme. Une preuve 4/4 honnête ne se vérifie donc pas contre un
    /// `fee` public différent.
    ///
    /// C'est la garde que la fin de l'accumulateur ne « glisse » pas : à une adresse
    /// FIGÉE (celle du 2/2), un bloc 4/4 aurait son équilibre asserté AU MILIEU de la
    /// trace, laissant les derniers segments libres d'inflation. Le RED correspondant
    /// (retirer l'assertion d'endpoint) fait passer un `fee` faux — `fee` n'étant lié
    /// par AUCUNE autre contrainte.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn d7_2_equilibre_scelle_a_la_fin_variable() {
        use crate::monolith::seg_trace::tests::witness_forme;
        let w = witness_forme(4, 4);
        let (pi, proof) = prove_seg_forme(&w);
        assert!(verify_seg_monolith(&pi, pi.depth, &proof), "4/4 honnête accepté");

        // `fee` falsifié : seule l'assertion d'endpoint (à used_rows(4,4)−1) le lie.
        let mut faux = pi.clone();
        faux.fee += 1;
        assert!(
            !verify_seg_monolith(&faux, faux.depth, &proof),
            "fee public falsifié : l'endpoint S = fee mord à la fin de la forme 4/4"
        );
    }

    /// RE-PORT DES FORGES EXISTANTES SOUS UNE FORME ≠ 2/2. Les liaisons éprouvées en
    /// 2/2 (secret owner↔nk, cm↔nullifier, montants, VACC initial) doivent mordre
    /// AUSSI sur une forme large — sur un segment (l'entrée 3) qui n'existe QUE à
    /// m ≥ 4, donc qu'aucun test 2/2 n'atteignait.
    ///
    /// ⚠️ Périmètre : forges SANS reconstruction d'arbre (celles-là restent 2/2 tant
    /// que `build_tree_from_leaves` est câblé profondeur 2 — dette D8, cf. spec).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn forges_existantes_sous_forme_4_4() {
        use crate::monolith::seg_trace::{build_seg_trace_forme_forge, tests::witness_forme, SegForge};
        let w = witness_forme(4, 4);
        let f = w.forme();
        let depth = w.inputs[0].path.len();
        use proved_hash::felt::Felt;
        let d = |seed: u64| {
            proved_hash::digest::Digest(core::array::from_fn(|i| {
                Felt::from_canonical_u64(seed + i as u64).unwrap()
            }))
        };

        // Chaque forge vise une liaison, sur un segment que 2/2 n'a pas : l'entrée 3.
        let forges = [
            ("SecretNk", SegForge::SecretNk(d(31_000))),
            ("CmNullifier@3", SegForge::CmNullifier(3, d(32_000))),
            ("NkConsomme@3", SegForge::NkConsomme(3, d(33_000))),
            ("RhoNullifier@3", SegForge::RhoNullifier(3, d(34_000))),
            ("ValeurEntrees", SegForge::ValeurEntrees(5)),
            ("ValeurSorties", SegForge::ValeurSorties(5)),
            ("VaccInitial", SegForge::VaccInitial(5)),
        ];
        for (nom, forge) in forges {
            let trace = build_seg_trace_forme_forge(&w, forge);
            let pi = publics_de_forme(f, &trace, w.fee, depth);
            let proof = prouver_trace(trace, &pi);
            assert!(
                !verify_seg_monolith(&pi, depth, &proof),
                "forge {nom} sous forme 4/4 doit être REJETÉE"
            );
        }
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
    /// ⚠️ Portée exacte : forge GROSSIÈRE (écrasement direct de la cellule), qui mord
    /// à la fois par l'assertion d'ancrage ET par la contrainte de transition `VACC`.
    /// Elle établit que la ligne d'ancrage est contrainte, pas que l'assertion seule
    /// suffirait. La forme FINE — bits recomposés en cascade pour n'exercer QUE
    /// l'ancrage — est désormais couverte par `SegForge::VaccInitial`
    /// (`forges_montants_et_inertie_du_blinding`), avec RED vérifié. Ce test est
    /// conservé comme garde bon marché sur l'ADRESSE de l'ancrage.
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
            nullifiers: vec![
                read4(&trace, SEG_SPONGE_OFF + RATE_START, seg_start(1, depth) + NF_ROWS_END - 1),
                read4(&trace, SEG_SPONGE_OFF + RATE_START, seg_start(2, depth) + NF_ROWS_END - 1),
            ],
            output_commitments: vec![
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

    /// Prouve une trace FORGÉE et rend le verdict du vérifieur. Les publics sont
    /// relus de la trace forgée (self-consistants) : le rejet ne peut donc venir
    /// que d'une contrainte ou d'une assertion, jamais d'un public incohérent.
    #[cfg(test)]
    fn verdict_forge(forge: crate::monolith::seg_trace::SegForge) -> bool {
        let (w, _root) = witness_de_test();
        verdict_forge_sur(&w, forge)
    }

    /// Idem, sur un témoin QUELCONQUE — permet de rejouer les forges à la
    /// profondeur consensus.
    #[cfg(test)]
    fn verdict_forge_sur(
        w: &MonolithWitness,
        forge: crate::monolith::seg_trace::SegForge,
    ) -> bool {
        use crate::monolith::seg_trace::build_seg_trace_forge;

        let depth = w.inputs[0].path.len();
        let trace = build_seg_trace_forge(w, forge);
        let pi = MonolithPublicInputs {
            root: read4(&trace, ROOT_C, 0),
            nullifiers: vec![
                read4(&trace, SEG_SPONGE_OFF + RATE_START, seg_start(1, depth) + NF_ROWS_END - 1),
                read4(&trace, SEG_SPONGE_OFF + RATE_START, seg_start(2, depth) + NF_ROWS_END - 1),
            ],
            output_commitments: vec![
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
        verify_seg_monolith(&pi, depth, &proof)
    }

    /// FORGES (RED) des liaisons ANTI-DOUBLE-DÉPENSE, ré-ancrées par segment.
    ///
    /// Chacune réécrit UN côté d'une liaison en laissant la porteuse honnête et
    /// toute la cascade cohérente : la trace forgée ne diffère d'une trace honnête
    /// QUE par l'égalité ciblée. Un verdict `true` signifierait que la liaison
    /// correspondante ne mord pas.
    ///
    /// Ces quatre-là ne demandent aucune reconstruction d'arbre (elles n'altèrent
    /// ni le commitment ni la feuille), donc elles ne peuvent pas être masquées par
    /// la liaison `root_in`.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn forges_liaisons_nullifier_rejetees() {
        use crate::monolith::seg_trace::SegForge;
        use proved_hash::digest::Digest;
        use proved_hash::felt::Felt;

        let dg = |seed: u64| {
            Digest(core::array::from_fn(|i| {
                Felt::from_canonical_u64(seed + i as u64).unwrap()
            }))
        };

        // Témoin de contrôle : sans forge, la trace DOIT être acceptée — sinon les
        // verdicts négatifs ci-dessous ne prouveraient rien.
        assert!(
            verdict_forge(SegForge::Aucune),
            "contrôle : la trace honnête doit être acceptée"
        );

        // Secret owner↔nk : owner d'une note possédée, nk d'une autre.
        assert!(
            !verdict_forge(SegForge::SecretNk(dg(4242))),
            "liaison secret owner↔nk doit mordre (sinon double-dépense)"
        );
        // nk consommé ≠ nk produit par la clé.
        assert!(
            !verdict_forge(SegForge::NkConsomme(0, dg(5150))),
            "liaison NK doit mordre"
        );
        // rho consommé dans le nullifier ≠ rho de la porteuse.
        assert!(
            !verdict_forge(SegForge::RhoNullifier(1, dg(6161))),
            "liaison RHO (côté nullifier) doit mordre"
        );
        // cm consommé dans le nullifier ≠ cm produit : LA liaison anti-double-dépense.
        assert!(
            !verdict_forge(SegForge::CmNullifier(0, dg(7272))),
            "liaison CM (côté nullifier) doit mordre — nullifier sur un autre cm"
        );
    }

    /// FORGES (RED) des liaisons COMMITMENT et FEUILLE, ré-ancrées par segment.
    ///
    /// Contrairement aux forges du nullifier, celles-ci changent la feuille injectée
    /// dans l'arbre. Le constructeur REBÂTIT donc l'arbre sur les feuilles
    /// réellement injectées, pour que les deux entrées restent sur la MÊME racine :
    /// sans ça, `root_in` mordrait à la place de la liaison visée et le verdict
    /// négatif ne prouverait rien sur la liaison testée.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn forges_liaisons_commitment_feuille_rejetees() {
        use crate::monolith::seg_trace::SegForge;
        use proved_hash::digest::Digest;
        use proved_hash::felt::Felt;

        let dg = |seed: u64| {
            Digest(core::array::from_fn(|i| {
                Felt::from_canonical_u64(seed + i as u64).unwrap()
            }))
        };

        // owner consommé dans le commitment ≠ owner produit par la clé : dépense
        // d'une note dont le prouveur n'est PAS propriétaire.
        assert!(
            !verdict_forge(SegForge::OwnerConsomme(0, dg(8080))),
            "liaison OWNER doit mordre (sinon dépense du bien d'autrui)"
        );
        // rho consommé côté COMMITMENT (cellules disjointes du côté nullifier).
        assert!(
            !verdict_forge(SegForge::RhoCommitment(1, dg(8181))),
            "liaison RHO (côté commitment) doit mordre"
        );
        // cm consommé dans la feuille ≠ cm produit par le commitment.
        assert!(
            !verdict_forge(SegForge::CmFeuille(0, dg(8282))),
            "liaison CM (côté feuille) doit mordre"
        );
        // feuille injectée dans le chemin ≠ feuille produite par l'éponge.
        assert!(
            !verdict_forge(SegForge::LeafChemin(1, dg(8383))),
            "liaison FEUILLE↔CHEMIN doit mordre"
        );
    }

    /// FORGES (RED) des MONTANTS, et test d'INERTIE du blinding.
    ///
    /// Les forges de valeur sont COMPENSÉES entre deux segments de même signe :
    /// sans cela, `S_final ≠ fee` et l'assertion d'équilibre rejetterait AVANT la
    /// liaison VIN/VOUT↔VACC — le test serait vert sans rien prouver sur elle. La
    /// compensation entre segments de même signe laisse `S` intact et n'expose que
    /// les liaisons de montant.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn forges_montants_et_inertie_du_blinding() {
        use crate::monolith::seg_trace::SegForge;

        // VIN : bits de l'entrée 0 gonflés de k, ceux de l'entrée 1 dégonflés de k.
        assert!(
            !verdict_forge(SegForge::ValeurEntrees(11)),
            "liaison VIN↔VACC doit mordre (montant décomposé ≠ porteuse)"
        );
        // VOUT : miroir sur les sorties — isole VOUT de VIN.
        assert!(
            !verdict_forge(SegForge::ValeurSorties(7)),
            "liaison VOUT↔VACC doit mordre"
        );

        // INERTIE (verdict INVERSE) : région de blinding choisie par l'attaquant —
        // recopies de lignes utiles et junk violant chaque famille. Rien ne la lit
        // (contraintes gatées `blind_off`, assertions toutes < used), donc le
        // statement prouvé est INCHANGÉ et la tx reste acceptée.
        assert!(
            verdict_forge(SegForge::BlindingAdversarial),
            "un blinding adverse ne doit RIEN changer : la tx reste acceptée"
        );

        // PADDING non canonique dans le commitment : la trace est INTERNEMENT
        // cohérente (rondes et absorptions valides, aval en cascade honnête sur le
        // digest forgé) — seule l'assertion PAD_ZERO la distingue. Sans elle, un
        // prouveur publierait un commitment hors schéma : LEN annonce 13 cellules
        // mais 15 cellules de junk sont absorbées (« hash jamais tronqué » violé).
        assert!(
            !verdict_forge(SegForge::PaddingCommitment(3)),
            "assertion PAD_ZERO du commitment doit mordre (hash jamais tronqué)"
        );
        // INFLATION par VACC initial libre — forge FINE. Toute la trace est
        // cohérente : les bits de l'entrée 0 décomposent `valeur₀ + k` mais le VACC
        // part de `−k`, donc à la ligne d'ancrage VACC = valeur₀ et la liaison VIN
        // reste HONNÊTE ; la sortie 0 est gonflée de k (commitment, VOUT et bits
        // tous cohérents) pour que S_final = fee tienne. SEUL `VACC[1re ligne] = 0`
        // distingue la forge — sans lui, k unités sont créées ex nihilo.
        assert!(
            !verdict_forge(SegForge::VaccInitial(13)),
            "ancrage VACC = 0 doit mordre (sinon inflation ex nihilo)"
        );
        // CONTRÔLE : k = 0 → forge dégénérée, identique à l'honnête, donc acceptée.
        // Confirme que le chemin de code de la forge n'introduit pas d'incohérence
        // parasite, et donc que le rejet ci-dessus vient bien du VACC non nul.
        assert!(
            verdict_forge(SegForge::VaccInitial(0)),
            "contrôle : VaccInitial(0) est la trace honnête, doit être acceptée"
        );

        // CONTRÔLE : la MÊME forge avec la valeur HONNÊTE (0) doit être acceptée.
        // Elle emprunte exactement le même chemin de code (préambule rebâti, éponge
        // rejouée, arbre reconstruit) — donc si celui-ci introduisait une incohérence
        // parasite, ce contrôle échouerait. Le rejet ci-dessus est bien imputable à
        // la VALEUR de la cellule de padding, à rien d'autre.
        assert!(
            verdict_forge(SegForge::PaddingCommitment(0)),
            "contrôle : padding à la valeur canonique (0) doit être accepté"
        );
    }

    /// Preuve segmentée à blinding SEEDÉ : deux graines → deux blindings distincts,
    /// tout le reste identique. Support du test de masquage.
    #[cfg(test)]
    fn preuve_seedee(w: &MonolithWitness, seed: u64) -> (MonolithPublicInputs, ValidityProof) {
        use crate::monolith::seg_trace::build_seg_trace_seeded;
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let depth = w.inputs[0].path.len();
        let trace = build_seg_trace_seeded(w, &mut StdRng::seed_from_u64(seed));
        let pi = MonolithPublicInputs {
            root: read4(&trace, ROOT_C, 0),
            nullifiers: vec![
                read4(&trace, SEG_SPONGE_OFF + RATE_START, seg_start(1, depth) + NF_ROWS_END - 1),
                read4(&trace, SEG_SPONGE_OFF + RATE_START, seg_start(2, depth) + NF_ROWS_END - 1),
            ],
            output_commitments: vec![
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
        (pi.clone(), ValidityProof(prover.prove(trace).expect("génération")))
    }

    /// Ouvertures FRI d'une colonne de trace (parsing des trace queries).
    #[cfg(test)]
    fn ouvertures_colonne(proof: &ValidityProof, col: usize) -> Vec<BaseElement> {
        let queries = proof.0.trace_queries[0].clone();
        let (_op, table) = queries
            .parse::<BaseElement, Blake3, MerkleTree<Blake3>>(
                proof.0.lde_domain_size(),
                proof.0.num_unique_queries as usize,
                WIDTH,
            )
            .expect("parse des trace queries");
        table.rows().map(|row| row[col]).collect()
    }

    /// Preuve blindée d'un SegWitness (forme variable), graine déterministe.
    fn preuve_seedee_forme(
        w: &crate::monolith::seg_trace::SegWitness,
        seed: u64,
    ) -> (MonolithPublicInputs, ValidityProof) {
        use crate::monolith::seg_trace::build_seg_trace_forme_seeded;
        use rand::{rngs::StdRng, SeedableRng};

        let f = w.forme();
        let depth = w.inputs[0].path.len();
        let trace = build_seg_trace_forme_seeded(w, &mut StdRng::seed_from_u64(seed));
        let pi = publics_de_forme(f, &trace, w.fee, depth);
        let prover = SegMonolithProver {
            options: crate::proof_options_hi(),
            pi: pi.clone(),
        };
        (pi.clone(), ValidityProof(prover.prove(trace).expect("génération")))
    }

    /// Ouvertures FRI d'une colonne, à la LARGEUR DE LA FORME (le parse a besoin de la
    /// vraie largeur de trace, pas de `WIDTH` figé).
    fn ouvertures_colonne_forme(
        proof: &ValidityProof,
        col: usize,
        largeur: usize,
    ) -> Vec<BaseElement> {
        let queries = proof.0.trace_queries[0].clone();
        let (_op, table) = queries
            .parse::<BaseElement, Blake3, MerkleTree<Blake3>>(
                proof.0.lde_domain_size(),
                proof.0.num_unique_queries as usize,
                largeur,
            )
            .expect("parse des trace queries");
        table.rows().map(|row| row[col]).collect()
    }

    /// MASQUAGE SOUS FORMES VARIABLES (1/1 et 4/4) — C2-T5.
    ///
    /// # Ce que ce test verrouille structurellement
    ///
    /// Le gating `blind_off` est un gate de LIGNE (transition dans `[used, len)`),
    /// pas une liste de colonnes ; et le constructeur de trace remplit d'aléa TOUTE
    /// cellule de `[used, len)` sur `0..width()`. Toute porteuse NOUVELLE d'une forme
    /// large (`f.vout_c(3)`, qui n'existe pas en 2/2) est donc masquée sans qu'aucune
    /// liste n'ait à la mentionner. Ce test le PROUVE : il éprouve, sur 1/1 et 4/4,
    /// CHAQUE porteuse de la forme — y compris celles qu'aucun test 2/2 n'atteint.
    ///
    /// Détecteur DUR : sans blinding, une porteuse constante rendrait un polynôme
    /// constant et chaque ouverture FRI vaudrait le témoin EN CLAIR. Pour chacune :
    /// (a) aucune ouverture ne vaut le témoin (reconstruit HORS-CIRCUIT) ; (b) les
    /// ouvertures ne sont pas toutes égales ; (c) deux graines → ouvertures
    /// disjointes (randomisé, pas déterministe).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "AIR gatée : générer en --release")]
    fn masquage_sous_formes_variables() {
        use crate::monolith::seg_trace::tests::witness_forme;
        use proved_hash::rescue;

        for (m, n) in [(1usize, 1usize), (4, 4)] {
            let w = witness_forme(m, n);
            let f = w.forme();
            let depth = w.inputs[0].path.len();
            let (pi1, p1) = preuve_seedee_forme(&w, 51);
            let (pi2, p2) = preuve_seedee_forme(&w, 52);
            assert!(verify_seg_monolith(&pi1, depth, &p1), "forme {m}/{n} preuve 1");
            assert!(verify_seg_monolith(&pi2, depth, &p2), "forme {m}/{n} preuve 2");

            // Témoins reconstruits hors-circuit.
            let owner = rescue::hash(Domain::Owner, w.secret.as_felts());
            let nk = rescue::hash(Domain::Nk, w.secret.as_felts());

            // Une cible par famille, POUR CHAQUE entrée et CHAQUE sortie de la forme —
            // dont les porteuses (rho/cm/leaf/vin/vout) des indices > 1, absents du 2/2.
            let mut cibles: Vec<(usize, BaseElement)> = vec![
                (OWNER_C, owner.0[0].to_winter()),
                (NK_C, nk.0[0].to_winter()),
            ];
            for i in 0..f.m() {
                let note = &w.inputs[i].note;
                let cm = rescue::note_commitment(note.value, &note.owner, &note.rho, &note.r);
                let leaf = proved_hash::merkle::leaf(&cm);
                cibles.push((f.rho_c(i), note.rho.0[0].to_winter()));
                cibles.push((f.cm_c(i), cm.0[0].to_winter()));
                cibles.push((f.leaf_c(i), leaf.0[0].to_winter()));
                cibles.push((f.vin_c(i), BaseElement::new(note.value)));
            }
            for j in 0..f.n() {
                cibles.push((f.vout_c(j), BaseElement::new(w.outputs[j].value)));
            }

            for (col, temoin) in cibles {
                let o1 = ouvertures_colonne_forme(&p1, col, f.width());
                let o2 = ouvertures_colonne_forme(&p2, col, f.width());
                assert!(!o1.is_empty(), "forme {m}/{n} : ouvertures non vides @col {col}");
                assert!(
                    !o1.contains(&temoin),
                    "FUITE forme {m}/{n} : ouverture FRI = témoin en clair @col {col}"
                );
                assert!(!o2.contains(&temoin), "FUITE (preuve 2) forme {m}/{n} @col {col}");
                assert!(
                    o1.iter().any(|v| *v != o1[0]),
                    "forme {m}/{n} : porteuse non masquée @col {col}"
                );
                assert!(
                    o1.iter().zip(o2.iter()).any(|(a, b)| a != b),
                    "forme {m}/{n} : masquage déterministe @col {col}"
                );
            }

            // Contrôle structurel : la DERNIÈRE colonne de la forme (juste avant S)
            // est blindée — la plus récente, celle qu'aucune liste manuelle ne
            // couvrirait. Sur 4/4 c'est vout_c(3), inexistante en 2/2.
            let derniere_porteuse = f.s_col() - 1;
            let od = ouvertures_colonne_forme(&p1, derniere_porteuse, f.width());
            assert!(
                od.iter().any(|v| *v != od[0]),
                "forme {m}/{n} : la dernière porteuse (@{derniere_porteuse}) doit être blindée"
            );
        }
    }

    /// INERTIE DU BLINDING sous forme variable : une région de blinding ADVERSE (au
    /// lieu d'aléa) ne change RIEN — aucune contrainte ni assertion ne la lit, sur
    /// 1/1 comme sur 4/4. C'est le pendant « acceptée » du détecteur de fuite.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn inertie_du_blinding_sous_formes_variables() {
        use crate::monolith::seg_trace::{
            build_seg_trace_forme_forge, tests::witness_forme, SegForge,
        };
        for (m, n) in [(1usize, 1usize), (4, 4)] {
            let w = witness_forme(m, n);
            let f = w.forme();
            let depth = w.inputs[0].path.len();
            let trace = build_seg_trace_forme_forge(&w, SegForge::BlindingAdversarial);
            let pi = publics_de_forme(f, &trace, w.fee, depth);
            let proof = prouver_trace(trace, &pi);
            assert!(
                verify_seg_monolith(&pi, depth, &proof),
                "forme {m}/{n} : blinding adverse doit rester ACCEPTÉ (rien ne le lit)"
            );
        }
    }

    /// MASQUAGE (witness-hiding) sous la disposition SEGMENTÉE — T5.
    ///
    /// Les colonnes PORTEUSES sont CONSTANTES sur `[0, used)`. Sans blinding, leur
    /// polynôme serait constant et CHAQUE ouverture FRI vaudrait le témoin EN CLAIR
    /// (fuite catastrophique constatée au zk-spike). C'est le détecteur DUR : il
    /// échouerait de façon déterministe si le gating `blind_off` sautait sur une
    /// famille lors du portage segmenté.
    ///
    /// Pour chaque porteuse : (a) aucune ouverture ne vaut le témoin, reconstruit
    /// HORS-CIRCUIT depuis `w` (jamais lu dans la trace) ; (b) les ouvertures ne
    /// sont pas toutes identiques ; (c) deux preuves de la MÊME tx (graines
    /// distinctes) ouvrent des valeurs DISJOINTES — le masquage est randomisé, pas
    /// déterministe.
    ///
    /// La porteuse `ROOT_C` est incluse mais NON comparée à un témoin secret : la
    /// racine est PUBLIQUE. Elle sert de contrôle de cohérence (elle ne doit pas
    /// fuiter par un canal witness), pas de test de masquage.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "AIR gatée : générer en --release")]
    fn masquage_porteuses_sous_segments() {
        use proved_hash::rescue;

        let (w, _root) = witness_de_test();
        let depth = w.inputs[0].path.len();
        let (pi1, p1) = preuve_seedee(&w, 41);
        let (pi2, p2) = preuve_seedee(&w, 42);
        assert!(verify_seg_monolith(&pi1, depth, &p1), "preuve blindée 1 acceptée");
        assert!(verify_seg_monolith(&pi2, depth, &p2), "preuve blindée 2 acceptée");

        // Témoins reconstruits HORS-CIRCUIT (jamais lus dans la trace).
        let owner = rescue::hash(Domain::Owner, w.secret.as_felts());
        let nk = rescue::hash(Domain::Nk, w.secret.as_felts());
        let cm0 = {
            let n = &w.inputs[0].note;
            rescue::note_commitment(n.value, &n.owner, &n.rho, &n.r)
        };
        let leaf0 = proved_hash::merkle::leaf(&cm0);

        // (colonne, valeur témoin attendue) — un représentant par famille.
        let cibles: Vec<(usize, BaseElement)> = vec![
            (OWNER_C, owner.0[0].to_winter()),
            (OWNER_C + 1, owner.0[1].to_winter()),
            (NK_C, nk.0[0].to_winter()),
            (NK_C + 1, nk.0[1].to_winter()),
            (RHO_C[0], w.inputs[0].note.rho.0[0].to_winter()),
            (CM_C[0], cm0.0[0].to_winter()),
            (LEAF_C[0], leaf0.0[0].to_winter()),
            (VIN_C[0], BaseElement::new(w.inputs[0].note.value)),
            (VOUT_C[0], BaseElement::new(w.outputs[0].value)),
        ];

        for (col, temoin) in cibles {
            let o1 = ouvertures_colonne(&p1, col);
            let o2 = ouvertures_colonne(&p2, col);
            assert!(!o1.is_empty(), "ouvertures non vides @col {col}");

            // (a) aucune ouverture ne révèle le témoin.
            assert!(
                !o1.contains(&temoin),
                "FUITE : une ouverture FRI vaut le témoin en clair @col {col}"
            );
            assert!(!o2.contains(&temoin), "FUITE (preuve 2) @col {col}");

            // (b) les ouvertures ne sont pas toutes identiques (polynôme non constant).
            assert!(
                o1.iter().any(|v| *v != o1[0]),
                "porteuse non masquée : ouvertures toutes identiques @col {col}"
            );

            // (c) deux blindings distincts → ouvertures disjointes.
            assert!(
                o1.iter().zip(o2.iter()).any(|(a, b)| a != b),
                "masquage déterministe : mêmes ouvertures pour 2 graines @col {col}"
            );
        }

        // ROOT_C : contrôle de cohérence (valeur PUBLIQUE, pas un secret).
        let or = ouvertures_colonne(&p1, ROOT_C);
        assert!(or.iter().any(|v| *v != or[0]), "ROOT_C doit aussi être blindée");
    }

    /// SOUNDNESS À LA PROFONDEUR CONSENSUS (32) — comble un trou de couverture.
    ///
    /// Toutes les autres forges tournent à la profondeur 2, où la géométrie est
    /// QUALITATIVEMENT différente :
    ///
    /// | | depth 2 | depth 32 |
    /// |---|---|---|
    /// | `in_len` | 64 | 512 |
    /// | chemin de Merkle | 32 lignes | 512 lignes |
    /// | slack dans le segment | 32 | **0** |
    /// | ancre de racine (locale) | 31 | **511 = seg_len − 1** |
    ///
    /// À la profondeur consensus, le chemin remplit EXACTEMENT le segment et l'ancre
    /// de racine tombe sur sa DERNIÈRE ligne — la transition y traverse vers le
    /// segment suivant. Un défaut de traitement de frontière serait invisible à la
    /// profondeur 2 et ne se manifesterait qu'en production. D'où ce test.
    ///
    /// Coûteux (deux preuves à profondeur 32) : ignoré par défaut.
    #[test]
    #[ignore = "coûteux (profondeur 32) : lancer avec --ignored"]
    fn soundness_a_la_profondeur_consensus() {
        use crate::monolith::seg_trace::SegForge;
        use crate::monolith::trace::witness_de_test_profondeur_consensus;
        use proved_hash::digest::Digest;
        use proved_hash::felt::Felt;

        let (w, _root) = witness_de_test_profondeur_consensus();
        let depth = w.inputs[0].path.len();
        assert_eq!(depth, 32);
        // Le cas limite : l'ancre de racine est bien sur la dernière ligne du segment.
        assert_eq!(MERKLE_LEVEL_ROWS * depth - 1, seg_len(SegKind::Input, depth) - 1);

        // (a) témoin honnête : accepté.
        let (pi, proof) = prove_seg_monolith(&w);
        assert!(
            verify_seg_monolith(&pi, depth, &proof),
            "témoin honnête accepté à la profondeur consensus"
        );

        // (b) TOUTES les forges qui n'exigent PAS de reconstruction d'arbre,
        // rejouées à la profondeur consensus.
        //
        // ⚠️ Les forges à reconstruction (OwnerConsomme, RhoCommitment, CmFeuille,
        // LeafChemin, PaddingCommitment) restent à la profondeur 2 : le helper
        // `build_tree_from_leaves` est câblé en dur sur un arbre de profondeur 2.
        // Les couvrir au consensus demanderait un constructeur d'arbre générique en
        // profondeur — limite résiduelle assumée, consignée dans la PR.
        let faux = Digest(core::array::from_fn(|i| {
            Felt::from_canonical_u64(9999 + i as u64).unwrap()
        }));
        let cas: [(&str, SegForge); 6] = [
            ("SecretNk (double-dépense)", SegForge::SecretNk(faux)),
            ("NkConsomme", SegForge::NkConsomme(0, faux)),
            ("RhoNullifier", SegForge::RhoNullifier(1, faux)),
            ("CmNullifier (anti-double-dépense)", SegForge::CmNullifier(0, faux)),
            ("ValeurEntrees (VIN↔VACC)", SegForge::ValeurEntrees(11)),
            ("VaccInitial (inflation)", SegForge::VaccInitial(13)),
        ];
        for (nom, forge) in cas {
            assert!(
                !verdict_forge_sur(&w, forge),
                "forge « {nom} » doit être rejetée AUSSI à la profondeur consensus"
            );
        }

        // (c) inertie du blinding : verdict INVERSE, la tx reste acceptée.
        assert!(
            verdict_forge_sur(&w, SegForge::BlindingAdversarial),
            "blinding adverse : inertie aussi à la profondeur consensus"
        );
    }

    /// Les cellules `PAD_ZERO*` des préambules de MERGE sont bien épinglées, à la
    /// bonne ligne ABSOLUE de leur segment.
    ///
    /// Motivation : le roundtrip honnête ne prouve RIEN ici — les `PAD_ZERO` y
    /// valent zéro naturellement, donc une assertion manquante passerait inaperçue
    /// et laisserait un prouveur absorber du junk (`node' = H(l ‖ r ‖ v ‖ 0…)`,
    /// violation de « hash jamais tronqué »). La forge `PaddingCommitment` couvre le
    /// mécanisme pour `m = 32` ; ce test couvre la borne `m = 12` du merge, dont le
    /// nombre de cellules de padding diffère (12..16, soit 4 — contre 17..32 pour le
    /// commitment).
    ///
    /// Test DIRECT sur les assertions produites, sans prouveur : il vérifie les
    /// cellules exactes, là où une forge se contenterait de constater « quelque
    /// chose rejette ».
    #[test]
    fn padding_des_merges_epingle_aux_bonnes_lignes() {
        use crate::sponge::locate;

        let depth = 2usize;
        // Un préambule de merge isolé, à la ligne de début du 1er segment d'entrée.
        let seg = seg_start(1, depth);
        let mut a: Vec<Assertion<BaseElement>> = Vec::new();
        push_preamble(&mut a, seg, SEG_MERKLE_OFF, 12, Domain::MerkleNode.tag() as u64, 8);

        // Cellules de padding attendues : `logical = 3 + 8 + 1 = 12` jusqu'à la
        // frontière de bloc `ceil(12/8)·8 = 16`.
        let attendues: Vec<(usize, usize)> = (12..16)
            .map(|i| {
                let (row, col) = locate(i);
                (SEG_MERKLE_OFF + col, seg + row)
            })
            .collect();
        assert_eq!(attendues.len(), 4, "m=12 → 4 cellules PAD_ZERO");

        for (col, row) in attendues {
            let trouvee = a.iter().any(|assertion| {
                assertion.column() == col
                    && assertion.first_step() == row
                    && assertion.values() == [BaseElement::ZERO]
            });
            assert!(
                trouvee,
                "cellule PAD_ZERO non épinglée à (col {col}, ligne {row}) — un \
                 prouveur pourrait y absorber du junk"
            );
        }

        // Et le décalage par segment est réel : le MÊME préambule au segment suivant
        // vise des lignes différentes.
        let seg2 = seg_start(2, depth);
        assert_ne!(seg, seg2);
        let mut b: Vec<Assertion<BaseElement>> = Vec::new();
        push_preamble(&mut b, seg2, SEG_MERKLE_OFF, 12, Domain::MerkleNode.tag() as u64, 8);
        let lignes_a: Vec<usize> = a.iter().map(|x| x.first_step()).collect();
        let lignes_b: Vec<usize> = b.iter().map(|x| x.first_step()).collect();
        assert_ne!(
            lignes_a, lignes_b,
            "les préambules des deux entrées doivent viser des lignes DISTINCTES"
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
            let col = par_segment(Forme::F22, depth, l, |_, _, _| BaseElement::ONE);
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
            let allumes = indices_non_nuls(&sel_key(Forme::F22, depth, l));
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
            let col = sel_sponge(Forme::F22, depth, l);
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
            let col = sel_m(Forme::F22, depth, l);
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
            let col = signe(Forme::F22, depth, l);
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
            let col = pow(Forme::F22, depth, l);
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
            assert_eq!(indices_non_nuls(&endblk(Forme::F22, depth, l)), attendus, "@ depth {depth}");
        }
    }

    /// `blind_off` : éteint dès la transition `used−1 → used`, donc sur toute la
    /// région de blinding (witness-hiding préservé).
    #[test]
    fn blind_off_eteint_la_region_de_blinding() {
        for depth in DEPTHS {
            let l = trace_len(depth);
            let col = blind_off(Forme::F22, depth, l);
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
            let (ix, cols) = build_periodic(Forme::F22, depth, l);

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
            assert_eq!(cols[ix.sel_key], sel_key(Forme::F22, depth, l));
            assert_eq!(cols[ix.sel_sponge], sel_sponge(Forme::F22, depth, l));
            assert_eq!(cols[ix.sel_m], sel_m(Forme::F22, depth, l));
            assert_eq!(cols[ix.sel_bal], sel_bal(Forme::F22, depth, l));
            assert_eq!(cols[ix.signe], signe(Forme::F22, depth, l));
            assert_eq!(cols[ix.pow], pow(Forme::F22, depth, l));
            assert_eq!(cols[ix.endblk], endblk(Forme::F22, depth, l));
            assert_eq!(cols[ix.blind_off], blind_off(Forme::F22, depth, l));
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
            let (ix, cols) = build_periodic(Forme::F22, depth, l);
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
            let (ix, cols) = build_periodic(Forme::F22, depth, l);
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
