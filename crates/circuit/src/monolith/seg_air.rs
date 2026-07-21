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

use super::seg_layout::*;
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;

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

#[cfg(test)]
mod tests {
    use super::*;

    const DEPTHS: [usize; 2] = [2, 32];

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
