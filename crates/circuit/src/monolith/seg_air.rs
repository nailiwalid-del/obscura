//! AIR du monolithe SEGMENTÉ (3z-c1, tâche T3) — **étape 1 : les sélecteurs**.
//!
//! Ce module porte les colonnes périodiques « pleine longueur » de la disposition
//! segmentée. Elles sont écrites comme des FONCTIONS PURES, testables sans faire
//! tourner le moindre prouveur : une erreur de sélecteur se traduirait sinon par
//! un échec de preuve illisible en `--release`, le pire mode de débogage sur un
//! circuit. L'implémentation du trait `winterfell::Air` (transitions, assertions,
//! degrés) est l'étape 2.
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
