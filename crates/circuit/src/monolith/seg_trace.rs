//! Constructeur de trace du monolithe SEGMENTÉ (3z-c1, tâche T2).
//!
//! Contrairement au monolithe côte-à-côte (`super::trace`), qui range chaque
//! entrée/sortie dans SES PROPRES colonnes sur les mêmes lignes, celui-ci empile
//! les unités en **segments séquentiels de lignes** partageant les MÊMES colonnes :
//! `[KEY][IN0][IN1][OUT0][OUT1]` puis les lignes de blinding. C'est ce qui permettra
//! (3z-c2) de faire varier le NOMBRE d'entrées/sorties sans exploser la largeur —
//! le côte-à-côte plafonne à ~255 colonnes.
//!
//! Ce module ne fait tourner AUCUN prouveur : il est la RÉFÉRENCE DIFFÉRENTIELLE
//! de la disposition segmentée (les cellules produites doivent coïncider avec
//! `rescue::note_commitment`, `merkle::leaf`, `merkle::fold`), exactement comme
//! `super::trace` l'est pour le côte-à-côte. L'AIR segmentée est la tâche T3.
//!
//! **Construit À CÔTÉ de l'existant** (cf. `super::mod`) : les gadgets de lignes
//! (`key_rows`, `sponge_rows_for`, `merkle_path::path_rows`) sont RÉUTILISÉS tels
//! quels depuis `super::trace` — les deux monolithes partagent donc la même
//! construction cryptographique, seule la DISPOSITION change. C'est ce qui rend
//! l'oracle de parité crédible.
//!
//! Witness-hiding (3z-b1) : la région `[used_rows, trace_len)` est remplie d'aléa
//! frais sur toutes les colonnes, comme dans le côte-à-côte.

use super::seg_layout::*;
use super::trace::{
    felt_alea, key_rows, read_digest, sponge_rows_for, MonolithWitness, KEY_NK_LOCAL_OFF,
};
use crate::sponge::RATE_START;
use proved_hash::digest::{Digest, DIGEST_FELTS};
use proved_hash::domain::Domain;
use proved_hash::rescue::note_commit_payload;
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;
use winterfell::TraceTable;

/// Recopie `rows` dans le tampon segmenté à `(row_off, col_off)`. Pendant de
/// `super::trace::segment`, mais pour la largeur `WIDTH` du layout SEGMENTÉ.
fn seg_copy<const N: usize>(
    dst: &mut [[BaseElement; WIDTH]],
    rows: &[[BaseElement; N]],
    row_off: usize,
    col_off: usize,
) {
    for (i, row) in rows.iter().enumerate() {
        dst[row_off + i][col_off..col_off + N].copy_from_slice(row);
    }
}

/// Écrit un digest sur TOUTES les lignes d'une colonne porteuse (valeur constante,
/// lisible depuis n'importe quel segment — c'est le mécanisme de chaînage
/// inter-segments, inchangé par rapport au côte-à-côte).
fn set_carrier_digest(rows: &mut [[BaseElement; WIDTH]], col: usize, d: &Digest) {
    let be: [BaseElement; DIGEST_FELTS] = core::array::from_fn(|k| d.0[k].to_winter());
    for row in rows.iter_mut() {
        row[col..col + DIGEST_FELTS].copy_from_slice(&be);
    }
}

/// Idem pour une porteuse scalaire (montants).
fn set_carrier_scalar(rows: &mut [[BaseElement; WIDTH]], col: usize, v: u64) {
    let be = BaseElement::new(v);
    for row in rows.iter_mut() {
        row[col] = be;
    }
}

/// Construit la trace segmentée avec un aléa de blinding tiré d'`OsRng`
/// (production). Voir `build_seg_trace_seeded` pour la couture de test.
pub(crate) fn build_seg_trace(w: &MonolithWitness) -> TraceTable<BaseElement> {
    build_seg_trace_seeded(w, &mut rand::rngs::OsRng)
}

/// Construit la trace segmentée du monolithe 2-in/2-out à partir du témoin `w`.
///
/// Parcourt le SCHEDULE (`schedule_2in2out`) et remplit chaque segment à sa ligne
/// de début (`seg_start`), selon son `SegKind` :
/// - `Key` : les deux blocs d'éponge owner/nk du MÊME secret (côte à côte en
///   colonnes dans le segment — 24 colonnes) ;
/// - `Input` : pile d'éponge `commitment → feuille → nullifier` (lignes locales
///   0..56) ET chemin de Merkle (lignes locales 0..16·depth) EN PARALLÈLE sur des
///   groupes de colonnes disjoints, plus les bits du montant ;
/// - `Output` : éponge de commitment (lignes locales 0..32) plus les bits du montant.
///
/// L'accumulateur d'équilibre `S` est CHAÎNÉ à travers tous les segments (colonne
/// partagée `S_COL`) : il vaut 0 à la première ligne, encaisse `+value` sur chaque
/// segment IN et `−value` sur chaque segment OUT, et vaut `fee` à la dernière ligne
/// utile. C'est le remplacement de la région d'équilibre dédiée du côte-à-côte.
pub(crate) fn build_seg_trace_seeded(
    w: &MonolithWitness,
    rng: &mut impl rand::Rng,
) -> TraceTable<BaseElement> {
    let depth = w.inputs[0].path.len();
    assert_eq!(
        depth,
        w.inputs[1].path.len(),
        "les deux chemins doivent avoir la même profondeur"
    );
    let len = trace_len(depth);
    let mut rows = vec![[BaseElement::ZERO; WIDTH]; len];
    let schedule = schedule_2in2out();

    // --- Segment KEY : owner ∧ nk du MÊME secret. ---
    let key_i = 0;
    debug_assert_eq!(schedule[key_i], SegKind::Key);
    let kr = key_rows(w.secret.as_felts());
    debug_assert_eq!(kr.len(), KEY_LEN);
    seg_copy(&mut rows, &kr, seg_start(key_i, depth), SEG_KEY_OFF);
    let owner = read_digest(&kr, kr.len() - 1, RATE_START);
    let nk = read_digest(&kr, kr.len() - 1, KEY_NK_LOCAL_OFF + RATE_START);
    set_carrier_digest(&mut rows, OWNER_C, &owner);
    set_carrier_digest(&mut rows, NK_C, &nk);

    // --- Segments d'ENTRÉE et de SORTIE, dans l'ordre du schedule. ---
    // `s` = accumulateur d'équilibre chaîné (valeur AVANT la contribution de la
    // ligne courante), `root_vu` = racine repliée (identique pour les deux entrées).
    let mut s = BaseElement::ZERO;
    let mut root_vu: Option<Digest> = None;
    let (mut n_in, mut n_out) = (0usize, 0usize);

    for (i, kind) in schedule.iter().enumerate() {
        let start = seg_start(i, depth);
        let seg_rows = seg_len(*kind, depth);
        match kind {
            SegKind::Key => {
                // Aucune contribution à l'équilibre : `S` reste constant, bits à 0.
                for r in 0..seg_rows {
                    rows[start + r][S_COL] = s;
                }
            }
            SegKind::Input => {
                let input = &w.inputs[n_in];
                let note = &input.note;

                // cm = H_NoteCommitment(value ‖ owner ‖ rho ‖ r) — lignes 0..32.
                let cm_payload =
                    note_commit_payload(note.value, &note.owner, &note.rho, &note.r);
                let cm_rows = sponge_rows_for(Domain::NoteCommitment, &cm_payload);
                debug_assert_eq!(cm_rows.len(), CM_ROWS_END - CM_ROWS_START);
                seg_copy(&mut rows, &cm_rows, start + CM_ROWS_START, SEG_SPONGE_OFF);
                let cm = read_digest(&cm_rows, cm_rows.len() - 1, RATE_START);

                // feuille = H_MerkleLeaf(cm) — lignes 32..40.
                let leaf_rows = sponge_rows_for(Domain::MerkleLeaf, &cm.0);
                debug_assert_eq!(leaf_rows.len(), LEAF_ROWS_END - LEAF_ROWS_START);
                seg_copy(&mut rows, &leaf_rows, start + LEAF_ROWS_START, SEG_SPONGE_OFF);
                let leaf_d = read_digest(&leaf_rows, leaf_rows.len() - 1, RATE_START);

                // nullifier = H_Nullifier(nk ‖ rho ‖ cm) — lignes 40..56.
                let mut nf_payload = Vec::with_capacity(3 * DIGEST_FELTS);
                nf_payload.extend_from_slice(&nk.0);
                nf_payload.extend_from_slice(&note.rho.0);
                nf_payload.extend_from_slice(&cm.0);
                let nf_rows = sponge_rows_for(Domain::Nullifier, &nf_payload);
                debug_assert_eq!(nf_rows.len(), NF_ROWS_END - NF_ROWS_START);
                seg_copy(&mut rows, &nf_rows, start + NF_ROWS_START, SEG_SPONGE_OFF);

                // Chemin de Merkle, EN PARALLÈLE de la pile d'éponge (colonnes
                // disjointes) : lignes locales 0..16·depth.
                let m_rows = crate::merkle_path::path_rows(&leaf_d, &input.path, input.index);
                debug_assert_eq!(m_rows.len(), MERKLE_LEVEL_ROWS * depth);
                debug_assert!(m_rows.len() <= seg_rows, "le chemin tient dans le segment");
                seg_copy(&mut rows, &m_rows, start, SEG_MERKLE_OFF);

                // Racine repliée = sortie d'éponge du DERNIER merge du chemin
                // (lue dans la trace, pas recopiée d'une référence : c'est ce que
                // l'AIR contraindra, et ce que le test différentiel compare à
                // `merkle::fold`).
                let root_i = read_digest(&m_rows, m_rows.len() - 1, RATE_START);
                match &root_vu {
                    None => root_vu = Some(root_i),
                    Some(r0) => debug_assert_eq!(
                        *r0, root_i,
                        "les deux entrées doivent prouver contre la MÊME racine"
                    ),
                }

                // Porteuses de l'entrée + bits/équilibre du montant.
                set_carrier_digest(&mut rows, RHO_C[n_in], &note.rho);
                set_carrier_digest(&mut rows, CM_C[n_in], &cm);
                set_carrier_digest(&mut rows, LEAF_C[n_in], &leaf_d);
                set_carrier_scalar(&mut rows, VIN_C[n_in], note.value);
                s = fill_segment_balance(&mut rows, start, seg_rows, note.value, true, s);

                n_in += 1;
            }
            SegKind::Output => {
                let out = &w.outputs[n_out];
                let cm_payload = note_commit_payload(out.value, &out.owner, &out.rho, &out.r);
                let out_rows = sponge_rows_for(Domain::NoteCommitment, &cm_payload);
                debug_assert_eq!(out_rows.len(), CM_ROWS_END - CM_ROWS_START);
                seg_copy(&mut rows, &out_rows, start + CM_ROWS_START, SEG_SPONGE_OFF);

                set_carrier_scalar(&mut rows, VOUT_C[n_out], out.value);
                s = fill_segment_balance(&mut rows, start, seg_rows, out.value, false, s);

                n_out += 1;
            }
        }
    }
    debug_assert_eq!((n_in, n_out), (2, 2));

    // Porteuse de racine : partagée, assertée publique une seule fois par l'AIR.
    if let Some(root) = root_vu {
        set_carrier_digest(&mut rows, ROOT_C, &root);
    }

    // --- Blinding (witness-hiding 3z-b1) : aléa frais sur TOUTES les colonnes de
    //     la région [used, len), S_COL comprise (l'AIR y est gatée par blind_off). ---
    let used = used_rows(depth);
    debug_assert_eq!(used, seg_start(N_SEGMENTS - 1, depth) + seg_len(schedule[N_SEGMENTS - 1], depth));
    for row in rows.iter_mut().skip(used) {
        for cell in row.iter_mut() {
            *cell = felt_alea(rng);
        }
    }

    let mut trace = TraceTable::new(WIDTH, len);
    for (i, row) in rows.iter().enumerate() {
        trace.update_row(i, row);
    }
    trace
}

/// Remplit les colonnes d'équilibre LOCALES d'un segment (bit du montant, `VACC`
/// partiel) et la colonne PARTAGÉE `S_COL`, et retourne la valeur de `S` après le
/// segment.
///
/// Sémantique reprise telle quelle du côte-à-côte (`super::trace::fill_balance`),
/// mais par segment : `S` porté par la ligne est la somme signée AVANT la
/// contribution de cette ligne ; `VACC` est la valeur partielle reconstruite depuis
/// les bits, remise à 0 au début du segment. Les lignes au-delà de `RANGE_BITS`
/// portent un bit nul (elles ne contribuent pas) — c'est ce qui borne le montant à
/// `< 2^RANGE_BITS`.
fn fill_segment_balance(
    rows: &mut [[BaseElement; WIDTH]],
    start: usize,
    seg_rows: usize,
    value: u64,
    est_entree: bool,
    s_initial: BaseElement,
) -> BaseElement {
    let sign = if est_entree {
        BaseElement::ONE
    } else {
        -BaseElement::ONE
    };
    let mut s = s_initial;
    let mut vacc = BaseElement::ZERO;
    for r in 0..seg_rows {
        let row = &mut rows[start + r];
        let bit = if r < crate::range_check::RANGE_BITS {
            (value >> r) & 1
        } else {
            0
        };
        let bit_be = BaseElement::new(bit);
        row[SEG_BALBIT_OFF + SEG_BAL_BIT] = bit_be;
        row[SEG_BALBIT_OFF + SEG_BAL_VACC] = vacc;
        row[S_COL] = s;
        if r < crate::range_check::RANGE_BITS {
            let pow = BaseElement::new(1u64 << r);
            s += sign * bit_be * pow;
            vacc += bit_be * pow;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spend::SpendNote;
    use crate::tx::ProvedInput;
    use proved_hash::digest::ShieldedSecret;
    use proved_hash::felt::Felt;
    use proved_hash::{merkle, rescue};
    use winterfell::Trace;

    fn digest(seed: u64) -> Digest {
        Digest(core::array::from_fn(|i| {
            Felt::from_canonical_u64(seed + i as u64).unwrap()
        }))
    }

    /// Arbre de profondeur 2 : `cm0` en index 0, `cm1` en index 3.
    fn build_tree(cm0: &Digest, cm1: &Digest) -> (Digest, Vec<Digest>, Vec<Digest>) {
        let l0 = merkle::leaf(cm0);
        let l1 = merkle::leaf(&digest(9001));
        let l2 = merkle::leaf(&digest(9002));
        let l3 = merkle::leaf(cm1);
        let n_left = merkle::node(&l0, &l1);
        let n_right = merkle::node(&l2, &l3);
        (merkle::node(&n_left, &n_right), vec![l1, n_right], vec![l2, n_left])
    }

    /// Témoin 2-in/2-out équilibré (1000 + 500 = 900 + 580 + fee 20), profondeur 2.
    fn witness_de_test() -> MonolithWitness {
        let secret = ShieldedSecret::from_felts(core::array::from_fn(|i| {
            Felt::from_canonical_u64(700 + i as u64).unwrap()
        }));
        let owner = rescue::hash(proved_hash::domain::Domain::Owner, secret.as_felts());
        let n0 = SpendNote { value: 1_000, owner, rho: digest(20), r: digest(30) };
        let n1 = SpendNote { value: 500, owner, rho: digest(40), r: digest(50) };
        let cm0 = rescue::note_commitment(n0.value, &n0.owner, &n0.rho, &n0.r);
        let cm1 = rescue::note_commitment(n1.value, &n1.owner, &n1.rho, &n1.r);
        let (_root, path0, path1) = build_tree(&cm0, &cm1);
        MonolithWitness {
            secret,
            inputs: [
                ProvedInput { note: n0, path: path0, index: 0 },
                ProvedInput { note: n1, path: path1, index: 3 },
            ],
            outputs: [
                SpendNote { value: 900, owner: digest(60), rho: digest(61), r: digest(62) },
                SpendNote { value: 580, owner: digest(70), rho: digest(71), r: digest(72) },
            ],
            fee: 20,
        }
    }

    /// Lit la cellule `(row, col)` d'une `TraceTable` (l'API winterfell est
    /// `get(col, row)` — on garde l'ordre `(row, col)` ici, plus lisible).
    fn cell(t: &TraceTable<BaseElement>, row: usize, col: usize) -> BaseElement {
        t.get(col, row)
    }

    fn cell_digest(t: &TraceTable<BaseElement>, row: usize, col: usize) -> Digest {
        Digest(core::array::from_fn(|k| {
            Felt::from_winter(cell(t, row, col + k)).expect("canonique")
        }))
    }

    /// Sanité DIFFÉRENTIELLE de la trace segmentée : chaque valeur produite dans les
    /// segments doit coïncider avec la référence HORS-CIRCUIT (`rescue::*`,
    /// `merkle::*`) — pas avec la construction elle-même.
    #[test]
    fn trace_segmentee_coincide_avec_les_references() {
        let w = witness_de_test();
        let depth = 2;
        let t = build_seg_trace(&w);
        assert_eq!(t.width(), WIDTH);
        assert_eq!(t.length(), trace_len(depth));

        // Porteuses owner/nk : dérivées du secret (P2/P4).
        let owner_attendu = rescue::hash(Domain::Owner, w.secret.as_felts());
        let nk_attendu = rescue::hash(Domain::Nk, w.secret.as_felts());
        assert_eq!(cell_digest(&t, 0, OWNER_C), owner_attendu);
        assert_eq!(cell_digest(&t, 0, NK_C), nk_attendu);

        // Segments d'entrée : cm, feuille, nullifier aux lignes du segment.
        let schedule = schedule_2in2out();
        let mut n_in = 0;
        for (i, kind) in schedule.iter().enumerate() {
            if *kind != SegKind::Input {
                continue;
            }
            let start = seg_start(i, depth);
            let note = &w.inputs[n_in].note;
            let cm = rescue::note_commitment(note.value, &note.owner, &note.rho, &note.r);
            let leaf = merkle::leaf(&cm);

            // Dernière ligne de chaque sous-pile d'éponge = le digest produit.
            assert_eq!(
                cell_digest(&t, start + CM_ROWS_END - 1, SEG_SPONGE_OFF + RATE_START),
                cm,
                "commitment de l'entrée {n_in}"
            );
            assert_eq!(
                cell_digest(&t, start + LEAF_ROWS_END - 1, SEG_SPONGE_OFF + RATE_START),
                leaf,
                "feuille de l'entrée {n_in}"
            );
            // Porteuses de l'entrée.
            assert_eq!(cell_digest(&t, 0, CM_C[n_in]), cm);
            assert_eq!(cell_digest(&t, 0, LEAF_C[n_in]), leaf);
            assert_eq!(cell_digest(&t, 0, RHO_C[n_in]), note.rho);
            assert_eq!(cell(&t, 0, VIN_C[n_in]), BaseElement::new(note.value));
            n_in += 1;
        }
        assert_eq!(n_in, 2);

        // Segments de sortie : commitment de sortie.
        let mut n_out = 0;
        for (i, kind) in schedule.iter().enumerate() {
            if *kind != SegKind::Output {
                continue;
            }
            let start = seg_start(i, depth);
            let out = &w.outputs[n_out];
            let oc = rescue::note_commitment(out.value, &out.owner, &out.rho, &out.r);
            assert_eq!(
                cell_digest(&t, start + CM_ROWS_END - 1, SEG_SPONGE_OFF + RATE_START),
                oc,
                "commitment de la sortie {n_out}"
            );
            assert_eq!(cell(&t, 0, VOUT_C[n_out]), BaseElement::new(out.value));
            n_out += 1;
        }
        assert_eq!(n_out, 2);

        // Porteuse de racine == racine hors-circuit de l'arbre.
        let cm0 = rescue::note_commitment(
            w.inputs[0].note.value,
            &w.inputs[0].note.owner,
            &w.inputs[0].note.rho,
            &w.inputs[0].note.r,
        );
        let cm1 = rescue::note_commitment(
            w.inputs[1].note.value,
            &w.inputs[1].note.owner,
            &w.inputs[1].note.rho,
            &w.inputs[1].note.r,
        );
        let (root_attendu, _, _) = build_tree(&cm0, &cm1);
        assert_eq!(cell_digest(&t, 0, ROOT_C), root_attendu);
    }

    /// Équilibre CHAÎNÉ : `S` vaut 0 à la première ligne et `fee` à la dernière
    /// ligne utile — c'est la propriété que l'AIR (T3) assertera.
    #[test]
    fn equilibre_chaine_de_zero_a_fee() {
        let w = witness_de_test();
        let depth = 2;
        let t = build_seg_trace(&w);

        assert_eq!(cell(&t, 0, S_COL), BaseElement::ZERO, "S démarre à 0");
        let used = used_rows(depth);
        assert_eq!(
            cell(&t, used - 1, S_COL),
            BaseElement::new(w.fee),
            "S vaut fee à la dernière ligne utile"
        );
    }

    /// La région de blinding `[used, len)` diffère d'un tirage à l'autre (aléa frais)
    /// alors que la région utile est identique — witness-hiding préservé.
    #[test]
    fn region_de_blinding_aleatoire_region_utile_deterministe() {
        let w = witness_de_test();
        let depth = 2;
        let t1 = build_seg_trace(&w);
        let t2 = build_seg_trace(&w);
        let used = used_rows(depth);

        // Région utile : identique (déterministe).
        for col in [OWNER_C, NK_C, S_COL, ROOT_C] {
            for row in [0, used - 1] {
                assert_eq!(cell(&t1, row, col), cell(&t2, row, col));
            }
        }
        // Région de blinding : au moins une cellule diffère (proba d'égalité ≈ 2^-64).
        let differe = (used..t1.length())
            .any(|row| (0..WIDTH).any(|col| cell(&t1, row, col) != cell(&t2, row, col)));
        assert!(differe, "la région de blinding doit être ré-aléatoirisée");
    }
}
