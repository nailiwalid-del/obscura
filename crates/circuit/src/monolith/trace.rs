//! Constructeur de trace du monolithe (3z-a2).
//!
//! Assemble, dans UNE seule `TraceTable` au layout de `layout.rs`, tout ce que la
//! version composée (3b5) répartissait entre plusieurs sous-preuves : la clé
//! (owner ∧ nk du même secret), les deux dépenses (commitment ‖ feuille ‖
//! nullifier ‖ chemin de Merkle), les deux sorties (commitment) et l'équilibre
//! (Σ entrées = Σ sorties + fee). AUCUN AIR ici — seulement la construction des
//! lignes et leur recopie aux bons offsets. Les contraintes (segments puis
//! liaisons par porteuses) sont les tâches T3/T4.
//!
//! Ce module ne fait tourner AUCUN prouveur : `build_monolith_trace` s'exécute en
//! mode debug et sert de RÉFÉRENCE DIFFÉRENTIELLE (les cellules produites doivent
//! coïncider avec les fonctions hors-circuit `rescue::note_commitment`,
//! `merkle::leaf`, `merkle::fold`).
//!
//! ⚠️ validity-only : aucune confidentialité ici (cf. avertissement du crate).
//!
//! `#[allow(dead_code)]` de module : `build_monolith_trace` n'a pour l'instant
//! qu'un seul appelant, le test différentiel (`#[cfg(test)]`). En build normal
//! (hors tests), rien dans le crate n'atteint encore ce module (aucun point
//! d'entrée public) — l'AIR de T3 puis `prove_monolith_tx` de T5 le rendront
//! atteignable ; l'allow tombera à ce moment-là.
#![allow(dead_code)]

use crate::monolith::layout::*;
use crate::rescue_round::{NUM_ROUNDS, STATE_WIDTH, TRACE_LEN as ROUND_LEN};
use crate::spend::SpendNote;
use crate::sponge::{sponge_rows, RATE_START, TRACE_WIDTH};
use crate::tx::ProvedInput;
use proved_hash::digest::{Digest, ShieldedSecret, DIGEST_FELTS};
use proved_hash::domain::{sponge_preamble, Domain, ENCODING_VERSION};
use proved_hash::felt::Felt;
use proved_hash::rescue::{absorbed_len, note_commit_payload};
use winter_crypto::hashers::Rp64_256;
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;
use winterfell::TraceTable;

/// Témoin complet du monolithe : le secret racine, les deux entrées prouvées
/// (note + chemin + position) et les deux sorties, plus les frais publics.
pub(crate) struct MonolithWitness {
    pub secret: ShieldedSecret,
    pub inputs: [ProvedInput; 2],
    pub outputs: [SpendNote; 2],
    pub fee: u64,
}

/// Recopie `rows` (segment `row_off..row_off+rows.len()`, `col_off..col_off+N`)
/// dans le tampon de trace `dst` (une ligne complète par entrée, largeur `WIDTH`).
/// Générique en largeur de segment (`N = 20` sponge/sortie, `24` clé, `29` chemin).
pub(crate) fn segment<const N: usize>(
    dst: &mut [[BaseElement; WIDTH]],
    rows: &[[BaseElement; N]],
    row_off: usize,
    col_off: usize,
) {
    for (i, row) in rows.iter().enumerate() {
        dst[row_off + i][col_off..col_off + N].copy_from_slice(row);
    }
}

/// Lit un digest (4 Felts) dans un tampon de lignes largeur `N`, à `(row, col)`.
fn read_digest<const N: usize>(rows: &[[BaseElement; N]], row: usize, col: usize) -> Digest {
    Digest(core::array::from_fn(|k| {
        Felt::from_winter(rows[row][col + k]).expect("digest canonique")
    }))
}

/// Lignes d'une éponge `H_domain(payload)`, alignées PAD_ZERO* (motif de
/// `sponge::prove_sponge`, sans le prouveur).
fn sponge_rows_for(domain: Domain, payload: &[Felt]) -> Vec<[BaseElement; TRACE_WIDTH]> {
    let mut preamble: Vec<BaseElement> = sponge_preamble(domain, payload)
        .iter()
        .map(|f| f.to_winter())
        .collect();
    preamble.resize(absorbed_len(preamble.len()), BaseElement::ZERO);
    sponge_rows(&preamble)
}

// ================================================================================================
// CLÉ (recopie locale de `key::build_key_trace`, cf. brief T2 — 2 blocs B=1, 8 lignes)
// ================================================================================================

const KEY_WIDTH: usize = 2 * STATE_WIDTH; // 24
const KEY_SECRET_START: usize = RATE_START + 3; // 7
const KEY_PAD_ONE_IDX: usize = 11;
const KEY_NK_LOCAL_OFF: usize = STATE_WIDTH; // 12 : bloc nk dans les 24 colonnes locales
const KEY_ABSORBED_LEN: u64 = 8; // préambule [V, tag, LEN, s0..s3, PAD_ONE] = 1 bloc
const KEY_PAYLOAD_LEN: u64 = DIGEST_FELTS as u64;

/// État initial d'un bloc `H_domain(secret)` (capacité + préambule), identique à
/// `key::initial_state`.
fn key_initial_state(domain: Domain, secret: &[Felt; DIGEST_FELTS]) -> [BaseElement; STATE_WIDTH] {
    let mut st = [BaseElement::ZERO; STATE_WIDTH];
    st[0] = BaseElement::new(KEY_ABSORBED_LEN);
    st[RATE_START] = BaseElement::new(ENCODING_VERSION as u64);
    st[RATE_START + 1] = BaseElement::new(domain.tag() as u64);
    st[RATE_START + 2] = BaseElement::new(KEY_PAYLOAD_LEN);
    for (i, s) in secret.iter().enumerate() {
        st[KEY_SECRET_START + i] = s.to_winter();
    }
    st[KEY_PAD_ONE_IDX] = BaseElement::new(1);
    st
}

/// Lignes de la trace de clé : bloc owner (colonnes locales `0..12`) + bloc nk
/// (`12..24`) côte à côte, pour LE MÊME secret — recopie de `key::build_key_trace`
/// (sans dépendre de sa visibilité privée).
fn key_rows(secret: &[Felt; DIGEST_FELTS]) -> Vec<[BaseElement; KEY_WIDTH]> {
    let mut o = key_initial_state(Domain::Owner, secret);
    let mut n = key_initial_state(Domain::Nk, secret);
    let mut rows = Vec::with_capacity(ROUND_LEN);
    for step in 0..ROUND_LEN {
        let mut row = [BaseElement::ZERO; KEY_WIDTH];
        row[..STATE_WIDTH].copy_from_slice(&o);
        row[KEY_NK_LOCAL_OFF..].copy_from_slice(&n);
        rows.push(row);
        if step < NUM_ROUNDS {
            Rp64_256::apply_round(&mut o, step);
            Rp64_256::apply_round(&mut n, step);
        }
    }
    rows
}

// ================================================================================================
// ÉQUILIBRE (BAL_OFF : 3 colonnes [bit, S, VACC], 4 blocs de 64 lignes)
// ================================================================================================

const BAL_BLOCK: usize = 64;
const BAL_BIT: usize = 0;
const BAL_S: usize = 1;
const BAL_VACC: usize = 2;

/// Remplit les 4 blocs d'équilibre (entrées puis sorties, signe implicite par
/// bloc : `+1` blocs 0-1, `-1` blocs 2-3). `S` = somme signée AVANT la
/// contribution de la ligne (`S[0] = 0`) ; `VACC` = valeur partielle du bloc
/// courant, remise à 0 à chaque début de bloc.
fn fill_balance(dst: &mut [[BaseElement; WIDTH]], amounts: [u64; 4]) {
    let mut s = BaseElement::ZERO;
    for (b, &amount) in amounts.iter().enumerate() {
        let sign = if b < 2 { BaseElement::ONE } else { -BaseElement::ONE };
        let mut vacc = BaseElement::ZERO;
        for r in 0..BAL_BLOCK {
            let row = b * BAL_BLOCK + r;
            let bit = if r < crate::range_check::RANGE_BITS {
                (amount >> r) & 1
            } else {
                0
            };
            let bit_be = BaseElement::new(bit);
            dst[row][BAL_OFF + BAL_BIT] = bit_be;
            dst[row][BAL_OFF + BAL_S] = s;
            dst[row][BAL_OFF + BAL_VACC] = vacc;
            if r < crate::range_check::RANGE_BITS {
                let pow = BaseElement::new(1u64 << r);
                s += sign * bit_be * pow;
                vacc += bit_be * pow;
            }
        }
    }

    // Complétude au-delà des 4 blocs (lignes idle 256..len) : la contrainte S est
    // NON gatée (le signe périodique la porte, cf. air.rs) et exige `S` constant
    // dès que `signe = 0` ; l'assertion finale `S[len−1] = fee` lit cette même
    // colonne. On PROPAGE donc `S = Σsigné` (= fee pour un témoin honnête) et on
    // maintient `VACC = 0`, `bit = 0` sur toute la traîne — sans quoi une trace
    // honnête à trace_len > 256 (profondeur ≥ 32) serait rejetée (S retomberait à 0).
    for row in dst.iter_mut().skip(4 * BAL_BLOCK) {
        row[BAL_OFF + BAL_BIT] = BaseElement::ZERO;
        row[BAL_OFF + BAL_S] = s;
        row[BAL_OFF + BAL_VACC] = BaseElement::ZERO;
    }
}

// ================================================================================================
// TRACE DU MONOLITHE
// ================================================================================================

/// Construit la trace complète du monolithe (2-in/2-out) à partir du témoin `w`.
/// Longueur `trace_len(depth)` où `depth` est la profondeur des chemins de Merkle
/// des deux entrées (doivent coïncider). Lignes idle (au-delà des segments actifs)
/// laissées à zéro.
pub(crate) fn build_monolith_trace(w: &MonolithWitness) -> TraceTable<BaseElement> {
    let depth = w.inputs[0].path.len();
    assert_eq!(
        depth,
        w.inputs[1].path.len(),
        "les deux chemins doivent avoir la même profondeur"
    );
    let len = trace_len(depth);
    let mut rows = vec![[BaseElement::ZERO; WIDTH]; len];

    // --- Clé : owner ∧ nk du même secret (8 lignes, KEY_OFF..KEY_OFF+24). ---
    let kr = key_rows(w.secret.as_felts());
    segment(&mut rows, &kr, 0, KEY_OFF);
    let owner = read_digest(&kr, kr.len() - 1, RATE_START);
    let nk = read_digest(&kr, kr.len() - 1, KEY_NK_LOCAL_OFF + RATE_START);

    let owner_be: [BaseElement; DIGEST_FELTS] = core::array::from_fn(|k| owner.0[k].to_winter());
    let nk_be: [BaseElement; DIGEST_FELTS] = core::array::from_fn(|k| nk.0[k].to_winter());
    for row in rows.iter_mut() {
        row[OWNER_C..OWNER_C + DIGEST_FELTS].copy_from_slice(&owner_be);
        row[NK_C..NK_C + DIGEST_FELTS].copy_from_slice(&nk_be);
    }

    // --- Entrées : U_i (commitment ‖ feuille ‖ nullifier) + M_i (chemin). ---
    let mut amounts = [0u64; 4];
    for (i, (u_off, m_off)) in [(U0_OFF, M0_OFF), (U1_OFF, M1_OFF)].into_iter().enumerate() {
        let input = &w.inputs[i];
        let note = &input.note;
        amounts[i] = note.value;

        // cm = H_NoteCommitment(value ‖ owner ‖ rho ‖ r) — lignes 0..32.
        let commit_payload = note_commit_payload(note.value, &note.owner, &note.rho, &note.r);
        let cm_rows = sponge_rows_for(Domain::NoteCommitment, &commit_payload);
        debug_assert_eq!(cm_rows.len(), CM_ROWS_END - CM_ROWS_START);
        segment(&mut rows, &cm_rows, CM_ROWS_START, u_off);
        let cm = read_digest(&cm_rows, cm_rows.len() - 1, RATE_START);

        // feuille = H_MerkleLeaf(cm) — lignes 32..40.
        let leaf_rows = sponge_rows_for(Domain::MerkleLeaf, &cm.0);
        debug_assert_eq!(leaf_rows.len(), LEAF_ROWS_END - LEAF_ROWS_START);
        segment(&mut rows, &leaf_rows, LEAF_ROWS_START, u_off);
        let leaf_d = read_digest(&leaf_rows, leaf_rows.len() - 1, RATE_START);

        // nullifier = H_Nullifier(nk ‖ rho ‖ cm) — lignes 40..56.
        let mut nf_payload = Vec::with_capacity(3 * DIGEST_FELTS);
        nf_payload.extend_from_slice(&nk.0);
        nf_payload.extend_from_slice(&note.rho.0);
        nf_payload.extend_from_slice(&cm.0);
        let nf_rows = sponge_rows_for(Domain::Nullifier, &nf_payload);
        debug_assert_eq!(nf_rows.len(), NF_ROWS_END - NF_ROWS_START);
        segment(&mut rows, &nf_rows, NF_ROWS_START, u_off);

        // chemin de Merkle : root = fold(feuille, path, index) — M_i.
        let m_rows = crate::merkle_path::path_rows(&leaf_d, &input.path, input.index);
        segment(&mut rows, &m_rows, 0, m_off);

        // Porteuses par entrée : rho, cm, feuille, valeur — mêmes valeurs sur
        // toutes les lignes.
        let rho_be: [BaseElement; DIGEST_FELTS] = core::array::from_fn(|k| note.rho.0[k].to_winter());
        let cm_be: [BaseElement; DIGEST_FELTS] = core::array::from_fn(|k| cm.0[k].to_winter());
        let leaf_be: [BaseElement; DIGEST_FELTS] = core::array::from_fn(|k| leaf_d.0[k].to_winter());
        let vin = BaseElement::new(note.value);
        for row in rows.iter_mut() {
            row[RHO_C[i]..RHO_C[i] + DIGEST_FELTS].copy_from_slice(&rho_be);
            row[CM_C[i]..CM_C[i] + DIGEST_FELTS].copy_from_slice(&cm_be);
            row[LEAF_C[i]..LEAF_C[i] + DIGEST_FELTS].copy_from_slice(&leaf_be);
            row[VIN_C[i]] = vin;
        }
    }

    // --- Sorties : O_j (commitment, lignes 0..32). ---
    for (j, o_off) in [O0_OFF, O1_OFF].into_iter().enumerate() {
        let out = &w.outputs[j];
        amounts[2 + j] = out.value;

        let commit_payload = note_commit_payload(out.value, &out.owner, &out.rho, &out.r);
        let out_rows = sponge_rows_for(Domain::NoteCommitment, &commit_payload);
        segment(&mut rows, &out_rows, 0, o_off);

        let vout = BaseElement::new(out.value);
        for row in rows.iter_mut() {
            row[VOUT_C[j]] = vout;
        }
    }

    // --- Équilibre : Σ entrées = Σ sorties + fee. ---
    fill_balance(&mut rows, amounts);

    // --- Assemblage. ---
    let mut trace = TraceTable::new(WIDTH, len);
    for (i, row) in rows.iter().enumerate() {
        trace.update_row(i, row);
    }
    trace
}

#[cfg(test)]
fn digest(seed: u64) -> Digest {
    Digest(core::array::from_fn(|i| {
        Felt::from_canonical_u64(seed + i as u64).unwrap()
    }))
}

/// Arbre de profondeur 2 (4 feuilles) : `cm0` en index 0, `cm1` en index 3, deux
/// feuilles muettes. Recopie de `tx.rs::tests::build_tree`.
#[cfg(test)]
fn build_tree(cm0: &Digest, cm1: &Digest) -> (Digest, Vec<Digest>, Vec<Digest>) {
    use proved_hash::merkle;
    let l0 = merkle::leaf(cm0);
    let l1 = merkle::leaf(&digest(9001));
    let l2 = merkle::leaf(&digest(9002));
    let l3 = merkle::leaf(cm1);
    let n_left = merkle::node(&l0, &l1);
    let n_right = merkle::node(&l2, &l3);
    let root = merkle::node(&n_left, &n_right);
    let path0 = vec![l1, n_right];
    let path1 = vec![l2, n_left];
    (root, path0, path1)
}

/// Témoin de test : deux entrées (1000/500, même `owner`) équilibrées avec deux
/// sorties (900/580) + fee 20, arbre de profondeur 2. Réutilisé par T3/T4.
#[cfg(test)]
pub(crate) fn witness_de_test() -> (MonolithWitness, Digest) {
    use proved_hash::rescue;

    let secret = ShieldedSecret::from_felts(core::array::from_fn(|i| {
        Felt::from_canonical_u64(700 + i as u64).unwrap()
    }));
    let owner = rescue::hash(Domain::Owner, secret.as_felts());

    let n0 = SpendNote { value: 1_000, owner, rho: digest(20), r: digest(30) };
    let n1 = SpendNote { value: 500, owner, rho: digest(40), r: digest(50) };
    let cm0 = rescue::note_commitment(n0.value, &n0.owner, &n0.rho, &n0.r);
    let cm1 = rescue::note_commitment(n1.value, &n1.owner, &n1.rho, &n1.r);
    let (root, path0, path1) = build_tree(&cm0, &cm1);

    // Sorties : 900 + 580 + fee 20 = 1500 = 1000 + 500.
    let o0 = SpendNote { value: 900, owner: digest(60), rho: digest(61), r: digest(62) };
    let o1 = SpendNote { value: 580, owner: digest(70), rho: digest(71), r: digest(72) };

    let inputs = [
        ProvedInput { note: n0, path: path0, index: 0 },
        ProvedInput { note: n1, path: path1, index: 3 },
    ];

    let w = MonolithWitness { secret, inputs, outputs: [o0, o1], fee: 20 };
    (w, root)
}

/// Témoin de test à profondeur CONSENSUS (32) : mêmes notes que `witness_de_test`,
/// mais insérées dans un vrai arbre `ProvedMerkleTree::consensus()` → chemins de
/// longueur 32, `trace_len = 512`. Sert au fix de complétude BAL et au roundtrip lent.
#[cfg(test)]
pub(crate) fn witness_de_test_profondeur_consensus() -> (MonolithWitness, Digest) {
    use proved_hash::merkle::ProvedMerkleTree;
    use proved_hash::rescue;

    let secret = ShieldedSecret::from_felts(core::array::from_fn(|i| {
        Felt::from_canonical_u64(700 + i as u64).unwrap()
    }));
    let owner = rescue::hash(Domain::Owner, secret.as_felts());

    let n0 = SpendNote { value: 1_000, owner, rho: digest(20), r: digest(30) };
    let n1 = SpendNote { value: 500, owner, rho: digest(40), r: digest(50) };
    let cm0 = rescue::note_commitment(n0.value, &n0.owner, &n0.rho, &n0.r);
    let cm1 = rescue::note_commitment(n1.value, &n1.owner, &n1.rho, &n1.r);

    let mut tree = ProvedMerkleTree::consensus();
    let i0 = tree.append(&cm0);
    let i1 = tree.append(&cm1);
    let root = tree.root();
    let path0 = tree.path(i0).unwrap();
    let path1 = tree.path(i1).unwrap();

    let o0 = SpendNote { value: 900, owner: digest(60), rho: digest(61), r: digest(62) };
    let o1 = SpendNote { value: 580, owner: digest(70), rho: digest(71), r: digest(72) };
    let inputs = [
        ProvedInput { note: n0, path: path0, index: i0 },
        ProvedInput { note: n1, path: path1, index: i1 },
    ];
    let w = MonolithWitness { secret, inputs, outputs: [o0, o1], fee: 20 };
    (w, root)
}

// ================================================================================================
// FORGE (test white-box des liaisons) — #[cfg(test)]
// ================================================================================================

/// Point de forge d'une trace : réécrit UN côté d'une liaison porteuse↔gadget en
/// gardant le PRODUCTEUR (porteuse) honnête, pour qu'une trace forgée ne diffère
/// d'une trace honnête QUE par l'égalité de liaison ciblée. Chaque variante
/// documente le segment AVAL recalculé en cascade.
#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum Forge {
    /// Aucune forge : trace honnête (délègue à `build_monolith_trace`).
    Aucune,
    /// Owner CONSOMMÉ dans le commitment de l'entrée 0 ≠ owner produit par la clé.
    /// Aval recalculé : cm0, feuille0, nullifier0 et l'arbre (root/chemins).
    OwnerConsomme(Digest),
    /// Nk CONSOMMÉ dans le nullifier de l'entrée 0 ≠ nk produit par la clé.
    /// Aval recalculé : nullifier0 (nf change).
    NkConsomme(Digest),
    /// Rho CONSOMMÉ dans le nullifier de l'entrée `i` ≠ rho du commitment (porteuse).
    /// Aval recalculé : nullifier_i.
    RhoNullifier(usize, Digest),
    /// Cm CONSOMMÉ dans la feuille de l'entrée `i` ≠ cm produit par le commitment.
    /// Aval recalculé : feuille_i et l'arbre (root/chemins).
    CmFeuille(usize, Digest),
    /// Cm CONSOMMÉ dans le NULLIFIER de l'entrée `i` ≠ cm produit par le commitment
    /// (cellules cm@47, cols +15..+19 — DISJOINTES de rho@47 en +12..+15). C'est la
    /// liaison anti-double-dépense : sans elle, un nullifier peut être calculé sur un
    /// autre cm que celui réellement dépensé. Aval recalculé : nullifier_i (nf change) ;
    /// commitment/feuille/arbre amont honnêtes.
    CmNullifier(usize, Digest),
    /// Feuille INJECTÉE dans le chemin de l'entrée `i` ≠ feuille produite par le sponge.
    /// Aval recalculé : l'arbre (root/chemins) pour la feuille forgée.
    LeafChemin(usize, Digest),
    /// Valeur du bloc d'équilibre `i` ≠ value du commitment (porteuse VIN/VOUT).
    /// Aval recalculé : équilibre, avec compensation sur le bloc OPPOSÉ (entrée→
    /// sortie 0, sortie→entrée 0) pour garder `S_final = fee` (sinon l'assertion S
    /// rejette AVANT la liaison). NB : exerce donc DEUX gates à la fois (celui du
    /// bloc forgé + celui du bloc de compensation).
    ValeurBal(usize, u64),
    /// Valeur du bloc BAL 0 forgée, compensée sur le bloc BAL 1 — deux blocs
    /// d'ENTRÉE (même signe +) → Σ signée reste fee et SEULS les gates VIN[0]/VIN[1]
    /// diffèrent de leurs porteuses (les gates VOUT restent honnêtes) : isole la
    /// famille VIN de la famille VOUT.
    ValeurBalEntrees(u64),
}

/// Arbre de profondeur 2 à partir des FEUILLES injectées directement (idx 0 et 3,
/// deux feuilles muettes), miroir de `build_tree` mais sans re-hacher les cm — utilisé
/// par la forge pour reconstruire un arbre cohérent après réécriture d'une feuille.
#[cfg(test)]
fn build_tree_from_leaves(leaf0: &Digest, leaf1: &Digest) -> (Digest, Vec<Digest>, Vec<Digest>) {
    use proved_hash::merkle;
    let l0 = *leaf0;
    let l1 = merkle::leaf(&digest(9001));
    let l2 = merkle::leaf(&digest(9002));
    let l3 = *leaf1;
    let n_left = merkle::node(&l0, &l1);
    let n_right = merkle::node(&l2, &l3);
    let root = merkle::node(&n_left, &n_right);
    (root, vec![l1, n_right], vec![l2, n_left])
}

/// Construit une trace de monolithe (profondeur 2) avec une forge de liaison. La
/// trace reste SELF-consistante (segments valides, root partagée, équilibre =fee) :
/// seule l'égalité de liaison ciblée est violée. Les publics se relisent de la trace
/// forgée (comme `prove_monolith`) — c'est la CONTRAINTE de liaison, pas une
/// assertion, qui doit mordre.
#[cfg(test)]
pub(crate) fn build_monolith_trace_forge(w: &MonolithWitness, forge: Forge) -> TraceTable<BaseElement> {
    if let Forge::Aucune = forge {
        return build_monolith_trace(w);
    }
    let len = trace_len(2);
    let mut rows = vec![[BaseElement::ZERO; WIDTH]; len];

    // --- Clé (honnête) : owner/nk PRODUCTEURS dérivés du secret. ---
    let kr = key_rows(w.secret.as_felts());
    segment(&mut rows, &kr, 0, KEY_OFF);
    let owner = read_digest(&kr, kr.len() - 1, RATE_START);
    let nk = read_digest(&kr, kr.len() - 1, KEY_NK_LOCAL_OFF + RATE_START);
    let owner_be: [BaseElement; DIGEST_FELTS] = core::array::from_fn(|k| owner.0[k].to_winter());
    let nk_be: [BaseElement; DIGEST_FELTS] = core::array::from_fn(|k| nk.0[k].to_winter());
    for row in rows.iter_mut() {
        row[OWNER_C..OWNER_C + DIGEST_FELTS].copy_from_slice(&owner_be);
        row[NK_C..NK_C + DIGEST_FELTS].copy_from_slice(&nk_be);
    }

    // --- Entrées : segments avec hooks de forge ; collecte des feuilles pour l'arbre. ---
    let mut amounts = [0u64; 4];
    let mut leaves_tree = [digest(0); 2];
    for (i, u_off) in [U0_OFF, U1_OFF].into_iter().enumerate() {
        let note = &w.inputs[i].note;
        amounts[i] = note.value;

        // owner consommé dans le commitment (forge OwnerConsomme sur i==0).
        let owner_commit = match forge {
            Forge::OwnerConsomme(a) if i == 0 => a,
            _ => note.owner,
        };
        let commit_payload = note_commit_payload(note.value, &owner_commit, &note.rho, &note.r);
        let cm_rows = sponge_rows_for(Domain::NoteCommitment, &commit_payload);
        segment(&mut rows, &cm_rows, CM_ROWS_START, u_off);
        let cm = read_digest(&cm_rows, cm_rows.len() - 1, RATE_START); // CM_C producteur

        // cm consommé dans la feuille (forge CmFeuille).
        let cm_leaf = match forge {
            Forge::CmFeuille(fi, a) if fi == i => a,
            _ => cm,
        };
        let leaf_rows = sponge_rows_for(Domain::MerkleLeaf, &cm_leaf.0);
        segment(&mut rows, &leaf_rows, LEAF_ROWS_START, u_off);
        let leaf_d = read_digest(&leaf_rows, leaf_rows.len() - 1, RATE_START); // LEAF_C producteur

        // nk / rho consommés dans le nullifier (forges NkConsomme, RhoNullifier) ;
        // le cm consommé @47 reste honnête (pas de variante dédiée).
        let nk_nf = match forge {
            Forge::NkConsomme(a) if i == 0 => a,
            _ => nk,
        };
        let rho_nf = match forge {
            Forge::RhoNullifier(fi, a) if fi == i => a,
            _ => note.rho,
        };
        // cm consommé dans le nullifier (forge CmNullifier — cellules cm@47,
        // DISJOINTES de rho@47) ; commitment/feuille/porteuse CM_C restent honnêtes.
        let cm_nf = match forge {
            Forge::CmNullifier(fi, a) if fi == i => a,
            _ => cm,
        };
        let mut nf_payload = Vec::with_capacity(3 * DIGEST_FELTS);
        nf_payload.extend_from_slice(&nk_nf.0);
        nf_payload.extend_from_slice(&rho_nf.0);
        nf_payload.extend_from_slice(&cm_nf.0);
        let nf_rows = sponge_rows_for(Domain::Nullifier, &nf_payload);
        segment(&mut rows, &nf_rows, NF_ROWS_START, u_off);

        // feuille injectée dans le chemin (forge LeafChemin).
        leaves_tree[i] = match forge {
            Forge::LeafChemin(fi, a) if fi == i => a,
            _ => leaf_d,
        };

        // Porteuses (producteurs HONNÊTES : rho/cm/leaf/value de la note).
        let rho_be: [BaseElement; DIGEST_FELTS] = core::array::from_fn(|k| note.rho.0[k].to_winter());
        let cm_be: [BaseElement; DIGEST_FELTS] = core::array::from_fn(|k| cm.0[k].to_winter());
        let leaf_be: [BaseElement; DIGEST_FELTS] = core::array::from_fn(|k| leaf_d.0[k].to_winter());
        let vin = BaseElement::new(note.value);
        for row in rows.iter_mut() {
            row[RHO_C[i]..RHO_C[i] + DIGEST_FELTS].copy_from_slice(&rho_be);
            row[CM_C[i]..CM_C[i] + DIGEST_FELTS].copy_from_slice(&cm_be);
            row[LEAF_C[i]..LEAF_C[i] + DIGEST_FELTS].copy_from_slice(&leaf_be);
            row[VIN_C[i]] = vin;
        }
    }

    // --- Arbre reconstruit à partir des feuilles injectées → root/chemins cohérents. ---
    let (_root, path0, path1) = build_tree_from_leaves(&leaves_tree[0], &leaves_tree[1]);
    let m0 = crate::merkle_path::path_rows(&leaves_tree[0], &path0, 0);
    segment(&mut rows, &m0, 0, M0_OFF);
    let m1 = crate::merkle_path::path_rows(&leaves_tree[1], &path1, 3);
    segment(&mut rows, &m1, 0, M1_OFF);

    // --- Sorties (honnêtes). ---
    for (j, o_off) in [O0_OFF, O1_OFF].into_iter().enumerate() {
        let out = &w.outputs[j];
        amounts[2 + j] = out.value;
        let commit_payload = note_commit_payload(out.value, &out.owner, &out.rho, &out.r);
        let out_rows = sponge_rows_for(Domain::NoteCommitment, &commit_payload);
        segment(&mut rows, &out_rows, 0, o_off);
        let vout = BaseElement::new(out.value);
        for row in rows.iter_mut() {
            row[VOUT_C[j]] = vout;
        }
    }

    // --- Équilibre (forges de montants — S_final reste = fee dans les deux cas). ---
    match forge {
        // Bloc `i` forgé, compensation sur le côté OPPOSÉ (exerce 2 gates VIN+VOUT).
        Forge::ValeurBal(i, autre) => {
            let delta = autre as i128 - amounts[i] as i128;
            amounts[i] = autre;
            let comp = if i < 2 { 2 } else { 0 };
            amounts[comp] = (amounts[comp] as i128 + delta) as u64;
        }
        // Bloc 0 forgé, compensation sur le bloc 1 (même signe +) : SEULS les gates
        // VIN diffèrent — isolation de la famille VIN.
        Forge::ValeurBalEntrees(autre) => {
            let delta = autre as i128 - amounts[0] as i128;
            amounts[0] = autre;
            amounts[1] = (amounts[1] as i128 - delta) as u64;
        }
        _ => {}
    }
    fill_balance(&mut rows, amounts);

    let mut trace = TraceTable::new(WIDTH, len);
    for (i, row) in rows.iter().enumerate() {
        trace.update_row(i, row);
    }
    trace
}

#[cfg(test)]
mod tests {
    use super::*;
    use proved_hash::merkle;
    use proved_hash::rescue;
    use winterfell::Trace;

    /// Sanité différentielle hors-prouveur : les cellules de la trace du
    /// monolithe reproduisent les références calculées hors-circuit
    /// (`rescue::note_commitment`, `merkle::leaf`, `merkle::fold`), sans faire
    /// tourner aucun prouveur/AIR (tourne en DEBUG).
    #[test]
    fn trace_reproduit_les_references_hors_circuit() {
        let (w, root) = witness_de_test();
        let t = build_monolith_trace(&w);
        let d = |col: usize, row: usize| Felt::from_winter(t.get(col, row)).unwrap();

        // owner/nk produits par la clé (ligne 7) == hash hors-circuit.
        let owner = rescue::hash(Domain::Owner, w.secret.as_felts());
        for k in 0..4 {
            assert_eq!(d(KEY_OFF + 4 + k, 7), owner.0[k]);
        }

        // cm, leaf, nf de l'entrée 0 aux positions du layout.
        let n = &w.inputs[0].note;
        let cm = rescue::note_commitment(n.value, &n.owner, &n.rho, &n.r);
        for k in 0..4 {
            assert_eq!(d(U0_OFF + 4 + k, 31), cm.0[k]);
        }
        for k in 0..4 {
            assert_eq!(d(U0_OFF + 4 + k, 39), merkle::leaf(&cm).0[k]);
        }

        // racine au bout du chemin M0 == root de l'arbre.
        let last = t.length() - 1;
        for k in 0..4 {
            assert_eq!(
                d(M0_OFF + 4 + k, 16 * w.inputs[0].path.len() - 1),
                root.0[k]
            );
        }

        // porteuses constantes : mêmes valeurs ligne 0 et dernière ligne.
        for c in CARRIER_OFF..WIDTH {
            assert_eq!(t.get(c, 0), t.get(c, last));
        }

        // équilibre : S final == fee.
        assert_eq!(
            d(BAL_OFF + 1, last),
            Felt::from_canonical_u64(w.fee).unwrap()
        );
    }

    /// Fix de complétude BAL (revue T3) : à profondeur consensus (trace_len 512), la
    /// colonne `S` doit rester CONSTANTE (= fee) sur toute la traîne idle 256..512,
    /// et `VACC`/`bit` restent nuls — sinon la contrainte S non gatée rejette une
    /// trace honnête. Test NON-prouveur (lit les cellules ; tourne en DEBUG).
    #[test]
    fn bal_s_constant_sur_les_lignes_idle_profondeur_32() {
        let (w, _root) = witness_de_test_profondeur_consensus();
        let t = build_monolith_trace(&w);
        assert_eq!(t.length(), 512, "profondeur 32 → trace_len 512");
        let fee = Felt::from_canonical_u64(w.fee).unwrap();
        for row in 256..t.length() {
            assert_eq!(Felt::from_winter(t.get(BAL_OFF + BAL_S, row)).unwrap(), fee, "S@{row}");
            assert_eq!(t.get(BAL_OFF + BAL_BIT, row), BaseElement::ZERO, "bit@{row}");
            assert_eq!(t.get(BAL_OFF + BAL_VACC, row), BaseElement::ZERO, "VACC@{row}");
        }
        // Continuité à la frontière 255→256 : S[255] == S[256] == fee.
        assert_eq!(Felt::from_winter(t.get(BAL_OFF + BAL_S, 255)).unwrap(), fee);
    }
}
