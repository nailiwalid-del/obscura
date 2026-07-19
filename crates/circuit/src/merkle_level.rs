//! Gadget d'UN niveau de Merkle (3b2a) : swap conditionnel + `merge`.
//!
//! Prouve `parent = MerkleNode(swap(courant, frère, bit))`, avec
//! `(gauche, droite) = bit==0 ? (courant, frère) : (frère, courant)`, puis
//! `parent = merge(MerkleNode, gauche, droite)` (sponge B=2, réutilisé de 3b1).
//!
//! Le swap est réparti sur la trace : `l0..l3, r0` sont dans l'état de la ligne 0,
//! `r1..r3` dans les colonnes d'inject de la ligne 7. Deux flags périodiques (init0,
//! init7) portent les contraintes de swap. `courant`/`frère`/`bit` sont des colonnes
//! témoins constantes ; `bit` est contraint booléen.
//!
//! ⚠️ validity-only. Différentiel : `parent == proved_hash::merkle::node` (avec swap).

use crate::sponge::{
    enforce_sponge_transition, locate, sponge_rows, INJECT_START, RATE_START, TRACE_WIDTH,
};
use crate::ValidityProof;
use proved_hash::digest::{Digest, DIGEST_FELTS};
use proved_hash::domain::{sponge_preamble, Domain, ENCODING_VERSION};
use proved_hash::felt::Felt;
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;
use winterfell::crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree};
use winterfell::matrix::ColMatrix;
use winterfell::{
    AirContext, Assertion, AuxRandElements, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, EvaluationFrame, PartitionOptions, ProofOptions, Prover, StarkDomain, Trace,
    TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

type Blake3 = Blake3_256<BaseElement>;

const LEVEL_LEN: usize = 16; // merge = B=2
const WIDTH: usize = TRACE_WIDTH + 2 * DIGEST_FELTS + 1; // 20 + 4 (cur) + 4 (sib) + 1 (bit) = 29
const CUR_START: usize = TRACE_WIDTH; // 20
const SIB_START: usize = CUR_START + DIGEST_FELTS; // 24
const BIT_COL: usize = SIB_START + DIGEST_FELTS; // 28
const MERGE_M: usize = 12; // préambule merge : [VER, tag, 8, l0..3, r0..3, PAD_ONE]
const MERGE_LEN: u64 = (2 * DIGEST_FELTS) as u64; // payload = gauche ‖ droite = 8

// ================================================================================================
// TRACE
// ================================================================================================

fn build_level_trace(cur: &[Felt; 4], sib: &[Felt; 4], bit: bool) -> TraceTable<BaseElement> {
    let (left, right) = if bit { (sib, cur) } else { (cur, sib) };
    let mut payload = Vec::with_capacity(2 * DIGEST_FELTS);
    payload.extend_from_slice(left);
    payload.extend_from_slice(right);

    let preamble: Vec<BaseElement> = sponge_preamble(Domain::MerkleNode, &payload)
        .iter()
        .map(|f| f.to_winter())
        .collect();
    let sp_rows = sponge_rows(&preamble);
    debug_assert_eq!(sp_rows.len(), LEVEL_LEN);

    let cur_be: [BaseElement; 4] = core::array::from_fn(|i| cur[i].to_winter());
    let sib_be: [BaseElement; 4] = core::array::from_fn(|i| sib[i].to_winter());
    let bit_be = if bit { BaseElement::ONE } else { BaseElement::ZERO };

    let mut trace = TraceTable::new(WIDTH, LEVEL_LEN);
    for (i, sr) in sp_rows.iter().enumerate() {
        let mut row = [BaseElement::ZERO; WIDTH];
        row[..TRACE_WIDTH].copy_from_slice(sr);
        row[CUR_START..CUR_START + 4].copy_from_slice(&cur_be);
        row[SIB_START..SIB_START + 4].copy_from_slice(&sib_be);
        row[BIT_COL] = bit_be;
        trace.update_row(i, &row);
    }
    trace
}

// ================================================================================================
// AIR
// ================================================================================================

#[derive(Clone)]
pub struct MerkleLevelPublicInputs {
    pub parent: [BaseElement; DIGEST_FELTS],
}

impl winterfell::math::ToElements<BaseElement> for MerkleLevelPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        self.parent.to_vec()
    }
}

pub struct MerkleLevelAir {
    context: AirContext<BaseElement>,
    parent: [BaseElement; DIGEST_FELTS],
}

impl winterfell::Air for MerkleLevelAir {
    type BaseField = BaseElement;
    type PublicInputs = MerkleLevelPublicInputs;

    fn new(trace_info: TraceInfo, pi: MerkleLevelPublicInputs, options: ProofOptions) -> Self {
        let alpha = crate::rescue_round::ALPHA as usize;
        let mut degrees = Vec::with_capacity(30);
        // [0..12] sponge (rondes + absorption), masque round_flag cycle 8.
        for _ in 0..12 {
            degrees.push(TransitionConstraintDegree::with_cycles(alpha, vec![8]));
        }
        // [12] bit booléen — `bit` étant une colonne CONSTANTE (copies ci-dessous),
        // sa contrainte `bit·(bit−1)` mesure un degré 0 (comme les copies).
        degrees.push(TransitionConstraintDegree::new(1));
        // [13..22] copies (cur 4, sib 4, bit 1) — colonnes constantes, degré 0.
        for _ in 0..9 {
            degrees.push(TransitionConstraintDegree::new(1));
        }
        // [22..30] swap (5 ligne 0 + 3 ligne 7) : contre une colonne d'état évolutive
        // (degré trace ~15) × flag d'init. Degré mesuré = 15.
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::new(2));
        }
        // assertions : capacité (4) + VER/tag/LEN (3) + PAD_ONE (1) + digest (4).
        let num_assertions = 4 + 3 + 1 + DIGEST_FELTS;
        MerkleLevelAir {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            parent: pi.parent,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let next = frame.next();
        let round_flag = periodic_values[0];
        let ark1 = &periodic_values[1..13];
        let ark2 = &periodic_values[13..25];
        let init0 = periodic_values[25];
        let init7 = periodic_values[26];

        // [0..12] sponge.
        enforce_sponge_transition(cur, next, round_flag, ark1, ark2, &mut result[..12]);

        let bit = cur[BIT_COL];
        let one = E::ONE;
        let cur_d: [E; 4] = core::array::from_fn(|i| cur[CUR_START + i]);
        let sib_d: [E; 4] = core::array::from_fn(|i| cur[SIB_START + i]);
        // gauche_i / droite_i selon le bit.
        let left = |i: usize| cur_d[i] + bit * (sib_d[i] - cur_d[i]);
        let right = |i: usize| sib_d[i] + bit * (cur_d[i] - sib_d[i]);

        // [12] booléen.
        result[12] = bit * (bit - one);

        // [13..22] copies (colonnes témoins constantes).
        for i in 0..4 {
            result[13 + i] = next[CUR_START + i] - cur[CUR_START + i];
            result[17 + i] = next[SIB_START + i] - cur[SIB_START + i];
        }
        result[21] = next[BIT_COL] - cur[BIT_COL];

        // [22..26] swap ligne 0 : état[7..11] = gauche ; état[11] = droite_0.
        for i in 0..4 {
            result[22 + i] = init0 * (cur[RATE_START + 3 + i] - left(i));
        }
        result[26] = init0 * (cur[RATE_START + 7] - right(0));

        // [27..30] swap ligne 7 : inject[0..3] = droite_1..3.
        for j in 0..3 {
            result[27 + j] = init7 * (cur[INJECT_START + j] - right(1 + j));
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut a = Vec::with_capacity(4 + 3 + 1 + DIGEST_FELTS);
        // Capacité ligne 0 : [M, 0, 0, 0].
        a.push(Assertion::single(0, 0, BaseElement::new(MERGE_M as u64)));
        a.push(Assertion::single(1, 0, BaseElement::ZERO));
        a.push(Assertion::single(2, 0, BaseElement::ZERO));
        a.push(Assertion::single(3, 0, BaseElement::ZERO));
        // Préambule public : VER, tag, LEN, PAD_ONE (positions via locate).
        let put = |a: &mut Vec<Assertion<BaseElement>>, idx: usize, val: BaseElement| {
            let (row, col) = locate(idx);
            a.push(Assertion::single(col, row, val));
        };
        put(&mut a, 0, BaseElement::new(ENCODING_VERSION as u64));
        put(&mut a, 1, BaseElement::new(Domain::MerkleNode.tag() as u64));
        put(&mut a, 2, BaseElement::new(MERGE_LEN));
        put(&mut a, MERGE_M - 1, BaseElement::new(1)); // PAD_ONE
        // Digest = parent (dernière ligne). courant/frère/bit : JAMAIS assertés.
        let last = LEVEL_LEN - 1;
        for (i, d) in self.parent.iter().enumerate() {
            a.push(Assertion::single(RATE_START + i, last, *d));
        }
        a
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut round_flag = vec![BaseElement::ONE; 8];
        round_flag[7] = BaseElement::ZERO;
        let mut cols = Vec::with_capacity(27);
        cols.push(round_flag);
        cols.extend(crate::rescue_round::periodic_ark_columns());
        // init0 = 1 uniquement à la ligne 0 ; init7 = 1 uniquement à la ligne 7.
        let mut init0 = vec![BaseElement::ZERO; LEVEL_LEN];
        init0[0] = BaseElement::ONE;
        let mut init7 = vec![BaseElement::ZERO; LEVEL_LEN];
        init7[7] = BaseElement::ONE;
        cols.push(init0);
        cols.push(init7);
        cols
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

// ================================================================================================
// PROVER
// ================================================================================================

struct MerkleLevelProver {
    options: ProofOptions,
}

impl Prover for MerkleLevelProver {
    type BaseField = BaseElement;
    type Air = MerkleLevelAir;
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

    fn get_pub_inputs(&self, trace: &Self::Trace) -> MerkleLevelPublicInputs {
        let last = trace.length() - 1;
        let parent = core::array::from_fn(|i| trace.get(RATE_START + i, last));
        MerkleLevelPublicInputs { parent }
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

// ================================================================================================
// API PUBLIQUE
// ================================================================================================

/// Prouve un niveau de Merkle : `parent = MerkleNode(swap(courant, frère, bit))`.
pub fn prove_merkle_level(
    cur: &Digest,
    sib: &Digest,
    bit: bool,
) -> (Digest, ValidityProof) {
    let trace = build_level_trace(&cur.0, &sib.0, bit);
    let last = trace.length() - 1;
    let parent = Digest(core::array::from_fn(|i| {
        Felt::from_winter(trace.get(RATE_START + i, last)).expect("digest canonique")
    }));
    let prover = MerkleLevelProver {
        options: crate::proof_options(),
    };
    let proof = prover.prove(trace).expect("génération de preuve");
    (parent, ValidityProof(proof))
}

/// Vérifie une preuve de niveau de Merkle contre `parent` public.
pub fn verify_merkle_level(parent: &Digest, proof: &ValidityProof) -> bool {
    let pi = MerkleLevelPublicInputs {
        parent: core::array::from_fn(|i| parent.0[i].to_winter()),
    };
    let acceptable = winterfell::AcceptableOptions::MinConjecturedSecurity(95);
    winterfell::verify::<MerkleLevelAir, Blake3, DefaultRandomCoin<Blake3>, MerkleTree<Blake3>>(
        proof.0.clone(),
        pi,
        &acceptable,
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proved_hash::merkle;

    fn digest(seed: u64) -> Digest {
        Digest(core::array::from_fn(|i| {
            Felt::from_canonical_u64(seed + i as u64).unwrap()
        }))
    }

    /// Différentiel : le circuit reproduit `merkle::node` avec le bon ordre selon le bit.
    #[test]
    fn differentiel_swap_les_deux_bits() {
        let cur = digest(1);
        let sib = digest(100);
        for bit in [false, true] {
            let (parent, proof) = prove_merkle_level(&cur, &sib, bit);
            let attendu = if bit {
                merkle::node(&sib, &cur)
            } else {
                merkle::node(&cur, &sib)
            };
            assert_eq!(parent, attendu, "bit={bit} : divergence circuit ⟷ référence");
            assert!(verify_merkle_level(&parent, &proof));
        }
    }

    /// Le bit agit vraiment : bit 0 et bit 1 donnent des parents différents.
    #[test]
    fn le_bit_change_le_parent() {
        let cur = digest(5);
        let sib = digest(50);
        let (p0, _) = prove_merkle_level(&cur, &sib, false);
        let (p1, _) = prove_merkle_level(&cur, &sib, true);
        assert_ne!(p0, p1);
    }

    #[test]
    fn parent_altere_rejete() {
        let cur = digest(3);
        let sib = digest(30);
        let (parent, proof) = prove_merkle_level(&cur, &sib, false);
        assert!(verify_merkle_level(&parent, &proof), "roundtrip doit être vert");
        let mut faux = parent;
        faux.0[0] = Felt::from_canonical_u64(faux.0[0].as_u64() ^ 1).unwrap();
        assert!(!verify_merkle_level(&faux, &proof));
    }
}
